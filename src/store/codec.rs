//! The store's binary layout: keys and values, nothing else (plan D7, "Encoding rules").
//!
//! - Keys are fixed-width big-endian with the sign bit flipped, so byte order is numeric order for
//!   negative and positive values alike, and every key of a company starts with its id: one
//!   company is one contiguous range.
//! - Every value starts with a format version, so a layout change is detected instead of misread.
//!
//! The report replies (`store::query`) reuse these value layouts verbatim, so the Go client decodes
//! one format per table rather than a second one for the wire.

use anyhow::{Result, bail};

use crate::limiter::block::Rejections;
use crate::limiter::credits_blob::Credits;
use crate::limiter::storage::{StoredBudget, StoredBudgetUsage, StoredExtraUsage};
use crate::sysmetrics::{MetricsSample, ServiceSample};

/// The version byte every value of this layout starts with.
pub const VALUE_VERSION: u8 = 1;

pub fn put_i16(buffer: &mut Vec<u8>, value: i16) {
    buffer.extend_from_slice(&((value as u16) ^ 0x8000).to_be_bytes());
}

pub fn put_i32(buffer: &mut Vec<u8>, value: i32) {
    buffer.extend_from_slice(&((value as u32) ^ 0x8000_0000).to_be_bytes());
}

pub fn read_key_i16(bytes: &[u8]) -> i16 {
    (u16::from_be_bytes([bytes[0], bytes[1]]) ^ 0x8000) as i16
}

pub fn read_key_i32(bytes: &[u8]) -> i32 {
    (u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) ^ 0x8000_0000) as i32
}

/// `usage_company`: `[company_id][time_frame]`.
pub fn company_usage_key(company_id: i32, time_frame: i32) -> Vec<u8> {
    let mut key = Vec::with_capacity(8);
    put_i32(&mut key, company_id);
    put_i32(&mut key, time_frame);
    key
}

/// `usage_user`: `[company_id][user_id][time_frame]`.
pub fn user_usage_key(company_id: i32, user_id: i32, time_frame: i32) -> Vec<u8> {
    let mut key = Vec::with_capacity(12);
    put_i32(&mut key, company_id);
    put_i32(&mut key, user_id);
    put_i32(&mut key, time_frame);
    key
}

/// `budget`: `[company_id]`.
pub fn budget_key(company_id: i32) -> Vec<u8> {
    let mut key = Vec::with_capacity(4);
    put_i32(&mut key, company_id);
    key
}

/// `server_metrics`: `[date][slot]`. Not a company table, so the key starts with the day and the
/// retention purge deletes a prefix range.
pub fn metrics_key(date: i16, slot: i16) -> Vec<u8> {
    let mut key = Vec::with_capacity(4);
    put_i16(&mut key, date);
    put_i16(&mut key, slot);
    key
}

/// One `usage_company` value: the refusal counters (D9) and the credits blob (`credits_blob.rs`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompanyUsageValue {
    pub rejections: Rejections,
    pub used_credits: Vec<u8>,
}

/// `[version][rejected_short:u32][rejected_long:u32][rejected_no_funds:u32][used_credits…]`
pub const COMPANY_USAGE_HEAD: usize = 1 + 3 * 4;

impl CompanyUsageValue {
    pub fn encode(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(COMPANY_USAGE_HEAD + self.used_credits.len());
        value.push(VALUE_VERSION);
        value.extend_from_slice(&self.rejections.short.to_be_bytes());
        value.extend_from_slice(&self.rejections.long.to_be_bytes());
        value.extend_from_slice(&self.rejections.no_funds.to_be_bytes());
        value.extend_from_slice(&self.used_credits);
        value
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        if value.len() < COMPANY_USAGE_HEAD || value[0] != VALUE_VERSION {
            bail!("usage_company value has an unknown layout");
        }
        let counter = |offset: usize| {
            u32::from_be_bytes([
                value[offset],
                value[offset + 1],
                value[offset + 2],
                value[offset + 3],
            ])
        };
        Ok(Self {
            rejections: Rejections {
                short: counter(1),
                long: counter(5),
                no_funds: counter(9),
            },
            used_credits: value[COMPANY_USAGE_HEAD..].to_vec(),
        })
    }
}

/// `usage_user`: `[version][used_credits…]`.
pub fn encode_user_usage(used_credits: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(1 + used_credits.len());
    value.push(VALUE_VERSION);
    value.extend_from_slice(used_credits);
    value
}

pub fn decode_user_usage(value: &[u8]) -> Result<Vec<u8>> {
    match value.split_first() {
        Some((&VALUE_VERSION, used_credits)) => Ok(used_credits.to_vec()),
        _ => bail!("usage_user value has an unknown layout"),
    }
}

/// One company's whole budget: the entitlement the panel sets and the usage counters the flush
/// publishes. One value because Fareward is now its only writer; the two halves are still written
/// by two separate calls, each replacing only its own half (`FjallStore` holds a lock across the
/// read-modify-write).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BudgetRecord {
    pub budget: StoredBudget,
    pub usage: StoredBudgetUsage,
}

/// Fixed width: version, twelve u64 credit figures, three i16 days and two i32 timestamps.
pub const BUDGET_VALUE_SIZE: usize = 1 + 12 * 8 + 3 * 2 + 2 * 4;

impl BudgetRecord {
    /// The fields in this order, all big-endian:
    ///
    /// ```text
    /// version u8
    /// daily_cpu u64, daily_inference u64, budget_month_start_day i16,
    /// monthly_cpu_ceiling u64, monthly_inference_ceiling u64,
    /// last_set_cpu u64, last_set_inference u64, updated i32,
    /// usage_day_period i16, day_cpu_used u64, day_inference_used u64,
    /// usage_month_start_day i16, month_cpu_used u64, month_inference_used u64,
    /// day_extra_cpu_used u64, month_extra_cpu_used u64, usage_updated i32
    /// ```
    ///
    /// u64 rather than the plan's u32: an entitlement is not a usage blob, and the panel and the
    /// load tests set budgets far past four billion.
    pub fn encode(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(BUDGET_VALUE_SIZE);
        let budget = &self.budget;
        let usage = &self.usage;
        value.push(VALUE_VERSION);
        value.extend_from_slice(&budget.daily.cpu.to_be_bytes());
        value.extend_from_slice(&budget.daily.inference.to_be_bytes());
        value.extend_from_slice(&budget.budget_month_start_day.to_be_bytes());
        value.extend_from_slice(&budget.monthly_ceiling.cpu.to_be_bytes());
        value.extend_from_slice(&budget.monthly_ceiling.inference.to_be_bytes());
        value.extend_from_slice(&budget.last_set.cpu.to_be_bytes());
        value.extend_from_slice(&budget.last_set.inference.to_be_bytes());
        value.extend_from_slice(&budget.updated.to_be_bytes());
        value.extend_from_slice(&usage.day_period.to_be_bytes());
        value.extend_from_slice(&usage.day_used.cpu.to_be_bytes());
        value.extend_from_slice(&usage.day_used.inference.to_be_bytes());
        value.extend_from_slice(&usage.month_start_day.to_be_bytes());
        value.extend_from_slice(&usage.month_used.cpu.to_be_bytes());
        value.extend_from_slice(&usage.month_used.inference.to_be_bytes());
        value.extend_from_slice(&usage.day_extra_cpu.to_be_bytes());
        value.extend_from_slice(&usage.month_extra_cpu.to_be_bytes());
        value.extend_from_slice(&usage.updated.to_be_bytes());
        debug_assert_eq!(value.len(), BUDGET_VALUE_SIZE);
        value
    }

    pub fn decode(company_id: i32, value: &[u8]) -> Result<Self> {
        if value.len() != BUDGET_VALUE_SIZE || value[0] != VALUE_VERSION {
            bail!("budget value of company {company_id} has an unknown layout");
        }
        let mut reader = Reader {
            bytes: value,
            offset: 1,
        };
        let daily = Credits {
            cpu: reader.u64(),
            inference: reader.u64(),
        };
        let budget_month_start_day = reader.i16();
        let monthly_ceiling = Credits {
            cpu: reader.u64(),
            inference: reader.u64(),
        };
        let last_set = Credits {
            cpu: reader.u64(),
            inference: reader.u64(),
        };
        let updated = reader.i32();
        let day_period = reader.i16();
        let day_used = Credits {
            cpu: reader.u64(),
            inference: reader.u64(),
        };
        let month_start_day = reader.i16();
        let month_used = Credits {
            cpu: reader.u64(),
            inference: reader.u64(),
        };
        let day_extra_cpu = reader.u64();
        let month_extra_cpu = reader.u64();
        let usage_updated = reader.i32();
        Ok(Self {
            budget: StoredBudget {
                company_id,
                daily,
                budget_month_start_day,
                monthly_ceiling,
                last_set,
                updated,
            },
            usage: StoredBudgetUsage {
                company_id,
                day_period,
                day_used,
                month_start_day,
                month_used,
                day_extra_cpu,
                month_extra_cpu,
                updated: usage_updated,
            },
        })
    }

    /// The extra-pool half the limiter reloads at cold start.
    pub fn extra(&self) -> StoredExtraUsage {
        StoredExtraUsage {
            day_period: self.usage.day_period,
            day_cpu: self.usage.day_extra_cpu,
            month_start_day: self.usage.month_start_day,
            month_cpu: self.usage.month_extra_cpu,
        }
    }
}

/// `server_metrics`: `[version]` then the eleven columns of `MetricsSample`, i16 each.
pub const METRICS_VALUE_SIZE: usize = 1 + 11 * 2;

pub fn encode_metrics(sample: &MetricsSample) -> Vec<u8> {
    let mut value = Vec::with_capacity(METRICS_VALUE_SIZE);
    value.push(VALUE_VERSION);
    for field in metrics_fields(sample) {
        value.extend_from_slice(&field.to_be_bytes());
    }
    value
}

pub fn decode_metrics(value: &[u8]) -> Result<MetricsSample> {
    if value.len() != METRICS_VALUE_SIZE || value[0] != VALUE_VERSION {
        bail!("server_metrics value has an unknown layout");
    }
    let mut reader = Reader {
        bytes: value,
        offset: 1,
    };
    Ok(MetricsSample {
        cpu_percent: reader.i16(),
        memory_percent: reader.i16(),
        disk_percent: reader.i16(),
        network_rx_rate: reader.i16(),
        network_tx_rate: reader.i16(),
        backend: ServiceSample {
            memory_mb: reader.i16(),
            cpu_percent: reader.i16(),
        },
        fareward: ServiceSample {
            memory_mb: reader.i16(),
            cpu_percent: reader.i16(),
        },
        scylla: ServiceSample {
            memory_mb: reader.i16(),
            cpu_percent: reader.i16(),
        },
    })
}

/// The column order of a metrics value. `scylla` is the database unit's sample, whatever it is.
fn metrics_fields(sample: &MetricsSample) -> [i16; 11] {
    [
        sample.cpu_percent,
        sample.memory_percent,
        sample.disk_percent,
        sample.network_rx_rate,
        sample.network_tx_rate,
        sample.backend.memory_mb,
        sample.backend.cpu_percent,
        sample.fareward.memory_mb,
        sample.fareward.cpu_percent,
        sample.scylla.memory_mb,
        sample.scylla.cpu_percent,
    ]
}

/// Reads the fixed-width values above. Only ever handed a value whose length was checked first.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0_u8; N];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + N]);
        self.offset += N;
        out
    }
    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take())
    }
    fn i32(&mut self) -> i32 {
        i32::from_be_bytes(self.take())
    }
    fn i16(&mut self) -> i16 {
        i16::from_be_bytes(self.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sort_numerically_across_the_sign() {
        let mut keys = [-5, -1, 0, 1, 7, i32::MIN, i32::MAX].map(|company| budget_key(company));
        keys.sort();
        let decoded: Vec<i32> = keys.iter().map(|key| read_key_i32(key)).collect();
        assert_eq!(decoded, [i32::MIN, -5, -1, 0, 1, 7, i32::MAX]);

        let mut metric_keys = [(3, 2), (-1, 9), (3, -4), (0, 0)].map(|(d, s)| metrics_key(d, s));
        metric_keys.sort();
        let decoded: Vec<(i16, i16)> = metric_keys
            .iter()
            .map(|key| (read_key_i16(&key[..2]), read_key_i16(&key[2..])))
            .collect();
        assert_eq!(decoded, [(-1, 9), (0, 0), (3, -4), (3, 2)]);
    }

    /// A company's rows are one contiguous range, users and frames inside it in order.
    #[test]
    fn a_company_prefixes_all_of_its_keys() {
        let prefix = budget_key(42);
        assert!(company_usage_key(42, 200_000_100).starts_with(&prefix));
        assert!(user_usage_key(42, 7, 100_000_000).starts_with(&prefix));
        assert!(user_usage_key(42, 7, 5) < user_usage_key(42, 8, 1));
    }

    #[test]
    fn values_round_trip() {
        let company = CompanyUsageValue {
            rejections: Rejections {
                short: 3,
                long: 70_000,
                no_funds: 1,
            },
            used_credits: vec![0, 4, 1, 2],
        };
        assert_eq!(
            CompanyUsageValue::decode(&company.encode()).unwrap(),
            company
        );
        assert_eq!(
            decode_user_usage(&encode_user_usage(&[9, 8])).unwrap(),
            [9, 8]
        );

        let record = BudgetRecord {
            budget: StoredBudget {
                company_id: 7,
                daily: Credits {
                    cpu: 1 << 40,
                    inference: 2,
                },
                budget_month_start_day: 20_390,
                monthly_ceiling: Credits {
                    cpu: 3,
                    inference: 4,
                },
                last_set: Credits {
                    cpu: 5,
                    inference: 6,
                },
                updated: 1_760_000_000,
            },
            usage: StoredBudgetUsage {
                company_id: 7,
                day_period: 20_400,
                day_used: Credits {
                    cpu: 8,
                    inference: 9,
                },
                month_start_day: 20_390,
                month_used: Credits {
                    cpu: 10,
                    inference: 11,
                },
                day_extra_cpu: 12,
                month_extra_cpu: 13,
                updated: -1,
            },
        };
        let encoded = record.encode();
        assert_eq!(encoded.len(), BUDGET_VALUE_SIZE);
        assert_eq!(BudgetRecord::decode(7, &encoded).unwrap(), record);

        let sample = MetricsSample {
            cpu_percent: 2_345,
            ..MetricsSample::default()
        };
        assert_eq!(decode_metrics(&encode_metrics(&sample)).unwrap(), sample);
    }

    #[test]
    fn an_unknown_version_is_refused() {
        assert!(CompanyUsageValue::decode(&[2; COMPANY_USAGE_HEAD]).is_err());
        assert!(decode_user_usage(&[]).is_err());
        assert!(BudgetRecord::decode(1, &[0; BUDGET_VALUE_SIZE]).is_err());
        assert!(decode_metrics(&[1; 3]).is_err());
    }
}
