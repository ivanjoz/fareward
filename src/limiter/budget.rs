//! Company credit-budget mutation codec for opcode `0x05`.

use colbin::Colbin;
use thiserror::Error;

use crate::limiter::credits_blob::Credits;

/// Ceiling on one budget payload, and therefore on what a client can make the daemon buffer before
/// its tag has been verified. Four fields at their widest: a key and a nine-byte descriptor run for
/// each of the two `u64`, five for the `i32`, two for the operation byte, plus the root.
pub const MUTATE_BUDGET_MAX_PAYLOAD_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BudgetOperation {
    SetDaily = 1,
    SetCurrent = 2,
    IncreaseCurrent = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetMutation {
    pub company_id: i32,
    pub operation: BudgetOperation,
    pub credits: Credits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BudgetMutationReply {
    Ok = 0,
    CurrentMonthNotConfigured = 1,
    Overflow = 2,
}

/// The frame as colbin carries it. Mirrors `budgetMutationFrame` in fareward/go/budgets.go.
#[derive(Colbin, Debug, Default, PartialEq, Eq)]
pub struct BudgetMutationFrame {
    #[cb(1)]
    pub company_id: i32,
    #[cb(2)]
    pub operation: u8,
    #[cb(3)]
    pub cpu: u64,
    #[cb(4)]
    pub inference: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BudgetProtocolError {
    #[error("budget payload is not a valid colbin message: {0}")]
    Malformed(#[from] colbin::Error),
    #[error("company_id must be positive")]
    InvalidCompany,
    #[error("unknown budget operation {0}")]
    InvalidOperation(u8),
    #[error("credit budget values must fit signed 64-bit database columns")]
    CreditOverflow,
}

/// Decodes one budget mutation.
///
/// The codec answers what the frame said; the checks below are protocol rules, which is why they
/// stay here rather than moving into the struct. An absent field is a zero — colbin does not write
/// one — so `InvalidCompany` is also what an empty payload gets.
pub fn parse_budget_mutation(payload: &[u8]) -> Result<BudgetMutation, BudgetProtocolError> {
    let frame = BudgetMutationFrame::decode(payload)?;
    if frame.company_id <= 0 {
        return Err(BudgetProtocolError::InvalidCompany);
    }
    let operation = match frame.operation {
        1 => BudgetOperation::SetDaily,
        2 => BudgetOperation::SetCurrent,
        3 => BudgetOperation::IncreaseCurrent,
        value => return Err(BudgetProtocolError::InvalidOperation(value)),
    };
    if frame.cpu > i64::MAX as u64 || frame.inference > i64::MAX as u64 {
        return Err(BudgetProtocolError::CreditOverflow);
    }

    Ok(BudgetMutation {
        company_id: frame.company_id,
        operation,
        credits: Credits {
            cpu: frame.cpu,
            inference: frame.inference,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(frame: BudgetMutationFrame) -> Vec<u8> {
        frame.encode()
    }

    #[test]
    fn parses_a_budget_frame() {
        let payload = encoded(BudgetMutationFrame {
            company_id: 0x12_34_56,
            operation: BudgetOperation::IncreaseCurrent as u8,
            cpu: 300,
            inference: 25,
        });

        assert_eq!(
            parse_budget_mutation(&payload).unwrap(),
            BudgetMutation {
                company_id: 0x12_34_56,
                operation: BudgetOperation::IncreaseCurrent,
                credits: Credits {
                    cpu: 300,
                    inference: 25,
                },
            }
        );
    }

    /// The reason this shape moved to a codec: a mutation that names one resource does not carry
    /// the other at all, where the fixed layout spent eight bytes saying zero.
    #[test]
    fn a_zero_field_costs_nothing_and_comes_back_zero() {
        let payload = encoded(BudgetMutationFrame {
            company_id: 7,
            operation: BudgetOperation::SetDaily as u8,
            cpu: 300,
            inference: 0,
        });
        assert!(
            payload.len() <= 12,
            "a one-resource mutation is {} bytes",
            payload.len()
        );
        let mutation = parse_budget_mutation(&payload).unwrap();
        assert_eq!(mutation.credits.inference, 0);
        assert_eq!(mutation.credits.cpu, 300);
    }

    #[test]
    fn refuses_a_frame_that_names_no_company_or_no_operation() {
        // An empty message: every field absent, so every field is zero.
        let empty = encoded(BudgetMutationFrame::default());
        assert_eq!(
            parse_budget_mutation(&empty),
            Err(BudgetProtocolError::InvalidCompany)
        );

        let payload = encoded(BudgetMutationFrame {
            company_id: 7,
            operation: 9,
            cpu: 1,
            inference: 0,
        });
        assert_eq!(
            parse_budget_mutation(&payload),
            Err(BudgetProtocolError::InvalidOperation(9))
        );
    }

    /// Bytes that are not a colbin message are refused by the codec rather than read as offsets,
    /// which is what the hand-written parser could not do — every twenty bytes were a valid frame.
    #[test]
    fn refuses_a_payload_that_is_not_colbin() {
        assert!(matches!(
            parse_budget_mutation(&[0x00; 20]),
            Err(BudgetProtocolError::Malformed(_))
        ));
    }

    /// The ceiling has to cover the widest frame the encoder can produce, or the widest legitimate
    /// frame is refused as oversized.
    #[test]
    fn the_ceiling_covers_the_widest_frame() {
        let widest = encoded(BudgetMutationFrame {
            company_id: i32::MAX,
            operation: 3,
            cpu: i64::MAX as u64,
            inference: i64::MAX as u64,
        });
        assert!(
            widest.len() <= MUTATE_BUDGET_MAX_PAYLOAD_SIZE,
            "widest budget frame is {} bytes, ceiling is {MUTATE_BUDGET_MAX_PAYLOAD_SIZE}",
            widest.len()
        );
    }
}
