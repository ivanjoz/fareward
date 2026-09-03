//! SipHash-2-4, the keyed pseudo-random function behind this process's two *internal* tags: the
//! raw-TCP frame tag and the bridge's service-auth header. The browser session token deliberately
//! does not use it — see `bridge::auth`, where a user-held credential gets a 128-bit
//! keyed-BLAKE2s tag instead.
//!
//! It is a *keyed PRF for short messages*, not a general-purpose hash. Nothing here may be used
//! as a public digest or relied on for collision resistance without the key — all three call
//! sites authenticate with a shared secret and publish nothing, which is precisely the case
//! SipHash was designed for, and at 64 bits of tag it is what those sites already emitted when
//! they truncated HMAC-SHA256.
//!
//! Hand-written rather than pulled from a crate because the Go client mirrors it byte for byte and
//! `fareward/go` may not take a dependency: two implementations that must agree are easier to keep
//! honest when they read the same way. Both are pinned against the reference vectors from the
//! SipHash paper, so they agree for a stronger reason than a shared fixture.

use sha2::{Digest, Sha256};

/// The four constants SipHash initializes its state from: "somepseudorandomlygeneratedbytes".
const INIT_0: u64 = 0x736f_6d65_7073_6575;
const INIT_1: u64 = 0x646f_7261_6e64_6f6d;
const INIT_2: u64 = 0x6c79_6765_6e65_7261;
const INIT_3: u64 = 0x7465_6462_7974_6573;

/// A SipHash key: 128 bits, as the two little-endian halves the algorithm mixes into its state.
#[derive(Clone, Copy)]
pub struct Key {
    k0: u64,
    k1: u64,
}

/// Compresses a secret of any length into the 128 bits SipHash takes.
///
/// The project's secrets are configuration strings, not 16-byte keys, so they cannot be fed in
/// raw: a shorter one would need padding and a longer one would silently ignore everything past
/// its sixteenth byte. Hashing first means every byte of the secret reaches the key.
/// `go/siphash` mirrors this exactly — a difference here rejects every frame.
pub fn derive_key(secret: &[u8]) -> Key {
    let digest = Sha256::digest(secret);
    Key {
        k0: u64::from_le_bytes(digest[0..8].try_into().expect("SHA-256 yields 32 bytes")),
        k1: u64::from_le_bytes(digest[8..16].try_into().expect("SHA-256 yields 32 bytes")),
    }
}

/// Incremental SipHash-2-4.
///
/// Incremental because every call site tags several separate pieces — a domain string, a nonce, a
/// sequence, a payload — and a one-shot interface would force them to concatenate first, which for
/// `LOG_REQUEST` means copying up to 64 KiB per frame just to hash it.
pub struct SipHasher24 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    /// Bytes of the current 8-byte word that have not been compressed yet.
    tail: [u8; 8],
    tail_len: usize,
    /// Total message length; its low byte is the padding SipHash finalizes with, which is what
    /// keeps two messages differing only in trailing zeros apart.
    total_len: usize,
}

impl SipHasher24 {
    pub fn new(key: &Key) -> Self {
        Self {
            v0: key.k0 ^ INIT_0,
            v1: key.k1 ^ INIT_1,
            v2: key.k0 ^ INIT_2,
            v3: key.k1 ^ INIT_3,
            tail: [0; 8],
            tail_len: 0,
            total_len: 0,
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.total_len += bytes.len();
        let mut remaining = bytes;

        // Finish the partial word left by the previous write before consuming whole words.
        if self.tail_len > 0 {
            let taken = remaining.len().min(8 - self.tail_len);
            self.tail[self.tail_len..self.tail_len + taken].copy_from_slice(&remaining[..taken]);
            self.tail_len += taken;
            remaining = &remaining[taken..];
            if self.tail_len < 8 {
                return;
            }
            let word = u64::from_le_bytes(self.tail);
            self.compress(word);
            self.tail_len = 0;
        }

        let mut chunks = remaining.chunks_exact(8);
        for chunk in &mut chunks {
            let word = u64::from_le_bytes(chunk.try_into().expect("chunks_exact(8) yields 8 bytes"));
            self.compress(word);
        }

        let leftover = chunks.remainder();
        self.tail[..leftover.len()].copy_from_slice(leftover);
        self.tail_len = leftover.len();
    }

    pub fn finish(mut self) -> u64 {
        // The last word is the leftover bytes with the message length's low byte on top.
        let mut last_word = (self.total_len as u64 & 0xff) << 56;
        for (index, byte) in self.tail[..self.tail_len].iter().enumerate() {
            last_word |= (*byte as u64) << (8 * index);
        }
        self.compress(last_word);

        self.v2 ^= 0xff;
        for _ in 0..4 {
            self.round();
        }
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }

    /// One message word: two rounds between the two XORs. The "2" of SipHash-2-4.
    fn compress(&mut self, word: u64) {
        self.v3 ^= word;
        self.round();
        self.round();
        self.v0 ^= word;
    }

    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);

        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;

        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;

        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 64 reference vectors from the SipHash paper: key `00 01 … 0f`, message `00 01 … n-1`.
    /// `go/siphash/siphash_test.go` asserts the same list, so the two implementations are pinned
    /// to the specification rather than to each other.
    const REFERENCE_VECTORS: [u64; 64] = [
        0x726f_db47_dd0e_0e31,
        0x74f8_39c5_93dc_67fd,
        0x0d6c_8009_d9a9_4f5a,
        0x8567_6696_d7fb_7e2d,
        0xcf27_94e0_2771_87b7,
        0x1876_5564_cd99_a68d,
        0xcbc9_466e_58fe_e3ce,
        0xab02_00f5_8b01_d137,
        0x93f5_f579_9a93_2462,
        0x9e00_82df_0ba9_e4b0,
        0x7a5d_bbc5_94dd_b9f3,
        0xf4b3_2f46_226b_ada7,
        0x751e_8fbc_860e_e5fb,
        0x14ea_5627_c084_3d90,
        0xf723_ca90_8e7a_f2ee,
        0xa129_ca61_49be_45e5,
        0x3f2a_cc7f_57c2_9bdb,
        0x699a_e9f5_2cbe_4794,
        0x4bc1_b3f0_968d_d39c,
        0xbb6d_c91d_a779_61bd,
        0xbed6_5cf2_1aa2_ee98,
        0xd0f2_cbb0_2e3b_67c7,
        0x9353_6795_e3a3_3e88,
        0xa80c_038c_cd5c_cec8,
        0xb8ad_50c6_f649_af94,
        0xbce1_92de_8a85_b8ea,
        0x17d8_35b8_5bbb_15f3,
        0x2f2e_6163_076b_cfad,
        0xde4d_aaac_a71d_c9a5,
        0xa6a2_5066_8795_6571,
        0xad87_a353_5c49_ef28,
        0x32d8_92fa_d841_c342,
        0x7127_512f_72f2_7cce,
        0xa7f3_2346_f959_78e3,
        0x12e0_b01a_bb05_1238,
        0x15e0_34d4_0fa1_97ae,
        0x314d_ffbe_0815_a3b4,
        0x0279_90f0_2962_3981,
        0xcadc_d4e5_9ef4_0c4d,
        0x9abf_d876_6a33_735c,
        0x0e3e_a96b_5304_a7d0,
        0xad0c_42d6_fc58_5992,
        0x1873_06c8_9bc2_15a9,
        0xd4a6_0abc_f379_2b95,
        0xf935_451d_e4f2_1df2,
        0xa953_8f04_1975_5787,
        0xdb9a_cddf_f56c_a510,
        0xd06c_98cd_5c09_75eb,
        0xe612_a3cb_9ecb_a951,
        0xc766_e62c_fcad_af96,
        0xee64_435a_9752_fe72,
        0xa192_d576_b245_165a,
        0x0a87_87bf_8ecb_74b2,
        0x81b3_e73d_20b4_9b6f,
        0x7fa8_220b_a3b2_ecea,
        0x2457_31c1_3ca4_2499,
        0xb78d_bfaf_3a8d_83bd,
        0xea1a_d565_322a_1a0b,
        0x60e6_1c23_a379_5013,
        0x6606_d7e4_4628_2b93,
        0x6ca4_ecb1_5c5f_91e1,
        0x9f62_6da1_5c96_25f3,
        0xe51b_3860_8ef2_5f57,
        0x958a_324c_eb06_4572,
    ];

    fn siphash_of(key: &Key, message: &[u8]) -> u64 {
        let mut hasher = SipHasher24::new(key);
        hasher.write(message);
        hasher.finish()
    }

    #[test]
    fn matches_the_reference_vectors() {
        let key = Key {
            k0: u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]),
            k1: u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]),
        };
        for (length, expected) in REFERENCE_VECTORS.iter().enumerate() {
            let message: Vec<u8> = (0..length as u8).collect();
            assert_eq!(siphash_of(&key, &message), *expected, "length {length}");
        }
    }

    #[test]
    fn writing_in_pieces_matches_writing_at_once() {
        // Every call site feeds several chunks; splitting must not change the tag.
        let key = derive_key(b"test secret");
        let message: Vec<u8> = (0..200_u32).map(|byte| byte as u8).collect();
        let whole = siphash_of(&key, &message);
        for split in [0, 1, 7, 8, 9, 63, 64, 199, 200] {
            let mut hasher = SipHasher24::new(&key);
            hasher.write(&message[..split]);
            hasher.write(&message[split..]);
            assert_eq!(hasher.finish(), whole, "split at {split}");
        }
    }

    #[test]
    fn every_byte_of_the_secret_reaches_the_key() {
        // Raw 16-byte truncation would make these two secrets identical.
        let first = derive_key(b"0123456789abcdef-first");
        let second = derive_key(b"0123456789abcdef-second");
        assert_ne!(siphash_of(&first, b"message"), siphash_of(&second, b"message"));
    }
}
