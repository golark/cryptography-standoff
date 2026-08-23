use super::sha256::{BLOCK_SIZE, DIGEST_SIZE};

#[cfg(target_arch = "aarch64")]
mod accel {
    use super::{BLOCK_SIZE, DIGEST_SIZE};
    use std::arch::aarch64::*;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    const H_INIT: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // ARMv8 Crypto Extensions pattern mirroring c/src/sha256_neon.c:
    // vsha256hq/vsha256h2q advance 4 rounds each; vsha256su0q/vsha256su1q
    // expand the message schedule one group ahead of the rounds.
    #[allow(unused_assignments)]
    unsafe fn process_blocks(state: &mut [u32; 8], mut data: *const u8, nblocks: usize) {
        let kptr = K.as_ptr();
        let mut state0 = vld1q_u32(state.as_ptr());
        let mut state1 = vld1q_u32(state.as_ptr().add(4));

        for _ in 0..nblocks {
            let abef_save = state0;
            let cdgh_save = state1;

            let mut msg0 = vld1q_u32(data.cast::<u32>());
            let mut msg1 = vld1q_u32(data.add(16).cast::<u32>());
            let mut msg2 = vld1q_u32(data.add(32).cast::<u32>());
            let mut msg3 = vld1q_u32(data.add(48).cast::<u32>());

            msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
            msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
            msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
            msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));

            let mut tmp0 = vaddq_u32(msg0, vld1q_u32(kptr));
            let mut tmp1: uint32x4_t;
            let mut tmp2: uint32x4_t;

            tmp2 = state0;
            tmp1 = vaddq_u32(msg1, vld1q_u32(kptr.add(0x04)));
            state0 = vsha256hq_u32(state0, state1, tmp0);
            state1 = vsha256h2q_u32(state1, tmp2, tmp0);
            msg0 = vsha256su1q_u32(vsha256su0q_u32(msg0, msg1), msg2, msg3);

            tmp2 = state0;
            tmp0 = vaddq_u32(msg2, vld1q_u32(kptr.add(0x08)));
            state0 = vsha256hq_u32(state0, state1, tmp1);
            state1 = vsha256h2q_u32(state1, tmp2, tmp1);
            msg1 = vsha256su1q_u32(vsha256su0q_u32(msg1, msg2), msg3, msg0);

            tmp2 = state0;
            tmp1 = vaddq_u32(msg3, vld1q_u32(kptr.add(0x0c)));
            state0 = vsha256hq_u32(state0, state1, tmp0);
            state1 = vsha256h2q_u32(state1, tmp2, tmp0);
            msg2 = vsha256su1q_u32(vsha256su0q_u32(msg2, msg3), msg0, msg1);

            tmp2 = state0;
            tmp0 = vaddq_u32(msg0, vld1q_u32(kptr.add(0x10)));
            state0 = vsha256hq_u32(state0, state1, tmp1);
            state1 = vsha256h2q_u32(state1, tmp2, tmp1);
            msg3 = vsha256su1q_u32(vsha256su0q_u32(msg3, msg0), msg1, msg2);

            tmp2 = state0;
            tmp1 = vaddq_u32(msg1, vld1q_u32(kptr.add(0x14)));
            state0 = vsha256hq_u32(state0, state1, tmp0);
            state1 = vsha256h2q_u32(state1, tmp2, tmp0);
            msg0 = vsha256su1q_u32(vsha256su0q_u32(msg0, msg1), msg2, msg3);

            tmp2 = state0;
            tmp0 = vaddq_u32(msg2, vld1q_u32(kptr.add(0x18)));
            state0 = vsha256hq_u32(state0, state1, tmp1);
            state1 = vsha256h2q_u32(state1, tmp2, tmp1);
            msg1 = vsha256su1q_u32(vsha256su0q_u32(msg1, msg2), msg3, msg0);

            tmp2 = state0;
            tmp1 = vaddq_u32(msg3, vld1q_u32(kptr.add(0x1c)));
            state0 = vsha256hq_u32(state0, state1, tmp0);
            state1 = vsha256h2q_u32(state1, tmp2, tmp0);
            msg2 = vsha256su1q_u32(vsha256su0q_u32(msg2, msg3), msg0, msg1);

            tmp2 = state0;
            tmp0 = vaddq_u32(msg0, vld1q_u32(kptr.add(0x20)));
            state0 = vsha256hq_u32(state0, state1, tmp1);
            state1 = vsha256h2q_u32(state1, tmp2, tmp1);
            msg3 = vsha256su1q_u32(vsha256su0q_u32(msg3, msg0), msg1, msg2);

            tmp2 = state0;
            tmp1 = vaddq_u32(msg1, vld1q_u32(kptr.add(0x24)));
            state0 = vsha256hq_u32(state0, state1, tmp0);
            state1 = vsha256h2q_u32(state1, tmp2, tmp0);
            msg0 = vsha256su1q_u32(vsha256su0q_u32(msg0, msg1), msg2, msg3);

            tmp2 = state0;
            tmp0 = vaddq_u32(msg2, vld1q_u32(kptr.add(0x28)));
            state0 = vsha256hq_u32(state0, state1, tmp1);
            state1 = vsha256h2q_u32(state1, tmp2, tmp1);
            msg1 = vsha256su1q_u32(vsha256su0q_u32(msg1, msg2), msg3, msg0);

            tmp2 = state0;
            tmp1 = vaddq_u32(msg3, vld1q_u32(kptr.add(0x2c)));
            state0 = vsha256hq_u32(state0, state1, tmp0);
            state1 = vsha256h2q_u32(state1, tmp2, tmp0);
            msg2 = vsha256su1q_u32(vsha256su0q_u32(msg2, msg3), msg0, msg1);

            tmp2 = state0;
            tmp0 = vaddq_u32(msg0, vld1q_u32(kptr.add(0x30)));
            state0 = vsha256hq_u32(state0, state1, tmp1);
            state1 = vsha256h2q_u32(state1, tmp2, tmp1);
            msg3 = vsha256su1q_u32(vsha256su0q_u32(msg3, msg0), msg1, msg2);

            tmp2 = state0;
            tmp1 = vaddq_u32(msg1, vld1q_u32(kptr.add(0x34)));
            state0 = vsha256hq_u32(state0, state1, tmp0);
            state1 = vsha256h2q_u32(state1, tmp2, tmp0);

            tmp2 = state0;
            tmp0 = vaddq_u32(msg2, vld1q_u32(kptr.add(0x38)));
            state0 = vsha256hq_u32(state0, state1, tmp1);
            state1 = vsha256h2q_u32(state1, tmp2, tmp1);

            tmp2 = state0;
            tmp1 = vaddq_u32(msg3, vld1q_u32(kptr.add(0x3c)));
            state0 = vsha256hq_u32(state0, state1, tmp0);
            state1 = vsha256h2q_u32(state1, tmp2, tmp0);

            tmp2 = state0;
            state0 = vsha256hq_u32(state0, state1, tmp1);
            state1 = vsha256h2q_u32(state1, tmp2, tmp1);

            state0 = vaddq_u32(state0, abef_save);
            state1 = vaddq_u32(state1, cdgh_save);

            data = data.add(BLOCK_SIZE);
        }

        vst1q_u32(state.as_mut_ptr(), state0);
        vst1q_u32(state.as_mut_ptr().add(4), state1);
    }

    pub fn sha256_neon(data: &[u8], digest: &mut [u8; DIGEST_SIZE]) {
        let mut state = H_INIT;

        let nblocks = data.len() / BLOCK_SIZE;
        if nblocks > 0 {
            unsafe {
                process_blocks(&mut state, data.as_ptr(), nblocks);
            }
        }

        // Padding: msg || 0x80 || zeros || 64-bit BE bit-length (FIPS 180-4 5.1.1)
        let rem = data.len() % BLOCK_SIZE;
        let mut tail = [0u8; 2 * BLOCK_SIZE];
        tail[..rem].copy_from_slice(&data[nblocks * BLOCK_SIZE..]);
        tail[rem] = 0x80;

        let npad = if rem < 56 { 1 } else { 2 };
        let bit_len = (data.len() as u64).wrapping_mul(8);
        for i in 0..8 {
            tail[npad * BLOCK_SIZE - 1 - i] = (bit_len >> (8 * i)) as u8;
        }
        unsafe {
            process_blocks(&mut state, tail.as_ptr(), npad);
        }

        for i in 0..8 {
            digest[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub use accel::sha256_neon;

#[cfg(not(target_arch = "aarch64"))]
pub fn sha256_neon(data: &[u8], digest: &mut [u8; DIGEST_SIZE]) {
    crate::sha256::sha256(data, digest);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::hex_digest;

    fn hash_str(s: &str) -> String {
        let mut d = [0u8; DIGEST_SIZE];
        sha256_neon(s.as_bytes(), &mut d);
        hex_digest(&d)
    }

    #[test]
    fn kat_empty() {
        assert_eq!(
            hash_str(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn kat_abc() {
        assert_eq!(
            hash_str("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn kat_padding_boundary_two_blocks() {
        assert_eq!(
            hash_str(&"b".repeat(56)),
            "a5fc6e203a4c2b657d0d153885932414b2ffc6a93f0f8bf8b3183315e5a7212c"
        );
    }

    #[test]
    fn kat_padding_boundary_single_block_max() {
        assert_eq!(
            hash_str(&"a".repeat(55)),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
    }

    #[test]
    fn kat_multiblock() {
        assert_eq!(
            hash_str(&"The quick brown fox jumps over the lazy dog".repeat(37)),
            "4691d2d1be75b3a135f28ba923c396a1856e35e29b7de22b4f39f0b2c40291c6"
        );
    }
}
