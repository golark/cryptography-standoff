pub const BLOCK_SIZE: usize = 64;
pub const DIGEST_SIZE: usize = 32;

const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// First 32 bits of the fractional parts of the cube roots of the first
// 64 primes (FIPS 180-4 section 4.2.2)
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

#[inline(always)]
fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

// FIPS 180-4 section 4.1.2
#[inline(always)]
fn sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

#[inline(always)]
fn sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

#[inline(always)]
fn eps0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

#[inline(always)]
fn eps1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];

    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[t * 4],
            block[t * 4 + 1],
            block[t * 4 + 2],
            block[t * 4 + 3],
        ]);
    }
    for t in 16..64 {
        w[t] = w[t - 16]
            .wrapping_add(sigma0(w[t - 15]))
            .wrapping_add(w[t - 7])
            .wrapping_add(sigma1(w[t - 2]));
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for t in 0..64 {
        let t1 = h
            .wrapping_add(eps1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = eps0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub fn sha256(data: &[u8], digest: &mut [u8; DIGEST_SIZE]) {
    let mut state = H_INIT;

    let nblocks = data.len() / BLOCK_SIZE;
    for i in 0..nblocks {
        compress(&mut state, &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
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
    for i in 0..npad {
        compress(&mut state, &tail[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
    }

    for i in 0..8 {
        digest[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
    }
}

pub fn hex_digest(digest: &[u8; DIGEST_SIZE]) -> String {
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_str(s: &str) -> String {
        let mut d = [0u8; DIGEST_SIZE];
        sha256(s.as_bytes(), &mut d);
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
        // 56-byte message forces the two-block padding path
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
