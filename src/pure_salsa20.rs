#![allow(unused)]

use byteorder::{ByteOrder, LittleEndian};

// const VERSION: &str = "p4.0";

pub struct Salsa20 {
    pub ctx: [i32; 16],
    pub rounds: u32,
    pub last_chunk_64: bool,
    pub iv_bitlen: u32,
}

impl Salsa20 {
    pub fn new(key: Option<&[u8]>, iv: Option<&[u8]>, rounds: u32) -> Self {
        let mut s20 = Salsa20 {
            ctx: [0; 16],
            rounds,
            last_chunk_64: true,
            iv_bitlen: 64,
        };
        if let Some(k) = key {
            s20.set_key(k);
        }
        if let Some(i) = iv {
            s20.set_iv(i);
        }
        s20
    }

    fn set_key(&mut self, key: &[u8]) {
        assert!(
            key.len() == 16 || key.len() == 32,
            "key length isn't 32 or 16 bytes. {}",
            key.len()
        );
        let constants = if key.len() == 32 {
            b"expand 32-byte k"
        } else {
            b"expand 16-byte k"
        };

        let mut temp = [0i32; 4];
        LittleEndian::read_i32_into(&key[0..16], &mut temp);
        self.ctx[1..5].copy_from_slice(&temp);

        if key.len() == 32 {
            LittleEndian::read_i32_into(&key[16..32], &mut temp);
            self.ctx[11..15].copy_from_slice(&temp);
        } else {
            LittleEndian::read_i32_into(&key[0..16], &mut temp);
            self.ctx[11..15].copy_from_slice(&temp);
        }

        self.ctx[0] = LittleEndian::read_i32(&constants[0..4]);
        self.ctx[5] = LittleEndian::read_i32(&constants[4..8]);
        self.ctx[10] = LittleEndian::read_i32(&constants[8..12]);
        self.ctx[15] = LittleEndian::read_i32(&constants[12..16]);
    }

    fn set_iv(&mut self, iv: &[u8]) {
        assert!(iv.len() * 8 == 64, "nonce (IV) not 64 bits");
        let mut temp = [0i32; 2];
        LittleEndian::read_i32_into(&iv[0..8], &mut temp);
        self.ctx[6..8].copy_from_slice(&temp);
        self.ctx[8] = 0;
        self.ctx[9] = 0;
    }

    fn set_counter(&mut self, counter: u64) {
        // No need to assert counter < 2^64 as counter is already u64
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, counter);
        let mut temp = [0i32; 2];
        LittleEndian::read_i32_into(&buf, &mut temp);
        self.ctx[8..10].copy_from_slice(&temp);
    }

    fn get_counter(&self) -> u64 {
        let mut buf = [0u8; 8];
        LittleEndian::write_i32_into(&self.ctx[8..10], &mut buf);
        LittleEndian::read_u64(&buf)
    }

    fn set_rounds(&mut self, rounds: u32) {
        assert!(
            rounds == 8 || rounds == 12 || rounds == 20,
            "rounds must be 8, 12, 20"
        );
        self.rounds = rounds;
    }

    pub fn encrypt_bytes(&mut self, data: &[u8]) -> Vec<u8> {
        assert!(
            self.last_chunk_64,
            "previous chunk not multiple of 64 bytes"
        );
        let mut munged = vec![0u8; data.len()];
        for (i, chunk) in data.chunks(64).enumerate() {
            let h = salsa20_wordtobyte(&self.ctx, self.rounds);
            self.set_counter(self.get_counter() + 1);
            for (j, &byte) in chunk.iter().enumerate() {
                munged[i * 64 + j] = byte ^ h[j];
            }
        }
        self.last_chunk_64 = data.len() % 64 == 0;
        munged
    }
}

fn salsa20_wordtobyte(input: &[i32; 16], n_rounds: u32) -> Vec<u8> {
    assert!(
        n_rounds == 8 || n_rounds == 12 || n_rounds == 20,
        "rounds must be 8, 12, 20"
    );
    let mut x = input.clone();
    for _ in 0..(n_rounds / 2) {
        x[4] ^= rot32(add32(x[0], x[12]), 7);
        x[8] ^= rot32(add32(x[4], x[0]), 9);
        x[12] ^= rot32(add32(x[8], x[4]), 13);
        x[0] ^= rot32(add32(x[12], x[8]), 18);
        x[9] ^= rot32(add32(x[5], x[1]), 7);
        x[13] ^= rot32(add32(x[9], x[5]), 9);
        x[1] ^= rot32(add32(x[13], x[9]), 13);
        x[5] ^= rot32(add32(x[1], x[13]), 18);
        x[14] ^= rot32(add32(x[10], x[6]), 7);
        x[2] ^= rot32(add32(x[14], x[10]), 9);
        x[6] ^= rot32(add32(x[2], x[14]), 13);
        x[10] ^= rot32(add32(x[6], x[2]), 18);
        x[3] ^= rot32(add32(x[15], x[11]), 7);
        x[7] ^= rot32(add32(x[3], x[15]), 9);
        x[11] ^= rot32(add32(x[7], x[3]), 13);
        x[15] ^= rot32(add32(x[11], x[7]), 18);

        x[1] ^= rot32(add32(x[0], x[3]), 7);
        x[2] ^= rot32(add32(x[1], x[0]), 9);
        x[3] ^= rot32(add32(x[2], x[1]), 13);
        x[0] ^= rot32(add32(x[3], x[2]), 18);
        x[6] ^= rot32(add32(x[5], x[4]), 7);
        x[7] ^= rot32(add32(x[6], x[5]), 9);
        x[4] ^= rot32(add32(x[7], x[6]), 13);
        x[5] ^= rot32(add32(x[4], x[7]), 18);
        x[11] ^= rot32(add32(x[10], x[9]), 7);
        x[8] ^= rot32(add32(x[11], x[10]), 9);
        x[9] ^= rot32(add32(x[8], x[11]), 13);
        x[10] ^= rot32(add32(x[9], x[8]), 18);
        x[12] ^= rot32(add32(x[15], x[14]), 7);
        x[13] ^= rot32(add32(x[12], x[15]), 9);
        x[14] ^= rot32(add32(x[13], x[12]), 13);
        x[15] ^= rot32(add32(x[14], x[13]), 18);
    }
    for i in 0..16 {
        x[i] = add32(x[i], input[i]);
    }
    let mut output = vec![0u8; 64];
    LittleEndian::write_i32_into(&x, &mut output);
    output
}

fn add32(a: i32, b: i32) -> i32 {
    let lo = (a & 0xFFFF) + (b & 0xFFFF);
    let hi = (a >> 16) + (b >> 16) + (lo >> 16);
    (-(hi & 0x8000) | (hi & 0x7FFF)) << 16 | (lo & 0xFFFF)
}

fn rot32(w: i32, n_left: i32) -> i32 {
    let n_left = n_left & 31;
    if n_left == 0 {
        return w;
    }
    let rrr = ((w >> 1) & 0x7FFF_FFFF) >> (31 - n_left);
    let sllllll = -((1 << (31 - n_left)) & w) | ((0x7FFF_FFFF >> n_left) & w);
    rrr | (sllllll << n_left)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salsa20() {
        let key: &[u8; 32] = b"This is 32-byte key for salsa20a";
        let iv = b"8Byte iv";
        let data = b"Hello, Salsa20!aaa";

        let mut salsa20 = Salsa20::new(Some(key), Some(iv), 20);
        let encrypted = salsa20.encrypt_bytes(data);
        println!("Encrypted: {:?}", encrypted);
    }
}
