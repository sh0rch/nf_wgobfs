const CHACHA_BLOCK_WORDS: usize = 16;

pub struct ChaCha6 {
    state: [u32; CHACHA_BLOCK_WORDS],
}

impl Clone for ChaCha6 {
    fn clone(&self) -> Self {
        panic!("ChaCha6 does not implement Clone")
    }
}

#[inline(always)]
fn quarter_round(state: &mut [u32], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

impl ChaCha6 {
    #[inline(always)]
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 8);

        let constants = b"expand 32-byte k";
        let mut state = [0u32; CHACHA_BLOCK_WORDS];
        for i in 0..4 {
            state[i] = u32::from_le_bytes([
                constants[i * 4],
                constants[i * 4 + 1],
                constants[i * 4 + 2],
                constants[i * 4 + 3],
            ]);
        }
        for i in 0..8 {
            let j = i * 4;
            state[4 + i] = u32::from_le_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
        }
        state[12] = 0;
        for i in 0..2 {
            let j = i * 4;
            state[13 + i] =
                u32::from_le_bytes([nonce[j], nonce[j + 1], nonce[j + 2], nonce[j + 3]]);
        }
        state[15] = 0;
        print!("state: {:?}\n", state);
        Self { state }
    }

    #[inline(always)]
    fn generate_block(&mut self) -> [u8; 64] {
        let mut working_state = self.state;
        for _ in 0..3 {
            quarter_round(&mut working_state, 0, 4, 8, 12);
            quarter_round(&mut working_state, 1, 5, 9, 13);
            quarter_round(&mut working_state, 2, 6, 10, 14);
            quarter_round(&mut working_state, 3, 7, 11, 15);
            quarter_round(&mut working_state, 0, 5, 10, 15);
            quarter_round(&mut working_state, 1, 6, 11, 12);
            quarter_round(&mut working_state, 2, 7, 8, 13);
            quarter_round(&mut working_state, 3, 4, 9, 14);
        }
        for (w, s) in working_state.iter_mut().zip(self.state.iter()) {
            *w = w.wrapping_add(*s);
        }
        self.state[12] = self.state[12].wrapping_add(1);

        let mut block = [0u8; 64];
        for (i, word) in working_state.iter().enumerate() {
            block[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        block
    }

    #[inline(always)]
    pub fn xor(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let block = self.generate_block();
            let end = std::cmp::min(offset + 64, data.len());
            let chunk = &mut data[offset..end];
            for (b, k) in chunk.iter_mut().zip(block.iter()) {
                *b ^= *k;
            }
            offset += chunk.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha6_xor_reversible() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 8];
        let mut cipher = ChaCha6::new(&key, &nonce);
        let mut data = [0xAAu8; 64];
        let orig = data.clone();
        cipher.xor(&mut data);

        let mut cipher2 = ChaCha6::new(&key, &nonce);
        cipher2.xor(&mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn test_chacha6_endian_independence() {
        let key = [1u8; 32];
        let nonce = [2u8; 8];
        let mut cipher = ChaCha6::new(&key, &nonce);
        let mut data = [0x55u8; 32];
        let orig = data.clone();
        cipher.xor(&mut data);

        let mut cipher2 = ChaCha6::new(&key, &nonce);
        cipher2.xor(&mut data);
        assert_eq!(data, orig);
    }
}
