use std::arch::x86_64::*;

use crate::STATE_WORDS;

pub fn chacha_avx2<const ROUNDS: usize>(mut state: [u32; 16], mut counter: u64, input: &mut [u8]) -> u64 {
    unsafe {
        for input_blocks in input.chunks_mut(64 * 8) {
            // inject counter
            state[12] = counter as u32;
            // state[13] = (counter >> 32) as u32;

            let mut keystream = [0u8; 8 * 64];
            chacha20_avx2_8blocks::<ROUNDS>(state, counter, &mut keystream);

            input_blocks
                .iter_mut()
                .zip(keystream.into_iter())
                .for_each(|(plaintext, keystream)| *plaintext ^= keystream);

            counter = counter.wrapping_add((input_blocks.len() as u64).div_ceil(64));
        }
    }

    return counter;
}

unsafe fn chacha20_avx2_8blocks<const ROUNDS: usize>(state: [u32; 16], counter: u64, keystream: &mut [u8; 8 * 64]) {
    unsafe {
        let mut counters = [0u32; 8];
        for i in 0..8 {
            counters[i] = counter.wrapping_add(i as u64) as u32;
        }
        // todo: counters high word

        // working state
        let mut x: [__m256i; 16] = [
            // constant
            _mm256_set1_epi32(state[0] as i32),
            _mm256_set1_epi32(state[1] as i32),
            _mm256_set1_epi32(state[2] as i32),
            _mm256_set1_epi32(state[3] as i32),
            // key
            _mm256_set1_epi32(state[4] as i32),
            _mm256_set1_epi32(state[5] as i32),
            _mm256_set1_epi32(state[6] as i32),
            _mm256_set1_epi32(state[7] as i32),
            _mm256_set1_epi32(state[8] as i32),
            _mm256_set1_epi32(state[9] as i32),
            _mm256_set1_epi32(state[10] as i32),
            _mm256_set1_epi32(state[11] as i32),
            // counter
            _mm256_loadu_si256(counters.as_ptr() as *const __m256i),
            _mm256_set1_epi32(state[13] as i32),
            // nonce
            _mm256_set1_epi32(state[14] as i32),
            _mm256_set1_epi32(state[15] as i32),
        ];

        macro_rules! quarter_round {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {
                // a += b; d ^= a; d <<<= 16
                $a = _mm256_add_epi32($a, $b);
                $d = _mm256_xor_si256($d, $a);
                $d = _mm256_xor_si256(_mm256_slli_epi32($d, 16), _mm256_srli_epi32($d, 16));

                // c += d; b ^= c; b <<<= 12
                $c = _mm256_add_epi32($c, $d);
                $b = _mm256_xor_si256($b, $c);
                $b = _mm256_xor_si256(_mm256_slli_epi32($b, 12), _mm256_srli_epi32($b, 20));

                // a += b; d ^= a; d <<<= 8
                $a = _mm256_add_epi32($a, $b);
                $d = _mm256_xor_si256($d, $a);
                $d = _mm256_xor_si256(_mm256_slli_epi32($d, 8), _mm256_srli_epi32($d, 24));

                // c += d; b ^= c; b <<<= 7
                $c = _mm256_add_epi32($c, $d);
                $b = _mm256_xor_si256($b, $c);
                $b = _mm256_xor_si256(_mm256_slli_epi32($b, 7), _mm256_srli_epi32($b, 25));
            };
        }
        for _ in 0..ROUNDS / 2 {
            // column rounds
            quarter_round!(x[0], x[4], x[8], x[12]);
            quarter_round!(x[1], x[5], x[9], x[13]);
            quarter_round!(x[2], x[6], x[10], x[14]);
            quarter_round!(x[3], x[7], x[11], x[15]);

            // diagonal rounds
            quarter_round!(x[0], x[5], x[10], x[15]);
            quarter_round!(x[1], x[6], x[11], x[12]);
            quarter_round!(x[2], x[7], x[8], x[13]);
            quarter_round!(x[3], x[4], x[9], x[14]);
        }

        let keystream = std::mem::transmute::<&mut [u8; 64 * 8], &mut [u32; 16 * 8]>(keystream);

        for word_index in 0..STATE_WORDS {
            // add working state to initial state to get the keystream
            x[word_index] = _mm256_add_epi32(x[word_index], _mm256_set1_epi32(state[word_index] as i32));

            let mut lanes = [0u32; 8];
            _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, x[word_index]);

            for block in 0..8 {
                keystream[(block * STATE_WORDS) + word_index] = lanes[block].to_le() as u32;
            }
        }
    }
}
