use std::arch::x86_64::*;

use crate::STATE_WORDS;

pub fn chacha_avx2<const ROUNDS: usize>(mut state: [u32; 16], mut counter: u64, input: &mut [u8]) -> u64 {
    unsafe {
        for input_blocks in input.chunks_mut(64 * 8) {
            // inject counter
            state[12] = counter as u32;
            state[13] = (counter >> 32) as u32;

            let mut keystream = [0u8; 8 * 64];
            chacha20_avx2_8blocks::<ROUNDS>(state, counter, &mut keystream);

            input_blocks
                .iter_mut()
                .zip(keystream)
                .for_each(|(plaintext, keystream)| *plaintext ^= keystream);

            counter = counter.wrapping_add((input_blocks.len() as u64).div_ceil(64));
        }
    }

    return counter;
}

#[repr(align(32))]
struct AlignedU32x8([u32; 8]);

#[inline]
unsafe fn chacha20_avx2_8blocks<const ROUNDS: usize>(state: [u32; 16], counter: u64, keystream: &mut [u8; 8 * 64]) {
    unsafe {
        // compute the counter lanes.
        // e.g for one 256-bit lane with 8 32-bit words: [counter, counter + 1, counter + 2, counter + 3...]
        let mut counter_lane_low = AlignedU32x8([0u32; 8]);
        let mut counter_lane_high = AlignedU32x8([0u32; 8]);
        for i in 0..8 {
            let counter_lane = counter.wrapping_add(i as u64);
            counter_lane_low.0[i] = counter_lane as u32;
            counter_lane_high.0[i] = (counter_lane >> 32) as u32;
        }

        // initial state state
        let original_state: [__m256i; 16] = [
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
            _mm256_load_si256(counter_lane_low.0.as_ptr() as *const __m256i),
            _mm256_load_si256(counter_lane_high.0.as_ptr() as *const __m256i),
            // _mm256_set1_epi32(state[13] as i32),
            // _mm256_load_si256(counter_lane_high.0.as_ptr() as *const __m256i),
            // nonce
            _mm256_set1_epi32(state[14] as i32),
            _mm256_set1_epi32(state[15] as i32),
        ];

        let mut working_state = original_state;

        macro_rules! quarter_round {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {
                // a += b; d ^= a; d <<<= 16
                $a = _mm256_add_epi32($a, $b);
                $d = _mm256_xor_si256($d, $a);
                $d = _mm256_or_si256(_mm256_slli_epi32($d, 16), _mm256_srli_epi32($d, 16));

                // c += d; b ^= c; b <<<= 12
                $c = _mm256_add_epi32($c, $d);
                $b = _mm256_xor_si256($b, $c);
                $b = _mm256_or_si256(_mm256_slli_epi32($b, 12), _mm256_srli_epi32($b, 20));

                // a += b; d ^= a; d <<<= 8
                $a = _mm256_add_epi32($a, $b);
                $d = _mm256_xor_si256($d, $a);
                $d = _mm256_or_si256(_mm256_slli_epi32($d, 8), _mm256_srli_epi32($d, 24));

                // c += d; b ^= c; b <<<= 7
                $c = _mm256_add_epi32($c, $d);
                $b = _mm256_xor_si256($b, $c);
                $b = _mm256_or_si256(_mm256_slli_epi32($b, 7), _mm256_srli_epi32($b, 25));
            };
        }

        for _ in 0..ROUNDS / 2 {
            // column rounds
            quarter_round!(working_state[0], working_state[4], working_state[8], working_state[12]);
            quarter_round!(working_state[1], working_state[5], working_state[9], working_state[13]);
            quarter_round!(working_state[2], working_state[6], working_state[10], working_state[14]);
            quarter_round!(working_state[3], working_state[7], working_state[11], working_state[15]);

            // diagonal rounds
            quarter_round!(working_state[0], working_state[5], working_state[10], working_state[15]);
            quarter_round!(working_state[1], working_state[6], working_state[11], working_state[12]);
            quarter_round!(working_state[2], working_state[7], working_state[8], working_state[13]);
            quarter_round!(working_state[3], working_state[4], working_state[9], working_state[14]);
        }

        // let keystream = std::mem::transmute::<&mut [u8; 64 * 8], &mut [u32; STATE_WORDS * 8]>(keystream);

        // for word_index in 0..STATE_WORDS {
        //     // add working state to initial state to get the keystream
        //     working_state[word_index] = _mm256_add_epi32(working_state[word_index], original_state[word_index]);

        //     let mut lanes = AlignedU32x8([0u32; 8]);
        //     _mm256_store_si256(lanes.0.as_mut_ptr() as *mut __m256i, working_state[word_index]);

        //     for block in 0..8 {
        //         keystream[(block * STATE_WORDS) + word_index] = lanes.0[block].to_le();
        //     }
        // }

        let keystream_ptr = keystream.as_mut_ptr();
        for word_index in 0..STATE_WORDS {
            working_state[word_index] = _mm256_add_epi32(working_state[word_index], original_state[word_index]);

            let mut lanes = AlignedU32x8([0u32; 8]);
            _mm256_store_si256(lanes.0.as_mut_ptr() as *mut __m256i, working_state[word_index]);

            // each lane is a 32-bit little-endian word
            for block in 0..8 {
                let word = lanes.0[block].to_le_bytes();
                let byte_offset = (block * STATE_WORDS * 4) + (word_index * 4);
                std::ptr::copy_nonoverlapping(word.as_ptr(), keystream_ptr.add(byte_offset), 4);
            }
        }
    }
}
