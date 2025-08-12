use std::arch::x86_64::*;

use crate::STATE_WORDS;

// https://doc.rust-lang.org/stable/core/arch/x86_64/

/// how many ChaCha blocks we compute in parallel (depends on the side of the SIMD vectors, here 256 / 32)
pub const SIMD_LANES: usize = 8;

/// A 8-lane array with guaranteed 32-byte alignment.
/// Used for _mm256_load_si256 / _mm256_store_si256 operations that should be faster than
/// unaligned operations (_mm256_loadu_si256 / _mm256_storeu_si256)
#[repr(align(32))]
struct AlignedU32x8([u32; SIMD_LANES]);

// AVX2 supports operations on 16 256-bit vectors.
// Each vector can be seen as 8 lanes, where each lane is 32-bit wide (8 * 32 = 356), allowing us to compute
// 8 ChaCha blocks in parallel.
// Thus, in a single 256-bit vector we will get the follwing state:
// [ block1 (32-bits) || block2 (32-bits) || block3 (32-bits) || block4 (32-bits) || block5 (32-bits) ... ]
// then we perform the normal ChaCha operations on these vectors, meaning that we compute
// 8 ChaCha blocks in parallel for every operation on these vectors.
pub fn chacha_avx2<const ROUNDS: usize>(
    state: [u32; 16],
    mut counter: u64,
    input: &mut [u8],
    last_keystream_block: &mut [u8; 64],
) -> u64 {
    let mut keystream = [0u8; SIMD_LANES * 64];

    let mut initial_state: [__m256i; 16] = unsafe {
        [
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
            // counter, set it to 0 for now, it is injected later during each iteration of the loop
            _mm256_set1_epi32(0),
            _mm256_set1_epi32(0),
            // nonce
            _mm256_set1_epi32(state[14] as i32),
            _mm256_set1_epi32(state[15] as i32),
        ]
    };

    // process input by chunks of 8 * 64 bytes
    for input_blocks in input.chunks_mut(64 * SIMD_LANES) {
        // inject counter (uint64 little-endian) as two 32-bit little-endian words for each lane
        // e.g for one 256-bit vector with 8 32-bit lanes: [counter, counter + 1, counter + 2, counter + 3...]
        let mut counter_lane_low = AlignedU32x8([0u32; SIMD_LANES]);
        let mut counter_lane_high = AlignedU32x8([0u32; SIMD_LANES]);
        for i in 0..SIMD_LANES {
            let counter_lane = counter.wrapping_add(i as u64);
            counter_lane_low.0[i] = counter_lane as u32;
            counter_lane_high.0[i] = (counter_lane >> 32) as u32;
        }

        unsafe {
            initial_state[12] = _mm256_load_si256(counter_lane_low.0.as_ptr() as *const __m256i);
            initial_state[13] = _mm256_load_si256(counter_lane_high.0.as_ptr() as *const __m256i);
        }

        // compute 8 64-byte ChaCha blocks in parallel
        chacha20_avx2_8blocks::<ROUNDS>(initial_state, &mut keystream);

        // XOR plaintext with keystream
        input_blocks
            .iter_mut()
            .zip(keystream)
            .for_each(|(plaintext, keystream)| *plaintext ^= keystream);

        counter = counter.wrapping_add((input_blocks.len() as u64).div_ceil(64));
    }

    let last_keystream_block_index = ((input.len() - 1) / 64) % SIMD_LANES;
    let last_keystream_block_offset = last_keystream_block_index * 64;
    last_keystream_block.copy_from_slice(&keystream[last_keystream_block_offset..last_keystream_block_offset + 64]);

    return counter;
}

/// Compute 8 64-byte ChaCha blocks in parallel using AVX2 vectors.
/// The keystream is the 8 64-byte blocks computed in parallel.
/// [ block1 (64 bytes) || block2 (64 bytes) || block3 (64 bytes) || block4 (64 bytes) ... ]
#[inline(always)]
fn chacha20_avx2_8blocks<const ROUNDS: usize>(initial_state: [__m256i; 16], keystream: &mut [u8; SIMD_LANES * 64]) {
    let keystream_ptr = keystream.as_mut_ptr();

    unsafe {
        let mut working_state = initial_state;

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

        // Each iteration of the loop writes a 32-bit word for each block (lane) into keystream.
        // The first iteration writes the following bytes: block1[0..4], block2[0..4], block3[0..4], block4[0..4], block5[0..4] ...
        // the second iteration writes block1[4..8], block2[4..8], block3[4..8], block4[4..8], block5[4..8] ...
        // the third iteration writes block1[4..8], block2[8..12], block3[8..12], block4[8..12], block5[8..12] ...
        // and so on, for the 16 32-bit words of the ChaCha state
        for word_index in 0..STATE_WORDS {
            // first we add the working state to the initial state to get the keystream
            working_state[word_index] = _mm256_add_epi32(working_state[word_index], initial_state[word_index]);

            // then we convert the SIMD lanes into the keystream bytes
            let mut lanes = AlignedU32x8([0u32; SIMD_LANES]);
            _mm256_store_si256(lanes.0.as_mut_ptr() as *mut __m256i, working_state[word_index]);

            // each lane is a 32-bit little-endian word
            for block in 0..SIMD_LANES {
                let word = lanes.0[block].to_le_bytes();
                let byte_offset = (block * STATE_WORDS * 4) + (word_index * 4);
                std::ptr::copy_nonoverlapping(word.as_ptr(), keystream_ptr.add(byte_offset), 4);
            }
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
    }
}
