use core::arch::x86_64::*;

use crate::{BLOCK_SIZE, STATE_WORDS, extract_counter_from_state, inject_counter_into_state};

// https://doc.rust-lang.org/stable/core/arch/x86_64
// https://en.wikipedia.org/wiki/AVX-512
// https://doc.rust-lang.org/stable/std/arch/macro.is_x86_feature_detected.html
// https://colfaxresearch.com/knl-avx512
// https://www.numberworld.org/blogs/2024_8_7_zen5_avx512_teardown

/// how many ChaCha blocks we compute in parallel (depends on the side of the SIMD vectors, here 512 / 32 = 16)
pub const SIMD_LANES: usize = 16;

/// A 16-lane array with guaranteed 64-byte alignment.
/// Used for _mm512_load_epi32 / _mm512_store_epi32 operations that should be faster than
/// unaligned operations (_mm512_loadu_epi32 / _mm512_storeu_epi32)
#[repr(align(64))]
struct AlignedU32x16([u32; SIMD_LANES]);

// AVX-512 supports operations on 512-bit registers (vectors).
// Each vector can be seen as 16 lanes, where each lane is 32-bit wide (16 * 32 = 512), allowing us to compute
// 16 ChaCha blocks in parallel.
// Thus, in a single 512-bit vector we will get the follwing state:
// [ block1 (32-bits) || block2 (32-bits) || block3 (32-bits) || block4 (32-bits) || block5 (32-bits) ... ]
// then we perform the normal ChaCha operations on these vectors, meaning that we compute
// 16 ChaCha blocks in parallel for every operation on these vectors.
pub fn chacha_avx512<const ROUNDS: usize>(
    state: &mut [u32; STATE_WORDS],
    input: &mut [u8],
    last_keystream_block: &mut [u8; BLOCK_SIZE],
) {
    let mut counter = extract_counter_from_state(state);
    let mut keystream = [0u8; SIMD_LANES * BLOCK_SIZE];

    let mut initial_state: [__m512i; STATE_WORDS] = unsafe {
        [
            // constant
            _mm512_set1_epi32(state[0] as i32),
            _mm512_set1_epi32(state[1] as i32),
            _mm512_set1_epi32(state[2] as i32),
            _mm512_set1_epi32(state[3] as i32),
            // key
            _mm512_set1_epi32(state[4] as i32),
            _mm512_set1_epi32(state[5] as i32),
            _mm512_set1_epi32(state[6] as i32),
            _mm512_set1_epi32(state[7] as i32),
            _mm512_set1_epi32(state[8] as i32),
            _mm512_set1_epi32(state[9] as i32),
            _mm512_set1_epi32(state[10] as i32),
            _mm512_set1_epi32(state[11] as i32),
            // counter, set it to 0 for now, it is injected later during each iteration of the loop
            _mm512_set1_epi32(0),
            _mm512_set1_epi32(0),
            // nonce
            _mm512_set1_epi32(state[14] as i32),
            _mm512_set1_epi32(state[15] as i32),
        ]
    };

    // process input by chunks of 16 * 64 bytes
    for input_blocks in input.chunks_mut(BLOCK_SIZE * SIMD_LANES) {
        // inject counter (uint64 little-endian) as two 32-bit little-endian words for each lane
        // e.g for one 512-bit vector with 16 32-bit lanes: [counter, counter + 1, counter + 2, counter + 3...]
        let mut counter_lane_low = AlignedU32x16([0u32; SIMD_LANES]);
        let mut counter_lane_high = AlignedU32x16([0u32; SIMD_LANES]);
        for i in 0..SIMD_LANES {
            let counter_lane = counter.wrapping_add(i as u64);
            counter_lane_low.0[i] = counter_lane as u32;
            counter_lane_high.0[i] = (counter_lane >> 32) as u32;
        }

        unsafe {
            initial_state[12] = _mm512_load_epi32(counter_lane_low.0.as_ptr() as *const i32);
            initial_state[13] = _mm512_load_epi32(counter_lane_high.0.as_ptr() as *const i32);
        }

        // compute 16 64-byte ChaCha blocks in parallel
        chacha20_avx512_16blocks::<ROUNDS>(initial_state, &mut keystream);

        // XOR plaintext with keystream
        input_blocks
            .iter_mut()
            .zip(keystream)
            .for_each(|(plaintext, keystream)| *plaintext ^= keystream);

        counter = counter.wrapping_add((input_blocks.len() as u64).div_ceil(BLOCK_SIZE as u64));
    }

    inject_counter_into_state(state, counter);

    if input.len() % BLOCK_SIZE != 0 {
        let last_keystream_block_index = ((input.len() - 1) / BLOCK_SIZE) % SIMD_LANES;
        let last_keystream_block_offset = last_keystream_block_index * BLOCK_SIZE;
        last_keystream_block
            .copy_from_slice(&keystream[last_keystream_block_offset..last_keystream_block_offset + BLOCK_SIZE]);
    }
}

/// Compute 16 64-byte ChaCha blocks in parallel using AVX-512 vectors.
/// The keystream is the 16 64-byte blocks computed in parallel.
/// [ block1 (64 bytes) || block2 (64 bytes) || block3 (64 bytes) || block4 (64 bytes) ... ]
#[inline(always)]
fn chacha20_avx512_16blocks<const ROUNDS: usize>(
    initial_state: [__m512i; STATE_WORDS],
    keystream: &mut [u8; SIMD_LANES * BLOCK_SIZE],
) {
    let keystream_ptr = keystream.as_mut_ptr();

    unsafe {
        let mut working_state = initial_state;

        macro_rules! quarter_round {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {
                // a += b; d ^= a; d <<<= 16
                $a = _mm512_add_epi32($a, $b);
                $d = _mm512_xor_si512($d, $a);
                $d = _mm512_rol_epi32($d, 16);

                // c += d; b ^= c; b <<<= 12
                $c = _mm512_add_epi32($c, $d);
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_rol_epi32($b, 12);

                // a += b; d ^= a; d <<<= 8
                $a = _mm512_add_epi32($a, $b);
                $d = _mm512_xor_si512($d, $a);
                $d = _mm512_rol_epi32($d, 8);

                // c += d; b ^= c; b <<<= 7
                $c = _mm512_add_epi32($c, $d);
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_rol_epi32($b, 7);
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
            working_state[word_index] = _mm512_add_epi32(working_state[word_index], initial_state[word_index]);

            // then we convert the SIMD lanes into the keystream bytes
            let mut lanes = AlignedU32x16([0u32; SIMD_LANES]);
            _mm512_store_epi32(lanes.0.as_mut_ptr() as *mut i32, working_state[word_index]);

            // each lane is a 32-bit little-endian word
            for block in 0..SIMD_LANES {
                let word = lanes.0[block].to_le_bytes();
                let byte_offset = (block * STATE_WORDS * 4) + (word_index * 4);
                core::ptr::copy_nonoverlapping(word.as_ptr(), keystream_ptr.add(byte_offset), 4);
            }
        }
    }
}
