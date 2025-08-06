use aes_gcm::{Aes256Gcm, aead::AeadMutInPlace};
use chacha12_blake3::ChaCha12Blake3;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use criterion::*;

fn bench(c: &mut Criterion) {
    for n in [64, 2000, 64 * 1000, 1000 * 1000, 10 * 1000 * 1000] {
        let mut group = c.benchmark_group(format!("{}", n));
        let mut plaintext = vec![0u8; n];

        let key = [0u8; 32];
        let nonce = [0u8; 32];
        let aad = [0u8; 128];
        let small_96b_nonce = [0u8; 12];

        let chacha12_blake3_cipher = ChaCha12Blake3::new(key);
        let mut chacha20poly1305_cipher = ChaCha20Poly1305::new(&key.try_into().unwrap());
        let mut aes_256_gcm_cipher = Aes256Gcm::new(&key.try_into().unwrap());

        group.throughput(Throughput::Bytes(plaintext.len() as u64));
        group.bench_function("AES-256-GCM", |b| {
            b.iter(|| {
                let _ = aes_256_gcm_cipher.encrypt_in_place_detached((&small_96b_nonce).into(), &aad, &mut plaintext);
            });
        });
        group.bench_function("ChaCha12-BLAKE3", |b| {
            b.iter(|| {
                let _ = chacha12_blake3_cipher.encrypt_in_place_detached(&nonce, &mut plaintext, &aad);
            });
        });
        group.bench_function("ChaCha20-Poly1305", |b| {
            b.iter(|| {
                let _ =
                    chacha20poly1305_cipher.encrypt_in_place_detached((&small_96b_nonce).into(), &aad, &mut plaintext);
            });
        });
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
