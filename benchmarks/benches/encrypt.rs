use aes_gcm::Aes256Gcm;
use chacha20::cipher::InOutBuf;
use chacha20_blake3::ChaCha20Blake3;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::AeadInOut};
use criterion::*;

fn bench(c: &mut Criterion) {
    for n in [64, 256, 1024, 4096, 16384, 65536] {
        let mut group = c.benchmark_group(format!("{}", n));
        let mut plaintext = vec![0u8; n];

        let key = [0u8; 32];
        let nonce_12 = [0u8; 12];
        let nonce_24 = [0u8; 24];
        let aad = [0u8; 128];

        let chacha20_blake3_cipher = ChaCha20Blake3::new(key);
        let xchacha20poly1305_cipher = XChaCha20Poly1305::new(&key.try_into().unwrap());
        let aes_256_gcm_cipher = Aes256Gcm::new(&key.try_into().unwrap());

        group.throughput(Throughput::Bytes(plaintext.len() as u64));

        group.bench_function("AES-256-GCM", |b| {
            b.iter(|| {
                let _ = aes_256_gcm_cipher.encrypt_inout_detached(
                    (&nonce_12).into(),
                    &aad,
                    InOutBuf::from(plaintext.as_mut_slice()),
                );
            });
        });

        group.bench_function("ChaCha20-BLAKE3", |b| {
            b.iter(|| {
                let _ = chacha20_blake3_cipher.encrypt_in_place_detached(&nonce_24, &mut plaintext, &aad);
            });
        });

        group.bench_function("XChaCha20-Poly1305", |b| {
            b.iter(|| {
                let _ = xchacha20poly1305_cipher.encrypt_inout_detached(
                    (&nonce_24).into(),
                    &aad,
                    InOutBuf::from(plaintext.as_mut_slice()),
                );
            });
        });
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
