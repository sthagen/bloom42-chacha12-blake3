use chacha::{ChaCha12, ChaCha20};
use criterion::*;

fn kdf(c: &mut Criterion) {
    let key = [0u8; 32];
    let djb_nonce = [0u8; 8];
    let extended_nonce = [0u8; 24];
    let mut plaintext = vec![0u8; 64];

    let mut chacha12 = ChaCha12::new(&key, &djb_nonce);
    let mut chacha20 = ChaCha20::new(&key, &djb_nonce);

    let mut group = c.benchmark_group("KDF");
    group.throughput(Throughput::Bytes(plaintext.len() as u64));

    group.bench_function("ChaCha12", |b| {
        b.iter(|| {
            // plaintext[0..19].copy_from_slice(b"ChaCha12-BLAKE3");
            chacha12.xor_keystream(&mut plaintext);
        });
    });

    group.bench_function("ChaCha20", |b| {
        b.iter(|| {
            // plaintext[0..19].copy_from_slice(b"ChaCha20-BLAKE3");
            chacha20.xor_keystream(&mut plaintext);
        });
    });

    group.bench_function("BLAKE3-KDF", |b| {
        // b.iter(|| blake3::derive_key("ChaCha20-BLAKE3", &key));
        b.iter(|| {
            let mut kdf_out = [0u8; 72];
            let mut hasher = blake3::Hasher::new_derive_key("ChaCha20-BLAKE3");
            hasher.update(&key);
            hasher.finalize_xof().fill(&mut kdf_out);
        });
    });

    group.bench_function("BLAKE3-MAC", |b| {
        b.iter(|| {
            let mut kdf_out = [0u8; 72];
            let mut hasher = blake3::Hasher::new_keyed(&key);
            // hasher.update(b"ChaCha20-BLAKE3");
            hasher.update(&extended_nonce);
            hasher.finalize_xof().fill(&mut kdf_out);
        });
    });
}

criterion_group!(benches, kdf);
criterion_main!(benches);
