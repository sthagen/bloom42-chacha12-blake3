use chacha12::{ChaCha12, ChaCha20};
use criterion::*;

fn kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("KDF");

    let key = [0u8; 32];
    let djb_nonce = [0u8; 8];
    let mut plaintext = vec![0u8; 64];

    let mut chacha12 = ChaCha12::new(&key, &djb_nonce);
    let mut chacha20 = ChaCha20::new(&key, &djb_nonce);

    group.throughput(Throughput::Bytes(plaintext.len() as u64));
    group.bench_function("ChaCha12", |b| {
        b.iter(|| {
            plaintext[0..19].copy_from_slice(b"ChaCha12-BLAKE3 KDF");
            chacha12.xor_keystream(&mut plaintext);
        });
    });
    group.bench_function("ChaCha20", |b| {
        b.iter(|| {
            plaintext[0..19].copy_from_slice(b"ChaCha12-BLAKE3 KDF");
            chacha20.xor_keystream(&mut plaintext);
        });
    });
    group.bench_function("BLAKE3", |b| {
        b.iter(|| blake3::derive_key("ChaCha12-BLAKE3 encryption key", &key));
    });
}

criterion_group!(benches, kdf);
criterion_main!(benches);
