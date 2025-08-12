use chacha12::ChaCha;
use chacha20::{ChaCha12, KeyIvInit, cipher::StreamCipher};
use criterion::*;

fn bench(c: &mut Criterion) {
    for n in [64, 2000, 64 * 1000, 1000 * 1000, 10 * 1000 * 1000] {
        let mut group = c.benchmark_group(format!("{}", n));
        let mut plaintext = vec![0u8; n];

        let key = [0u8; 32];
        let djb_nonce = [0u8; 8];
        let ietf_96b_nonce = [0u8; 12];

        let mut chacha12_rust_crypto = ChaCha12::new(&key.into(), &ietf_96b_nonce.into());
        let mut chacha12 = ChaCha::<12>::new(&key, &djb_nonce);

        group.throughput(Throughput::Bytes(plaintext.len() as u64));
        group.bench_function("ChaCha12", |b| {
            b.iter(|| {
                chacha12.xor_keystream(&mut plaintext);
            });
        });
        group.bench_function("ChaCha12-RustCrypto", |b| {
            b.iter(|| {
                chacha12_rust_crypto.apply_keystream(&mut plaintext);
            });
        });
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
