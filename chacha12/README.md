# ChaCha

Pure-Rust, SIMD-accelerated ChaCha20 / ChaCha12 / ChaCha8 for any platform.

> **⚠️ Warning ⚠️:** This is a preliminary release, DO NOT USE IN PRODUCTION.


```rust
use chacha12::ChaCha;

fn main() {
    // DO NOT USE A ALL-ZERO KEY / NONCE, THIS CODE IS FOR DEMONSTRATION ONLY
    let key = [0u8; 32];
    let nonce = [0u8; 8];

    let mut message = b"Hello World!".to_vec();

    let mut cipher = ChaCha::<12>::new(&key, &nonce);
    cipher.xor_keystream(&mut message);
}
```
