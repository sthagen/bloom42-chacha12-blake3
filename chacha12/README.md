# ChaCha

Pure-Rust, SIMD-accelerated ChaCha20 / ChaCha12 / ChaCha8 for any platform.

> **⚠️ Warning ⚠️:** This is a preliminary release, DO NOT USE IN PRODUCTION.


<div>
  <!-- Version -->
  <a href="https://crates.io/crates/chacha12">
    <img src="https://img.shields.io/crates/v/chacha12.svg?style=flat-square" alt="Crates.io version" />
  </a>
  <!-- Docs -->
  <a href="https://docs.rs/chacha12">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square" alt="docs.rs docs" />
  </a>
</div>


`Cargo.toml`
```toml
[dependencies]
chacha12 = "0.1"
```

```rust
use chacha12::ChaCha12;

fn main() {
    // DO NOT USE A ALL-ZERO KEY / NONCE, THIS CODE IS FOR DEMONSTRATION ONLY
    let key = [0u8; 32];
    let nonce = [0u8; 8];

    let mut message = b"Hello World!".to_vec();

    let mut cipher = ChaCha12::new(&key, &nonce);
    cipher.xor_keystream(&mut message);
}
```


## Features

| Feature | Default? | Description |
| --------| ---------| ----------- |
| `std` | ✓ | Enables runtime SIMD detection for platforms that support it, which requires the standard library. Disable it to use compile-time CPU features detection in no-std environments. |
| `zeroize` | ✓ | Enables [`zeroize`](https://crates.io/crates/zeroize) to erase sensitive secrets from memory. |

