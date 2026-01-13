# ChaCha20-BLAKE3

Simple, Secure and Fast encryption for any CPU.


ChaCha20-BLAKE3 is a secure Authenticated Encryption with Associated Data (AEAD) algorithm that is:
- more secure than classic AEADs by providing full context commitment
- uses long nonces that can be safely generated randomly
- doesn't require any specific harware instruction but instead scales with the width of the SIMD instructions of your CPU (AVX2 / AVX-512 on amd64 and NEON / SVE on arm)

Which make it a great fit for everything from microcontrollers to huge servers.


It has been designed to be the only encryption algorithm you will ever need.


## Specification

[https://kerkour.com/chacha20-blake3](https://kerkour.com/chacha20-blake3)


## Usage

<!-- <div>
  <!-- Version -- >
  <a href="https://crates.io/crates/chacha12-blake3">
    <img src="https://img.shields.io/crates/v/chacha12-blake3.svg?style=flat-square" alt="Crates.io version" />
  </a>
  <!-- Docs -- >
  <a href="https://docs.rs/chacha12-blake3">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square" alt="docs.rs docs" />
  </a>
</div> -->


**Warning ⚠️: A (key, nonce) pair SHOULD NEVER be used to encrypt two messages. You can use either the same key with unique random nonces, an unique key with random or fixed nonces, or the same key with a NON-REPEATING counter in the first X bytes of the nonce. See the specification to learn how much data you can safely encrypt.**

`Cargo.toml`
```toml
[dependencies]
chacha20-blake3 = { git = "https://github.com/skerkour/chacha20-blake3", branch = "main" }
```

```rust
use chacha20_blake3::ChaCha20Blake3;

fn main() {
    // DO NOT USE A ALL-ZERO KEY / NONCE, THIS CODE IS FOR DEMONSTRATION ONLY
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    // or with an u64 counter to encrypt up to 2^64 messages with a single key:
    // let mut nonce = [0u8; 24];
    // nonce[..8].copy_from_slice(&counter.to_le_bytes());

    let message = b"Hello World!";

    let cipher = ChaCha20Blake3::new(key);

    let ciphertext: Vec<u8> = cipher.encrypt(&nonce, message, &[]);

    let plaintext: Vec<u8> = cipher.decrypt(&nonce, &ciphertext, &[]).unwrap();

    assert_eq!(plaintext, message);
}
```

## Features

| Feature | Default? | Description |
| --------| ---------| ----------- |
| `std` | ✓ |  Enables use of the standard library such as runtime SIMD detection. Enabling `std` automatically enables `alloc`.  |
| `alloc` | ✓ | Enables the `encrypt` / `decrypt` APIs that allocate memory. |
| `zeroize` | ✓ | Enables [`zeroize`](https://crates.io/crates/zeroize) to erase sensitive secrets from memory. |


## License

MIT. See `LICENSE.txt`
