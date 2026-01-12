use chacha20_blake3::ChaCha20Blake3;

struct Test {
    plaintext: Vec<u8>,
    key: [u8; 32],
    nonce: [u8; 24],
    aad: Vec<u8>,
    expected_ciphertext: Vec<u8>,
}

#[test]
fn chacha20_blake3_test_vectors() {
    let tests = vec![
        Test {
            plaintext: [].to_vec(),
            key: hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap(),
            nonce: hex::decode("000000000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap(),
            aad: [].to_vec(),
            expected_ciphertext: hex::decode("4fbdd67d41f66924b4304f0fc1eaa87a8e90fc7c5304fe3078f0a1b6e6142c33")
                .unwrap(),
        },
        Test {
            plaintext: b"ChaCha20".to_vec(),
            key: hex::decode("0100000000000000000000000000000000000000000000000000000000000010")
                .unwrap()
                .try_into()
                .unwrap(),
            nonce: hex::decode("100000000000000000000000000000000000000000000001")
                .unwrap()
                .try_into()
                .unwrap(),
            aad: b"BLAKE3".to_vec(),
            expected_ciphertext: hex::decode(
                "48fecfaf8d9553bfe7121700da72362e77e09080ddd55101aaca18cdcf259953923150cb89e1fef2",
            )
            .unwrap(),
        },
        Test {
            plaintext: hex::decode("b8f60975cd7057a003ac84df00d514624fe40cb7855c50dd6594f59b3a2580e5").unwrap(),
            key: hex::decode("3eb02a239a2a66de159b9bb5486ccc10a6f63ddf5862ef076650513372353622")
                .unwrap()
                .try_into()
                .unwrap(),
            nonce: hex::decode("768e9bda14afb5686cc34de26210f9ff6fa1dfadc64ee3f0")
                .unwrap()
                .try_into()
                .unwrap(),
            aad: hex::decode("c8d69ca92da6c5fd22f1805179fcd36cb7a9d45848fa346ba7118c2f34d23a48").unwrap(),
            expected_ciphertext: hex::decode(
                "444d593bb2dea9ecde9cd3839d166141de70481340ce30739b3f0f28b059d63232324ace49e8a19729ac5110a093fba10acaeed93099dea1a9c20463a278c3a7",
            )
            .unwrap(),
        },
    ];

    for (i, test) in tests.iter().enumerate() {
        let cipher = ChaCha20Blake3::new(test.key);
        let ciphertext = cipher.encrypt(&test.nonce, &test.plaintext, &test.aad);

        assert_eq!(
            ciphertext,
            test.expected_ciphertext,
            "encryption [{i}] failed. Got: {}\nExpected: {}",
            hex::encode(&ciphertext),
            hex::encode(&test.expected_ciphertext)
        );

        let plaintext = cipher.decrypt(&test.nonce, &ciphertext, &test.aad).unwrap();
        assert_eq!(
            plaintext,
            test.plaintext,
            "decryption [{i}] failed. Got: {}\nExpected: {}",
            hex::encode(&plaintext),
            hex::encode(&test.plaintext)
        );
    }
}
