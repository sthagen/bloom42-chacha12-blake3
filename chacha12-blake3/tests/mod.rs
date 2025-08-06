use chacha12_blake3::ChaCha12Blake3;

struct Test {
    plaintext: Vec<u8>,
    key: [u8; 32],
    nonce: [u8; 32],
    aad: Vec<u8>,
    expected_ciphertext: Vec<u8>,
}

#[test]
fn chacha12_blake3_test_vectors() {
    let tests = vec![
        Test {
            plaintext: [].to_vec(),
            key: hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap(),
            nonce: hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap(),
            aad: [].to_vec(),
            expected_ciphertext: hex::decode("8f3a9c4002093df3e3fa54b595d73ebfc18c8c151d7c9ae6ab06d12f2631bb52")
                .unwrap(),
        },
        Test {
            plaintext: b"ChaCha12".to_vec(),
            key: hex::decode("0100000000000000000000000000000000000000000000000000000000000010")
                .unwrap()
                .try_into()
                .unwrap(),
            nonce: hex::decode("1000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
                .try_into()
                .unwrap(),
            aad: b"BLAKE3".to_vec(),
            expected_ciphertext: hex::decode(
                "920ca696bb4df0b2e545be4dc2d25155909d98e96738d9db0c64677a74d628c091ff8f02f57f5480",
            )
            .unwrap(),
        },
        Test {
            plaintext: hex::decode("b8f60975cd7057a003ac84df00d514624fe40cb7855c50dd6594f59b3a2580e5").unwrap(),
            key: hex::decode("3eb02a239a2a66de159b9bb5486ccc10a6f63ddf5862ef076650513372353622")
                .unwrap()
                .try_into()
                .unwrap(),
            nonce: hex::decode("768e9bda14afb5686cc34de26210f9ff6fa1dfadc64ee3f0793e4979a30fc304")
                .unwrap()
                .try_into()
                .unwrap(),
            aad: hex::decode("c8d69ca92da6c5fd22f1805179fcd36cb7a9d45848fa346ba7118c2f34d23a48").unwrap(),
            expected_ciphertext: hex::decode(
                "50e6fa9c40c6ef226330ac9a43986cad7ab36367813b1383dd6ed48377ce86c8bc9811551750b2b3650af6b039016c9fa720ca758fa330c09de4a10f76586310",
            )
            .unwrap(),
        },
    ];

    for (i, test) in tests.iter().enumerate() {
        let cipher = ChaCha12Blake3::new(test.key);
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
