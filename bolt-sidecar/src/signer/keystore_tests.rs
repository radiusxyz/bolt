#[cfg(feature = "keystore-tests")]
#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::Write,
        path::{Path, PathBuf},
    };

    use blst::min_pk::SecretKey;
    use ethereum_consensus::crypto::PublicKey as BlsPublicKey;

    use crate::{config::ChainConfig, signer::local::LocalSigner};

    use crate::signer::KeystoreSigner;
    /// The str path of the root of the project
    pub const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

    const KEYSTORES_DEFAULT_PATH_TEST: &str = "test_data/keys";
    const KEYSTORES_SECRETS_DEFAULT_PATH_TEST: &str = "test_data/secrets";

    /// If `path` is `Some`, returns a clone of it. Otherwise, returns the path to the
    /// `fallback_relative_path` starting from the root of the cargo project.
    fn make_path(relative_path: &str) -> PathBuf {
        let project_root = env!("CARGO_MANIFEST_DIR");
        Path::new(project_root).join(relative_path)
    }

    #[test]
    fn test_keystore_signer() {
        // 0. Test data setup

        // Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
        let tests_keystore_json = [
            r#"
            {
                "crypto": {
                    "kdf": {
                        "function": "scrypt",
                        "params": {
                            "dklen": 32,
                            "n": 262144,
                            "p": 1,
                            "r": 8,
                            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                        },
                        "message": ""
                    },
                    "checksum": {
                        "function": "sha256",
                        "params": {},
                        "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                    },
                    "cipher": {
                        "function": "aes-128-ctr",
                        "params": {
                            "iv": "264daa3f303d7259501c93d997d84fe6"
                        },
                        "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                    }
                },
                "description": "This is a test keystore that uses scrypt to secure the secret.",
                "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "path": "m/12381/60/3141592653/589793238",
                "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
                "version": 4
            }
        "#,
            r#"
            {
                "crypto": {
                    "kdf": {
                        "function": "pbkdf2",
                        "params": {
                            "dklen": 32,
                            "c": 262144,
                            "prf": "hmac-sha256",
                            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                        },
                        "message": ""
                    },
                    "checksum": {
                        "function": "sha256",
                        "params": {},
                        "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                    },
                    "cipher": {
                        "function": "aes-128-ctr",
                        "params": {
                            "iv": "264daa3f303d7259501c93d997d84fe6"
                        },
                        "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                    }
                },
                "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
                "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "path": "m/12381/60/0/0",
                "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
                "version": 4
            }
        "#,
        ];

        // Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
        let password = r#"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"#;
        let public_key = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
        let public_key_bytes: [u8; 48] = [
            0x96, 0x12, 0xd7, 0xa7, 0x27, 0xc9, 0xd0, 0xa2, 0x2e, 0x18, 0x5a, 0x1c, 0x76, 0x84,
            0x78, 0xdf, 0xe9, 0x19, 0xca, 0xda, 0x92, 0x66, 0x98, 0x8c, 0xb3, 0x23, 0x59, 0xc1,
            0x1f, 0x2b, 0x7b, 0x27, 0xf4, 0xae, 0x40, 0x40, 0x90, 0x23, 0x82, 0xae, 0x29, 0x10,
            0xc1, 0x5e, 0x2b, 0x42, 0x0d, 0x07,
        ];
        let secret_key = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let chain_config = ChainConfig::mainnet();

        let keystore_path =
            format!("{}/{}/{}", CARGO_MANIFEST_DIR, KEYSTORES_DEFAULT_PATH_TEST, public_key);
        let keystore_path = PathBuf::from(keystore_path);
        let keystore_path = keystore_path.join("test-voting-keystore.json");
        for test_keystore_json in tests_keystore_json {
            // 1. Write the keystore in a `test-voting-keystore.json` file so we test both scrypt
            //    and PBDKF2

            let mut tmp_keystore_file =
                File::create(&keystore_path).expect("to create new keystore file");

            tmp_keystore_file
                .write_all(test_keystore_json.as_bytes())
                .expect("to write to temp file");

            // Create a file for the secret, we are going to test it as well
            let keystores_secrets_path = make_path(KEYSTORES_SECRETS_DEFAULT_PATH_TEST);
            let mut tmp_secret_file = File::create(keystores_secrets_path.join(public_key))
                .expect("to create secret file");

            tmp_secret_file.write_all(password.as_bytes()).expect("to write to temp file");

            let keys_path = make_path(KEYSTORES_DEFAULT_PATH_TEST);
            let keystore_signer_from_password =
                KeystoreSigner::from_password(&keys_path, password.as_bytes(), chain_config)
                    .expect("to create keystore signer from password");

            let keypairs = keystore_signer_from_password.get_key_pairs();
            assert_eq!(keypairs.len(), 3);
            assert_eq!(keypairs.first().expect("to get keypair").pk.to_string(), public_key);

            let keystore_signer_from_directory = KeystoreSigner::from_secrets_directory(
                &keys_path,
                &keystores_secrets_path,
                chain_config,
            )
            .expect("to create keystore signer from secrets dir");

            let keypairs = keystore_signer_from_directory.get_key_pairs();
            assert_eq!(keypairs.len(), 3);
            assert_eq!(keypairs.first().expect("to get keypair").pk.to_string(), public_key);

            // 2. Sign a message with the signer and check the signature

            let keystore_sk_bls = SecretKey::from_bytes(
                hex::decode(secret_key).expect("to decode secret key").as_slice(),
            )
            .expect("to create secret key");

            let local_signer = LocalSigner::new(keystore_sk_bls, chain_config);

            let sig_local = local_signer.sign_commit_boost_root([0; 32]).expect("to sign message");
            let sig_keystore = keystore_signer_from_password
                .sign_commit_boost_root(
                    [0; 32],
                    &BlsPublicKey::try_from(public_key_bytes.as_ref()).unwrap(),
                )
                .expect("to sign message");
            assert_eq!(sig_local, sig_keystore);
        }
        assert!(std::fs::remove_file(&keystore_path).is_ok());
    }
}
