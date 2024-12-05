use ethereum_consensus::crypto::SecretKey;

use crate::cli::{GenerateCommand, GenerateSubcommand};

impl GenerateCommand {
    pub fn run(&self) -> eyre::Result<()> {
        match self.generate {
            GenerateSubcommand::Bls => {
                let mut rng = rand::thread_rng();
                let sk = SecretKey::random(&mut rng)?;

                let pubkey = sk.public_key();

                println!("BLS secret key: 0x{}", hex::encode(sk.to_bytes()));
                println!("BLS public key: {pubkey:?}");
            }
        }

        Ok(())
    }
}
