use crate::{
    cli::PubkeyHashCommand,
    common::{hash::compress_bls_pubkey, parse_bls_public_key},
};

impl PubkeyHashCommand {
    pub fn run(&self) -> eyre::Result<()> {
        let parsed = parse_bls_public_key(&self.key)?;
        let hash = compress_bls_pubkey(&parsed);

        println!("{}", alloy::hex::encode_prefixed(hash));

        Ok(())
    }
}
