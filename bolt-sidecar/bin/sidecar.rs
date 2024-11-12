use clap::Parser;
use eyre::bail;
use tracing::info;

use bolt_sidecar::{
    config::{remove_empty_envs, Opts},
    telemetry::init_telemetry_stack,
    SidecarDriver,
};

const BOLT: &str = r#"
██████╗  ██████╗ ██╗  ████████╗
██╔══██╗██╔═══██╗██║  ╚══██╔══╝
██████╔╝██║   ██║██║     ██║
██╔══██╗██║   ██║██║     ██║
██████╔╝╚██████╔╝███████╗██║
╚═════╝  ╚═════╝ ╚══════╝╚═╝   "#;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    println!("{}", BOLT);

    read_env_file()?;

    let opts = Opts::parse();

    init_telemetry_stack(opts.telemetry.metrics_port())?;

    info!(chain = opts.chain.name(), "Starting Bolt sidecar");

    if opts.constraint_signing.constraint_private_key.is_some() {
        SidecarDriver::with_local_signer(&opts).await?.run_forever().await
    } else if opts.constraint_signing.commit_boost_signer_url.is_some() {
        SidecarDriver::with_commit_boost_signer(&opts).await?.run_forever().await
    } else {
        SidecarDriver::with_keystore_signer(&opts).await?.run_forever().await
    }
}

fn read_env_file() -> eyre::Result<()> {
    match dotenvy::dotenv() {
        // It means the .env file hasn't been found but it's okay since it's optional
        Err(dotenvy::Error::Io(_)) => (),
        Err(err) => bail!("Failed to load .env file: {:?}", err),
        Ok(path) => println!("Loaded environment variables from path: {:?}", path),
    };

    remove_empty_envs()?;
    Ok(())
}
