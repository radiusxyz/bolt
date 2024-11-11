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
    read_env_file()?;

    let opts = Opts::parse();

    init_telemetry_stack(opts.telemetry.metrics_port())?;

    println!("{BOLT}");

    info!(chain = opts.chain.name(), "Starting Bolt sidecar");

    if opts.constraint_signing.constraint_private_key.is_some() {
        match SidecarDriver::with_local_signer(&opts).await {
            Ok(driver) => driver.run_forever().await,
            Err(err) => {
                bail!("Failed to initialize the sidecar driver with local signer: {:?}", err)
            }
        }
    } else if opts.constraint_signing.commit_boost_signer_url.is_some() {
        match SidecarDriver::with_commit_boost_signer(&opts).await {
            Ok(driver) => driver.run_forever().await,
            Err(err) => {
                bail!("Failed to initialize the sidecar driver with commit boost: {:?}", err)
            }
        }
    } else {
        match SidecarDriver::with_keystore_signer(&opts).await {
            Ok(driver) => driver.run_forever().await,
            Err(err) => {
                bail!("Failed to initialize the sidecar driver with keystore signer: {:?}", err)
            }
        }
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
