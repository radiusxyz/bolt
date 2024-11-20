use eyre::bail;
use tracing::info;

use bolt_sidecar::{config::Opts, telemetry::init_telemetry_stack, SidecarDriver};

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

    let opts = Opts::try_parse()?;

    init_telemetry_stack(opts.telemetry.metrics_port())?;

    info!(chain = opts.chain.name(), "Starting Bolt sidecar");

    let use_local_signer = opts.constraint_signing.constraint_private_key.is_some();
    let use_commit_boost_signer = opts.constraint_signing.commit_boost_signer_url.is_some();
    let use_keystore_signer = opts.constraint_signing.keystore_path.is_some();

    if use_local_signer {
        SidecarDriver::with_local_signer(&opts).await?.run_forever().await
    } else if use_commit_boost_signer {
        SidecarDriver::with_commit_boost_signer(&opts).await?.run_forever().await
    } else if use_keystore_signer {
        SidecarDriver::with_keystore_signer(&opts).await?.run_forever().await
    } else {
        bail!("No signing method specified")
    }
}
