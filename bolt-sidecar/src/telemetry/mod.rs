use std::net::SocketAddr;

use eyre::{bail, Result};
use metrics_exporter_prometheus::PrometheusBuilder;
use tracing::info;

mod metrics;
pub use metrics::ApiMetrics;

/// Initialize the tracing stack and Prometheus metrics recorder.
///
/// **This function should be called at the beginning of the program.**
pub fn init_telemetry_stack(metrics_port: Option<u16>) -> Result<()> {
    if let Some(metrics_port) = metrics_port {
        let prometheus_addr = SocketAddr::from(([0, 0, 0, 0], metrics_port));
        let builder = PrometheusBuilder::new().with_http_listener(prometheus_addr);

        if let Err(e) = builder.install() {
            bail!("failed to install Prometheus recorder: {:?}", e);
        } else {
            info!(
                "Telemetry initialized. Serving Prometheus metrics at: http://{}",
                prometheus_addr
            );
        }

        ApiMetrics::describe_all();
    };

    Ok(())
}
