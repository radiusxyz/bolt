use std::{fs, path::PathBuf};

use eyre::Result;
use serde::Serialize;

/// BoltManager contract bindings.
pub mod bolt_manager;

/// Common signing utilities and API integrations.
pub mod signing;

/// Write some serializable data to an output json file
pub fn write_to_file<T: Serialize>(out: &str, data: &T) -> Result<()> {
    let out_path = PathBuf::from(out);
    let out_file = fs::File::create(out_path)?;
    serde_json::to_writer_pretty(out_file, data)?;
    Ok(())
}
