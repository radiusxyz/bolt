use crate::cli::{OperatorsCommand, OperatorsSubcommand};

mod eigenlayer;
mod symbiotic;

impl OperatorsCommand {
    /// Run the operators command by dispatching to the appropriate subcommand.
    pub async fn run(self) -> eyre::Result<()> {
        match self.subcommand {
            OperatorsSubcommand::EigenLayer { subcommand } => subcommand.run().await,
            OperatorsSubcommand::Symbiotic { subcommand } => subcommand.run().await,
        }
    }
}
