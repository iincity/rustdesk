use std::path::PathBuf;

/// Third-party AI Agent launch request. The agent remains an external process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
}
