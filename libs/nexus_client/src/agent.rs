use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Result as IoResult},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

const NEXUS_CREDENTIAL_ENVIRONMENT: &[&str] = &[
    "NEXUS_RUSTDESK_REGISTRATION_TOKEN",
    "NEXUS_CONTROL_PLANE_TUNNEL_SIGNING_KEY",
    "NEXUS_CONTROL_PLANE_TUNNEL_VERIFYING_KEYS",
    "NEXUS_CONTROL_PLANE_CLIENT_CONFIGURATION_SIGNING_KEY",
    "NEXUS_RELAY_NODE_CREDENTIALS",
    "NEXUS_RELAY_BOOTSTRAP_SECRET",
    "NEXUS_RELAY_TELEMETRY_TOKEN",
    "NEXUS_PRESENCE_RESOLVER_TOKEN",
    "NEXUS_BILLING_WEBHOOK_TOKEN",
    "NEXUS_NOTIFICATION_WEBHOOK_TOKEN",
    "NEXUS_WEB_GATEWAY_TOKEN",
];

/// Third-party AI Agent launch request. The agent remains an external process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// The sole Tunnel material an external Agent may receive. It identifies a
/// local listener and proves one execution; it is not a bearer, device key,
/// grant, publishing identity, or RustDesk stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentLocalProxy {
    pub endpoint: String,
    pub capability: String,
}

/// Maximum combined stdout or stderr retained for an Agent audit result.
/// The process is never allowed to make unbounded in-memory output accumulate.
pub const MAX_AGENT_OUTPUT_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentProvider {
    Codex,
    Claude,
    Gemini,
    OpenClaw,
}

impl AgentProvider {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "codex" => Some(Self::Codex),
            "claude" => Some(Self::Claude),
            "gemini" => Some(Self::Gemini),
            "openclaw" => Some(Self::OpenClaw),
            _ => None,
        }
    }
}

/// Device-bound job envelope consumed by the host Agent supervisor.
///
/// The control plane supplies the immutable identity binding and bounded
/// execution inputs; a user bearer token is never part of this payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentJob {
    pub job_id: String,
    pub tenant_id: String,
    pub device_uid: String,
    pub machine_id: String,
    pub provider: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub timeout_ms: u64,
}

impl AgentJob {
    pub fn command(&self) -> Option<(AgentProvider, AgentCommand)> {
        Some((
            AgentProvider::parse(&self.provider)?,
            AgentCommand {
                program: self.program.clone(),
                args: self.args.clone(),
            },
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentProcessState {
    Running,
    Completed,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentExit {
    pub state: AgentProcessState,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentError {
    InvalidProgram,
    InvalidArgument,
    SpawnFailed,
    WaitFailed,
}

/// One restricted external Agent process. Nexus runtime credentials are removed
/// before launch; callers decide the working directory and bridge only audited
/// outputs back to the control plane.
pub struct AgentProcess {
    child: Child,
    stdout: Receiver<Vec<u8>>,
    stderr: Receiver<Vec<u8>>,
    started_at: Instant,
    timeout: Option<Duration>,
}

impl AgentCommand {
    /// Validates that a command targets a configured supported Agent binary,
    /// never an arbitrary shell expression.
    pub fn validate(&self, provider: AgentProvider) -> Result<(), AgentError> {
        let filename = self
            .program
            .file_stem()
            .and_then(|name| name.to_str())
            .map(str::to_ascii_lowercase)
            .ok_or(AgentError::InvalidProgram)?;
        let expected = match provider {
            AgentProvider::Codex => "codex",
            AgentProvider::Claude => "claude",
            AgentProvider::Gemini => "gemini",
            AgentProvider::OpenClaw => "openclaw",
        };
        if filename != expected || self.args.iter().any(|arg| arg.contains('\0')) {
            return Err(AgentError::InvalidArgument);
        }
        Ok(())
    }

    /// Starts the Agent with no shell and no inherited stdin. Output readers
    /// run independently so a verbose child cannot deadlock the RustDesk host.
    pub fn spawn(
        &self,
        provider: AgentProvider,
        working_directory: Option<&std::path::Path>,
        timeout: Option<Duration>,
    ) -> Result<AgentProcess, AgentError> {
        self.spawn_with_local_proxy(provider, working_directory, timeout, None)
    }

    /// Starts an Agent with an optional Host-created local proxy. No arbitrary
    /// environment map is accepted here, so callers cannot accidentally pass
    /// control-plane credentials through this boundary.
    pub fn spawn_with_local_proxy(
        &self,
        provider: AgentProvider,
        working_directory: Option<&std::path::Path>,
        timeout: Option<Duration>,
        local_proxy: Option<&AgentLocalProxy>,
    ) -> Result<AgentProcess, AgentError> {
        self.validate(provider)?;
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        remove_nexus_credentials(&mut command);
        if let Some(local_proxy) = local_proxy {
            if local_proxy.endpoint.trim().is_empty()
                || local_proxy.capability.len() != 64
                || !local_proxy
                    .capability
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(AgentError::InvalidArgument);
            }
            command
                .env("NEXUS_AGENT_TUNNEL_ENDPOINT", &local_proxy.endpoint)
                .env("NEXUS_AGENT_TUNNEL_CAPABILITY", &local_proxy.capability);
        }
        if let Some(working_directory) = working_directory {
            command.current_dir(working_directory);
        }
        let mut child = command.spawn().map_err(|_| AgentError::SpawnFailed)?;
        let stdout = child.stdout.take().ok_or(AgentError::SpawnFailed)?;
        let stderr = child.stderr.take().ok_or(AgentError::SpawnFailed)?;
        Ok(AgentProcess {
            child,
            stdout: drain_limited(stdout),
            stderr: drain_limited(stderr),
            started_at: Instant::now(),
            timeout,
        })
    }
}

fn remove_nexus_credentials(command: &mut Command) {
    for variable in NEXUS_CREDENTIAL_ENVIRONMENT {
        command.env_remove(variable);
    }
}

impl AgentProcess {
    /// Polls once and enforces the caller-selected wall-clock timeout.
    pub fn poll(&mut self) -> Result<Option<AgentExit>, AgentError> {
        if self
            .timeout
            .is_some_and(|timeout| self.started_at.elapsed() >= timeout)
        {
            return self
                .finish_after_kill(AgentProcessState::TimedOut)
                .map(Some);
        }
        match self.child.try_wait().map_err(|_| AgentError::WaitFailed)? {
            Some(status) => Ok(Some(self.finish(status, AgentProcessState::Completed))),
            None => Ok(None),
        }
    }

    /// Requests cancellation without allowing the Agent failure to terminate
    /// RustDesk. `Child::kill` is the portable immediate-child boundary.
    pub fn cancel(&mut self) -> Result<AgentExit, AgentError> {
        self.finish_after_kill(AgentProcessState::Cancelled)
    }

    fn finish_after_kill(&mut self, state: AgentProcessState) -> Result<AgentExit, AgentError> {
        if let Err(error) = self.child.kill() {
            if error.kind() != std::io::ErrorKind::InvalidInput {
                return Err(AgentError::WaitFailed);
            }
        }
        let status = self.child.wait().map_err(|_| AgentError::WaitFailed)?;
        Ok(self.finish(status, state))
    }

    fn finish(&mut self, status: ExitStatus, state: AgentProcessState) -> AgentExit {
        AgentExit {
            state,
            exit_code: status.code(),
            stdout: decode_output(&self.stdout),
            stderr: decode_output(&self.stderr),
        }
    }
}

fn drain_limited(mut reader: impl Read + Send + 'static) -> Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(read_limited(&mut reader).unwrap_or_default());
    });
    receiver
}

fn read_limited(reader: &mut impl Read) -> IoResult<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0; 8_192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(output);
        }
        let remaining = MAX_AGENT_OUTPUT_BYTES.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..read.min(remaining)]);
    }
}

fn decode_output(receiver: &Receiver<Vec<u8>>) -> String {
    let output = receiver.recv().unwrap_or_default();
    let mut text = String::from_utf8_lossy(&output).into_owned();
    if output.len() == MAX_AGENT_OUTPUT_BYTES {
        text.push_str("\n[output truncated]");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{
        drain_limited, remove_nexus_credentials, AgentCommand, AgentError, AgentLocalProxy,
        AgentProcess, AgentProcessState, AgentProvider,
    };
    use std::{
        ffi::OsStr,
        path::PathBuf,
        process::{Command, Stdio},
        time::Instant,
    };

    #[test]
    fn agent_command_is_provider_bound_and_never_accepts_shell_data() {
        let command = AgentCommand {
            program: PathBuf::from("codex.exe"),
            args: vec!["exec".into(), "safe prompt".into()],
        };
        assert_eq!(command.validate(AgentProvider::Codex), Ok(()));
        assert_eq!(
            command.validate(AgentProvider::Claude),
            Err(AgentError::InvalidArgument)
        );
        assert_eq!(
            AgentCommand {
                program: PathBuf::from("cmd.exe"),
                args: vec!["/c\0whoami".into()],
            }
            .validate(AgentProvider::Codex),
            Err(AgentError::InvalidArgument)
        );
    }

    #[test]
    fn agent_launch_removes_nexus_credentials_but_keeps_other_environment() {
        let mut command = Command::new("agent");
        command
            .env("NEXUS_CONTROL_PLANE_TUNNEL_SIGNING_KEY", "secret")
            .env("NEXUS_RELAY_BOOTSTRAP_SECRET", "secret")
            .env("AGENT_USER_SETTING", "kept");

        remove_nexus_credentials(&mut command);

        let environments: Vec<_> = command.get_envs().collect();
        assert!(environments.iter().any(|(name, value)| {
            *name == OsStr::new("NEXUS_CONTROL_PLANE_TUNNEL_SIGNING_KEY") && value.is_none()
        }));
        assert!(environments.iter().any(|(name, value)| {
            *name == OsStr::new("NEXUS_RELAY_BOOTSTRAP_SECRET") && value.is_none()
        }));
        assert!(environments.iter().any(|(name, value)| {
            *name == OsStr::new("AGENT_USER_SETTING") && value == &Some(OsStr::new("kept"))
        }));
    }

    #[test]
    fn local_proxy_launch_input_only_accepts_endpoint_and_256_bit_capability() {
        let command = AgentCommand {
            program: PathBuf::from("codex"),
            args: vec!["exec".into()],
        };
        assert!(matches!(
            command.spawn_with_local_proxy(
                AgentProvider::Codex,
                None,
                None,
                Some(&AgentLocalProxy {
                    endpoint: "127.0.0.1:10000".into(),
                    capability: "x".repeat(64),
                }),
            ),
            Err(AgentError::InvalidArgument)
        ));
    }

    #[test]
    fn cancellation_kills_the_running_agent_process() {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("cmd");
            command.args(["/c", "ping -n 30 127.0.0.1 > nul"]);
            command
        };
        #[cfg(not(windows))]
        let mut command = {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 30"]);
            command
        };
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("long-running child");
        let mut process = AgentProcess {
            stdout: drain_limited(child.stdout.take().expect("stdout")),
            stderr: drain_limited(child.stderr.take().expect("stderr")),
            child,
            started_at: Instant::now(),
            timeout: None,
        };

        let exit = process.cancel().expect("cancel child");
        assert_eq!(exit.state, AgentProcessState::Cancelled);
        #[cfg(windows)]
        assert!(exit.exit_code.is_some());
        #[cfg(not(windows))]
        assert_eq!(exit.exit_code, None, "SIGKILL has no POSIX exit code");
    }
}
