//! Execution-scoped local-proxy capability boundary.
//!
//! The Host keeps the registry in memory.  An external Agent receives only a
//! loopback endpoint and one 256-bit capability, never a device key, bearer,
//! grant, or RustDesk stream.  A proxy consumes the capability before it
//! forwards its first connection, making replay and cross-execution use fail.

use std::{
    collections::HashMap,
    io::Read,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const CAPABILITY_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalProxyCapability {
    pub execution_id: String,
    pub value: String,
}

pub struct LocalProxyCapabilities {
    active: Mutex<HashMap<String, String>>,
}

/// One execution-bound loopback listener.  It accepts no target from the
/// Agent: the Host supplies the already-authorized destination at creation.
pub struct LoopbackProxy {
    endpoint: SocketAddr,
    stopping: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

impl Default for LocalProxyCapabilities {
    fn default() -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
        }
    }
}

impl LocalProxyCapabilities {
    /// Issues exactly one opaque capability for an execution. Reissuing
    /// replaces the previous value, so a retry cannot reuse an old Agent's
    /// loopback credential.
    pub fn issue(&self, execution_id: &str) -> Result<LocalProxyCapability, String> {
        if execution_id.trim().is_empty() {
            return Err("execution ID is required".into());
        }
        let mut bytes = [0_u8; CAPABILITY_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|_| "local capability generation failed")?;
        let value = hex::encode(bytes);
        self.active
            .lock()
            .map_err(|_| "local capability registry unavailable")?
            .insert(execution_id.to_owned(), value.clone());
        Ok(LocalProxyCapability {
            execution_id: execution_id.to_owned(),
            value,
        })
    }

    /// Authenticates and consumes a capability before forwarding.  Consumption
    /// is intentionally atomic with lookup: a replay cannot win a second race.
    pub fn consume(&self, execution_id: &str, value: &str) -> bool {
        let Ok(mut active) = self.active.lock() else {
            return false;
        };
        let valid = active
            .get(execution_id)
            .is_some_and(|expected| constant_time_equal(expected.as_bytes(), value.as_bytes()));
        if valid {
            active.remove(execution_id);
        }
        valid
    }

    /// Revokes a pending capability on cancel, terminal completion, or retry.
    pub fn revoke(&self, execution_id: &str) -> bool {
        self.active
            .lock()
            .ok()
            .and_then(|mut active| active.remove(execution_id))
            .is_some()
    }

    fn is_active(&self, execution_id: &str) -> bool {
        self.active
            .lock()
            .ok()
            .is_some_and(|active| active.contains_key(execution_id))
    }
}

impl LoopbackProxy {
    /// Starts a single-use loopback TCP proxy for one execution.  The caller
    /// owns cancellation through the shared capability registry or `Drop`.
    pub fn start(
        capabilities: Arc<LocalProxyCapabilities>,
        capability: LocalProxyCapability,
        target: SocketAddr,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| "local proxy bind failed")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "local proxy setup failed")?;
        let endpoint = listener
            .local_addr()
            .map_err(|_| "local proxy endpoint unavailable")?;
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopping);
        let task = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) && capabilities.is_active(&capability.execution_id)
            {
                match listener.accept() {
                    Ok((client, _)) => {
                        if authenticate_and_forward(client, &capabilities, &capability, target) {
                            return;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });
        Ok(Self {
            endpoint,
            stopping,
            task: Some(task),
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

impl Drop for LoopbackProxy {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        // A native PortForward peer may retain its reverse half after the
        // Agent has exited. Joining here would then block execution finish,
        // cancellation, and retries indefinitely. The thread owns only this
        // revoked listener/capability and exits once its current copy returns.
        let _ = self.task.take();
    }
}

fn authenticate_and_forward(
    mut client: TcpStream,
    capabilities: &LocalProxyCapabilities,
    capability: &LocalProxyCapability,
    target: SocketAddr,
) -> bool {
    // An unauthenticated local peer must not hold the single-use listener
    // forever and starve the execution it belongs to.
    if client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .is_err()
    {
        return false;
    }
    let mut presented = [0_u8; CAPABILITY_BYTES * 2 + 1];
    if client.read_exact(&mut presented).is_err()
        || presented[CAPABILITY_BYTES * 2] != b'\n'
        || !capabilities.consume(
            &capability.execution_id,
            std::str::from_utf8(&presented[..CAPABILITY_BYTES * 2]).unwrap_or_default(),
        )
    {
        return false;
    }
    let Ok(mut target) = TcpStream::connect(target) else {
        return true;
    };
    let Ok(mut reverse) = client.try_clone() else {
        return true;
    };
    let Ok(mut target_reverse) = target.try_clone() else {
        return true;
    };
    let reverse_task = thread::spawn(move || std::io::copy(&mut target_reverse, &mut reverse));
    let _ = std::io::copy(&mut client, &mut target);
    let _ = reverse_task.join();
    true
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::{LocalProxyCapabilities, LoopbackProxy};
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::Arc,
        thread,
    };

    #[test]
    fn capability_is_256_bit_single_use_and_execution_scoped() {
        let capabilities = LocalProxyCapabilities::default();
        let capability = capabilities.issue("execution-a").unwrap();

        assert_eq!(capability.value.len(), 64);
        assert!(!capabilities.consume("execution-b", &capability.value));
        assert!(capabilities.consume("execution-a", &capability.value));
        assert!(!capabilities.consume("execution-a", &capability.value));
    }

    #[test]
    fn revocation_and_reissue_invalidate_previous_capabilities() {
        let capabilities = LocalProxyCapabilities::default();
        let first = capabilities.issue("execution-a").unwrap();
        let second = capabilities.issue("execution-a").unwrap();

        assert_ne!(first.value, second.value);
        assert!(!capabilities.consume("execution-a", &first.value));
        assert!(capabilities.revoke("execution-a"));
        assert!(!capabilities.consume("execution-a", &second.value));
    }

    #[test]
    fn loopback_proxy_authenticates_before_forwarding() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_addr = target.local_addr().unwrap();
        let echo = thread::spawn(move || {
            let (mut stream, _) = target.accept().unwrap();
            let mut received = [0_u8; 5];
            stream.read_exact(&mut received).unwrap();
            stream.write_all(&received).unwrap();
        });
        let capabilities = Arc::new(LocalProxyCapabilities::default());
        let capability = capabilities.issue("execution-a").unwrap();
        let proxy =
            LoopbackProxy::start(Arc::clone(&capabilities), capability.clone(), target_addr)
                .unwrap();

        let mut rejected = TcpStream::connect(proxy.endpoint()).unwrap();
        rejected.write_all(b"x").unwrap();
        drop(rejected);
        let mut client = TcpStream::connect(proxy.endpoint()).unwrap();
        client
            .write_all(format!("{}\nping!", capability.value).as_bytes())
            .unwrap();
        let mut echoed = [0_u8; 5];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping!");
        assert!(!capabilities.consume("execution-a", &capability.value));
        echo.join().unwrap();
    }
}
