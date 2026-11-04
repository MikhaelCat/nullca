//! Process Spawn & Trace Mode.
//!
//! Spawns a target process command, attaches eBPF uprobes to its execution boundary
//! before network activity occurs, and streams unencrypted traffic to the TUI or terminal.

use crate::bpf::loader::BpfLoader;
use crate::engine::event::TlsEvent;
use std::process::Stdio;
use thiserror::Error;
use tokio::process::Command;
use tokio::sync::mpsc;

#[derive(Error, Debug)]
pub enum SpawnError {
    #[error("Failed to spawn process: {0}")]
    Io(#[from] std::io::Error),
    #[error("Process exited immediately without PID")]
    MissingPid,
}

pub struct ProcessLauncher;

impl ProcessLauncher {
    /// Spawns a command with arguments and traces its TLS activity until exit.
    pub async fn run_and_trace(
        command_line: &[String],
        event_tx: mpsc::Sender<TlsEvent>,
        emulate: bool,
    ) -> Result<i32, SpawnError> {
        if command_line.is_empty() {
            return Err(SpawnError::MissingPid);
        }

        let prog = &command_line[0];
        let args = &command_line[1..];

        let mut child = Command::new(prog)
            .args(args)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let pid = child.id().ok_or(SpawnError::MissingPid)?;

        let loader = BpfLoader::new(Some(pid));
        let emul = emulate || !BpfLoader::has_bpf_capabilities();

        // Spawn BPF trace loop for this specific child PID
        let bpf_handle = tokio::spawn(async move {
            let _ = loader.run_event_loop(None, event_tx, emul).await;
        });

        // Await child process termination
        let exit_status = child.wait().await?;
        let code = exit_status.code().unwrap_or(0);

        bpf_handle.abort();
        Ok(code)
    }
}
