//! Unix Domain Socket IPC Streaming Daemon & Client.
//!
//! Allows external scripts, Python/pwntools bots, and terminal viewers to stream
//! live decrypted TLS events in real-time as NDJSON from a running NullCA instance.

use crate::engine::event::TlsEvent;
use crate::engine::filter::FilterEngine;
use crate::export::terminal::TerminalFormatter;
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

pub const DEFAULT_SOCKET_PATH: &str = "/tmp/nullca.sock";

#[derive(Clone)]
pub struct IpcServer {
    socket_path: PathBuf,
    tx: Arc<broadcast::Sender<String>>,
}

impl IpcServer {
    /// Binds and starts the Unix Domain Socket IPC broadcast server.
    pub fn start<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
        let path_buf = socket_path.as_ref().to_path_buf();
        // Remove existing stale socket file if it exists
        if path_buf.exists() {
            let _ = std::fs::remove_file(&path_buf);
        }

        let listener = UnixListener::bind(&path_buf)
            .map_err(|e| anyhow!("Failed to bind IPC socket at {:?}: {}", path_buf, e))?;

        let (tx, _) = broadcast::channel::<String>(512);
        let tx = Arc::new(tx);
        let tx_clone = Arc::clone(&tx);

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut rx = tx_clone.subscribe();
                tokio::spawn(async move {
                    while let Ok(line) = rx.recv().await {
                        if stream.write_all(line.as_bytes()).await.is_err() {
                            break;
                        }
                        if stream.write_all(b"\n").await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        Ok(Self {
            socket_path: path_buf,
            tx,
        })
    }

    /// Broadcasts an intercepted TLS event to all connected clients.
    pub fn broadcast(&self, event: &TlsEvent) {
        if self.tx.receiver_count() > 0 {
            if let Ok(json_line) = serde_json::to_string(event) {
                let _ = self.tx.send(json_line);
            }
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

pub struct IpcClient;

impl IpcClient {
    /// Connects to a running NullCA IPC server and streams live decrypted events to stdout.
    pub async fn stream<P: AsRef<Path>>(
        socket_path: P,
        filter_engine: Option<FilterEngine>,
        json_mode: bool,
        hexdump: bool,
    ) -> Result<()> {
        let path = socket_path.as_ref();
        if !path.exists() {
            return Err(anyhow!(
                "NullCA socket not found at {:?}. Is 'nullca trace' or 'nullca run' running?",
                path
            ));
        }

        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| anyhow!("Failed to connect to NullCA socket {:?}: {}", path, e))?;

        let reader = BufReader::new(stream);
        let mut lines = reader.lines();
        let mut formatter = TerminalFormatter::new(hexdump);

        while let Some(line) = lines.next_line().await? {
            if let Ok(event) = serde_json::from_str::<TlsEvent>(&line) {
                if let Some(ref f) = filter_engine {
                    if !f.matches(&event) {
                        continue;
                    }
                }

                if json_mode {
                    println!("{}", line);
                } else {
                    let formatted = formatter.format_event(&event);
                    print!("{}", formatted);
                }
            }
        }

        Ok(())
    }
}
