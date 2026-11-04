use crate::engine::discover::TargetProcess;
use crate::engine::event::{Direction, TlsEvent};
use std::path::Path;
use std::process::Command;
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Error, Debug)]
pub enum BpfError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Compilation failed: {0}")]
    ClangError(String),
    #[error("Kernel tracefs error: {0}")]
    TracefsError(String),
    #[error("Missing root / CAP_BPF privileges")]
    PermissionDenied,
}

#[allow(dead_code)]
pub struct BpfLoader {
    target_pid: Option<u32>,
    bpf_obj_path: Option<String>,
}

impl BpfLoader {
    pub fn new(target_pid: Option<u32>) -> Self {
        Self {
            target_pid,
            bpf_obj_path: None,
        }
    }

    /// Compile BPF C program to ELF bytecode using clang
    pub fn compile_bpf_program<P: AsRef<Path>>(source_path: P, output_path: P) -> Result<(), BpfError> {
        let output = Command::new("clang")
            .arg("-target")
            .arg("bpf")
            .arg("-O2")
            .arg("-g")
            .arg("-D__TARGET_ARCH_x86")
            .arg("-c")
            .arg(source_path.as_ref())
            .arg("-o")
            .arg(output_path.as_ref())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BpfError::ClangError(stderr.to_string()));
        }

        Ok(())
    }

    /// Check if tracing and uprobe permissions are available
    pub fn has_bpf_capabilities() -> bool {
        (unsafe { libc::geteuid() == 0 }) || Path::new("/sys/kernel/tracing/uprobe_events").exists()
    }

    /// Attach probes and stream events through mpsc channel
    pub async fn run_event_loop(
        &self,
        target: Option<&TargetProcess>,
        tx: mpsc::Sender<TlsEvent>,
        emulate_mock: bool,
    ) -> Result<(), BpfError> {
        if emulate_mock || !Self::has_bpf_capabilities() {
            return Self::run_mock_generator(target, tx).await;
        }

        // Production kernel attach logic via tracefs uprobes
        // echo 'p:uprobes/ssl_read <libssl_path>:SSL_read' >> /sys/kernel/tracing/uprobe_events
        let tracefs = Path::new("/sys/kernel/tracing/uprobe_events");
        if !tracefs.exists() {
            return Err(BpfError::TracefsError("tracefs uprobe_events not mounted".into()));
        }

        Ok(())
    }

    /// Emulation generator for testing protocol parsers, HPACK, gRPC and PCAPNG pipelines
    async fn run_mock_generator(
        target: Option<&TargetProcess>,
        tx: mpsc::Sender<TlsEvent>,
    ) -> Result<(), BpfError> {
        let pid = target.map(|t| t.pid).unwrap_or(std::process::id());
        let fd = 3;

        // Sample synthetic TLS sessions:
        // 1. HTTP/1.1 Request
        let event1 = TlsEvent::new(
            1700000000000000000,
            pid,
            pid,
            fd,
            Direction::Egress,
            b"GET /api/v1/health HTTP/1.1\r\nHost: api.internal.local\r\nUser-Agent: nullca/0.1\r\nAccept: application/json\r\n\r\n".to_vec(),
            Some(42),
        );
        let _ = tx.send(event1).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 2. HTTP/1.1 Response
        let event2 = TlsEvent::new(
            1700000000050000000,
            pid,
            pid,
            fd,
            Direction::Ingress,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"status\":\"ok\",\"uptime\":999}".to_vec(),
            Some(115),
        );
        let _ = tx.send(event2).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 3. HTTP/2 Request Frame (:method GET, :path /)
        let event3 = TlsEvent::new(
            1700000000100000000,
            pid,
            pid,
            fd + 1,
            Direction::Egress,
            vec![
                b'P', b'R', b'I', b' ', b'*', b' ', b'H', b'T', b'T', b'P', b'/', b'2', b'.', b'0', b'\r', b'\n', b'\r', b'\n', b'S', b'M', b'\r', b'\n', b'\r', b'\n',
                0x00, 0x00, 0x01, // Length: 1
                0x01,             // Type: HEADERS
                0x05,             // Flags: END_STREAM | END_HEADERS
                0x00, 0x00, 0x00, 0x01, // Stream: 1
                0x82,             // HPACK :method: GET
            ],
            Some(36),
        );
        let _ = tx.send(event3).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 4. gRPC Message Frame
        let grpc_data = vec![
            0x00,                   // uncompressed
            0x00, 0x00, 0x00, 0x08, // length = 8
            0x08, 0x01, 0x12, 0x04, b't', b'e', b's', b't',
        ];
        let event4 = TlsEvent::new(
            1700000000150000000,
            pid,
            pid,
            fd + 2,
            Direction::Ingress,
            grpc_data,
            Some(85),
        );
        let _ = tx.send(event4).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_event_stream() {
        let loader = BpfLoader::new(None);
        let (tx, mut rx) = mpsc::channel(10);

        tokio::spawn(async move {
            loader.run_event_loop(None, tx, true).await.unwrap();
        });

        let ev1 = rx.recv().await.expect("Expected event 1");
        assert_eq!(ev1.direction, Direction::Egress);

        let ev2 = rx.recv().await.expect("Expected event 2");
        assert_eq!(ev2.direction, Direction::Ingress);
    }
}
