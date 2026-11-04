use nullca::engine::event::{Direction, TlsEvent};
use nullca::engine::ipc::IpcServer;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;

#[tokio::test]
async fn test_ipc_server_broadcast_to_client() {
    let dir = tempdir().expect("create temp dir");
    let socket_path = dir.path().join("test_nullca.sock");

    let server = IpcServer::start(&socket_path).expect("IPC server must start");

    // Connect a client socket
    let stream = UnixStream::connect(&socket_path)
        .await
        .expect("Client connects to socket");

    let mut reader = BufReader::new(stream).lines();

    // Broadcast an event from server
    let event = TlsEvent::new(
        123456789,
        9999,
        9999,
        7,
        Direction::Ingress,
        "test_daemon".into(),
        b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
        Some(15),
    );

    // Give background accept task a tiny moment
    tokio::time::sleep(Duration::from_millis(50)).await;

    server.broadcast(&event);

    // Read client line
    let received_line = tokio::time::timeout(Duration::from_secs(2), reader.next_line())
        .await
        .expect("No timeout")
        .expect("Stream not broken")
        .expect("Line exists");

    let parsed_event: TlsEvent = serde_json::from_str(&received_line).expect("Valid JSON event");
    assert_eq!(parsed_event.pid, 9999);
    assert_eq!(parsed_event.comm, "test_daemon");
    assert_eq!(parsed_event.direction, Direction::Ingress);
}
