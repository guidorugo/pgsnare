// SPDX-License-Identifier: Apache-2.0

//! What the tests of this program share: a `pgsnare` process and what it
//! wrote, a directory for its files, a database made of a few lines, and
//! just enough of the wire protocol to log in.

use std::future::Future;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustix::process::{Pid, Signal, kill_process};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// How long a test waits for something that must happen.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// Waits for something that must happen within [`PATIENCE`].
pub async fn soon<T>(work: impl Future<Output = T>) -> T {
    tokio::time::timeout(PATIENCE, work)
        .await
        .expect("this happens in time")
}

/// Waits until a condition holds, checking it every few milliseconds.
pub async fn until(mut condition: impl FnMut() -> bool) {
    soon(async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// A directory that is removed again when the test ends.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "pgsnare-command-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Writes a file that only its owner can read.
    pub fn write(&self, name: &str, content: &[u8]) -> PathBuf {
        self.write_with_mode(name, content, 0o600)
    }

    pub fn write_with_mode(&self, name: &str, content: &[u8], mode: u32) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A port of this machine that nothing listens on at the moment.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ---------------------------------------------------------------------------
// The process
// ---------------------------------------------------------------------------

/// Everything a stream of a process has written so far.
#[derive(Clone, Default)]
pub struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn follow(&self, mut stream: impl Read + Send + 'static) -> thread::JoinHandle<()> {
        let all = Arc::clone(&self.0);
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => return,
                    Ok(count) => all.lock().unwrap().extend_from_slice(&buffer[..count]),
                }
            }
        })
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    /// The complete lines written so far.
    pub fn lines(&self) -> Vec<String> {
        let text = self.text();
        let complete = text.rfind('\n').map_or("", |end| &text[..end]);
        complete.lines().map(str::to_owned).collect()
    }
}

/// A `pgsnare` process, and what it wrote.
pub struct Pgsnare {
    child: Child,
    pub stdout: Captured,
    pub stderr: Captured,
    readers: Vec<thread::JoinHandle<()>>,
}

impl Pgsnare {
    /// Starts the binary of this build with these arguments. The process
    /// gets the environment variables given here and no others.
    pub fn start(arguments: &[&str], environment: &[(&str, &str)]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pgsnare"))
            .args(arguments)
            .env_clear()
            .envs(environment.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary of this build can be started");
        let (stdout, stderr) = (Captured::default(), Captured::default());
        let readers = vec![
            stdout.follow(child.stdout.take().unwrap()),
            stderr.follow(child.stderr.take().unwrap()),
        ];
        Self {
            child,
            stdout,
            stderr,
            readers,
        }
    }

    /// Starts `pgsnare run` with a configuration file.
    pub fn run(config: &Path, environment: &[(&str, &str)]) -> Self {
        Self::start(&["run", "--config", config.to_str().unwrap()], environment)
    }

    /// Waits until the process accepts connections on a port of this
    /// machine.
    pub async fn listening(&mut self, port: u16) {
        soon(async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    panic!(
                        "pgsnare ended with {status} before it listened:\n{}",
                        self.stderr.text()
                    );
                }
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
    }

    /// Sends the process a signal.
    pub fn signal(&self, signal: Signal) {
        let pid = Pid::from_child(&self.child);
        kill_process(pid, signal).expect("the process can be signalled");
    }

    /// Waits until the process has ended and everything it wrote has been
    /// read.
    pub async fn ended(&mut self) -> ExitStatus {
        let status = soon(async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        status
    }
}

impl Drop for Pgsnare {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A message with a type byte, as it goes on the wire.
pub fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// A startup message for protocol 3.0.
pub fn startup_message(user: &str, database: &str, application_name: &str) -> Vec<u8> {
    let mut body = 196_608u32.to_be_bytes().to_vec();
    for (name, value) in [
        ("user", user),
        ("database", database),
        ("application_name", application_name),
    ] {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut bytes = u32::try_from(body.len() + 4)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    bytes.extend_from_slice(&body);
    bytes
}

pub fn query(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    frame(b'Q', &body)
}

/// A message no session can follow: it announces a length below the
/// minimum, so nobody can tell where the next message begins.
pub const BROKEN: [u8; 7] = [b'Q', 0, 0, 0, 1, b'x', b'y'];

/// What the test database sends a client it has let in.
pub fn welcome() -> Vec<u8> {
    let mut bytes = frame(b'R', &0u32.to_be_bytes());
    bytes.extend_from_slice(&frame(b'S', b"server_version\x0018.6\0"));
    let mut key = 4242i32.to_be_bytes().to_vec();
    key.extend_from_slice(&[1, 2, 3, 4]);
    bytes.extend_from_slice(&frame(b'K', &key));
    bytes.extend_from_slice(&frame(b'Z', b"I"));
    bytes
}

/// The answer of the test database to a query: the query text as the only
/// column of one row.
pub fn answer(sql: &[u8]) -> Vec<u8> {
    let mut row = vec![0, 1];
    row.extend_from_slice(&u32::try_from(sql.len()).unwrap().to_be_bytes());
    row.extend_from_slice(sql);
    let mut bytes = frame(b'D', &row);
    bytes.extend_from_slice(&frame(b'C', b"SELECT 1\0"));
    bytes.extend_from_slice(&frame(b'Z', b"I"));
    bytes
}

/// Reads one startup-phase packet: a length and that many bytes.
pub async fn read_packet(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let total = usize::try_from(u32::from_be_bytes(length)).unwrap();
    let mut packet = length.to_vec();
    packet.resize(total.max(4), 0);
    stream.read_exact(&mut packet[4..]).await?;
    Ok(packet)
}

/// Reads one message with a type byte.
pub async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let length = usize::try_from(u32::from_be_bytes(header[1..].try_into().unwrap())).unwrap();
    let mut frame = header.to_vec();
    frame.resize(1 + length.max(4), 0);
    stream.read_exact(&mut frame[5..]).await?;
    Ok(frame)
}

/// Reads messages up to and including `ReadyForQuery`, and returns them
/// all, joined.
pub async fn read_until_ready(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut all = Vec::new();
    loop {
        let frame = read_frame(stream).await?;
        let done = frame[0] == b'Z';
        all.extend_from_slice(&frame);
        if done {
            return Ok(all);
        }
    }
}

// ---------------------------------------------------------------------------
// A database
// ---------------------------------------------------------------------------

/// A database that lets every client in, answers each query with the text
/// of the query, and takes everything else without a word.
pub struct Database {
    pub address: SocketAddr,
    task: JoinHandle<()>,
}

impl Database {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let _ = serve(&mut stream).await;
                });
            }
        });
        Self { address, task }
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(stream: &mut TcpStream) -> io::Result<()> {
    read_packet(stream).await?;
    stream.write_all(&welcome()).await?;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        // A whole query in one read is answered. Whatever else arrives,
        // such as what a session passes on once it has given up following
        // the traffic, is taken and not answered.
        let received = &buffer[..count];
        if received[0] == b'Q' && received.len() > 6 && received[count - 1] == 0 {
            let length = usize::try_from(u32::from_be_bytes(received[1..5].try_into().unwrap()));
            if length == Ok(count - 1) {
                stream.write_all(&answer(&received[5..count - 1])).await?;
            }
        }
    }
}

/// Connects to a proxy, logs in and returns the connection.
pub async fn log_in(port: u16, user: &str, database: &str, application_name: &str) -> TcpStream {
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    client
        .write_all(&startup_message(user, database, application_name))
        .await
        .unwrap();
    soon(read_until_ready(&mut client)).await.unwrap();
    client
}
