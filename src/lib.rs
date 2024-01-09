// #![warn(missing_docs)]

//!
//! LND
//!
//! Utility to run a regtest LND process, useful in integration testing environment
//!

mod error;
// mod ext;
mod versions;

use bitcoind::anyhow;
use bitcoind::anyhow::Context;
use bitcoind::bitcoincore_rpc::jsonrpc::serde_json::Value;
use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::tempfile::TempDir;
use bitcoind::{get_available_port, BitcoinD};
use tonic_lnd::Client;
use log::{error, warn};
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

// re-export bitcoind
pub use bitcoind;

pub use error::Error;
pub use which;

/// Lnd configuration parameters, implements a convenient [Default] for most common use.
///
/// Default values:
/// ```
/// let mut conf = lnd::Conf::default();
/// conf.view_stdout = false;
/// conf.network = "regtest";
/// conf.tmpdir = None;
/// conf.staticdir = None;
/// conf.minchansize = None;
/// conf.maxchansize = None;
/// assert_eq!(conf, lnd::Conf::default());
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Conf<'a> {
    /// Lnd command line arguments
    pub args: Vec<&'a str>,

    /// if `true` lnd log output will not be suppressed
    pub view_stdout: bool,

    /// if `true` lnd log error output will not be suppressed
    pub view_stderr: bool,

    /// Must match bitcoind network
    pub network: &'a str,

    /// Optionally specify a temporary or persistent working directory for the lnd.
    /// lnd index files will be stored in this path.
    /// The following two parameters can be configured to simulate desired working directory configuration.
    ///
    /// tmpdir is Some() && staticdir is Some() : Error. Cannot be enabled at same time.
    /// tmpdir is Some(temp_path) && staticdir is None : Create temporary directory at `tmpdir` path.
    /// tmpdir is None && staticdir is Some(work_path) : Create persistent directory at `staticdir` path.
    /// tmpdir is None && staticdir is None: Creates a temporary directory in OS default temporary directory (eg /tmp) or `TEMPDIR_ROOT` env variable path.
    ///
    /// Temporary directory path
    pub tmpdir: Option<PathBuf>,

    /// Persistent directory path
    pub staticdir: Option<PathBuf>,

    /// Try to spawn the process `attempt` time
    ///
    /// The OS is giving available ports to use, however, they aren't booked, so it could rarely
    /// happen they are used at the time the process is spawn. When retrying other available ports
    /// are returned reducing the probability of conflicts to negligible.
    attempts: u8,

    listen_port: u16,

    pub minchansize: Option<u64>,

    pub maxchansize: Option<u64>
}

impl Default for Conf<'_> {
    fn default() -> Self {
        // let args = if cfg!(feature = "lnd_0_9_1")
        //     || cfg!(feature = "lnd_0_8_10")
        //     || cfg!(feature = "esplora_a33e97e1")
        //     || cfg!(feature = "legacy")
        // {
        //     vec!["-vvv"]
        // } else {
        //     vec![]
        // };
        //
        let args = vec![];

        Conf {
            args,
            view_stderr: false,
            view_stdout: false,
            network: "regtest",
            listen_port: 9735,
            tmpdir: None,
            staticdir: None,
            attempts: 3,
            minchansize: None,
            maxchansize: None
        }
    }
}

/// Struct representing the lnd process with related information
pub struct Lnd {
    /// Process child handle, used to terminate the process when this struct is dropped
    process: Child,
    /// LND client connected to the lnd process
    pub client: Client,
    /// Work directory, where the lnd stores indexes and other stuffs.
    work_dir: DataDir,
    /// Url to connect to the gRPC server
    pub grpc_url: String,
    /// Url to connect to the REST server
    pub rest_url: String,
    /// Url to connect to p2p network
    pub listen_url: Option<String>,
    /// Admin macaroon hex
    pub admin_macaroon: String,
    /// TLS Cert hex
    pub tls_cert: String
}

/// The DataDir struct defining the kind of data directory lnd will use.
/// /// Data directory can be either persistent, or temporary.
pub enum DataDir {
    /// Persistent Data Directory
    Persistent(PathBuf),
    /// Temporary Data Directory
    Temporary(TempDir),
}

impl DataDir {
    /// Return the data directory path
    fn path(&self) -> PathBuf {
        match self {
            Self::Persistent(path) => path.to_owned(),
            Self::Temporary(tmp_dir) => tmp_dir.path().to_path_buf(),
        }
    }
}

impl Lnd {
    /// Create a new lnd process connected with the given bitcoind and default args.
    pub async fn new<S: AsRef<OsStr>>(exe: S, bitcoind: &BitcoinD) -> anyhow::Result<Lnd> {
        Lnd::with_conf(exe, &Conf::default(), bitcoind).await
    }

    /// Create a new lnd process using given [Conf] connected with the given bitcoind
    #[async_recursion::async_recursion(?Send)]
    pub async fn with_conf<S: AsRef<OsStr>>(
        exe: S,
        conf: &Conf<'_>,
        bitcoind: &BitcoinD,
    ) -> anyhow::Result<Lnd> {
        let response = bitcoind.client.call::<Value>("getblockchaininfo", &[])?;
        if response
            .get("initialblockdownload")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            // bitcoind will remain in IBD if doesn't see a block from a long time, thus adding a block
            let node_address = bitcoind.client.call::<Value>("getnewaddress", &[])?;
            bitcoind
                .client
                .call::<Value>("generatetoaddress", &[1.into(), node_address])
                .unwrap();
        }

        let mut args = conf.args.clone();

        let work_dir = match (&conf.tmpdir, &conf.staticdir) {
            (Some(_), Some(_)) => return Err(Error::BothDirsSpecified.into()),
            (Some(tmpdir), None) => DataDir::Temporary(TempDir::new_in(tmpdir)?),
            (None, Some(workdir)) => {
                std::fs::create_dir_all(workdir)?;
                DataDir::Persistent(workdir.to_owned())
            }
            (None, None) => match env::var("TEMPDIR_ROOT").map(PathBuf::from) {
                Ok(path) => DataDir::Temporary(TempDir::new_in(path)?),
                Err(_) => DataDir::Temporary(TempDir::new()?),
            },
        };

        let db_dir = format!("--lnddir={}", work_dir.path().display());
        args.push(&db_dir);

        let tls_path = format!("--tlscertpath={}/tls.cert", work_dir.path().display());
        args.push(&tls_path);

        let network = format!("--bitcoin.{}", conf.network);
        args.push(&network);

        args.push("--bitcoin.active");

        args.push("--bitcoin.node=bitcoind");

        let cookie = format!("--bitcoind.rpccookie={}", bitcoind.params.cookie_file.to_str().unwrap());
        args.push(&cookie);

        let rpc_socket = bitcoind.params.rpc_socket.to_string();
        let host = format!("--bitcoind.rpchost={}", rpc_socket);
        args.push(&host);

        let raw_block_port = bitcoind.params.zmq_pub_raw_block_socket.unwrap();
        let raw_tx_port = bitcoind.params.zmq_pub_raw_tx_socket.unwrap();

        let zmq_raw_block = format!("--bitcoind.zmqpubrawblock=tcp://{}", raw_block_port);
        args.push(&zmq_raw_block);
        let zmq_raw_tx = format!("--bitcoind.zmqpubrawtx=tcp://{}", raw_tx_port);
        args.push(&zmq_raw_tx);


        let listen_port = get_available_port()?;
        let listen_url = format!("0.0.0.0:{}", listen_port);
        let listen_arg = format!("--listen={}", listen_url);
        args.push(&listen_arg);

        let grpc_port = get_available_port()?;
        let grpc_url = format!("0.0.0.0:{}", grpc_port);
        let grpc_arg = format!("--rpclisten={}", grpc_url);
        args.push(&grpc_arg);

        let rest_port = get_available_port()?;
        let rest_url = format!("0.0.0.0:{}", rest_port);
        let rest_arg = format!("--restlisten={}", rest_url);
        args.push(&rest_arg);

        args.push("--noseedbackup");

        args.push("--protocol.wumbo-channels");

        let view_stderr = if conf.view_stdout {
            Stdio::inherit()
        } else {
            Stdio::null()
        };

        let view_stdout = if conf.view_stdout {
            Stdio::inherit()
        } else {
            Stdio::null()
        };

        let mut process = Command::new(&exe)
            .args(args)
            .stderr(view_stderr)
            .stdout(view_stdout)
            .spawn()
            .with_context(|| format!("Error while executing {:?}", exe.as_ref()))?;

        let cert_file = work_dir.path().join("tls.cert");
        let macaroon_file = work_dir.path().join(format!("data/chain/bitcoin/{}/admin.macaroon", conf.network));

        let client = loop {
            if let Some(status) = process.try_wait()? {
                if conf.attempts > 0 {
                    warn!("early exit with: {:?}. Trying to launch again ({} attempts remaining), maybe some other process used our available port", status, conf.attempts);
                    let mut conf = conf.clone();
                    conf.attempts -= 1;
                    return Self::with_conf(exe, &conf, bitcoind).await
                        .with_context(|| format!("Remaining attempts {}", conf.attempts));
                } else {
                    error!("early exit with: {:?}", status);
                    return Err(Error::EarlyExit(status).into());
                }
            }

            match tonic_lnd::connect(format!("https://localhost:{}", grpc_port.clone()), &cert_file, &macaroon_file).await {
                Ok(client) => break client,
                Err(e) => {
                    error!("Error creating client: {}", e);
                    std::thread::sleep(Duration::from_millis(500));
                }
            };
        };

        let cert = std::fs::read(cert_file)?;
        let tls_cert = hex::encode(&cert);

        let mac = std::fs::read(macaroon_file)?;
        let admin_macaroon = hex::encode(&mac);

        // Sleep for 5 seconds because the gRPC server needs to warm up.
        tokio::time::sleep(Duration::from_secs(5)).await;

        Ok(Lnd {
            process,
            client,
            work_dir,
            grpc_url: format!("https://localhost:{}", grpc_port),
            rest_url: format!("https://localhost:{}", rest_port),
            listen_url: Some(format!("localhost:{}", listen_port)),
            admin_macaroon,
            tls_cert,
        })
    }

    /// triggers lnd sync by sending the `SIGUSR1` signal, useful to call after a block for example
    pub fn trigger(&self) -> anyhow::Result<()> {
        Ok(nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.process.id() as i32),
            nix::sys::signal::SIGUSR1,
        )?)
    }

    /// Return the current workdir path of the running lnd
    pub fn workdir(&self) -> PathBuf {
        self.work_dir.path()
    }

    /// terminate the lnd process
    pub fn kill(&mut self) -> anyhow::Result<()> {
        match self.work_dir {
            DataDir::Persistent(_) => {
                // Send SIGINT signal to lnd
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(self.process.id() as i32),
                    nix::sys::signal::SIGINT,
                )?;
                // Wait for the process to exit
                match self.process.wait() {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.into()),
                }
            }
            DataDir::Temporary(_) => Ok(self.process.kill()?),
        }
    }
}

impl Drop for Lnd {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

/// Provide the lnd executable path if a version feature has been specified
pub fn downloaded_exe_path() -> Option<String> {
    if versions::HAS_FEATURE {
        Some(format!(
            "{}/lnd/{}/lnd",
            env!("OUT_DIR"),
            versions::lnd_name(),
        ))
    } else {
        None
    }
}

/// Returns the daemon `lnd` executable with the following precedence:
///
/// 1) If it's specified in the `LND_EXEC` or in `LND_EXE` env var
/// (errors if both env vars are present)
/// 2) If there is no env var but an auto-download feature such as `lnd_0_9_11` is enabled, returns the
/// path of the downloaded executabled
/// 3) If neither of the precedent are available, the `lnd` executable is searched in the `PATH`
pub fn exe_path() -> anyhow::Result<String> {
    if let (Ok(_), Ok(_)) = (std::env::var("LND_EXEC"), std::env::var("LND_EXE")) {
        return Err(error::Error::BothEnvVars.into());
    }
    if let Ok(path) = std::env::var("LND_EXEC") {
        return Ok(path);
    }
    if let Ok(path) = std::env::var("LND_EXE") {
        return Ok(path);
    }
    if let Some(path) = downloaded_exe_path() {
        return Ok(path);
    }
    which::which("lnd")
        .map_err(|_| Error::NoLndExecutableFound.into())
        .map(|p| p.display().to_string())
}

#[cfg(test)]
mod test {
    use crate::exe_path;
    use crate::Lnd;
    use bitcoind::BitcoinD;
    use bitcoind::bitcoincore_rpc::RpcApi;
    use log::{debug, log_enabled, Level};
    use tonic_lnd::lnrpc::GetInfoRequest;
    use std::env;

    #[test]
    fn test_both_env_vars() {
        env::set_var("LND_EXEC", "placeholder");
        env::set_var("LND_EXE", "placeholder");
        assert!(exe_path().is_err());
        // unsetting because this errors everything in mod test!
        env::remove_var("LND_EXEC");
        env::remove_var("LND_EXE");
    }

    #[tokio::test]
    async fn two_lnd_nodes() {
        let (lnd_exe, _, bitcoind) = setup_nodes().await;

        let lnd = Lnd::new(&lnd_exe, &bitcoind).await;

        assert!(lnd.is_ok());
    }

    #[tokio::test]
    async fn test_with_gen_blocks() {
        let (_, _, bitcoind) = setup_nodes().await;

        let address = bitcoind
            .client
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();

        bitcoind.client.generate_to_address(100, &address).expect("Blocks not generated to address.");
    }

    #[tokio::test]
    async fn test_kill() {
        let (_, mut lnd, bitcoind) = setup_nodes().await;
        let _ = bitcoind.client.ping().unwrap(); // without using bitcoind, it is dropped and all the rest fails.
        let info = lnd.client.lightning().get_info(GetInfoRequest {}).await;
        assert!(info.is_ok());
        lnd.kill().unwrap();
        let info = lnd.client.lightning().get_info(GetInfoRequest {}).await;
        assert!(info.is_err());
    }

    pub(crate) async fn setup_nodes() -> (String, Lnd, BitcoinD) {
        let (bitcoind_exe, lnd_exe) = init();
        debug!("bitcoind: {}", &bitcoind_exe);
        debug!("lnd: {}", &lnd_exe);

        let mut bitcoin_conf = bitcoind::Conf::default();
        bitcoin_conf.enable_zmq = true;
        let bitcoind = BitcoinD::with_conf(bitcoind_exe, &bitcoin_conf).unwrap();

        let lnd_conf = crate::Conf::default();
        let lnd = Lnd::with_conf(&lnd_exe, &lnd_conf, &bitcoind).await.unwrap();

        (lnd_exe, lnd, bitcoind)
    }

    fn init() -> (String, String) {
        let bitcoind_exe_path = bitcoind::exe_path().unwrap();
        let lnd_exe_path = exe_path().unwrap();
        (bitcoind_exe_path, lnd_exe_path)
    }
}
