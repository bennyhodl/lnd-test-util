# Lnd Integration Test Utility
[![Crate](https://img.shields.io/crates/v/lnd.svg?logo=rust)](https://crates.io/crates/lnd)
[![Documentation](https://img.shields.io/static/v1?logo=read-the-docs&label=docs.rs&message=lnd&color=informational)](https://docs.rs/lnd)

> Mostly a copy of [`electrsd`](https://github.com/RCasatta/electrsd) & [`bitcoind`](https://github.com/rust-bitcoin/bitcoind) fit for LND.

Utility to run a regtest [LND](https://github.com/lightningnetwork/lnd) process connected to a given [bitcoind](https://github.com/RCasatta/bitcoind) instance, 
useful in integration testing environment.

```rust
use lnd::bitcoind::Conf;
use lnd::LndConf;
use lnd::bitcoind::BitcoinD;
use lnd::Lnd;

// Create a bitcoind instance
let mut bitcoin_conf = Conf::default();

#[cfg(feature = "download")]
let bitcoind = BitcoinD::with_conf(lnd::bitcoind::exe_path(), &bitcoin_conf).unwrap();

#[cfg(not(feature = "download"))]
let bitcoind = BitcoinD::with_conf("<local path to exe>", &bitcoin_conf).unwrap();

let lnd_conf = LndConf::default();

// Pass the path, conf, and bitcoind
#[cfg(feature = "download")]
let mut lnd = Lnd::with_conf(lnd::exe_path(), lnd_conf, &bitcoind);

#[cfg(not(feature = "download"))]
let mut lnd = Lnd::with_conf("<path to lnd>", lnd_conf, &bitcoind);

let node_info = lnd.client.lightning().get_info(GetInfoRequest {}).await; 

assert!(node_info.is_ok());
```

## Automatic binaries download

In your project Cargo.toml, activate the following features

```yml
lnd = { version = "*", features = ["download"] }
```

To use it:

```rust
let bitcoind_exe = lnd::bitcoind::downloaded_exe_path().expect("bitcoind version feature must be enabled");
let bitcoind = lnd::bitcoind::BitcoinD::new(bitcoind_exe).unwrap();
let lnd_exe = lnd::downloaded_exe_path().expect("lnd version feature must be enabled");
let lnd = lnd::Lnd::new(lnd_exe, bitcoind).unwrap();
```

When the `LND_DOWNLOAD_ENDPOINT`/`BITCOIND_DOWNLOAD_ENDPOINT` environment variables are set,
`lnd`/`bitcoind` will try to download the binaries from the given endpoints.

When you don't use the auto-download feature you have the following options:

- have `lnd` executable in the `PATH`
- provide the `lnd` executable via the `LND_EXEC` env var

```rust
if let Ok(exe_path) = lnd::exe_path() {
  let lnd = lnd::Lnd::new(exe_path, &bitcoind).unwrap();
}
```
## Features

  * lnd use a temporary directory as db dir
  * A free port is asked to the OS (a very low probability race condition is still possible) 
  * The process is killed when the struct goes out of scope no matter how the test finishes

Thanks to these features every `#[test]` could easily run isolated with its own environment
