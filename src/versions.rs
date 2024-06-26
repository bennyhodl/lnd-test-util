#[cfg(target_os = "macos")]
const OS: &str = "darwin";

#[cfg(target_os = "linux")]
const OS: &str = "linux";

#[cfg(feature = "lnd_0_17_5")]
const VERSION: &str = "v0.17.5-beta";

#[cfg(feature = "lnd_16_4")]
const VERSION: &str = "v0.16.4-beta";

#[cfg(not(any(feature = "lnd_0_17_5", feature = "lnd_0_16_4",)))]

const VERSION: &str = "NA";

pub const HAS_FEATURE: bool = cfg!(any(feature = "lnd_0_17_5", feature = "lnd_0_16_4",));

pub fn lnd_name() -> String {
    // todo: add arm64 and armv7 support
    // todo support windows
    format!("lnd-{}-amd64-{}", OS, VERSION)
}
