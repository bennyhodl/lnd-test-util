#[cfg(not(feature = "download"))]
fn main() {}

#[cfg(feature = "download")]
fn main() {
    download::download()
}

#[cfg(feature = "download")]
mod download {
    use bitcoin_hashes::{sha256, Hash};
    use flate2::read::GzDecoder;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Cursor};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::str::FromStr;

    include!("src/versions.rs");
    const GITHUB_URL: &str = "https://github.com/lightningnetwork/lnd/releases/download/";

    fn get_expected_sha256(filename: &str) -> Result<sha256::Hash, String> {
        let file = File::open("sha256").map_err(|_| "File not found in sha256".to_string())?;
        for line in BufReader::new(file).lines().flatten() {
            let tokens: Vec<_> = line.split("  ").collect();
            if tokens.len() == 2 && filename == tokens[1] {
                return sha256::Hash::from_str(tokens[0])
                    .map_err(|_| "Hash not found in sha256".to_string());
            }
        }
        panic!("File not found in sha256");
    }

    pub fn download() {
        if std::env::var_os("LND_SKIP_DOWNLOAD").is_some() {
            return;
        }

        if !HAS_FEATURE {
            return;
        }
        let download_filename_without_extension = lnd_name();
        let download_filename = format!("{}.tar.gz", download_filename_without_extension);
        dbg!(&download_filename);
        let expected_hash = get_expected_sha256(&download_filename).unwrap();
        let out_dir = std::env::var_os("OUT_DIR").unwrap();
        let lnd_exe_home = Path::new(&out_dir).join("lnd");
        let destination_filename = lnd_exe_home
            .join(&download_filename_without_extension);

        dbg!(&destination_filename);

        if !destination_filename.exists() {
            println!(
                "filename:{} version:{} hash:{}",
                download_filename, VERSION, expected_hash
            );

            let download_endpoint =
                std::env::var("LND_DOWNLOAD_ENDPOINT").unwrap_or(GITHUB_URL.to_string());
            let url = format!("{download_endpoint}/{VERSION}/{download_filename}");

            let downloaded_bytes = minreq::get(url).send().unwrap().into_bytes();

            let downloaded_hash = sha256::Hash::hash(&downloaded_bytes);
            assert_eq!(expected_hash, downloaded_hash);
            let cursor = Cursor::new(downloaded_bytes);

            let mut archive = tar::Archive::new(GzDecoder::new(cursor));
            std::fs::create_dir_all(destination_filename.parent().unwrap()).unwrap();
            archive.unpack(&lnd_exe_home).unwrap();

            std::fs::set_permissions(
                &destination_filename,
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        } else {
            println!("File already exists");
        }
    }
}
