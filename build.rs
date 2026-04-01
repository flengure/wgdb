// build.rs — downloads and embeds wintun.dll for Windows targets.
//
// When compiling for Windows (natively or cross), this script:
//   1. Downloads wintun-0.14.1.zip from wintun.net
//   2. Extracts the arch-specific wintun.dll into OUT_DIR
//   3. Sets the WINTUN_DLL_PATH env var so wg.rs can `include_bytes!` it
//
// wintun is MIT licensed; redistribution is permitted.
// On non-Windows targets this script is a no-op.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    let wintun_arch = match target_arch.as_str() {
        "x86_64"  => "amd64",
        "aarch64" => "arm64",
        "x86"     => "x86",
        other     => panic!("unsupported target arch for wintun: {other}"),
    };

    let dll_path = std::path::PathBuf::from(&out_dir).join("wintun.dll");

    // Skip download if already cached (incremental builds / CI cache hit).
    if dll_path.exists() {
        println!("cargo:rustc-env=WINTUN_DLL_PATH={}", dll_path.display());
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    let zip_url = "https://www.wintun.net/builds/wintun-0.14.1.zip";
    let zip_path = std::path::PathBuf::from(&out_dir).join("wintun.zip");

    eprintln!("build.rs: downloading wintun from {zip_url}");

    // Download with curl — present on Windows 10+, macOS, and all GitHub runners.
    let status = std::process::Command::new("curl")
        .args(["-fsSL", "-o", zip_path.to_str().unwrap(), zip_url])
        .status()
        .expect("curl not found — install curl to build for Windows");
    assert!(status.success(), "curl failed to download {zip_url}");

    // Extract: use PowerShell on Windows hosts, unzip on Unix.
    let entry_in_zip = format!("wintun/bin/{wintun_arch}/wintun.dll");

    #[cfg(target_os = "windows")]
    {
        // PowerShell's Expand-Archive doesn't support single-entry extraction
        // easily, so use the .NET ZipFile API via a one-liner.
        let ps_cmd = format!(
            r#"Add-Type -Assembly System.IO.Compression.FileSystem; \
               $z = [IO.Compression.ZipFile]::OpenRead('{zip}'); \
               $e = $z.Entries | Where-Object {{ $_.FullName -eq '{entry}' }}; \
               [IO.Compression.ZipFileExtensions]::ExtractToFile($e, '{out}', $true); \
               $z.Dispose()"#,
            zip   = zip_path.display(),
            entry = entry_in_zip,
            out   = dll_path.display(),
        );
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_cmd])
            .status()
            .expect("powershell not found");
        assert!(status.success(), "PowerShell failed to extract wintun.dll");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let status = std::process::Command::new("unzip")
            .args([
                "-jo",
                zip_path.to_str().unwrap(),
                &entry_in_zip,
                "-d",
                &out_dir,
            ])
            .status()
            .expect("unzip not found — install unzip");
        assert!(status.success(), "unzip failed to extract wintun.dll");
    }

    assert!(dll_path.exists(), "wintun.dll not found in OUT_DIR after extraction");
    println!("cargo:rustc-env=WINTUN_DLL_PATH={}", dll_path.display());
    println!("cargo:rerun-if-changed=build.rs");
}
