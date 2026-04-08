// Embed Windows version resource into binaries.
// This provides file metadata (product name, version, description) that
// helps antivirus heuristics identify the binary as legitimate software.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "teams-usb-fix");
    res.set("FileDescription", "Fix for USB audio devices that crash Microsoft Teams");
    res.set("CompanyName", "Open Source (MIT License)");
    res.set("LegalCopyright", "Copyright (c) 2026 Jeff Noel. MIT License.");
    res.set("FileVersion", env!("CARGO_PKG_VERSION"));
    res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
    res.set("OriginalFilename", "teams-usb-fix.exe");

    if let Err(e) = res.compile() {
        eprintln!("cargo:warning=Failed to compile Windows resource: {}", e);
    }
}
