//! Injector — finds ms-teams.exe and injects teams_usb_fix.dll via LoadLibrary.

#[path = "inject.rs"]
mod inject;
use inject::*;

fn main() {
    let dll_path = match resolve_dll_path() {
        Some(p) => p,
        None => {
            eprintln!("ERROR: teams_usb_fix.dll not found.");
            eprintln!("Place teams_usb_fix.dll next to this executable.");
            std::process::exit(1);
        }
    };

    println!("DLL path: {}", dll_path);

    // Preflight: check for USB devices with broken string descriptors
    println!("\nRunning USB descriptor preflight check...");
    let broken = inject::preflight_check();
    if broken.is_empty() {
        println!("No USB devices with broken string descriptors detected. Injection may not be necessary.");
    } else {
        println!("Found {} device(s) with broken string descriptors:", broken.len());
        for dev in &broken {
            println!(
                "  VID:{:04X} PID:{:04X}  port {}  hub: {}  failed indices: {:?}",
                dev.vid, dev.pid, dev.port, dev.hub_path, dev.failed_string_indices
            );
        }
    }
    println!();

    let pids = find_teams_pids();
    if pids.is_empty() {
        eprintln!("ERROR: ms-teams.exe is not running.");
        std::process::exit(1);
    }

    println!("Found {} ms-teams.exe process(es): {:?}", pids.len(), pids);

    // Inject into all Teams processes — we don't know which one does USB polling
    let mut already_count = 0;
    for &pid in &pids {
        print!("PID {}... ", pid);
        if is_dll_loaded(pid, "teams_usb_fix.dll") {
            println!("SKIP (already injected)");
            already_count += 1;
            continue;
        }
        match inject_dll(pid, &dll_path) {
            Ok(()) => println!("OK"),
            Err(e) => println!("FAILED: {}", e),
        }
    }

    if already_count == pids.len() {
        println!("\nHook already active in all Teams processes. Nothing to do.");
    }

    println!("\nDone. Check %LOCALAPPDATA%\\teams-usb-fix\\teams-usb-fix.log for hook activity.");
}
