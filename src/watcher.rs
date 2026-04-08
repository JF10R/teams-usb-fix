//! Watcher — monitors for ms-teams.exe launches and auto-injects the fix DLL.
//!
//! Usage:
//!   teams-usb-fix-service.exe              Run in console mode (foreground)
//!   teams-usb-fix-service.exe --install    Install as Windows Service
//!   teams-usb-fix-service.exe --uninstall  Remove Windows Service
//!   teams-usb-fix-service.exe --tray       Run with system tray icon (no console)

#[path = "inject.rs"]
mod inject;

use std::collections::HashSet;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SERVICE_NAME: &str = "TeamsUSBFix";
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const INJECT_DELAY: Duration = Duration::from_secs(2);

fn log_dir() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join("teams-usb-fix")
}

fn log(msg: &str) {
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("teams-usb-fix.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let now = timestamp();
        let _ = writeln!(f, "[{}] [watcher] {}", now, msg);
    }
    println!("[watcher] {}", msg);
}

fn timestamp() -> String {
    #[repr(C)]
    struct SystemTime {
        year: u16, month: u16, _dow: u16, day: u16,
        hour: u16, minute: u16, second: u16, millis: u16,
    }
    extern "system" {
        fn GetLocalTime(st: *mut SystemTime);
    }
    unsafe {
        let mut st = std::mem::zeroed::<SystemTime>();
        GetLocalTime(&mut st);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            st.year, st.month, st.day,
            st.hour, st.minute, st.second, st.millis
        )
    }
}

// ---------------------------------------------------------------------------
// Shared watcher state (used by tray mode for Status display)
// ---------------------------------------------------------------------------

/// State updated by `watch_loop` and read by the tray UI.
struct WatcherState {
    injected_count: u32,
    last_injection: Option<String>, // e.g. "PID 1234 at 16:30"
    broken_devices: u32,
}

impl WatcherState {
    fn new() -> Self {
        WatcherState {
            injected_count: 0,
            last_injection: None,
            broken_devices: 0,
        }
    }
}

/// Core watch loop: polls for new Teams processes and injects the DLL.
///
/// `state` is optional; when `Some`, it is updated on each injection so that
/// the tray "Status" menu item can reflect live data.
/// `notify_tx` is optional; when `Some`, a balloon-notification message is
/// sent on each successful injection.
fn watch_loop(
    running: Arc<AtomicBool>,
    state: Option<Arc<Mutex<WatcherState>>>,
    notify_tx: Option<std::sync::mpsc::Sender<String>>,
) {
    let dll_path = match inject::resolve_dll_path() {
        Some(p) => p,
        None => {
            log("ERROR: teams_usb_fix.dll not found next to this executable. Exiting.");
            return;
        }
    };

    log(&format!("Started watching for ms-teams.exe (DLL: {})", dll_path));

    // Log preflight USB descriptor check results at startup
    let broken = inject::preflight_check();
    let broken_count = broken.len() as u32;
    if broken.is_empty() {
        log("Preflight: no USB devices with broken string descriptors detected");
    } else {
        log(&format!("Preflight: {} device(s) with broken string descriptors:", broken.len()));
        for dev in &broken {
            log(&format!(
                "  Preflight: VID:{:04X} PID:{:04X}  port {}  hub: {}  failed indices: {:?}",
                dev.vid, dev.pid, dev.port, dev.hub_path, dev.failed_string_indices
            ));
        }
    }

    // Propagate broken_devices count to shared state
    if let Some(ref s) = state {
        if let Ok(mut g) = s.lock() {
            g.broken_devices = broken_count;
        }
    }

    let mut injected_pids: HashSet<u32> = HashSet::new();

    while running.load(Ordering::SeqCst) {
        let pids = inject::find_teams_pids();

        // Clean up dead PIDs
        injected_pids.retain(|pid| pids.contains(pid));

        // Find new PIDs
        let new_pids: Vec<u32> = pids
            .iter()
            .filter(|pid| !injected_pids.contains(pid))
            .copied()
            .collect();

        if !new_pids.is_empty() {
            log(&format!("New Teams process(es) detected: {:?}", new_pids));

            // Give Teams time to initialize
            std::thread::sleep(INJECT_DELAY);

            for pid in new_pids {
                if inject::is_dll_loaded(pid, "teams_usb_fix.dll") {
                    log(&format!("PID {}: already injected, skipping", pid));
                    injected_pids.insert(pid);
                    continue;
                }

                match inject::inject_dll(pid, &dll_path) {
                    Ok(()) => {
                        log(&format!("PID {}: injected successfully", pid));
                        injected_pids.insert(pid);

                        // Update shared state
                        if let Some(ref s) = state {
                            if let Ok(mut g) = s.lock() {
                                g.injected_count += 1;
                                // Build a short timestamp for last_injection
                                g.last_injection = Some(format!("PID {} at {}", pid, &timestamp()[11..16]));
                            }
                        }

                        // Send balloon notification event
                        if let Some(ref tx) = notify_tx {
                            let _ = tx.send(format!("Injected into Teams (PID {})", pid));
                        }
                    }
                    Err(e) => {
                        log(&format!("PID {}: injection failed: {}", pid, e));
                    }
                }
            }
        }

        std::thread::sleep(POLL_INTERVAL);
    }

    log("Watcher stopped");
}

// ---------------------------------------------------------------------------
// Tray mode
// ---------------------------------------------------------------------------

/// Custom window messages used internally by the tray window.
const WM_TRAY_ICON: u32 = 0x0400 + 1; // WM_USER + 1 — posted by Shell_NotifyIcon callback
const WM_TRAY_BALLOON: u32 = 0x0400 + 2; // WM_USER + 2 — posted by background thread to trigger balloon

/// IDs for the right-click context menu items.
const IDM_STATUS: usize = 1001;
const IDM_OPEN_LOG: usize = 1002;
const IDM_EXIT: usize = 1003;

/// Tray icon ID (arbitrary non-zero value).
const TRAY_ICON_ID: u32 = 1;

/// Shared balloon text, written by the background thread via PostMessageW lParam,
/// then read back in WM_TRAY_BALLOON handler.  We use a static Mutex<String> so
/// the wndproc (which must be a plain fn pointer) can reach it.
static BALLOON_TEXT: Mutex<String> = Mutex::new(String::new());

/// The running flag for the watch_loop, stored statically so the wndproc can
/// signal exit without needing to capture anything.
static TRAY_RUNNING: AtomicBool = AtomicBool::new(true);

/// Shared WatcherState for the Status menu item.
static TRAY_STATE: Mutex<Option<Arc<Mutex<WatcherState>>>> = Mutex::new(None);

fn run_tray_mode() {
    // Outer-scope imports: only what the outer unsafe block and wndproc
    // signature use.  tray_wndproc has its own local use statements for the
    // items it calls.
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP,
        NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW,
        LoadIconW, MSG, PostMessageW,
        RegisterClassExW, TranslateMessage, WNDCLASSEXW, WS_EX_NOACTIVATE,
        CS_HREDRAW, CS_VREDRAW, HMENU, IDI_APPLICATION, HWND_MESSAGE,
        WINDOW_STYLE,
    };
    use windows::Win32::Graphics::Gdi::HBRUSH;
    use windows::core::PCWSTR;

    // -----------------------------------------------------------------------
    // Helpers: encode a &str to a null-terminated Vec<u16>
    // -----------------------------------------------------------------------
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Copy a &str into a fixed-size [u16; N] array (truncates if too long).
    fn fill_wide<const N: usize>(s: &str, buf: &mut [u16; N]) {
        for (i, c) in s.encode_utf16().take(N - 1).enumerate() {
            buf[i] = c;
        }
    }

    // -----------------------------------------------------------------------
    // Set up shared state
    // -----------------------------------------------------------------------
    TRAY_RUNNING.store(true, Ordering::SeqCst);

    let watcher_state = Arc::new(Mutex::new(WatcherState::new()));
    *TRAY_STATE.lock().unwrap() = Some(watcher_state.clone());

    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<String>();

    // -----------------------------------------------------------------------
    // Register a message-only window class
    // -----------------------------------------------------------------------
    let class_name = to_wide("TeamsUSBFixTrayWnd");

    unsafe extern "system" fn tray_wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        use windows::Win32::Foundation::{LRESULT, POINT};
        use windows::Win32::UI::Shell::{
            Shell_NotifyIconW, NIF_INFO, NIM_MODIFY,
            NOTIFYICONDATAW, NIIF_INFO, ShellExecuteW,
        };
        use windows::Win32::UI::WindowsAndMessaging::{
            AppendMenuW, CreatePopupMenu, DestroyMenu, DestroyWindow,
            GetCursorPos, MessageBoxW, PostQuitMessage,
            SetForegroundWindow, TrackPopupMenu,
            MB_OK, MB_ICONINFORMATION,
            MF_STRING, MF_ENABLED,
            TPM_RIGHTBUTTON, TPM_BOTTOMALIGN, TPM_LEFTALIGN,
            WM_COMMAND, WM_DESTROY, WM_RBUTTONUP,
            SW_SHOW,
        };
        use windows::core::PCWSTR;

        fn to_wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }
        fn fill_wide<const N: usize>(s: &str, buf: &mut [u16; N]) {
            for (i, c) in s.encode_utf16().take(N - 1).enumerate() {
                buf[i] = c;
            }
        }

        match msg {
            // Shell tray callback — right-click triggers the context menu
            m if m == WM_TRAY_ICON => {
                let event = lparam.0 as u32 & 0xFFFF;
                if event == WM_RBUTTONUP {
                    // Build popup menu
                    let menu = CreatePopupMenu().unwrap_or_default();
                    let _ = AppendMenuW(menu, MF_STRING | MF_ENABLED, IDM_STATUS, PCWSTR(to_wide("Status").as_ptr()));
                    let _ = AppendMenuW(menu, MF_STRING | MF_ENABLED, IDM_OPEN_LOG, PCWSTR(to_wide("Open Log").as_ptr()));
                    let _ = AppendMenuW(menu, MF_STRING | MF_ENABLED, IDM_EXIT, PCWSTR(to_wide("Exit").as_ptr()));

                    let mut pt = POINT::default();
                    let _ = GetCursorPos(&mut pt);
                    let _ = SetForegroundWindow(hwnd);
                    let _ = TrackPopupMenu(
                        menu,
                        TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                        pt.x,
                        pt.y,
                        0,
                        hwnd,
                        None,
                    );
                    let _ = DestroyMenu(menu);
                }
                LRESULT(0)
            }

            // Menu item chosen
            WM_COMMAND => {
                let item_id = (wparam.0 & 0xFFFF) as usize;
                match item_id {
                    IDM_STATUS => {
                        // Build status string from shared state
                        let (injected_count, last_injection, broken_devices, teams_running) = {
                            let guard = TRAY_STATE.lock().unwrap();
                            if let Some(ref arc) = *guard {
                                let s = arc.lock().unwrap();
                                let teams_running = !inject::find_teams_pids().is_empty();
                                (s.injected_count, s.last_injection.clone(), s.broken_devices, teams_running)
                            } else {
                                (0, None, 0, false)
                            }
                        };
                        let last_str = last_injection
                            .as_deref()
                            .unwrap_or("(none yet)");
                        let teams_str = if teams_running { "Yes" } else { "No" };
                        let msg_text = format!(
                            "Teams USB Fix — Status\n\nInjections: {}\nLast injection: {}\nBroken USB devices: {}\nTeams running: {}",
                            injected_count, last_str, broken_devices, teams_str
                        );
                        let wide_text = to_wide(&msg_text);
                        let wide_title = to_wide("Teams USB Fix");
                        let _ = MessageBoxW(hwnd, PCWSTR(wide_text.as_ptr()), PCWSTR(wide_title.as_ptr()), MB_OK | MB_ICONINFORMATION);
                    }
                    IDM_OPEN_LOG => {
                        let log_path = log_dir().join("teams-usb-fix.log");
                        let path_wide = to_wide(&log_path.to_string_lossy());
                        let op = to_wide("open");
                        let _ = ShellExecuteW(
                            hwnd,
                            PCWSTR(op.as_ptr()),
                            PCWSTR(path_wide.as_ptr()),
                            PCWSTR::null(),
                            PCWSTR::null(),
                            SW_SHOW,
                        );
                    }
                    IDM_EXIT => {
                        TRAY_RUNNING.store(false, Ordering::SeqCst);
                        let _ = DestroyWindow(hwnd);
                    }
                    _ => {}
                }
                LRESULT(0)
            }

            // Background thread posted a balloon request; text is in BALLOON_TEXT static
            m if m == WM_TRAY_BALLOON => {
                let text = {
                    let g = BALLOON_TEXT.lock().unwrap();
                    g.clone()
                };
                // Re-issue Shell_NotifyIconW with NIF_INFO to show balloon
                let mut nid = NOTIFYICONDATAW::default();
                nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                nid.hWnd = hwnd;
                nid.uID = TRAY_ICON_ID;
                nid.uFlags = NIF_INFO;
                nid.dwInfoFlags = NIIF_INFO;
                fill_wide::<256>(&text, &mut nid.szInfo);
                fill_wide::<64>("Teams USB Fix", &mut nid.szInfoTitle);
                nid.Anonymous.uTimeout = 5000;
                let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
                LRESULT(0)
            }

            WM_DESTROY => {
                TRAY_RUNNING.store(false, Ordering::SeqCst);
                PostQuitMessage(0);
                LRESULT(0)
            }

            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    unsafe {
        // Register window class
        let hinstance = windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
            .unwrap_or_default();

        let mut wc = WNDCLASSEXW::default();
        wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = Some(tray_wndproc);
        wc.hInstance = hinstance.into();
        wc.lpszClassName = PCWSTR(class_name.as_ptr());
        wc.hbrBackground = HBRUSH(std::ptr::null_mut());

        if RegisterClassExW(&wc) == 0 {
            log("ERROR: RegisterClassExW failed for tray window");
            return;
        }

        // Create a message-only window (HWND_MESSAGE parent → no taskbar entry)
        let hwnd = match CreateWindowExW(
            WS_EX_NOACTIVATE,
            PCWSTR(class_name.as_ptr()),
            PCWSTR(to_wide("Teams USB Fix Tray").as_ptr()),
            WINDOW_STYLE(0),
            0, 0, 0, 0,
            HWND_MESSAGE,
            HMENU(std::ptr::null_mut()),
            hinstance,
            None,
        ) {
            Ok(h) => h,
            Err(e) => {
                log(&format!("ERROR: CreateWindowExW failed for tray window: {}", e));
                return;
            }
        };

        // -----------------------------------------------------------------------
        // Add tray icon
        // -----------------------------------------------------------------------
        let icon = LoadIconW(None, IDI_APPLICATION).unwrap_or_default();

        let mut nid = NOTIFYICONDATAW::default();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ICON_ID;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY_ICON;
        nid.hIcon = icon;
        fill_wide::<128>("Teams USB Fix - Watching", &mut nid.szTip);

        if !Shell_NotifyIconW(NIM_ADD, &nid).as_bool() {
            log("WARNING: Shell_NotifyIconW NIM_ADD failed (tray icon may not appear)");
        }

        // -----------------------------------------------------------------------
        // Spawn watch_loop on background thread
        // -----------------------------------------------------------------------
        let running_flag = Arc::new(AtomicBool::new(true));
        let running_clone = running_flag.clone();
        let state_clone = watcher_state.clone();
        let hwnd_raw = hwnd.0 as usize; // HWND is not Send; pass as usize
        let hwnd_raw_cleanup = hwnd_raw; // keep a copy for cleanup after spawn

        std::thread::spawn(move || {
            // Forward injection events from the mpsc channel to PostMessageW
            let (inner_tx, inner_rx) = (notify_tx, notify_rx);
            let running_inner = running_clone.clone();
            let state_inner = state_clone.clone();

            // Spawn the actual watch loop
            let wl_running = running_inner.clone();
            std::thread::spawn(move || {
                watch_loop(wl_running, Some(state_inner), Some(inner_tx));
            });

            // Relay balloon events to the tray window via PostMessageW
            while running_inner.load(Ordering::SeqCst) {
                match inner_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(text) => {
                        // Store the text in the static, then notify the window
                        *BALLOON_TEXT.lock().unwrap() = text;
                        let h = HWND(hwnd_raw as *mut std::ffi::c_void);
                        let _ = PostMessageW(h, WM_TRAY_BALLOON, WPARAM(0), LPARAM(0));
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Check if TRAY_RUNNING was cleared by Exit menu item
                        if !TRAY_RUNNING.load(Ordering::SeqCst) {
                            running_inner.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            }
        });

        // -----------------------------------------------------------------------
        // Message pump — runs on the main thread
        // -----------------------------------------------------------------------
        let mut msg = MSG::default();
        loop {
            let ret = GetMessageW(&mut msg, None, 0, 0);
            if ret.0 <= 0 {
                break;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);

            // Also honour the running flag being cleared from outside the pump
            if !TRAY_RUNNING.load(Ordering::SeqCst) {
                break;
            }
        }

        // -----------------------------------------------------------------------
        // Cleanup: remove tray icon
        // -----------------------------------------------------------------------
        let mut nid_del = NOTIFYICONDATAW::default();
        nid_del.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid_del.hWnd = HWND(hwnd_raw_cleanup as *mut std::ffi::c_void);
        nid_del.uID = TRAY_ICON_ID;
        let _ = Shell_NotifyIconW(NIM_DELETE, &nid_del);

        log("Tray mode exited");
    }
}

// ---------------------------------------------------------------------------
// Windows Service support
// ---------------------------------------------------------------------------

fn install_service() -> Result<(), String> {
    use windows::Win32::System::Services::*;
    use windows::core::PCWSTR;

    let exe = std::env::current_exe()
        .map_err(|e| format!("Failed to get exe path: {}", e))?;
    let exe_path = exe.to_string_lossy().to_string();

    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CREATE_SERVICE)
            .map_err(|e| format!("OpenSCManager: {} (run as Administrator)", e))?;

        let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let display: Vec<u16> = "Teams USB Descriptor Fix"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path: Vec<u16> = format!("\"{}\" --service", exe_path)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let result = CreateServiceW(
            scm,
            PCWSTR(name.as_ptr()),
            PCWSTR(display.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        );

        let _ = CloseServiceHandle(scm);

        match result {
            Ok(svc) => {
                let _ = CloseServiceHandle(svc);
                println!("Service '{}' installed successfully.", SERVICE_NAME);
                println!("Start it with: sc start {}", SERVICE_NAME);
                Ok(())
            }
            Err(e) => Err(format!("CreateService: {}", e)),
        }
    }
}

fn uninstall_service() -> Result<(), String> {
    use windows::Win32::System::Services::*;
    use windows::core::PCWSTR;

    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
            .map_err(|e| format!("OpenSCManager: {} (run as Administrator)", e))?;

        let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        let svc = OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_ALL_ACCESS)
            .map_err(|e| {
                let _ = CloseServiceHandle(scm);
                format!("OpenService: {}", e)
            })?;

        // Stop the service first if running
        let mut status = SERVICE_STATUS::default();
        let _ = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);

        let result = DeleteService(svc);

        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);

        match result {
            Ok(()) => {
                println!("Service '{}' uninstalled.", SERVICE_NAME);
                Ok(())
            }
            Err(e) => Err(format!("DeleteService: {}", e)),
        }
    }
}

fn run_as_service() {
    use windows::Win32::System::Services::*;
    use windows::core::PCWSTR;

    // Static state for the service handler
    static SERVICE_RUNNING: AtomicBool = AtomicBool::new(true);
    // SERVICE_STATUS_HANDLE is a *mut c_void wrapper — not Send, so wrap in usize
    static SERVICE_HANDLE_RAW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    unsafe extern "system" fn service_handler(control: u32) {
        if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
            SERVICE_RUNNING.store(false, Ordering::SeqCst);
            let raw = SERVICE_HANDLE_RAW.load(Ordering::SeqCst);
            if raw != 0 {
                let handle = SERVICE_STATUS_HANDLE(raw as *mut std::ffi::c_void);
                let status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STATUS_CURRENT_STATE(1), // SERVICE_STOPPED
                    dwControlsAccepted: SERVICE_ACCEPT_STOP,
                    ..Default::default()
                };
                let _ = SetServiceStatus(handle, &status);
            }
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows::core::PWSTR) {
        let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = RegisterServiceCtrlHandlerW(PCWSTR(name.as_ptr()), Some(service_handler));

        if let Ok(handle) = handle {
            SERVICE_HANDLE_RAW.store(handle.0 as usize, Ordering::SeqCst);

            // Report running
            let status = SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: SERVICE_STATUS_CURRENT_STATE(4), // SERVICE_RUNNING
                dwControlsAccepted: SERVICE_ACCEPT_STOP,
                ..Default::default()
            };
            let _ = SetServiceStatus(handle, &status);

            let running = Arc::new(AtomicBool::new(true));
            let running_clone = running.clone();

            // Monitor SERVICE_RUNNING flag
            std::thread::spawn(move || {
                while SERVICE_RUNNING.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(500));
                }
                running_clone.store(false, Ordering::SeqCst);
            });

            watch_loop(running, None, None);
        }
    }

    unsafe {
        let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: windows::core::PWSTR(name.as_ptr() as *mut u16),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: windows::core::PWSTR::null(),
                lpServiceProc: None,
            },
        ];

        if let Err(e) = StartServiceCtrlDispatcherW(&table[0]) {
            eprintln!("Failed to start service dispatcher: {}", e);
            eprintln!("If running from console, use no arguments for console mode.");
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "--install" => {
                if let Err(e) = install_service() {
                    eprintln!("ERROR: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "--uninstall" => {
                if let Err(e) = uninstall_service() {
                    eprintln!("ERROR: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "--service" => {
                run_as_service();
                return;
            }
            "--tray" => {
                run_tray_mode();
                return;
            }
            "--help" | "-h" => {
                println!("teams-usb-fix-service");
                println!();
                println!("Usage:");
                println!("  teams-usb-fix-service.exe              Console mode (foreground)");
                println!("  teams-usb-fix-service.exe --install     Install as Windows Service");
                println!("  teams-usb-fix-service.exe --uninstall   Remove Windows Service");
                println!("  teams-usb-fix-service.exe --tray        System tray mode (no console window)");
                println!();
                println!("Logs: %LOCALAPPDATA%\\teams-usb-fix\\teams-usb-fix.log");
                return;
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                eprintln!("Use --help for usage.");
                std::process::exit(1);
            }
        }
    }

    // Console mode
    println!("teams-usb-fix watcher — press Ctrl+C to stop");
    println!("Logs: %LOCALAPPDATA%\\teams-usb-fix\\teams-usb-fix.log");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc_handler(r);

    watch_loop(running, None, None);
}

/// Simple Ctrl+C handler without external crate dependency.
fn ctrlc_handler(running: Arc<AtomicBool>) {
    use windows::Win32::System::Console::SetConsoleCtrlHandler;

    // Store the Arc in a static so the handler can access it
    static RUNNING: std::sync::Mutex<Option<Arc<AtomicBool>>> = std::sync::Mutex::new(None);
    *RUNNING.lock().unwrap() = Some(running);

    unsafe extern "system" fn handler(ctrl_type: u32) -> windows::Win32::Foundation::BOOL {
        // CTRL_C_EVENT = 0, CTRL_BREAK_EVENT = 1
        if ctrl_type <= 1 {
            if let Ok(guard) = RUNNING.lock() {
                if let Some(ref r) = *guard {
                    r.store(false, Ordering::SeqCst);
                }
            }
            return windows::Win32::Foundation::BOOL(1);
        }
        windows::Win32::Foundation::BOOL(0)
    }

    unsafe {
        let _ = SetConsoleCtrlHandler(Some(handler), true);
    }
}
