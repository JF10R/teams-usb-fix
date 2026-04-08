//! usb_descriptor_fix — DLL that hooks DeviceIoControl to fix broken USB
//! string descriptors on any device that returns ERROR_GEN_FAILURE for
//! IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION with a string descriptor type.
//!
//! When a device returns an invalid bLength or no serial number, host software
//! (e.g. Teams, audio pipelines) can crash or loop. This hook intercepts the
//! failure, synthesizes a deterministic serial based on hub handle + port, and
//! logs whatever device identity information it can recover.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{BOOL, HANDLE, GetLastError, SetLastError, WIN32_ERROR};
use windows::Win32::System::IO::OVERLAPPED;

const IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION: u32 = 0x00220410;
const IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX: u32 = 0x00220448;
const USB_STRING_DESCRIPTOR_TYPE: u8 = 3;
const USB_DEVICE_DESCRIPTOR_TYPE: u8 = 1;
const ERROR_GEN_FAILURE: u32 = 0x1F;

static HOOK_ACTIVE: AtomicBool = AtomicBool::new(false);

// -------------------------------------------------------------------
// Structs
// -------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct UsbDescriptorRequest {
    connection_index: u32,
    bm_request: u8,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    w_length: u16,
}

/// Matches the Windows USB_NODE_CONNECTION_INFORMATION_EX layout up through
/// the product ID fields. Only the fields we actually use are named.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct UsbNodeConnectionInfoEx {
    connection_index: u32,
    _dd_b_length: u8,
    _dd_b_descriptor_type: u8,
    _dd_bcd_usb: u16,
    _dd_b_device_class: u8,
    _dd_b_device_sub_class: u8,
    _dd_b_device_protocol: u8,
    _dd_b_max_packet_size0: u8,
    dd_id_vendor: u16,
    dd_id_product: u16,
    // remaining fields not used; buffer allocated large enough at call site
}

// -------------------------------------------------------------------
// Hook infrastructure
// -------------------------------------------------------------------

type DeviceIoControlFn = unsafe extern "system" fn(
    HANDLE, u32, *const c_void, u32, *mut c_void, u32, *mut u32, *mut OVERLAPPED,
) -> BOOL;

static mut ORIGINAL_DEVICE_IO_CONTROL: Option<DeviceIoControlFn> = None;

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

/// 4-hex-digit deterministic hash of hub handle + port number.
/// Produces a stable label per physical device location.
fn port_hash(handle: isize, port: u32) -> u16 {
    // FNV-1a over the bytes of handle and port
    let mut h: u32 = 0x811c_9dc5;
    for &b in handle.to_le_bytes().iter().chain(port.to_le_bytes().iter()) {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    // fold to 16 bits
    ((h ^ (h >> 16)) & 0xFFFF) as u16
}

/// Write a synthetic USB string descriptor into `out_buf`.
/// Serial is `USBFIX-XXXX` where XXXX is the 4-hex-digit port hash.
/// Returns total bytes written (request header + descriptor), or 0 on failure.
fn build_synthetic_serial(out_buf: *mut u8, buf_size: usize, handle: isize, port: u32) -> u32 {
    let tag = port_hash(handle, port);
    // Build UTF-16LE characters for "USBFIX-XXXX"
    let prefix: &[u16] = &[
        b'U' as u16, b'S' as u16, b'B' as u16, b'F' as u16, b'I' as u16,
        b'X' as u16, b'-' as u16,
    ];
    let hex_digits: [u8; 4] = [
        (tag >> 12) as u8,
        ((tag >> 8) & 0xF) as u8,
        ((tag >> 4) & 0xF) as u8,
        (tag & 0xF) as u8,
    ];
    let hex_chars: [u16; 4] = hex_digits.map(|n| {
        if n < 10 { b'0' as u16 + n as u16 } else { b'A' as u16 + n as u16 - 10 }
    });

    let serial_chars: usize = prefix.len() + hex_chars.len(); // 11
    let desc_len = 2 + serial_chars * 2;
    let total = std::mem::size_of::<UsbDescriptorRequest>() + desc_len;

    if buf_size < total {
        return 0;
    }

    unsafe {
        let desc_ptr = out_buf.add(std::mem::size_of::<UsbDescriptorRequest>());
        *desc_ptr = desc_len as u8;
        *desc_ptr.add(1) = USB_STRING_DESCRIPTOR_TYPE;
        let str_ptr = desc_ptr.add(2) as *mut u16;
        for (i, &ch) in prefix.iter().chain(hex_chars.iter()).enumerate() {
            std::ptr::write_unaligned(str_ptr.add(i), ch);
        }
    }
    total as u32
}

// -------------------------------------------------------------------
// Device identification helpers (all use the ORIGINAL DeviceIoControl)
// -------------------------------------------------------------------

/// Query VID:PID for `handle` + `port` via IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX.
/// Returns `Some((vid, pid))` or `None`.
unsafe fn query_vid_pid(
    original: DeviceIoControlFn,
    handle: HANDLE,
    port: u32,
) -> Option<(u16, u16)> {
    // Allocate a buffer large enough for the full struct (Windows extends it)
    const BUF_SIZE: usize = 512;
    let mut buf = [0u8; BUF_SIZE];

    // Write connection_index at offset 0
    std::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, port);

    let mut returned: u32 = 0;
    let ok = unsafe {
        original(
            handle,
            IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
            buf.as_ptr() as *const c_void,
            std::mem::size_of::<u32>() as u32,
            buf.as_mut_ptr() as *mut c_void,
            BUF_SIZE as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };

    if !ok.as_bool() || (returned as usize) < std::mem::size_of::<UsbNodeConnectionInfoEx>() {
        return None;
    }

    let info = unsafe { &*(buf.as_ptr() as *const UsbNodeConnectionInfoEx) };
    Some((info.dd_id_vendor, info.dd_id_product))
}

/// Query the device descriptor to get the `iProduct` string index.
/// Returns `Some(index)` or `None`.
unsafe fn query_iproduct_index(
    original: DeviceIoControlFn,
    handle: HANDLE,
    port: u32,
) -> Option<u8> {
    // Device descriptor is type 1, index 0, 18 bytes
    const DESC_LEN: usize = 18;
    const BUF_SIZE: usize = std::mem::size_of::<UsbDescriptorRequest>() + DESC_LEN;
    let mut buf = [0u8; BUF_SIZE];

    let req = UsbDescriptorRequest {
        connection_index: port,
        bm_request: 0x80,
        b_request: 0x06,
        w_value: ((USB_DEVICE_DESCRIPTOR_TYPE as u16) << 8) | 0x00,
        w_index: 0,
        w_length: DESC_LEN as u16,
    };
    unsafe { std::ptr::write_unaligned(buf.as_mut_ptr() as *mut UsbDescriptorRequest, req) };

    let mut returned: u32 = 0;
    let ok = unsafe {
        original(
            handle,
            IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
            buf.as_ptr() as *const c_void,
            BUF_SIZE as u32,
            buf.as_mut_ptr() as *mut c_void,
            BUF_SIZE as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };

    if !ok.as_bool() {
        return None;
    }

    // Device descriptor: bLength(1) bDescriptorType(1) bcdUSB(2) bDeviceClass(1)
    //   bDeviceSubClass(1) bDeviceProtocol(1) bMaxPacketSize0(1) idVendor(2) idProduct(2)
    //   bcdDevice(2) iManufacturer(1) iProduct(1) iSerialNumber(1) bNumConfigurations(1)
    // iProduct is at byte offset 15 relative to start of descriptor (after request header)
    let hdr = std::mem::size_of::<UsbDescriptorRequest>();
    if (returned as usize) < hdr + 16 {
        return None;
    }
    let i_product = buf[hdr + 15];
    if i_product == 0 {
        None
    } else {
        Some(i_product)
    }
}

/// Query a USB string descriptor by index. Returns decoded UTF-8 string or None.
unsafe fn query_string_descriptor(
    original: DeviceIoControlFn,
    handle: HANDLE,
    port: u32,
    index: u8,
) -> Option<String> {
    const MAX_STR_LEN: usize = 126; // max USB string descriptor payload
    const BUF_SIZE: usize = std::mem::size_of::<UsbDescriptorRequest>() + 2 + MAX_STR_LEN * 2;
    let mut buf = [0u8; BUF_SIZE];

    let req = UsbDescriptorRequest {
        connection_index: port,
        bm_request: 0x80,
        b_request: 0x06,
        w_value: ((USB_STRING_DESCRIPTOR_TYPE as u16) << 8) | (index as u16),
        w_index: 0x0409, // English (US)
        w_length: (2 + MAX_STR_LEN * 2) as u16,
    };
    unsafe { std::ptr::write_unaligned(buf.as_mut_ptr() as *mut UsbDescriptorRequest, req) };

    let mut returned: u32 = 0;
    let ok = unsafe {
        original(
            handle,
            IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
            buf.as_ptr() as *const c_void,
            BUF_SIZE as u32,
            buf.as_mut_ptr() as *mut c_void,
            BUF_SIZE as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };

    if !ok.as_bool() {
        return None;
    }

    let hdr = std::mem::size_of::<UsbDescriptorRequest>();
    if (returned as usize) < hdr + 2 {
        return None;
    }

    let desc_len = buf[hdr] as usize;
    if desc_len < 2 || (returned as usize) < hdr + desc_len {
        return None;
    }

    let str_bytes = desc_len - 2;
    if str_bytes == 0 || str_bytes % 2 != 0 {
        return None;
    }

    let str_start = hdr + 2;
    let u16_words: Vec<u16> = (0..(str_bytes / 2))
        .map(|i| unsafe {
            std::ptr::read_unaligned(buf.as_ptr().add(str_start + i * 2) as *const u16)
        })
        .collect();

    Some(String::from_utf16_lossy(&u16_words).to_string())
}

// -------------------------------------------------------------------
// Hooked function
// -------------------------------------------------------------------

unsafe extern "system" fn hooked_device_io_control(
    h_device: HANDLE,
    dw_io_control_code: u32,
    lp_in_buffer: *const c_void,
    n_in_buffer_size: u32,
    lp_out_buffer: *mut c_void,
    n_out_buffer_size: u32,
    lp_bytes_returned: *mut u32,
    lp_overlapped: *mut OVERLAPPED,
) -> BOOL {
    let original = unsafe { ORIGINAL_DEVICE_IO_CONTROL.unwrap() };

    let result = unsafe {
        original(
            h_device, dw_io_control_code, lp_in_buffer, n_in_buffer_size,
            lp_out_buffer, n_out_buffer_size, lp_bytes_returned, lp_overlapped,
        )
    };

    // Fast exit: only care about failed string descriptor requests
    if result.as_bool()
        || dw_io_control_code != IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION
    {
        return result;
    }

    let err = unsafe { GetLastError() };
    if err != WIN32_ERROR(ERROR_GEN_FAILURE) {
        return result;
    }

    if lp_in_buffer.is_null()
        || (n_in_buffer_size as usize) < std::mem::size_of::<UsbDescriptorRequest>()
    {
        return result;
    }

    let req = unsafe { std::ptr::read_unaligned(lp_in_buffer as *const UsbDescriptorRequest) };
    let descriptor_type = (req.w_value >> 8) as u8;

    if descriptor_type != USB_STRING_DESCRIPTOR_TYPE {
        return result;
    }

    if lp_out_buffer.is_null() {
        unsafe { SetLastError(err) };
        return result;
    }

    let port = req.connection_index;
    let handle_key = h_device.0 as isize;

    // Build synthetic serial before identification queries so we always have it
    let bytes = build_synthetic_serial(
        lp_out_buffer as *mut u8,
        n_out_buffer_size as usize,
        handle_key,
        port,
    );
    if bytes == 0 {
        unsafe { SetLastError(err) };
        return result;
    }

    // Identify the device using the ORIGINAL DeviceIoControl (no recursion risk)
    let tag = port_hash(handle_key, port);
    let serial_str = format!("USBFIX-{:04X}", tag);

    let vid_pid = unsafe { query_vid_pid(original, h_device, port) };
    let product_name = if vid_pid.is_some() {
        let idx = unsafe { query_iproduct_index(original, h_device, port) };
        if let Some(i) = idx {
            unsafe { query_string_descriptor(original, h_device, port, i) }
                .filter(|s| !s.trim().is_empty())
        } else {
            None
        }
    } else {
        None
    };

    let msg = match (product_name.as_deref(), vid_pid) {
        (Some(name), Some((vid, pid))) => format!(
            "Fixed USB string descriptor for \"{}\" (VID:{:04X} PID:{:04X}) on port {} -- synthetic serial {}",
            name, vid, pid, port, serial_str
        ),
        (None, Some((vid, pid))) => format!(
            "Fixed USB string descriptor for unknown device (VID:{:04X} PID:{:04X}) on port {} -- synthetic serial {}",
            vid, pid, port, serial_str
        ),
        _ => format!(
            "Fixed USB string descriptor for unidentified device on port {} -- synthetic serial {}",
            port, serial_str
        ),
    };

    log(msg);

    if !lp_bytes_returned.is_null() {
        unsafe { *lp_bytes_returned = bytes };
    }

    unsafe { SetLastError(WIN32_ERROR(0)) };
    BOOL(1)
}

// -------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------

fn install_hook() -> Result<(), String> {
    unsafe {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
        use windows::core::s;

        let module = GetModuleHandleA(s!("kernelbase.dll"))
            .map_err(|e| format!("GetModuleHandle: {}", e))?;

        let proc = GetProcAddress(module, s!("DeviceIoControl"))
            .ok_or("GetProcAddress(DeviceIoControl) failed")?;

        let target: DeviceIoControlFn = std::mem::transmute(proc);

        let trampoline = minhook::MinHook::create_hook(
            target as *mut c_void,
            hooked_device_io_control as *mut c_void,
        )
        .map_err(|e| format!("create_hook: {:?}", e))?;

        ORIGINAL_DEVICE_IO_CONTROL = Some(std::mem::transmute(trampoline));

        minhook::MinHook::enable_all_hooks()
            .map_err(|e| format!("enable_all_hooks: {:?}", e))?;

        HOOK_ACTIVE.store(true, Ordering::SeqCst);
        log("Hook installed on DeviceIoControl (kernelbase.dll)".to_string());
        Ok(())
    }
}

fn remove_hook() {
    if HOOK_ACTIVE.load(Ordering::SeqCst) {
        unsafe {
            let _ = minhook::MinHook::disable_all_hooks();
            let _ = minhook::MinHook::uninitialize();
        }
        HOOK_ACTIVE.store(false, Ordering::SeqCst);
        log("Hook removed".to_string());
    }
}

// -------------------------------------------------------------------
// Logging
// -------------------------------------------------------------------

fn log_dir() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join("teams-usb-fix")
}

fn log(msg: String) {
    use std::io::Write;
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("teams-usb-fix.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let now = chrono_lite_timestamp();
        let _ = writeln!(f, "[{}] {}", now, msg);
    }
}

fn chrono_lite_timestamp() -> String {
    #[repr(C)]
    struct SystemTime {
        year: u16, month: u16, day_of_week: u16, day: u16,
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

// -------------------------------------------------------------------
// DLL entry point
// -------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _h_inst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match fdw_reason {
        DLL_PROCESS_ATTACH => match install_hook() {
            Ok(()) => log("usb_descriptor_fix loaded successfully".to_string()),
            Err(e) => log(format!("Hook install failed: {}", e)),
        },
        DLL_PROCESS_DETACH => remove_hook(),
        _ => {}
    }

    BOOL(1)
}
