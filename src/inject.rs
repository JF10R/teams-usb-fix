//! Shared DLL injection primitives used by injector and watcher binaries.

#[path = "common.rs"]
pub mod common;
use common::*;

use std::ffi::c_void;
use std::mem;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS,
};
use windows::core::s;

/// Returns PIDs for all running ms-teams.exe processes.
pub fn find_teams_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return pids;
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name: String = entry
                    .szExeFile
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8 as char)
                    .collect();

                if name.eq_ignore_ascii_case("ms-teams.exe") {
                    pids.push(entry.th32ProcessID);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    pids
}

/// Returns true if the named DLL is already loaded in the given process.
pub fn is_dll_loaded(pid: u32, dll_name: &str) -> bool {
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        else {
            return false;
        };

        let mut entry = MODULEENTRY32W {
            dwSize: mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name: String = entry
                    .szModule
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8 as char)
                    .collect();

                if name.eq_ignore_ascii_case(dll_name) {
                    let _ = CloseHandle(snapshot);
                    return true;
                }

                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    false
}

/// Injects `dll_path` into `pid` via the classic CreateRemoteThread + LoadLibraryW technique.
pub fn inject_dll(pid: u32, dll_path: &str) -> Result<(), String> {
    let dll_path_wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let dll_path_size = dll_path_wide.len() * 2;

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| format!("OpenProcess({}): {}", pid, e))?;

        // Allocate memory in the target process for the DLL path
        let remote_mem = VirtualAllocEx(
            process,
            Some(std::ptr::null()),
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = CloseHandle(process);
            return Err("VirtualAllocEx failed".into());
        }

        // Write the DLL path to the remote process
        let mut bytes_written = 0usize;
        let write_ok = windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
            process,
            remote_mem,
            dll_path_wide.as_ptr() as *const c_void,
            dll_path_size,
            Some(&mut bytes_written),
        );

        if write_ok.is_err() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE).ok();
            let _ = CloseHandle(process);
            return Err("WriteProcessMemory failed".into());
        }

        // Get LoadLibraryW address
        let kernel32 = GetModuleHandleA(s!("kernel32.dll"))
            .map_err(|e| format!("GetModuleHandle(kernel32): {}", e))?;

        let load_library = GetProcAddress(kernel32, s!("LoadLibraryW"))
            .ok_or("GetProcAddress(LoadLibraryW) failed")?;

        let load_library_fn: unsafe extern "system" fn(*mut c_void) -> u32 =
            mem::transmute(load_library);

        // Create a remote thread that calls LoadLibraryW with our DLL path
        let thread = CreateRemoteThread(
            process,
            None,
            0,
            Some(load_library_fn),
            Some(remote_mem),
            0,
            None,
        )
        .map_err(|e| format!("CreateRemoteThread: {}", e))?;

        // Wait for the thread to complete (WAIT_OBJECT_0 = 0x0)
        let wait_result = WaitForSingleObject(thread, 10000);

        // Only free remote memory if the thread finished; if it timed out
        // the thread may still be using the memory — leak it to avoid corruption
        if wait_result.0 == 0 {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE).ok();
        } else {
            eprintln!(
                "  WARN: LoadLibraryW timed out in PID {}, leaking remote allocation to avoid corruption",
                pid
            );
        }

        let _ = CloseHandle(thread);
        let _ = CloseHandle(process);
    }

    Ok(())
}

/// Finds `teams_usb_fix.dll` next to the current executable.
/// Returns `None` if the file does not exist there.
pub fn resolve_dll_path() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    let candidate = exe_dir.join("teams_usb_fix.dll");
    if candidate.exists() {
        Some(candidate.to_string_lossy().into_owned())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Pre-injection USB descriptor preflight check
// ---------------------------------------------------------------------------

/// A USB device found to have at least one broken string descriptor.
#[derive(Debug)]
pub struct BrokenDevice {
    pub vid: u16,
    pub pid: u16,
    pub hub_path: String,
    pub port: u32,
    pub failed_string_indices: Vec<u8>,
}

// IOCTL constants are provided by common.rs via `use common::*`.

/// GUID_DEVINTERFACE_USB_HOST_CONTROLLER = {3ABF6F2D-71C4-462A-8A92-1E6861E6AF27}
const GUID_USB_HOST_CONTROLLER: windows::core::GUID = windows::core::GUID::from_values(
    0x3ABF6F2D,
    0x71C4,
    0x462A,
    [0x8A, 0x92, 0x1E, 0x68, 0x61, 0xE6, 0xAF, 0x27],
);

/// Enumerates USB host controllers, checks each hub's ports for connected devices,
/// and probes string descriptor indices 1–3. Returns devices where any string
/// descriptor fetch fails with ERROR_GEN_FAILURE (indicating broken firmware).
pub fn preflight_check() -> Vec<BrokenDevice> {
    let mut broken = Vec::new();
    unsafe {
        let hub_paths = enumerate_hub_paths();
        for hub_path in hub_paths {
            check_hub(&hub_path, &mut broken);
        }
    }
    broken
}

/// Returns the device interface paths for all USB host controllers (which are
/// also the root hubs we can open with CreateFileW + IOCTL_USB_GET_NODE_INFORMATION).
unsafe fn enumerate_hub_paths() -> Vec<String> {
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
        SetupDiGetDeviceInterfaceDetailW, SP_DEVICE_INTERFACE_DATA,
        DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
    };

    let mut paths = Vec::new();

    let devinfo = match SetupDiGetClassDevsW(
        Some(&GUID_USB_HOST_CONTROLLER),
        windows::core::PCWSTR::null(),
        windows::Win32::Foundation::HWND(std::ptr::null_mut()),
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
    ) {
        Ok(h) => h,
        Err(_) => return paths,
    };

    let mut iface_data = SP_DEVICE_INTERFACE_DATA {
        cbSize: std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
        ..Default::default()
    };

    let mut index = 0u32;
    loop {
        if SetupDiEnumDeviceInterfaces(devinfo, None, &GUID_USB_HOST_CONTROLLER, index, &mut iface_data).is_err() {
            break;
        }
        index += 1;

        // First call: get required buffer size
        let mut required_size = 0u32;
        let _ = SetupDiGetDeviceInterfaceDetailW(
            devinfo,
            &iface_data,
            None,
            0,
            Some(&mut required_size),
            None,
        );

        if required_size < 6 {
            continue;
        }

        // Allocate a raw byte buffer. The struct layout is:
        //   cbSize: u32 (4 bytes)
        //   DevicePath: [u16; N] — variable length, null-terminated
        // On x86_64: cbSize must be set to 8 (sizeof SP_DEVICE_INTERFACE_DETAIL_DATA_W).
        // On x86:    cbSize must be set to 6 (packed struct).
        let buf_size = required_size as usize;
        let mut buf: Vec<u8> = vec![0u8; buf_size];

        #[cfg(target_arch = "x86")]
        let cb_size: u32 = 6;
        #[cfg(not(target_arch = "x86"))]
        let cb_size: u32 = 8;

        std::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, cb_size);

        use windows::Win32::Devices::DeviceAndDriverInstallation::SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        let detail_ptr = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;

        if SetupDiGetDeviceInterfaceDetailW(
            devinfo,
            &iface_data,
            Some(detail_ptr),
            buf_size as u32,
            Some(&mut required_size),
            None,
        ).is_err() {
            continue;
        }

        // Read DevicePath from the buffer starting at byte offset 4 (after cbSize)
        // The path is a null-terminated UTF-16LE string.
        let path_ptr = buf.as_ptr().add(4) as *const u16;
        // Safe upper bound: (buf_size - 4) / 2 u16 words
        let max_words = (buf_size - 4) / 2;
        let mut len = 0usize;
        while len < max_words && *path_ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(path_ptr, len);
        let path = String::from_utf16_lossy(slice).to_string();
        if !path.is_empty() {
            paths.push(path);
        }
    }

    let _ = SetupDiDestroyDeviceInfoList(devinfo);
    paths
}

/// Opens a USB hub (or host controller root hub path) and checks all ports for
/// broken string descriptors.
unsafe fn check_hub(hub_path: &str, broken: &mut Vec<BrokenDevice>) {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::Foundation::GENERIC_WRITE;

    let path_wide: Vec<u16> = hub_path.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = match CreateFileW(
        windows::core::PCWSTR(path_wide.as_ptr()),
        GENERIC_WRITE.0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        windows::Win32::Foundation::HANDLE(std::ptr::null_mut()),
    ) {
        Ok(h) => h,
        Err(_) => return,
    };

    // Get hub port count via IOCTL_USB_GET_NODE_INFORMATION
    use windows::Win32::Devices::Usb::USB_NODE_INFORMATION;
    let mut node_info = USB_NODE_INFORMATION::default();
    let mut returned = 0u32;
    if DeviceIoControl(
        handle,
        IOCTL_USB_GET_NODE_INFORMATION,
        None,
        0,
        Some(&mut node_info as *mut _ as *mut std::ffi::c_void),
        std::mem::size_of::<USB_NODE_INFORMATION>() as u32,
        Some(&mut returned),
        None,
    ).is_err() {
        let _ = CloseHandle(handle);
        return;
    }

    // node_info.u.HubInformation.HubDescriptor.bNumberOfPorts
    let port_count = node_info.u.HubInformation.HubDescriptor.bNumberOfPorts as u32;
    if port_count == 0 {
        let _ = CloseHandle(handle);
        return;
    }

    for port in 1..=port_count {
        check_port(handle, hub_path, port, broken);
    }

    let _ = CloseHandle(handle);
}

/// Checks a single hub port for a connected device with broken string descriptors.
unsafe fn check_port(
    hub: windows::Win32::Foundation::HANDLE,
    hub_path: &str,
    port: u32,
    broken: &mut Vec<BrokenDevice>,
) {
    use windows::Win32::System::IO::DeviceIoControl;

    // USB_NODE_CONNECTION_INFORMATION_EX has a variable tail (PipeList[1]);
    // allocate a generous fixed buffer so Windows doesn't truncate it.
    const BUF: usize = 512;
    let mut buf = [0u8; BUF];
    // ConnectionIndex at offset 0
    std::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, port);

    let mut returned = 0u32;
    if DeviceIoControl(
        hub,
        IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
        Some(buf.as_ptr() as *const std::ffi::c_void),
        std::mem::size_of::<u32>() as u32,
        Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
        BUF as u32,
        Some(&mut returned),
        None,
    // Minimum size check: need at least through ConnectionStatus field at offset 31+4=35 bytes
    ).is_err() || (returned as usize) < 35 {
        return;
    }

    // USB_NODE_CONNECTION_INFORMATION_EX is packed(1). Read each field we need
    // via read_unaligned to avoid misaligned reference UB. Offsets (packed layout):
    //   ConnectionIndex: u32      @ 0
    //   DeviceDescriptor starts @ 4:
    //     bLength(1) bDescriptorType(1) bcdUSB(2) bDeviceClass(1) bDeviceSubClass(1)
    //     bDeviceProtocol(1) bMaxPacketSize0(1) idVendor(2) idProduct(2) ...
    //     so idVendor @ 4+8=12, idProduct @ 14
    //   CurrentConfigurationValue: u8 @ 4+18 = 22
    //   Speed: u8                    @ 23
    //   DeviceIsHub: BOOLEAN (u8)    @ 24
    //   DeviceAddress: u16           @ 25
    //   NumberOfOpenPipes: u32       @ 27
    //   ConnectionStatus: USB_CONNECTION_STATUS (i32) @ 31
    let base = buf.as_ptr();
    let vid: u16 = std::ptr::read_unaligned(base.add(12) as *const u16);
    let pid: u16 = std::ptr::read_unaligned(base.add(14) as *const u16);
    let device_is_hub: u8 = std::ptr::read_unaligned(base.add(24));
    let connection_status: i32 = std::ptr::read_unaligned(base.add(31) as *const i32);

    // Skip if no device or if this port is itself a hub
    use windows::Win32::Devices::Usb::DeviceConnected;
    if connection_status != DeviceConnected.0 || device_is_hub != 0 {
        return;
    }

    // Probe string descriptor indices 1 (manufacturer), 2 (product), 3 (serial)
    let mut failed_indices = Vec::new();
    for &idx in &[1u8, 2, 3] {
        if probe_string_descriptor_fails(hub, port, idx) {
            failed_indices.push(idx);
        }
    }

    if !failed_indices.is_empty() {
        broken.push(BrokenDevice {
            vid,
            pid,
            hub_path: hub_path.to_string(),
            port,
            failed_string_indices: failed_indices,
        });
    }
}

/// Returns true if requesting string descriptor `index` from the given port
/// fails with ERROR_GEN_FAILURE (indicating broken USB firmware).
unsafe fn probe_string_descriptor_fails(
    hub: windows::Win32::Foundation::HANDLE,
    port: u32,
    index: u8,
) -> bool {
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::Foundation::{GetLastError, WIN32_ERROR};

    const MAX_STR: usize = 126;
    // USB_DESCRIPTOR_REQUEST layout (packed): ConnectionIndex(4) + SetupPacket(8) + Data[1]
    // Total header = 4 + 1 + 1 + 2 + 2 + 2 = 12 bytes; data payload follows.
    const HDR: usize = 12;
    const BUF: usize = HDR + 2 + MAX_STR * 2;
    let mut buf = [0u8; BUF];

    // Write request fields (packed layout):
    //   [0..4]  ConnectionIndex: u32
    //   [4]     bmRequest: u8  = 0x80
    //   [5]     bRequest: u8   = 0x06 (GET_DESCRIPTOR)
    //   [6..8]  wValue: u16    = (type << 8) | index
    //   [8..10] wIndex: u16    = 0x0409 (English)
    //   [10..12] wLength: u16  = data area size
    std::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, port);
    buf[4] = 0x80;
    buf[5] = 0x06;
    let w_value: u16 = ((USB_STRING_DESCRIPTOR_TYPE as u16) << 8) | (index as u16);
    std::ptr::write_unaligned(buf.as_mut_ptr().add(6) as *mut u16, w_value);
    let w_index: u16 = 0x0409;
    std::ptr::write_unaligned(buf.as_mut_ptr().add(8) as *mut u16, w_index);
    let w_length: u16 = (BUF - HDR) as u16;
    std::ptr::write_unaligned(buf.as_mut_ptr().add(10) as *mut u16, w_length);

    let mut returned = 0u32;
    let ok = DeviceIoControl(
        hub,
        IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
        Some(buf.as_ptr() as *const std::ffi::c_void),
        BUF as u32,
        Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
        BUF as u32,
        Some(&mut returned),
        None,
    );

    if ok.is_err() {
        let err = GetLastError();
        return err == WIN32_ERROR(ERROR_GEN_FAILURE);
    }

    false
}
