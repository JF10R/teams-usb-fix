//! Shared constants, logging utilities, and string helpers.
//!
//! This module is included by both the cdylib (lib.rs) and the binary crates
//! (inject.rs, watcher.rs) via `#[path = "common.rs"] mod common;`.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// USB IOCTL codes
// ---------------------------------------------------------------------------

pub const IOCTL_USB_GET_NODE_INFORMATION: u32 = 0x00220408;
pub const IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX: u32 = 0x00220448;
pub const IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION: u32 = 0x00220410;

// ---------------------------------------------------------------------------
// USB descriptor type constants
// ---------------------------------------------------------------------------

pub const USB_STRING_DESCRIPTOR_TYPE: u8 = 3;
pub const USB_DEVICE_DESCRIPTOR_TYPE: u8 = 1;

// ---------------------------------------------------------------------------
// Win32 error codes
// ---------------------------------------------------------------------------

pub const ERROR_GEN_FAILURE: u32 = 0x1F;

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

/// Returns the log directory: `%LOCALAPPDATA%\teams-usb-fix` (or `%TEMP%` fallback).
pub fn log_dir() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join("teams-usb-fix")
}

/// Returns the current local time as a formatted timestamp string.
///
/// Uses the Win32 `GetLocalTime` API directly to avoid pulling in `chrono`.
pub fn timestamp() -> String {
    #[repr(C)]
    struct SystemTime {
        year: u16,
        month: u16,
        _day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        millis: u16,
    }
    extern "system" {
        fn GetLocalTime(st: *mut SystemTime);
    }
    unsafe {
        let mut st = std::mem::zeroed::<SystemTime>();
        GetLocalTime(&mut st);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            st.year, st.month, st.day, st.hour, st.minute, st.second, st.millis
        )
    }
}

// ---------------------------------------------------------------------------
// Wide-string helpers (Windows UTF-16)
// ---------------------------------------------------------------------------

/// Encodes a `&str` as a null-terminated UTF-16 `Vec<u16>`.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Copies a `&str` into a fixed-size `[u16; N]` buffer (truncates if too long).
/// The buffer is always null-terminated.
pub fn fill_wide<const N: usize>(s: &str, buf: &mut [u16; N]) {
    for (i, c) in s.encode_utf16().take(N - 1).enumerate() {
        buf[i] = c;
    }
}
