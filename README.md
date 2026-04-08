# Fix for Microsoft Teams USB Audio Crashes

**teams-usb-fix** is an open-source Windows utility that fixes USB audio device crashes in Microsoft Teams. It intercepts broken USB string descriptor requests at the Windows API level and returns valid responses — stopping the crash without modifying Teams or the device.

Originally discovered with the [Schiit Magni Unity](https://www.schiit.com/products/magni-unity) (VID:`30BE` PID:`101C`), but works for any USB audio device with broken string descriptors.

---

## Table of Contents

- [Symptoms](#symptoms)
- [Why This Happens](#why-this-happens)
- [How the Fix Works](#how-the-fix-works)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [How to Check If You're Affected](#how-to-check-if-youre-affected)
- [Building from Source](#building-from-source)
- [Technical Details](#technical-details)
- [FAQ](#faq)
- [Credits](#credits)

---

## Symptoms

If you're experiencing these issues, your USB audio device may have broken string descriptors:

- Audio devices randomly disconnect and reconnect **only in Teams**
- Teams shows repeated "Audio device changed" notifications
- The same device works perfectly in **Spotify, Discord, VLC, and other apps**
- Calls drop or audio cuts out intermittently during Teams meetings
- Problem persists until Teams is restarted — and returns immediately
- Windows Device Manager shows the device as healthy

## Why This Happens

Some USB audio devices have subtly broken USB string descriptors — they return an invalid `bLength` field or fail to provide a serial number. Most Windows audio apps use **WASAPI** and never see this bug.

**Microsoft Teams is different.** Teams uses a custom USB enumeration pipeline in `RtmPal.dll` rather than WASAPI. It directly queries USB devices via `DeviceIoControl` with `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION` — bypassing the standard Windows audio stack.

When Teams polls a device with a broken string descriptor (type 3), the USB hub driver returns `ERROR_GEN_FAILURE` (0x1F). Teams interprets this as a device state change, fires an `AudioOutputDeviceChanged` event, and re-enumerates devices. This triggers another poll, another failure, another event — creating a cascade that crashes the audio pipeline.

**Root cause:** Teams' `RtcPalUSBHostController::ProbePorts` in `RtmPal.dll` does not gracefully handle USB string descriptor failures. Verified via [Ghidra reverse engineering analysis](GHIDRA_ANALYSIS.md).

## How the Fix Works

`teams_usb_fix.dll` hooks `DeviceIoControl` at the `kernelbase.dll` level within the Teams process:

1. Monitors all `DeviceIoControl` calls for USB descriptor requests (`IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION`)
2. Passes through the original call — working devices are never touched
3. If the call **fails** with `ERROR_GEN_FAILURE` and the request was for a **string descriptor** (type 3): synthesizes a valid UTF-16LE descriptor with a deterministic serial number
4. Identifies the failing device (VID, PID, product name) and logs it
5. Does **not** touch device descriptors (type 1) or configuration descriptors (type 2)
6. Does **not** affect any process other than Teams
7. Does **not** modify device firmware, Windows registry, or Teams files

### Architecture

```
Microsoft Teams (ms-teams.exe)
    |
    v
RtmPal.dll (custom USB enumeration)
    |
    v
Windows USB Stack (setupapi.dll, cfgmgr32.dll)
    |
    v
DeviceIoControl (kernelbase.dll)  <-- [HOOK] teams_usb_fix.dll intercepts here
    |
    v
USB Hub Driver (usbhub3.sys)
    |
    v
USB Device (broken string descriptor)
```

Call chain: Teams → RtmPal.dll → setupapi.dll → `DeviceIoControl` → **[HOOK]** → USB Hub Driver → Device

## Quick Start

Download the [latest release](https://github.com/jf10r/teams-usb-fix/releases), extract, and run:

```
injector.exe
```

That's it. The fix is active until Teams exits. For automatic protection, see [Installation](#installation).

## Installation

| Method | Use Case | Persists? | Admin Required? |
|--------|----------|-----------|-----------------|
| **One-shot** (`injector.exe`) | Quick test or one-time fix | Until Teams exits | No |
| **Windows Service** (`--install`) | Permanent automatic protection | Yes, starts with Windows | Yes |
| **System Tray** (`--tray`) | Background with UI controls | While running | No |
| **Build from Source** | Verify code, custom builds | Manual | No |

### Option 1: One-Shot Injection

Run `injector.exe` while Teams is open. The DLL is injected immediately.

```
injector.exe
```

The injector runs a **preflight check** first — it scans your USB bus for devices with broken descriptors and reports what it finds. The fix stays active until Teams exits.

### Option 2: Auto-Inject Service

Install as a Windows Service that watches for Teams and injects automatically:

```powershell
# Install (run as Administrator)
teams-usb-fix-service.exe --install
sc start TeamsUSBFix

# Uninstall
teams-usb-fix-service.exe --uninstall
```

The service starts with Windows and handles Teams restarts automatically.

### Option 3: System Tray

Run in the background with a system tray icon:

```
teams-usb-fix-service.exe --tray
```

Right-click the tray icon for status, log access, and exit. Balloon notifications appear when the DLL is injected.

### Option 4: Build from Source

```
git clone https://github.com/jf10r/teams-usb-fix
cd teams-usb-fix
cargo build --release
```

## Output Binaries

| File | Description |
|------|-------------|
| `teams_usb_fix.dll` | Hook DLL — injected into Teams |
| `injector.exe` | One-shot injector with preflight USB check |
| `teams-usb-fix-service.exe` | Watcher — service, tray, or console mode |

Place all three files in the same directory. The injector and service locate `teams_usb_fix.dll` relative to their own path.

## How to Check If You're Affected

1. Connect your USB audio device
2. Open Teams and join a call (or open audio settings)
3. Watch for repeated "Audio device changed" notifications
4. Run `injector.exe` — the preflight check will report broken devices
5. Check `%LOCALAPPDATA%\teams-usb-fix\teams-usb-fix.log` — if your device appears, it had broken descriptors

**Other indicators:**
- The device works in every other application
- Teams audio issues started when you connected the USB device
- Audio works briefly after joining a call, then cuts out
- Problem goes away when you switch to a different audio device

## Building from Source

**Prerequisites:**
- [Rust](https://rustup.rs/) (stable, 1.75+)
- Windows 10 or 11
- Microsoft C++ Build Tools (for the `windows` crate linker)

```
git clone https://github.com/jf10r/teams-usb-fix
cd teams-usb-fix
cargo build --release
```

Binaries are in `target/release/`:
- `teams_usb_fix.dll`
- `injector.exe`
- `teams-usb-fix-service.exe`

## Technical Details

For the full reverse engineering analysis of how Teams enumerates USB devices, see [GHIDRA_ANALYSIS.md](GHIDRA_ANALYSIS.md).

| Detail | Value |
|--------|-------|
| Hook target | `DeviceIoControl` in `kernelbase.dll` |
| Hook method | [MinHook](https://github.com/TsudaKageworx/minhook-rs) inline trampoline |
| Intercepted IOCTL | `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION` (`0x00220410`) |
| Tracked IOCTL | `IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX` (`0x00220448`) |
| Trigger condition | `ERROR_GEN_FAILURE` (0x1F) on string descriptor (type 3) |
| Synthetic descriptor | UTF-16LE string `USBFIX-XXXX` (deterministic hash of hub + port) |
| Log file | `%LOCALAPPDATA%\teams-usb-fix\teams-usb-fix.log` |

**Requirements:**
- Windows 10 or Windows 11
- Microsoft Teams (new client / MSIX version — `ms-teams.exe`)
- No administrator rights needed for one-shot injection
- No kernel drivers or code signing required

> **Note:** The Windows Service (`--install`) requires Administrator rights.

## FAQ

**Q: Is this safe?**
Yes. The hook only modifies `DeviceIoControl` behavior within the Teams process. It returns valid USB string descriptors for devices that fail to provide them. No data is written to disk other than the log file. The full source code is available for inspection.

**Q: Will antivirus software flag this?**
Yes — expect ~3/72 detections on [VirusTotal](https://www.virustotal.com/). All detections are **ML/heuristic** (not signature-based) and triggered by the `CreateRemoteThread` + `VirtualAllocEx` + `LoadLibraryW` injection pattern, which is identical to how malware injects DLLs. This is inherent to any DLL injection tool and cannot be eliminated through code changes — only **code signing** with a trusted certificate (~$200/yr) would suppress these heuristics. The tool is fully open source — build it yourself and verify the behavior. If your AV blocks it, add an exception for the directory.

**Q: Does this work with apps other than Teams?**
The injector targets `ms-teams.exe` specifically. The DLL itself is generic and could be injected into other processes, but Teams is the only known app with this issue (because it uses custom USB enumeration instead of WASAPI).

**Q: Will Teams updates break this?**
Unlikely. The hook targets `DeviceIoControl` in `kernelbase.dll` — a stable Windows API. It does not patch Teams internals, `RtmPal.dll`, or any Teams-specific offsets.

**Q: Does this affect other USB devices?**
No. The hook only activates when a `DeviceIoControl` call **fails** with `ERROR_GEN_FAILURE`. USB devices with valid descriptors pass through without modification.

**Q: What USB devices are known to be affected?**
Any USB audio device whose string descriptor requests fail with `ERROR_GEN_FAILURE`. The log file identifies your device by VID, PID, and product name.

Known affected devices:
- **Schiit Magni Unity** (VID:`30BE` PID:`101C`)

*If you discover another affected device, please [open an issue](https://github.com/jf10r/teams-usb-fix/issues) with the VID:PID from the log file.*

**Q: Why doesn't Microsoft fix this in Teams?**
Teams' `RtmPal.dll` should handle descriptor failures gracefully instead of treating them as device state changes. This appears to be a bug in Teams' custom USB enumeration code.

**Q: How long does the fix take to install?**
Under 1 minute. Download, extract, run `injector.exe`.

**Q: Do I need admin rights?**
No for one-shot injection (injects into your own user processes). Yes for installing the Windows Service (`--install`).

## About This Project

**Author:** Jeff Noel ([@jf10r](https://github.com/jf10r))
**Repository:** [github.com/jf10r/teams-usb-fix](https://github.com/jf10r/teams-usb-fix)
**License:** [MIT](LICENSE)

Created to solve a Teams USB enumeration bug discovered with the Schiit Magni Unity. The root cause was identified through reverse engineering of Microsoft Teams' `RtmPal.dll` — full analysis in [GHIDRA_ANALYSIS.md](GHIDRA_ANALYSIS.md).

## Credits

- Reverse engineering performed with [Ghidra](https://ghidra-sre.org/) and [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- Built with [Rust](https://www.rust-lang.org/) and the [windows](https://github.com/microsoft/windows-rs) crate
