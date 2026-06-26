# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

MySEQ is a two-process EverQuest map overlay tool. The **server** (`server/`) is a Win32/x64 C++ application that reads EQ game memory via `ReadProcessMemory` and serves parsed spawn/zone/item data over TCP. The **client** (`client/`) is a C# WinForms (.NET 4.8) application that connects to the server and renders an interactive map with mob tracking, filtering, and proximity alerts.

## Build System

Open `MySEQ.sln` in VS2022 (PlatformToolset v143) to build both projects together.

**Server** (C++):
- Project file: `server/MySEQ.server.vcxproj`
- Configurations:
  - `Debug - GUI|Win32` / `Debug - GUI|x64` — GUI tray app with debug symbols
  - `Debug - Console|Win32` / `Debug - Console|x64` — headless console build
  - `Release|Win32` / `Release|x64`
- Use x64 when targeting the current 64-bit EQ client (addresses in `myseqserver.ini` are 64-bit, e.g. `0x140eb4914`). Use Win32 only for legacy 32-bit EQ.

**Client** (C#, .NET 4.8):
- Project file: `client/MySEQ.client.csproj`
- Configurations: `Debug|x86`, `Debug|x64`, `Debug - GUI|x86`, `Release|x86`, `Release|x64`
- Output path for debug x86: `../../Program Files (x86)/MySEQ/`

There are no automated tests in this codebase.

## Architecture

### Server (`server/`)

The server runs as a Win32/x64 GUI application (system tray) or as a Windows Service (`-k`). In normal mode it owns a hidden dialog (`h_MySEQServer`) and uses WinSock async messages (`FD_ACCEPT`, `FD_READ`, `FD_CLOSE`) to drive its network loop from the Win32 message pump.

**Core globals** (declared in `MySEQ.server.h`):
- `MemReader memReader` — wraps `ReadProcessMemory`; finds and attaches to `eqgame.exe`
- `IniReader iniReader` — parses `myseqserver.ini` for all memory offsets and port config
- `NetworkServer netServer` — TCP listener/client socket + data serialization
- `Debugger debugger` — debug CLI loop (spawned on a separate thread when run with `debug` arg)
- `EQGameScanner scanner` — binary pattern scanner backing the Offset Finder dialog (`IDD_EQOFFSETSFINDER`)

**Data flow (normal mode)**:
1. Client connects → `FD_ACCEPT` → `openClientSocket()`
2. Client sends a `RequestTypes` bitmask (see `Enums.cs` / `inc_packet_types` in `NetworkServer.h`)
3. `FD_READ` → `processReceivedData()` → reads EQ memory via `MemReader` → serializes into `netBuffer_t` structs → sends back
4. `FD_CLOSE` / disconnect → `closeClientSocket()`

**Offset Finder dialog** (`IDD_EQOFFSETSFINDER`) — opened from the server tray menu:

| Button | ID | Action |
|--------|----|--------|
| Find EQgame.exe | `IDC_BUTTON1` | Browse for / auto-locate `eqgame.exe` |
| Scan Primary | `IDOK` | Run `ScanExecutable` — uses existing scanner patterns to resolve current primary VAs |
| Scan Secondary | `IDC_BUTTON3` | Run `ScanSecondary` — uses existing scanner patterns to resolve struct member offsets |
| Find Patterns | `IDC_BUTTON5` | Run `FindAndWriteAllPatterns` — reads current VAs/offsets from INI, scans the EXE binary, and auto-writes all 29 scanner patterns (6 primaries + 18 SpawnInfo + 5 WorldInfo) |
| Write Offsets to ini file | `IDC_BUTTON2` | Re-run `ScanExecutable` with `write_out=true` to persist primary offsets into INI |

**Scanner pattern format** — each of the 29 scanner sections in `myseqserver.ini` has three keys:
- `Start` — hex file offset into `eqgame.exe` to begin the search window
- `Pattern` — escaped byte sequence (e.g. `\x48\x8b\x05\x00\x00\x00\x00`) with wildcard bytes
- `Mask` — character per byte: `x`=exact match, `r`=RIP-relative disp32 (extract + resolve), `t`=direct value extract (1 or 4 bytes), `?`=wildcard

For **primary offsets** (`[ZoneAddr]` etc.), the mask is `xxxxxxxxxxxrrrrxxxxxx` (21 bytes): 8 pre-context + REX/op/ModRM (`xxx`) + disp32 (`rrrr`) + 6 post-context. `findEQPointerOffset` resolves the RIP-relative address as `IMAGE_BASE + fileOffsetToRVA(match + rPos + 4) + disp32`.

For **secondary/WorldInfo offsets** (`[SpawnInfoNextOffset]`, `[WorldInfoHourOffset]` etc.), disp32 offsets (value > 127) use mask `xxxxxxxxttttxxxxxx` (18 bytes, `t`=4); disp8 offsets (value ≤ 127) use mask `xxxxxxxxxxxxxxxxxxxxxtxxxxxxxx` (23 bytes, `t`=1). `findEQPointerOffset` extracts the `t` bytes as the struct member offset.

**Memory reading** (all offsets from `myseqserver.ini`):
- Primary offsets (`[Memory Offsets]`): absolute addresses in the EQ process for ZoneAddr, SpawnHeaderAddr, CharInfo, TargetAddr, ItemsAddr, WorldAddr
- Secondary offsets (`[SpawnInfo Offsets]`): byte offsets within a spawn struct for name, position, level, class, race, etc.
- `Spawn.cpp` walks the doubly-linked list starting at `SpawnHeaderAddr` using `NextOffset`/`PrevOffset`

**Wire format** — each packet is a packed `netBuffer_t` struct (100 bytes, `#pragma pack(1)`):

| Field | Type | Bytes |
|-------|------|-------|
| name | char[30] | 30 |
| x, y, z | float×3 | 12 |
| heading, speed | float×2 | 8 |
| id, owner | UINT×2 | 8 |
| type, class | BYTE×2 | 2 |
| race | UINT | 4 |
| level, hidden | BYTE×2 | 2 |
| primary, offhand | UINT×2 | 8 |
| lastName | char[22] | 22 |
| flags | UINT | 4 |
| **total** | | **100** |

The `flags` field is the packet type discriminator — `OPT_spawns=0x00`, `OPT_target=0x01`, `OPT_zone=0x04`, `OPT_ground=0x05`, `OPT_world=0x08`, `OPT_self=0xFD`.

**Debug mode** (`server debug`):
- `AllocConsole()` + `freopen` redirects stdio to a new console window — the server uses Windows Console API (`ReadConsole`/`_getch`), so stdin pipes from external processes do not work
- `DoDebugLoop()` runs `Debugger::enterDebugLoop()` on a separate thread
- Debug commands: `fz`, `ft`, `fs`, `et`, `es`, `ew`, `sg`, `sfw`, `wt`, `wv`, `sp`, `sft`, `sfa`, `spo`, `sso`, `d`, `r`, `x`

**Server run modes** (parsed by `ReadArgs()`):
- Default: tray GUI
- `debug`: console debug CLI
- `console`: headless console
- `-f <file>`: alternate INI path
- `-i` / `-d`: install/uninstall as Windows Service
- `-k`: run as Windows Service

### Client (`client/`)

A C# WinForms .NET 4.8 application. `Structures.cs` from the older codebase has been split into dedicated files:

| File | Role |
|------|------|
| `MainForm.cs` | Main window, menu, layout host for dockable panels (was `frmMain.cs`) |
| `EQCommunications.cs` | TCP socket client, packet parsing, spawn list management |
| `EQData.cs` | In-memory game state (spawns, ground items, zone, player) |
| `MapCon.cs` | Map rendering (GDI+), spawn dot drawing, con-level coloring |
| `MapPane.cs` | Dockable panel wrapping `MapCon` |
| `Filters.cs` | XML-based zone filter parsing (hunt/caution/danger/alert mobs) |
| `SPAWNINFO.cs` | `Spawninfo` class — matches server's `netBuffer_t` byte-for-byte |
| `SPAWNTIMER.cs` | `Spawntimer` class — tracks respawn timing data |
| `Enums.cs` | All enums: `PacketType`, `DrawOptions`, `RequestTypes`, `FollowOption`, `LogLevel` |
| `GroundItem.cs` | `GroundItem` and `ListItem` structs |
| `IniFile.cs` | P/Invoke wrapper around `WritePrivateProfileString`/`GetPrivateProfileString` |
| `RegexHelper.cs` | Pre-compiled regex patterns for spawn name classification |
| `PrettyNames.cs` | Lookup tables for class/race/body type names (was `Classes.cs`) |
| `MobTrails.cs` | Records recent position history per mob for trail rendering |
| `MobsTimers.cs` | Manages spawn respawn timers (was `MobsTimer.cs`) |
| `MarkLookup.cs` | Adhoc lookup slots (up to 6) with L/F mode and level filtering |
| `FormMethods.cs` | Helper methods extracted from the main form |
| `FileOps.cs` | File path helpers, cfg directory resolution |
| `ExtensionMethods.cs` | Extension methods used across the client |
| `ProcessInfo.cs` | Holds EQ process ID and character name for multi-process support |
| `OptionsForm.cs` | Settings dialog (was `frmOptions.cs`) |
| `Properties/Settings.*` | User settings via `Settings.Default` (was `Settings.cs`) |

> **Note**: `AlertStatus.cs` exists in the repo but is entirely commented out — it is in-progress code for a planned audio/speech alert system.

**Client data flow**:
1. Login dialog → user enters server IP/port → `EQCommunications` opens TCP socket
2. Timer fires → sends `RequestTypes` bitmask to server
3. `EQCommunications` receives raw bytes → deserializes into `Spawninfo` objects → updates `EQData`
4. `MapCon.OnPaint` renders from `EQData` using GDI+; `MobTrails` data drawn as position history lines

**Spawn classification**: spawns in `EQCommunications`/`EQData` are tagged (`IsHunt`, `IsCaution`, `IsDanger`, `IsAlert`, `IsPet`, `IsMerc`, `IsCorpse`, `IsMount`, `IsFamiliar`) by matching against zone filter XML files in `cfg/`.

**Filter files** (`cfg/*.Ini`): zone-specific XML with `<section name="Hunt">` / `<section name="Primary">` / `<section name="Offhand">` etc., each containing `<oldfilter><regex>...</regex></oldfilter>` entries.

**Adhoc lookups** (`MarkLookup.cs`): up to 6 slots; each is Lookup (L) or Filter (F) mode with optional level constraint (`L:xx`). Slots chain left-to-right.

**`DrawOptions` flags** (`Enums.cs`): bitfield controlling what `MapCon` renders — `DrawMap`, `Player`, `Spawns`, `SpawnTrails`, `GroundItems`, `SpawnTimers`, `DirectionLines`, `SpawnRings`, `GridLines`, `ZoneText`. Composites `DrawNormal`, `DrawLess`, `DrawEvenLess` are predefined.

## Configuration

`server/myseqserver.ini` is the single source of truth for memory addresses. Sections:
- `[File Info]`: PatchDate, ClientHash, BuildString
- `[Memory Offsets]`: 6 absolute process addresses (64-bit hex when targeting 64-bit EQ, e.g. `0x140eb4914`)
- `[WorldInfo Offsets]`: byte offsets within the world time struct
- `[SpawnInfo Offsets]`: ~18 byte offsets within the spawn struct
- `[GroundItem Offsets]`: byte offsets within ground item structs
- `[Port]`: TCP port (default 5555)
- `[ZoneAddr]`, `[SpawnHeaderAddr]`, `[CharInfo]`, `[TargetAddr]`, `[ItemsAddr]`, `[WorldAddr]`: scanner patterns for the 6 primary offsets
- `[SpawnInfoNextOffset]` … `[SpawnInfoOffhandOffset]`: scanner patterns for the 18 SpawnInfo struct member offsets
- `[WorldInfoHourOffset]` … `[WorldInfoYearOffset]`: scanner patterns for the 5 WorldInfo struct member offsets

Client user settings are stored via `Properties/Settings.settings` (accessed as `Settings.Default.*`).

## Key Constraints

- **x64 vs Win32 server**: The current live EQ client is 64-bit (addresses like `0x140eb4914` confirm this). Use the x64 server build. The Win32 build is retained for legacy/EQEmu 32-bit servers.
- **Admin privileges required**: The server calls `OpenProcess` with `PROCESS_VM_READ`, which requires elevation.
- **Debug console is not pipeable**: The server's debug mode uses `AllocConsole()` + Windows Console API. External tools cannot drive it via stdin pipes — use the paste-based `offset_wizard.py` instead.
- **Wire format alignment**: `Spawninfo.FromBytes()` and `netBuffer_t` must stay byte-for-byte aligned — both use `Pack=1` / `#pragma pack(1)`. Any field added to one must be added to the other.
- **Offset updates required each EQ patch**: The typical workflow after a patch is:
  1. Use `offset_wizard.py` (in `../offset_finder/`) or the debug server CLI to find the new primary VAs and update `[Memory Offsets]` and `[SpawnInfo Offsets]` / `[WorldInfo Offsets]` in the INI.
  2. Click **Find Patterns** in the Offset Finder dialog (`FindAndWriteAllPatterns`) to regenerate all 29 scanner patterns from the updated VAs/offsets — this replaces the need to run `find_patterns.py` + `find_secondary_patterns.py` manually.
  3. Verify with **Scan Primary** and **Scan Secondary** that all patterns resolve correctly.
