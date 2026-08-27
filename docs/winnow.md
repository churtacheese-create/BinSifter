# BinSifter Winnow

Winnow is BinSifter's Linux-focused variant: a full rewrite in Python and PySide6 (the `binsifter/` package). If you're on Windows, use [Rowan](rowan.md) instead - Winnow's platform focus is Linux specifically, packaged for the major distro families rather than offered as a generic cross-platform build.

Both the scan engine and the GUI are real and working, not a placeholder: a full desktop app (Dashboard, Results grid, Scan Queue, Settings, Logs, YARA/capa rule management, Help, About) backed by the same detection pipeline as Rowan - hashing/entropy, NSRL, blocklist, YARA with MITRE ATT&CK enrichment, CAPA, FLOSS, Speakeasy emulation, Authenticode (embedded + catalog-based) verification, archive/compressed-file expansion, IOC extraction, SSDEEP/imphash clustering, draft YARA rule generation, and CSV reporting.

Winnow is newer than Rowan and hasn't seen as much real-casework mileage yet - please report anything that looks wrong rather than assuming it's expected.

## Requirements

- Linux: Debian/Ubuntu, Fedora/RHEL, Arch, and derivatives. Python 3.10+ only if installing from source - the packaged releases (`.deb`/`.rpm`/`.pkg.tar.zst`) are self-contained and don't need a separate Python install.
- An NSRL known-good hash set (not included - see Settings). NSRL ships as RDSv3 hashes; BinSifter's NSRL loader expects the older RDSv2 text-file format, so you'll need to convert first - see NIST's own [RDSv3 to RDSv2 text files conversion guide](https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/RDSv3_Docs/RDSv3_to_RDSv2_text_files.pdf) (PDF).
- Whichever of the optional external quick-launch tools below you want right-click access to (not included - point BinSifter at a single tools directory in Settings and it searches it recursively). Winnow's archive/compressed-file support additionally needs a `7z` binary available.

**No separate install needed for YARA, capa, FLOSS, or ssdeep.** Unlike the quick-launch tools below, these four run as in-process Python libraries (`yara-python`, `flare-capa`, `flare-floss`, `ppdeep`) bundled with Winnow itself - there is no standalone Linux binary to download or point Settings at for any of them. "Path to YARA rules" and "Path to capa rules" in Settings are your *rule/signature files*, not the engines themselves - those you do need to supply (YARA `.yar`/`.yara` rules, a capa rules directory), same as on Rowan.

## Getting started

Pick whichever matches your Linux distro:

- **Debian/Ubuntu and derivatives:** `sudo apt install ./binsifter-winnow.deb`
- **Fedora/RHEL/openSUSE and derivatives:** `sudo dnf install ./binsifter-winnow.rpm` (or `sudo zypper install`/`sudo rpm -i`)
- **Arch Linux and derivatives:** `sudo pacman -U binsifter-winnow.pkg.tar.zst`

All three are self-contained (no separate Python install needed) and add a normal application-menu entry plus a `binsifter-winnow` terminal command. Grab them from the latest GitHub Release.

Running from source instead: `pip install -e .` from the repo root, then `python -m binsifter.gui` to launch the desktop app (or `binsifter-scan --src-dir ... --yara-rules ... --nsrl-path ...` for a headless scan). Building from source on Linux needs a C/C++ toolchain present (`build-essential`/`python3-dev`/`automake`/`libtool`/`pkg-config`/`libssl-dev` on Debian/Ubuntu, or your distro's equivalents) - `yara-python` and FLOSS's `binary2strings` dependency both compile native extensions from source on Linux, since neither publishes a prebuilt Linux wheel. See `installer/README.md` for how the packaged releases are built.

## Quick-launch tools

Right-click any row in Results for on-demand actions, driven by "Path to tools"/"Path to Ghidra" in Settings:

- **PE-bear** and **Anya** - static PE inspection/resource editing, replacing Rowan's PE Studio/CFF Explorer/Resource Hacker (all Windows-only, no Linux build).
- **DIE** (Detect It Easy) - packer/compiler detection, same as Rowan.
- **Rizin** and **Angr** - reverse-engineering/analysis framework and symbolic-execution framework, replacing Rowan's x64dbg/x32dbg (also Windows-only).
- **Ghidra** headless analysis - same as Rowan, found via its Linux `analyzeHeadless` script (not the Windows `.bat`).
- **Isolated Speakeasy code emulation** - asks for confirmation first, since emulating a live sample's code is execution-adjacent; output shows in a popup report window.
- **Export for AI analysis** writes a Markdown+JSON pair of the file's already-extracted findings for you to hand to whatever AI tool you choose - no AI is called from BinSifter itself.

None of these five tools ship one single canonical Linux binary name the way a Windows `.exe` usually does, so BinSifter tries a couple of common filename spellings for each - if your install uses a different filename, rename or symlink it to match, or check the Logs page to see what BinSifter actually searched for. Sigcheck (Rowan's Sysinternals signature check) has no Linux equivalent and isn't offered here.

Any entry showing "(not configured)" means that tool's path wasn't found under "Path to tools" (or "Path to Ghidra" for the Ghidra entry).

## Dark/light mode

Winnow follows your desktop's theme automatically at startup - checked once at launch, not live (a theme change while Winnow is running needs a relaunch to pick up). Detection isn't distro-specific (dark/light mode is a desktop-environment concept, not a distro one - any of Debian/Red Hat/Arch's families can run GNOME, KDE Plasma, XFCE, or something else), so it tries, in order: the desktop-agnostic `xdg-desktop-portal` Settings API (covers whichever desktop environment provides a portal backend), GNOME's `gsettings`, KDE Plasma's `kdeglobals` config file, then XFCE's `xfconf-query`. Falls back to light mode if none of those can tell.

## License

BinSifter is source-available, not open source. See the repo root's `LICENSE` (PolyForm Strict License 1.0.0).
