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
- **Cutter** and **Angr** - reverse-engineering/analysis framework and symbolic-execution framework, replacing Rowan's x64dbg/x32dbg (also Windows-only). Cutter is rizin's own official Qt GUI front-end.
- **GDB**, paired with the **GEF** extension - live debugging, opened in a real terminal.
- **Binwalk** - firmware/embedded-file signature scanning and carving, also opened in a terminal.
- **Malwoverview** - looks up the selected file's hash against VirusTotal (sends only the hash, never the sample itself - see [malwoverview's own docs](https://github.com/alexandreborges/malwoverview) before relying on this for sensitive samples), opened in a terminal.
- **Ghidra** headless analysis - same as Rowan, found via its Linux `analyzeHeadless` script (not the Windows `.bat`).
- **Isolated Speakeasy code emulation** - asks for confirmation first, since emulating a live sample's code is execution-adjacent; output shows in a popup report window.
- **Export for AI analysis** writes a Markdown+JSON pair of the file's already-extracted findings for you to hand to whatever AI tool you choose - no AI is called from BinSifter itself.

None of these tools ship one single canonical Linux binary name the way a Windows `.exe` usually does, so BinSifter tries a couple of common filename spellings for each - if your install uses a different filename, rename or symlink it to match, or check the Logs page to see what BinSifter actually searched for. Sigcheck (Rowan's Sysinternals signature check) has no Linux equivalent and isn't offered here.

GDB, Binwalk, and Malwoverview are plain command-line tools with no window of their own - BinSifter opens them inside a real terminal (whichever of `x-terminal-emulator`/`gnome-terminal`/`konsole`/`xfce4-terminal`/`xterm` is found on PATH) instead of a background launch that would otherwise silently do nothing. That terminal also stays open after the command exits and prints its exit status - a fast crash (e.g. a broken system `gdb`) is now visible instead of the window flashing shut before you can read anything.

PE-bear/DIE/Cutter are launched with `--appimage-extract-and-run` whenever the target genuinely is an AppImage (detected from the file's own signature, not guessed) - this works whether or not `libfuse2` is installed, which several modern distros (Ubuntu 22.04+ among them) no longer ship by default. Without it, an AppImage on a machine missing FUSE exits instantly with no window and no visible error at all.

Any quick-launch tool that exits immediately after being launched (crashes, a missing library, anything else that isn't a normal Python-level launch failure) now shows an error dialog with whatever it printed to stderr, instead of silently doing nothing - previously this class of failure was invisible.

**Most of these tools also install themselves automatically - you don't have to do any of this by hand.** As of 2026-09-03, on every startup BinSifter checks whether each of PE-bear/Anya/DIE/Cutter/Angr/Binwalk/Malwoverview/Ghidra is already findable (your "Path to tools"/"Path to Ghidra" directory, your normal shell PATH, or a copy BinSifter downloaded itself previously); anything missing gets downloaded and installed automatically in the background, without ever blocking the window from opening or a scan from running. Everything is a plain per-user download - never `sudo`, never a system package manager - so nothing here needs elevated permissions:

- **PE-bear, DIE, and Cutter** are fetched directly from each project's own GitHub Releases as Linux AppImages and dropped into a BinSifter-managed folder.
- **Anya** is fetched the same way, using its static Linux CLI tarball.
- **Angr, Binwalk, and Malwoverview** are PyPI packages, not downloadable binaries - each gets its own dedicated virtualenv (kept separate from BinSifter's own Python environment and from each other), the same approach angr's own docs recommend for itself. Angr's install additionally tries a prebuilt wheel first, since it has a native/Rust extension that can otherwise require a Rust toolchain to build from source. That virtualenv is built using a real system `python3` found on PATH, not BinSifter's own (packaged) interpreter - the packaged app's own executable isn't a general-purpose Python interpreter, so using it to create a venv doesn't work.
- **Ghidra** is fetched from its own GitHub Releases (a single, platform-independent zip) and extracted into a BinSifter-managed folder; if no JDK 21+ is already on PATH, BinSifter also downloads a portable one (Eclipse Temurin, via Adoptium's own release API) rather than requiring you to install a system JDK first.

**GDB itself is the one exception - it's never auto-installed**, since that would need a real distro package manager (`apt`/`dnf`/`pacman`), not a per-user download. BinSifter only ever looks for it on PATH; install it yourself (see below) and relaunch. Once BinSifter finds a `gdb` on PATH, though, it does auto-install the [GEF](https://github.com/bata24/gef) extension for it - GEF is a single script sourced from `~/.gdbinit`, genuinely a per-user, root-free install.

If there's no internet connection when a tool is missing, BinSifter tells you so (in a popup once the check finishes, and in the Logs page) and offers two options: reconnect and relaunch Winnow so it tries again, or install the tool yourself using the commands below - either way, a missing tool never stops the rest of the app from working. Manual install, if you'd rather do it that way or the automatic download fails for some reason:

- **Cutter** has native packages on most distros (`sudo apt install cutter`, `sudo pacman -S cutter`, etc.) or its own Linux AppImage on GitHub Releases - install either way and BinSifter finds it.
- **PE-bear** and **DIE** both publish Linux AppImages on their GitHub Releases. Make the AppImage executable and drop it somewhere already on PATH (e.g. `~/.local/bin/pe-bear`) rather than a scratch folder, and it's found the same way.
- **[Anya](https://github.com/elementmerc/anya)** publishes real Linux packages too (`.AppImage`/`.deb`/`.rpm` for the GUI, a static musl binary tarball for the CLI) and its own one-liner installer (`curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/main/install.sh | bash`) that puts a plain `anya` command on PATH directly - no build step, no venv, of the tools here this is the simplest to get running.
- **Angr** is a PyPI package, not a standalone binary - its own docs recommend installing into a dedicated virtualenv rather than system-wide. The cleanest way to get it onto PATH as a single runnable command is [`pipx`](https://pipx.pypa.io/) (`pipx install angr`, plus a small wrapper script if you want a one-shot CLI over angr's Python API rather than writing a script by hand each time) - pipx builds the isolated venv for you and exposes just the command.
- **GDB** needs your distro's own package manager - `sudo apt install gdb`, `sudo dnf install gdb`, `sudo pacman -S gdb`, etc.
- **Binwalk** and **Malwoverview** are both PyPI packages - `pipx install binwalk` / `pipx install malwoverview` (or your distro's `binwalk` package, which additionally pulls in extraction-helper libraries the pip package doesn't ship).
- **Ghidra** - download the latest release from [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra/releases/latest), extract it anywhere, and point "Path to Ghidra" at the extracted folder. Needs a JDK 21+ - install one via your distro's package manager (e.g. `sudo apt install openjdk-21-jdk`) or from [adoptium.net](https://adoptium.net/) if you'd rather not let Winnow download its own copy.

"Path to tools" still works exactly as before for anything you'd rather keep in one curated directory (including a fully-self-built venv/wrapper) - a hit under that directory always wins over a PATH hit for the same tool. It's just no longer the only way to get a tool found.

Any entry showing "(not configured)" means that tool's path wasn't found under "Path to tools" (or "Path to Ghidra" for the Ghidra entry).

## Dark/light mode

Winnow follows your desktop's theme automatically at startup - checked once at launch, not live (a theme change while Winnow is running needs a relaunch to pick up). Detection isn't distro-specific (dark/light mode is a desktop-environment concept, not a distro one - any of Debian/Red Hat/Arch's families can run GNOME, KDE Plasma, XFCE, or something else), so it tries, in order: the desktop-agnostic `xdg-desktop-portal` Settings API (covers whichever desktop environment provides a portal backend), GNOME's `gsettings`, KDE Plasma's `kdeglobals` config file, then XFCE's `xfconf-query`. Falls back to light mode if none of those can tell.

## License

BinSifter is source-available, not open source. See the repo root's `LICENSE` (PolyForm Strict License 1.0.0).
