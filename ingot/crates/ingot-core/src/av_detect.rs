//! Antivirus / EDR detection + a Windows-Defender scan-exclusion helper -
//! port of `binsifter.core.av_detect` and the (since-removed from Winnow)
//! `binsifter.core.defender`.
//!
//! Real-time protection races a bulk malware scan: a sample can be
//! quarantined between the moment Ingot enumerates it and the moment a
//! worker opens it, surfacing as an I/O error mid-scan. [`detect_av_products`]
//! answers "what AV is actually here", [`guidance_for`] points at that
//! vendor's own exclusion settings, and (Windows only, opt-in, one explicit
//! click) [`add_defender_exclusion`] adds a folder to Defender's exclusion
//! list via an elevated `Add-MpPreference`.
//!
//! Detection is two genuinely different implementations, not one with a
//! branch: Windows reads the `root/SecurityCenter2` WMI `AntiVirusProduct`
//! class (what Windows Security itself uses; no admin needed to read it);
//! Linux checks a curated table of systemd units / `/proc` process names /
//! install paths. macOS is not implemented. An empty result on either
//! platform is a valid outcome, never an error.

use std::path::Path;
use std::process::Command;

use base64::Engine;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvProduct {
    pub name: String,
    /// Best-effort pointer to where this product's own exclusion list lives.
    pub guidance: String,
    /// True if this looks like Microsoft Defender (the one product the
    /// exclusion button can automate).
    pub is_defender: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AvError {
    #[error("{0}")]
    Detect(String),
    #[error("{0}")]
    Exclude(String),
}

pub fn looks_like_defender(name: &str) -> bool {
    name.to_ascii_lowercase().contains("defender")
}

/// (substring match, guidance). Windows-console-oriented; the Linux table
/// below is checked first.
const VENDOR_GUIDANCE: &[(&str, &str)] = &[
    ("windows defender", "Use the exclusion button below - Ingot can add this automatically."),
    ("microsoft defender", "Use the exclusion button below - Ingot can add this automatically."),
    ("mcafee", "McAfee: Endpoint Security console > Threat Prevention > Exclusions (or pushed from ePO if centrally managed)."),
    ("eset", "ESET: open the product > Setup > Detection Engine (or Antivirus) > Exclusions."),
    ("sophos", "Sophos: Sophos Endpoint > Exclusions, or Sophos Central > policy Exclusions if centrally managed."),
    ("symantec", "Symantec/Broadcom Endpoint Protection: exclusions are normally pushed from the SEP Manager console - a local client usually can't add its own."),
    ("broadcom", "Broadcom Endpoint Protection: exclusions are normally pushed from the SEP Manager console - a local client usually can't add its own."),
    ("crowdstrike", "CrowdStrike Falcon: exclusions are managed centrally from the Falcon console by design - there is no supported local self-exclusion."),
    ("sentinelone", "SentinelOne: exclusions are managed centrally from the Management Console by design - there is no supported local self-exclusion."),
    ("bitdefender", "Bitdefender: Protection > Antivirus > Settings > Manage Exceptions."),
    ("kaspersky", "Kaspersky: Settings > Threats and Exclusions > Manage Exclusions."),
    ("trend micro", "Trend Micro: open the console/agent's Scan Exclusion List settings."),
    ("malwarebytes", "Malwarebytes: Settings > Exclusions > Add Exclusion."),
    ("avast", "Avast: Menu > Settings > General > Exceptions."),
    ("avg", "AVG: Menu > Settings > General > Exceptions."),
    ("webroot", "Webroot: PC Security > Identity & Privacy Shields > Application/Exclusion list."),
    ("f-secure", "F-Secure: Settings > find the exclusion/exception list for real-time scanning."),
    ("norton", "Norton: Settings > Antivirus > Scans and Risks > Exclusions/Low Risks."),
];

/// Checked before [`VENDOR_GUIDANCE`] - a vendor's Linux agent usually
/// excludes via a config file / CLI, not the Windows GUI wording.
const LINUX_VENDOR_GUIDANCE: &[(&str, &str)] = &[
    ("clamav", "ClamAV: add an ExcludePath directive to /etc/clamav/clamd.conf, then restart the clamav-daemon service."),
    ("defender for endpoint", "Microsoft Defender for Endpoint on Linux: run `mdatp exclusion path add --path <folder>` - the button below only automates Windows Defender, not the Linux agent."),
    ("sophos", "Sophos for Linux: check your Sophos Central policy first if centrally managed; otherwise exclusions are set via the on-box config."),
    ("bitdefender", "Bitdefender GravityZone (Linux): exclusions are normally pushed from the GravityZone console, not set locally."),
    ("trend micro", "Trend Micro Deep Security Agent: exclusions are configured from the Deep Security Manager console."),
    ("symantec", "Symantec/Broadcom Endpoint Protection for Linux: exclusions are pushed from the SEP Manager console."),
    ("broadcom", "Symantec/Broadcom Endpoint Protection for Linux: exclusions are pushed from the SEP Manager console."),
    ("eset", "ESET Endpoint Antivirus for Linux: check /etc/opt/eset/esets/esets.cfg's exclusion list, or the ESET PROTECT console."),
    ("kaspersky", "Kaspersky Endpoint Security for Linux: exclusions are set via the kesl-control CLI, or the management console."),
];

pub fn guidance_for(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    for (pat, hint) in LINUX_VENDOR_GUIDANCE {
        if lowered.contains(pat) {
            return (*hint).to_string();
        }
    }
    for (pat, hint) in VENDOR_GUIDANCE {
        if lowered.contains(pat) {
            return (*hint).to_string();
        }
    }
    format!(
        "No specific guidance for {name} - check its settings for a scan exclusion/exception list."
    )
}

fn product(name: &str) -> AvProduct {
    AvProduct {
        name: name.to_string(),
        guidance: guidance_for(name),
        is_defender: looks_like_defender(name),
    }
}

/// Every AV/EDR product this platform's detection found, deduplicated by
/// name. An empty list is valid (see module docs). Errors only on a hard
/// failure (Windows query can't run) or an unsupported platform.
pub fn detect_av_products() -> Result<Vec<AvProduct>, AvError> {
    #[cfg(target_os = "windows")]
    {
        detect_windows()
    }
    #[cfg(target_os = "linux")]
    {
        Ok(detect_linux())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(AvError::Detect(
            "Antivirus detection isn't implemented for this platform yet - only Windows and Linux."
                .to_string(),
        ))
    }
}

#[cfg(target_os = "windows")]
fn detect_windows() -> Result<Vec<AvProduct>, AvError> {
    // -ErrorAction Stop turns "namespace missing" (Windows Server, Security
    // Center disabled) into a catchable error mapped to an empty list.
    let script = "$ErrorActionPreference='Stop'; try { \
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct \
        | Select-Object -ExpandProperty displayName | ConvertTo-Json -Compress \
        } catch { '[]' }";

    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| AvError::Detect(format!("could not run powershell.exe: {e}")))?;

    let raw = String::from_utf8_lossy(&out.stdout);
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    // ConvertTo-Json: a bare string for one result, an array otherwise.
    let names: Vec<String> = match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::String(s)) => vec![s],
        Ok(serde_json::Value::Array(a)) => a
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => return Ok(Vec::new()),
    };

    let mut seen = std::collections::HashSet::new();
    Ok(names
        .into_iter()
        .filter(|n| !n.is_empty() && seen.insert(n.clone()))
        .map(|n| product(&n))
        .collect())
}

/// (display name, systemd unit, process names in /proc, representative
/// install paths). A hit on ANY signal counts as installed.
#[cfg(target_os = "linux")]
const LINUX_AV_SIGNATURES: &[(&str, &str, &[&str], &[&str])] = &[
    (
        "ClamAV",
        "clamav-daemon.service",
        &["clamd", "freshclam"],
        &["/usr/sbin/clamd", "/usr/bin/clamscan"],
    ),
    (
        "Microsoft Defender for Endpoint",
        "mdatp.service",
        &["wdavdaemon", "mdatp"],
        &["/opt/microsoft/mdatp/sbin/wdavdaemon"],
    ),
    (
        "CrowdStrike Falcon",
        "falcon-sensor.service",
        &["falcon-sensor"],
        &["/opt/CrowdStrike/falcon-sensor"],
    ),
    (
        "SentinelOne",
        "sentinelone.service",
        &["sentinelctl", "sentineld"],
        &["/opt/sentinelone/bin/sentinelctl"],
    ),
    (
        "Sophos",
        "sophos-spl.service",
        &["sophos_threat_detector", "savdctl"],
        &["/opt/sophos-spl"],
    ),
    (
        "Trend Micro Deep Security Agent",
        "ds_agent.service",
        &["ds_agent"],
        &["/opt/ds_agent/ds_agent"],
    ),
    (
        "Bitdefender GravityZone",
        "bd.service",
        &["bdsec", "epag", "bdredline"],
        &["/opt/bitdefender-security-tools"],
    ),
    (
        "Symantec/Broadcom Endpoint Protection",
        "sisidsdaemon.service",
        &["rtvscand", "symcfgd"],
        &["/opt/Symantec/symantec_antivirus"],
    ),
    (
        "ESET Endpoint Antivirus",
        "esets.service",
        &["esets_daemon"],
        &["/opt/eset/esets/sbin/esets_daemon"],
    ),
    (
        "Kaspersky Endpoint Security",
        "kesl.service",
        &["kesl"],
        &["/opt/kaspersky/kesl"],
    ),
];

#[cfg(target_os = "linux")]
fn detect_linux() -> Vec<AvProduct> {
    let running = linux_process_names();
    LINUX_AV_SIGNATURES
        .iter()
        .filter(|(_, unit, procs, paths)| {
            systemd_unit_installed(unit)
                || procs.iter().any(|p| running.contains(*p))
                || paths.iter().any(|p| Path::new(p).exists())
        })
        .map(|(name, ..)| product(name))
        .collect()
}

#[cfg(target_os = "linux")]
fn systemd_unit_installed(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["list-unit-files", unit, "--no-legend"])
        .output()
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linux_process_names() -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return names;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .chars()
            .all(|c| c.is_ascii_digit())
        {
            if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
                names.insert(comm.trim().to_string());
            }
        }
    }
    names
}

/// Add `folder` to Windows Defender's scan-exclusion list. Windows only,
/// opt-in (one explicit click + confirmation on the caller's side). Spawns a
/// **separate** elevated PowerShell via `Start-Process -Verb RunAs` so
/// Windows' own UAC dialog does the elevation - Ingot never gains admin.
pub fn add_defender_exclusion(folder: &Path) -> Result<(), AvError> {
    if !cfg!(target_os = "windows") {
        return Err(AvError::Exclude(
            "Windows Defender exclusions are a Windows-only feature.".to_string(),
        ));
    }
    // best-effort: the folder existing means the exclusion is immediately
    // visible in Windows Security's own UI. Add-MpPreference doesn't require it.
    let _ = std::fs::create_dir_all(folder);

    let escaped = folder.to_string_lossy().replace('\'', "''");
    let inner =
        format!("try {{ Add-MpPreference -ExclusionPath '{escaped}'; exit 0 }} catch {{ exit 1 }}");
    // -EncodedCommand wants base64 of UTF-16LE - avoids nested-quote hell.
    let mut utf16 = Vec::new();
    for u in inner.encode_utf16() {
        utf16.extend_from_slice(&u.to_le_bytes());
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(&utf16);

    // Start-Process -Verb RunAs *throws* (rather than returning a bad exit
    // code) when UAC is declined - catch it and map to 1223 (ERROR_CANCELLED).
    let outer = format!(
        "$ErrorActionPreference='Stop'; try {{ \
         $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru \
         -ArgumentList '-NoProfile -NonInteractive -EncodedCommand {encoded}'; \
         exit $p.ExitCode }} catch {{ exit 1223 }}"
    );

    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &outer])
        .output()
        .map_err(|e| AvError::Exclude(format!("could not run powershell.exe: {e}")))?;

    match out.status.code() {
        Some(0) => Ok(()),
        Some(1223) => Err(AvError::Exclude(
            "UAC elevation was declined (or the elevated process could not start) - no changes made."
                .to_string(),
        )),
        _ => Err(AvError::Exclude(
            "Add-MpPreference failed. Usually this means Defender isn't the active antivirus, \
             its real-time protection is off, or Tamper Protection is blocking preference changes."
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defender_recognised() {
        assert!(looks_like_defender("Windows Defender"));
        assert!(looks_like_defender("Microsoft Defender Antivirus"));
        assert!(!looks_like_defender("ESET Endpoint Antivirus"));
    }

    #[test]
    fn guidance_prefers_linux_wording() {
        assert!(guidance_for("ClamAV").contains("clamd.conf"));
        assert!(guidance_for("ESET Endpoint Antivirus for Linux").contains("esets.cfg"));
        // unknown product -> honest fallback, not a guess
        assert!(guidance_for("Frobozz AV").contains("No specific guidance"));
    }

    #[test]
    fn exclusion_is_windows_only_off_windows() {
        if !cfg!(target_os = "windows") {
            assert!(add_defender_exclusion(Path::new("/tmp/x")).is_err());
        }
    }
}
