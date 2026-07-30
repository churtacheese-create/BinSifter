<#
BinSifter - PowerShell 7+ WinForms binary triage application

Performs fast, repeatable, bounded-parallel triage of a directory full of
files. Each file is hashed once (SHA-1/MD5), checked against an NSRL known-
good hash set, and - if not already known-good - run through YARA and, on
YARA hits, CAPA, with SSDEEP fuzzy hashing and post-scan clustering across
the batch. Optional layers add packer/compiler ID, import-hash clustering,
Authenticode verification, IOC extraction, offline hash-blocklist reputation
checks, draft YARA rule generation, per-file triage disposition tracking,
and on-demand deep-analysis actions (Sigcheck, Ghidra, x64dbg/x32dbg,
Speakeasy) from the Results grid. It does not replace reverse engineering or
a full malware-analysis workflow - its job is to reduce a large collection
into smaller, useful groups for an analyst to work through.

Required configuration (Settings page):
- Source Directory - the folder to scan.
- NSRL Path - an NSRL RDS hash file (SHA-1 in the first CSV field).
- YARA Rules, CAPA Rules - the rule file/directory each engine applies.
- Path to tools - one directory holding yara64.exe, capa.exe, and ssdeep.exe
  (required), plus any optional tools BinSifter integrates with, searched
  recursively.
- Path to Ghidra - optional, a Ghidra install root; analyzeHeadless.bat is
  located inside it automatically.

Report output, MITRE ATT&CK data, and the known-bad hash blocklist default
to Reports\, Attack\, and Blocklist\ subfolders next to this script, created
automatically. Settings field values are cached between launches. Full
configuration details are in the in-app Help page; version history is in
BinSifter_CHANGELOG.md next to this script.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-SystemDarkMode {
    try {
        $value = Get-ItemPropertyValue `
            -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' `
            -Name 'AppsUseLightTheme' -ErrorAction Stop
        return ($value -eq 0)
    }
    catch {
        return $false
    }
}

function New-STARunspace {
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
    $runspace.ApartmentState = [System.Threading.ApartmentState]::STA
    $runspace.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $runspace.Open()
    return $runspace
}

# Builds and shows the entire application (blocking until the window closes).
function Show-MainWindow {
    [CmdletBinding()]
    param(
        [bool]$IsDarkMode,
        [string]$LogoHorizontalPath,
        [string]$WindowIconPath,
        [int]$ThrottleLimit,
        [string]$AppVersion
    )

    $runspace = New-STARunspace
    $runspace.SessionStateProxy.SetVariable('IsDarkMode', $IsDarkMode)
    $runspace.SessionStateProxy.SetVariable('LogoHorizontalPath', $LogoHorizontalPath)
    $runspace.SessionStateProxy.SetVariable('WindowIconPath', $WindowIconPath)
    $runspace.SessionStateProxy.SetVariable('ThrottleLimit', $ThrottleLimit)
    $runspace.SessionStateProxy.SetVariable('AppVersion', $AppVersion)

    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $runspace
    $null = $ps.AddScript({
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        [System.Windows.Forms.Application]::EnableVisualStyles()

        # ================= Native hot paths (compiled C#) =================
        # NSRL parsing, file enumeration, and CSV export all run often enough that
        # PowerShell's interpreter overhead was the actual bottleneck, not the I/O.
        # FileRecord uses public fields so existing ".Prop = value" access elsewhere
        # keeps working unchanged. Add-Type runs once here; every runspace in this
        # process (dispatcher, worker pool) shares the same loaded types after that.
        # Guarded so re-running this script in an already-loaded pwsh session (e.g.
        # from an IDE that reuses the terminal) doesn't fail with "type already exists".
        # IMPORTANT: this must check a type that's unique to the CURRENT version's
        # Add-Type block, not just any BinSifter.* type - checking a type that also
        # existed in an older version means this guard sees it, assumes the newer
        # types exist too, and silently skips recompiling them. (This exact bug
        # broke YARA/CAPA in v1.2.1 when the guard checked NsrlLoader, which
        # predated it.) When adding new types in a future version, update this
        # check to reference one of them.
        if (-not ('BinSifter.ImphashClusterer' -as [type])) {
        Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace BinSifter
{
    public struct HashKey : IEquatable<HashKey>
    {
        public readonly ulong A;
        public readonly ulong B;
        public readonly uint C;

        public HashKey(byte[] bytes) : this(bytes, 0) { }

        public HashKey(byte[] bytes, int offset)
        {
            A = BitConverter.ToUInt64(bytes, offset);
            B = BitConverter.ToUInt64(bytes, offset + 8);
            C = BitConverter.ToUInt32(bytes, offset + 16);
        }

        public bool Equals(HashKey other)
        {
            return A == other.A && B == other.B && C == other.C;
        }

        public override bool Equals(object obj)
        {
            return obj is HashKey other && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hash = 17;
                hash = hash * 31 + A.GetHashCode();
                hash = hash * 31 + B.GetHashCode();
                hash = hash * 31 + C.GetHashCode();
                return hash;
            }
        }
    }

    public static class NsrlLoader
    {
        // SHA-1 is the first (optionally quoted) CSV column. Streams raw 20-byte
        // records to a cache file while building the set, so repeat loads skip parsing.
        public static HashSet<HashKey> BuildFromCsv(string csvPath, string cacheBuildPath)
        {
            var set = new HashSet<HashKey>();
            byte[] record = new byte[20];

            using (var reader = new StreamReader(csvPath, Encoding.UTF8, true, 1 << 20))
            using (var cacheStream = new FileStream(cacheBuildPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    ReadOnlySpan<char> span = line.AsSpan();
                    int comma = span.IndexOf(',');
                    if (comma <= 0) continue;

                    ReadOnlySpan<char> field = span.Slice(0, comma);
                    if (field.Length >= 2 && field[0] == '"' && field[field.Length - 1] == '"')
                    {
                        field = field.Slice(1, field.Length - 2);
                    }
                    if (field.Length != 40) continue;
                    if (!TryParseHex40(field, record)) continue;

                    cacheStream.Write(record, 0, 20);
                    set.Add(new HashKey(record));
                }
            }

            return set;
        }

        // Fast path: read a previously-built cache (flat 20-byte records, no CSV parsing).
        public static HashSet<HashKey> LoadFromCache(string cachePath, long headerBytes)
        {
            var set = new HashSet<HashKey>();
            byte[] buffer = new byte[20 * 65536];

            using (var stream = new FileStream(cachePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
            {
                stream.Seek(headerBytes, SeekOrigin.Begin);
                while (true)
                {
                    int totalRead = 0;
                    while (totalRead < buffer.Length)
                    {
                        int n = stream.Read(buffer, totalRead, buffer.Length - totalRead);
                        if (n == 0) break;
                        totalRead += n;
                    }
                    if (totalRead == 0) break;

                    int records = totalRead / 20;
                    for (int i = 0; i < records; i++)
                    {
                        set.Add(new HashKey(buffer, i * 20));
                    }
                }
            }

            return set;
        }

        // Counts valid SHA-1 rows without retaining anything - used for the NSRL
        // page's manual "Reload Now" preview when no cache exists yet.
        public static long CountRows(string csvPath)
        {
            long count = 0;
            using (var reader = new StreamReader(csvPath, Encoding.UTF8, true, 1 << 20))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    ReadOnlySpan<char> span = line.AsSpan();
                    int comma = span.IndexOf(',');
                    if (comma <= 0) continue;

                    ReadOnlySpan<char> field = span.Slice(0, comma);
                    if (field.Length >= 2 && field[0] == '"' && field[field.Length - 1] == '"')
                    {
                        field = field.Slice(1, field.Length - 2);
                    }
                    if (field.Length == 40) count++;
                }
            }
            return count;
        }

        private static bool TryParseHex40(ReadOnlySpan<char> hex, byte[] output)
        {
            for (int i = 0; i < 20; i++)
            {
                int hi = HexVal(hex[i * 2]);
                int lo = HexVal(hex[i * 2 + 1]);
                if (hi < 0 || lo < 0) return false;
                output[i] = (byte)((hi << 4) | lo);
            }
            return true;
        }

        private static int HexVal(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
    }

    // Public fields, not properties - PowerShell's ".Prop = value" access works
    // the same either way, and this replaces a pscustomobject without touching
    // the rest of the script.
    public class FileRecord
    {
        public string Path;
        public string Status = "Queued";
        public int Progress;
        public string MD5;
        public string SHA1;
        public string SSDEEP;
        public bool NsrlMatch;
        public string YaraMatches;
        public int YaraHitCount;
        public bool CapaEligible;
        public bool PossibleFalseNegative;
        public string CAPAOutput;
        public int CapaDetectionCount;
        // "sc32"/"sc64" when CapaEligible came from the shellcode heuristic and
        // capa succeeded under that bitness guess; null for PE/ELF (capa auto-
        // detects those from real headers, no guess needed) or when both
        // shellcode formats failed to produce a detection.
        public string CapaShellcodeFormat;
        // Worst-case (highest) severity across every YARA rule that matched this
        // file. "Unknown" means no matched rule carried a recognizable severity
        // field - deliberately not guessed. YaraSeverityScore is the normalized
        // 0-100 value behind the bucket, or -1 when the bucket came from a plain
        // word (e.g. tc_policy_severity) rather than a number.
        public string YaraSeverity = "Unknown";
        public int YaraSeverityScore = -1;
        // Semicolon-joined "T#### Name [Tactic]" entries resolved from any
        // matched rule's meta fields via the local MITRE ATT&CK dataset. Null
        // when no rule referenced ATT&CK or no ATT&CK data file is configured.
        public string YaraAttackTechniques;
        // -1 = not computed (e.g. an NSRL-known file never reaches this stage).
        // 0.0-8.0 bits/byte Shannon entropy over the whole file - see
        // BinSifter.EntropyAnalyzer. Computed for every file that gets hashed,
        // not just PossibleFalseNegative ones, since it's free once the file is
        // already being read for SHA-1/MD5.
        public double Entropy = -1;
        public string Error;
        public DateTime Added;
        // -1 = floss wasn't run (not a PossibleFalseNegative file, or no
        // FlossExe configured). Best-effort string/IOC recovery fallback for
        // files YARA flagged that couldn't go through capa.
        public int FlossStringCount = -1;
        // "path (score); path (score)" - other files in this same run whose
        // ssdeep fuzzy hash scored above threshold against this file's hash.
        // Populated in a post-scan pass, not per-file - see the SSDEEP
        // clustering step in Start-ScanEngine.
        public string SsdeepMatches;
        // -1 = not in any cluster (never ssdeep-hashed, e.g. an NSRL-known file).
        // 0+ = the cluster this file belongs to; size-1 clusters are singletons
        // (hashed, but matched nothing above threshold). See SsdeepClusterer.
        public int SsdeepClusterId = -1;
        public int SsdeepClusterSize = 0;
        // True if any of this file's matches scored >= 85 against another file -
        // drives the heat map's "Files above 85%" tile.
        public bool SsdeepHasHighSimilarity;
        // True if this file's cluster (size >= 2) shares a member with a cluster
        // from a PRIOR run, per the persisted cluster history file. Not "this
        // exact cluster existed before" - "at least one of these files was seen
        // clustered before," which tolerates new variants joining an existing
        // family from run to run.
        public bool SsdeepPreviouslySeen;

        // ===== v1.3-proto1 fields =====

        // DIE (Detect It Easy) console-mode packer/compiler detection. Empty
        // string = DIE wasn't run on this file (not in the gated subset, or no
        // DieConsoleExe configured), not "nothing detected".
        public string PackerDetected = "";
        public string Compiler = "";

        // Import-table hash (imphash) - MD5 of the ordered "dllname.funcname"
        // list from the PE import table, lowercased. Survives repacks/rebuilds
        // that change ssdeep's fuzzy-hash score, since it reflects the linked
        // API set rather than raw bytes. Null when the file isn't a parseable
        // PE, has no import table (e.g. a pure resource DLL), or parsing failed
        // (deliberately best-effort - see PeImportHasher).
        public string Imphash;
        // Rich header hash (MD5 of the decoded, un-XORed Rich header bytes) -
        // present only for PE files built with MSVC that retained the Rich
        // header. A secondary, coarser toolchain-fingerprint signal.
        public string RichHash;
        // -1 = not in any imphash cluster (no Imphash, or Imphash unique in this
        // batch). Exact-match grouping (not fuzzy like ssdeep) - see
        // ImphashClusterer.
        public int ImphashClusterId = -1;
        public int ImphashClusterSize = 0;

        // Get-AuthenticodeSignature result. Status mirrors the .NET
        // System.Management.Automation.SignatureStatus enum as a string
        // (Valid/NotSigned/HashMismatch/NotTrusted/NotSupportedFileFormat/
        // UnknownError) rather than a bool, since "not signed" and "signed but
        // invalid" are very different triage signals.
        public string SignatureStatus = "";
        public string SignerName = "";

        // Regex-mined from FLOSS output already generated for
        // PossibleFalseNegative files (see IOC extraction step). Empty when
        // FLOSS didn't run on this file or nothing matched.
        public int IocCount = 0;
        public string ExtractedIOCs = "";

        // Local offline blocklist lookup, same shape as the existing NSRL
        // known-good check but for known-bad hashes. "" = blocklist not
        // configured or file not checked; "Clean" = checked, no match;
        // "KnownBad" = matched an entry in the configured blocklist file.
        public string ReputationStatus = "";
        public string ReputationSource = "";

        // Analyst-set triage disposition. Defaults to Untriaged; persisted by
        // SHA-1 across runs (see the disposition history file in
        // Start-ScanEngine / the Results grid's disposition column handler) so
        // re-opening a case or re-scanning the same files keeps prior calls.
        public string Disposition = "Untriaged";
    }

    public class EnumerationResult
    {
        public List<string> Files = new List<string>();
        public int ErrorCount;
    }

    public static class FileScanner
    {
        // Stack-based, not recursive calls, so a deep tree can't blow the stack.
        // Each directory is wrapped individually so one bad subfolder doesn't
        // abort the rest - mirrors Get-ChildItem -ErrorAction SilentlyContinue.
        public static EnumerationResult EnumerateFiles(string rootPath)
        {
            var result = new EnumerationResult();
            var pending = new Stack<string>();
            pending.Push(rootPath);

            while (pending.Count > 0)
            {
                string dir = pending.Pop();

                string[] subDirs;
                try
                {
                    subDirs = Directory.GetDirectories(dir);
                }
                catch
                {
                    result.ErrorCount++;
                    subDirs = Array.Empty<string>();
                }
                for (int i = 0; i < subDirs.Length; i++)
                {
                    pending.Push(subDirs[i]);
                }

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir))
                    {
                        result.Files.Add(file);
                    }
                }
                catch
                {
                    result.ErrorCount++;
                }
            }

            return result;
        }
    }

    public static class CsvWriter
    {
        // mode: "full" | "suspicious" | "yara" | "capa" - filters which rows get
        // written without needing a PowerShell-supplied delegate.
        public static void WriteReport(string path, List<FileRecord> records, string mode)
        {
            using (var writer = new StreamWriter(path, false, new UTF8Encoding(true), 1 << 20))
            {
                writer.Write("FilePath,SHA1,MD5,SSDEEP,IsKnownGood,YaraHitCount,YaraMatches,YaraSeverity,YaraSeverityScore,AttackTechniques,CapaEligible,PossibleFalseNegative,CapaDetections,Status,Error,Entropy,CapaShellcodeFormat,FlossStringCount,SsdeepMatches,SsdeepClusterId,SsdeepClusterSize,SsdeepHighSimilarity,SsdeepPreviouslySeen,PackerDetected,Compiler,Imphash,RichHash,ImphashClusterId,ImphashClusterSize,SignatureStatus,SignerName,IocCount,ExtractedIOCs,ReputationStatus,ReputationSource,Disposition\r\n");

                foreach (var r in records)
                {
                    if (mode == "suspicious" && r.NsrlMatch) continue;
                    if (mode == "yara" && r.YaraHitCount <= 0) continue;
                    if (mode == "capa" && !r.CapaEligible) continue;

                    WriteRow(
                        writer, r.Path, r.SHA1, r.MD5, r.SSDEEP, r.NsrlMatch.ToString(),
                        r.YaraHitCount.ToString(), r.YaraMatches, r.YaraSeverity,
                        r.YaraSeverityScore.ToString(), r.YaraAttackTechniques,
                        r.CapaEligible.ToString(), r.PossibleFalseNegative.ToString(),
                        r.CapaDetectionCount.ToString(), r.Status, r.Error,
                        r.Entropy >= 0 ? r.Entropy.ToString("F3") : "",
                        r.CapaShellcodeFormat,
                        r.FlossStringCount >= 0 ? r.FlossStringCount.ToString() : "",
                        r.SsdeepMatches,
                        r.SsdeepClusterId >= 0 ? r.SsdeepClusterId.ToString() : "",
                        r.SsdeepClusterSize > 0 ? r.SsdeepClusterSize.ToString() : "",
                        r.SsdeepHasHighSimilarity.ToString(),
                        r.SsdeepPreviouslySeen.ToString(),
                        r.PackerDetected, r.Compiler, r.Imphash, r.RichHash,
                        r.ImphashClusterId >= 0 ? r.ImphashClusterId.ToString() : "",
                        r.ImphashClusterSize > 0 ? r.ImphashClusterSize.ToString() : "",
                        r.SignatureStatus, r.SignerName,
                        r.IocCount > 0 ? r.IocCount.ToString() : "",
                        r.ExtractedIOCs, r.ReputationStatus, r.ReputationSource,
                        r.Disposition);
                }
            }
        }

        private static readonly char[] NeedsQuoting = { ',', '"', '\r', '\n' };

        private static void WriteRow(StreamWriter writer, params string[] fields)
        {
            for (int i = 0; i < fields.Length; i++)
            {
                if (i > 0) writer.Write(',');
                WriteField(writer, fields[i]);
            }
            writer.Write("\r\n");
        }

        private static void WriteField(StreamWriter writer, string field)
        {
            if (string.IsNullOrEmpty(field)) return;

            if (field.IndexOfAny(NeedsQuoting) < 0)
            {
                writer.Write(field);
            }
            else
            {
                writer.Write('"');
                writer.Write(field.Replace("\"", "\"\""));
                writer.Write('"');
            }
        }
    }

    // Parses `yara -m` output ("RuleName [key1=\"val1\",key2=42] /path") into a
    // rule name plus its meta key/value pairs. Falls back gracefully to a bare
    // rule name with no meta if a line has no bracketed section (e.g. -m wasn't
    // used, or the rule genuinely has no meta block), so this never throws on
    // plain `yara` output either.
    public static class YaraMetaParser
    {
        public class MatchInfo
        {
            public string RuleName;
            public Dictionary<string, string> Meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public static List<MatchInfo> Parse(string yaraOutput)
        {
            var results = new List<MatchInfo>();
            if (string.IsNullOrWhiteSpace(yaraOutput)) return results;

            foreach (var rawLine in yaraOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string line = rawLine.Trim();
                if (line.Length == 0) continue;

                int spaceIdx = line.IndexOf(' ');
                if (spaceIdx < 0)
                {
                    results.Add(new MatchInfo { RuleName = line });
                    continue;
                }

                var match = new MatchInfo { RuleName = line.Substring(0, spaceIdx) };
                string rest = line.Substring(spaceIdx + 1).TrimStart();

                if (rest.Length > 0 && rest[0] == '[')
                {
                    int closeIdx = FindMatchingBracket(rest);
                    if (closeIdx > 0)
                    {
                        ParseMetaBlob(rest.Substring(1, closeIdx - 1), match.Meta);
                    }
                }

                results.Add(match);
            }

            return results;
        }

        private static int FindMatchingBracket(string s)
        {
            bool inQuotes = false;
            for (int i = 1; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '"' && s[i - 1] != '\\') inQuotes = !inQuotes;
                else if (c == ']' && !inQuotes) return i;
            }
            return -1;
        }

        private static void ParseMetaBlob(string blob, Dictionary<string, string> target)
        {
            int i = 0;
            while (i < blob.Length)
            {
                while (i < blob.Length && (blob[i] == ',' || blob[i] == ' ')) i++;
                if (i >= blob.Length) break;

                int eq = blob.IndexOf('=', i);
                if (eq < 0) break;
                string key = blob.Substring(i, eq - i).Trim();
                i = eq + 1;

                string value;
                if (i < blob.Length && blob[i] == '"')
                {
                    int start = i + 1;
                    int end = start;
                    while (end < blob.Length && !(blob[end] == '"' && blob[end - 1] != '\\')) end++;
                    value = blob.Substring(start, end - start).Replace("\\\"", "\"");
                    i = end + 1;
                }
                else
                {
                    int start = i;
                    while (i < blob.Length && blob[i] != ',') i++;
                    value = blob.Substring(start, i - start).Trim();
                }

                if (key.Length > 0) target[key] = value;
            }
        }
    }

    // Resolves a matched rule's meta fields to a Low/Medium/High/Critical bucket.
    // Priority: an explicit 0-100 "score" field, bucketed on CVSS's official
    // severity bands (https://nvd.nist.gov/vuln-metrics/cvss) scaled x10 - then
    // ReversingLabs' documented 0-5 tc_detection_factor (scaled x20) - then a
    // plain severity word if present. No usable field means "Unknown", not a
    // guessed default.
    public static class SeverityScorer
    {
        public static string BucketScore(int score)
        {
            if (score >= 90) return "Critical";
            if (score >= 70) return "High";
            if (score >= 40) return "Medium";
            if (score >= 1) return "Low";
            return "Unknown";
        }

        public static Tuple<string, int> Resolve(Dictionary<string, string> meta)
        {
            string scoreStr;
            int score;
            if (meta.TryGetValue("score", out scoreStr) && int.TryParse(scoreStr, out score))
            {
                return Tuple.Create(BucketScore(score), score);
            }

            string factorStr;
            int factor;
            if (meta.TryGetValue("tc_detection_factor", out factorStr) && int.TryParse(factorStr, out factor))
            {
                int scaled = factor * 20;
                return Tuple.Create(BucketScore(scaled), scaled);
            }

            string word;
            if (meta.TryGetValue("severity", out word) || meta.TryGetValue("tc_policy_severity", out word) ||
                meta.TryGetValue("importance", out word))
            {
                string normalized = NormalizeWord(word);
                if (normalized != null) return Tuple.Create(normalized, -1);
            }

            return Tuple.Create("Unknown", -1);
        }

        private static string NormalizeWord(string w)
        {
            switch (w.Trim().ToLowerInvariant())
            {
                case "low": return "Low";
                case "medium":
                case "moderate": return "Medium";
                case "high": return "High";
                case "critical":
                case "severe": return "Critical";
                default: return null;
            }
        }
    }

    public class AttackTechniqueInfo
    {
        public string Id;
        public string Name;
        public string Tactic;
    }

    // Loads MITRE ATT&CK's public STIX/JSON bundle once per scan and resolves
    // any attack.mitre.org URL found in a rule's meta values to the technique(s)
    // it maps to. Direct technique links (/techniques/T1082) resolve immediately;
    // software/group links (/software/S0021, /groups/G0016) resolve indirectly
    // through that entity's documented "uses" relationships in the dataset,
    // since a rule's reference to a piece of malware doesn't by itself say which
    // technique matched - only that the file might be related to that malware.
    public class AttackDb
    {
        private readonly Dictionary<string, AttackTechniqueInfo> _techniquesById =
            new Dictionary<string, AttackTechniqueInfo>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _entityExternalIdToStixId =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<string>> _usesTechniques =
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        private static readonly Regex AttackUrlPattern = new Regex(
            @"attack\.mitre\.org/(techniques|software|groups)/([A-Za-z0-9\./]+)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public int TechniqueCount { get { return _techniquesById.Count; } }

        public static AttackDb Load(string jsonPath)
        {
            var db = new AttackDb();
            var stixIdToExternalId = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            using (var stream = File.OpenRead(jsonPath))
            using (var doc = JsonDocument.Parse(stream))
            {
                var objects = doc.RootElement.GetProperty("objects");

                foreach (var obj in objects.EnumerateArray())
                {
                    JsonElement typeProp;
                    if (!obj.TryGetProperty("type", out typeProp)) continue;
                    string type = typeProp.GetString();

                    if (type != "attack-pattern" && type != "malware" && type != "tool" && type != "intrusion-set")
                        continue;
                    if (IsTrue(obj, "revoked") || IsTrue(obj, "x_mitre_deprecated")) continue;

                    string stixId = obj.GetProperty("id").GetString();
                    string externalId = GetAttackExternalId(obj);
                    if (externalId == null) continue;

                    stixIdToExternalId[stixId] = externalId;

                    if (type == "attack-pattern")
                    {
                        JsonElement nameProp;
                        string name = obj.TryGetProperty("name", out nameProp) ? nameProp.GetString() : externalId;
                        db._techniquesById[externalId] = new AttackTechniqueInfo
                        {
                            Id = externalId,
                            Name = name,
                            Tactic = GetPrimaryTactic(obj)
                        };
                    }
                    else
                    {
                        db._entityExternalIdToStixId[externalId] = stixId;
                    }
                }

                foreach (var obj in objects.EnumerateArray())
                {
                    JsonElement typeProp;
                    if (!obj.TryGetProperty("type", out typeProp) || typeProp.GetString() != "relationship") continue;

                    JsonElement relTypeProp;
                    if (!obj.TryGetProperty("relationship_type", out relTypeProp) || relTypeProp.GetString() != "uses")
                        continue;
                    if (IsTrue(obj, "revoked")) continue;

                    JsonElement srcProp, tgtProp;
                    if (!obj.TryGetProperty("source_ref", out srcProp) || !obj.TryGetProperty("target_ref", out tgtProp))
                        continue;

                    string sourceRef = srcProp.GetString();
                    string targetRef = tgtProp.GetString();
                    if (sourceRef == null || targetRef == null) continue;
                    if (!targetRef.StartsWith("attack-pattern--", StringComparison.OrdinalIgnoreCase)) continue;

                    string techExternalId;
                    if (!stixIdToExternalId.TryGetValue(targetRef, out techExternalId)) continue;

                    List<string> list;
                    if (!db._usesTechniques.TryGetValue(sourceRef, out list))
                    {
                        list = new List<string>();
                        db._usesTechniques[sourceRef] = list;
                    }
                    list.Add(techExternalId);
                }
            }

            return db;
        }

        private static bool IsTrue(JsonElement obj, string propName)
        {
            JsonElement p;
            return obj.TryGetProperty(propName, out p) && p.ValueKind == JsonValueKind.True;
        }

        private static string GetAttackExternalId(JsonElement obj)
        {
            JsonElement refs;
            if (!obj.TryGetProperty("external_references", out refs)) return null;

            foreach (var r in refs.EnumerateArray())
            {
                JsonElement src, extId;
                if (r.TryGetProperty("source_name", out src) && src.GetString() == "mitre-attack" &&
                    r.TryGetProperty("external_id", out extId))
                {
                    return extId.GetString();
                }
            }
            return null;
        }

        private static string GetPrimaryTactic(JsonElement obj)
        {
            JsonElement phases;
            if (!obj.TryGetProperty("kill_chain_phases", out phases)) return null;

            var names = new List<string>();
            foreach (var p in phases.EnumerateArray())
            {
                JsonElement kcn, phaseName;
                if (p.TryGetProperty("kill_chain_name", out kcn) && kcn.GetString() == "mitre-attack" &&
                    p.TryGetProperty("phase_name", out phaseName))
                {
                    names.Add(TitleCase(phaseName.GetString()));
                }
            }
            return names.Count > 0 ? string.Join("/", names) : null;
        }

        private static string TitleCase(string kebab)
        {
            if (string.IsNullOrEmpty(kebab)) return kebab;
            var parts = kebab.Split('-');
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i].Length > 0)
                    parts[i] = char.ToUpperInvariant(parts[i][0]) + parts[i].Substring(1);
            }
            return string.Join(" ", parts);
        }

        // Returns every technique resolvable from this rule match's meta values,
        // deduplicated, capped at 10 (a prolific threat actor can use 50+
        // techniques - past that point it stops being useful on a dashboard row).
        public List<AttackTechniqueInfo> Resolve(Dictionary<string, string> meta)
        {
            var results = new List<AttackTechniqueInfo>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var value in meta.Values)
            {
                if (string.IsNullOrEmpty(value)) continue;

                foreach (Match m in AttackUrlPattern.Matches(value))
                {
                    string kind = m.Groups[1].Value.ToLowerInvariant();
                    string id = m.Groups[2].Value.Trim('/', '.', ')');

                    if (kind == "techniques")
                    {
                        string techId = id.Replace("/", ".");
                        AttackTechniqueInfo info;
                        if (_techniquesById.TryGetValue(techId, out info) && seen.Add(info.Id))
                            results.Add(info);
                    }
                    else
                    {
                        string stixId;
                        if (!_entityExternalIdToStixId.TryGetValue(id, out stixId)) continue;

                        List<string> techIds;
                        if (!_usesTechniques.TryGetValue(stixId, out techIds)) continue;

                        foreach (var techId in techIds)
                        {
                            AttackTechniqueInfo info;
                            if (_techniquesById.TryGetValue(techId, out info) && seen.Add(info.Id))
                                results.Add(info);
                        }
                    }

                    if (results.Count >= 10) return results;
                }
            }

            return results;
        }
    }

    // Shannon entropy over the whole file, computed incrementally from the same
    // buffered read loop already hashing the file - no extra I/O. 0.0 (a single
    // repeated byte value) to 8.0 (perfectly uniform byte distribution) bits per
    // byte. High entropy (roughly >= 7.5) is a common signal for packed,
    // compressed, or encrypted content - useful precisely when a file can't be
    // parsed as PE/ELF (so capa can't run) and there's otherwise no structural
    // signal left to go on.
    public static class EntropyAnalyzer
    {
        public static void AddCounts(long[] counts, byte[] buffer, int length)
        {
            for (int i = 0; i < length; i++) counts[buffer[i]]++;
        }

        public static double ComputeEntropy(long[] counts, long totalBytes)
        {
            if (totalBytes <= 0) return 0.0;
            double entropy = 0.0;
            for (int i = 0; i < counts.Length; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / totalBytes;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }
    }

    public class SsdeepMatch
    {
        public string FileA;
        public string FileB;
        public int Score;
    }

    // Parses a line of `ssdeep -c -m <knownfile> <targets...>` output ("input
    // file,known file,matching score"). Fields are quoted only when the
    // embedded value needs it, so this is a small quote-aware CSV splitter
    // rather than a blind String.Split(',') - a file path is exactly the kind
    // of field that can legitimately contain a comma.
    public static class SsdeepMatchParser
    {
        public static SsdeepMatch ParseLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return null;
            var fields = SplitCsvLine(line);
            if (fields.Count < 3) return null;

            int score;
            if (!int.TryParse(fields[fields.Count - 1].Trim(), out score)) return null;

            return new SsdeepMatch
            {
                FileA = fields[0],
                FileB = fields[1],
                Score = score
            };
        }

        private static List<string> SplitCsvLine(string line)
        {
            var result = new List<string>();
            int i = 0;
            int len = line.Length;

            while (i < len)
            {
                string field;
                if (line[i] == '"')
                {
                    int j = i + 1;
                    var sb = new StringBuilder();
                    while (j < len)
                    {
                        if (line[j] == '"')
                        {
                            if (j + 1 < len && line[j + 1] == '"') { sb.Append('"'); j += 2; continue; }
                            j++;
                            break;
                        }
                        sb.Append(line[j]);
                        j++;
                    }
                    field = sb.ToString();
                    i = j;
                    if (i < len && line[i] == ',') i++;
                }
                else
                {
                    int start = i;
                    while (i < len && line[i] != ',') i++;
                    field = line.Substring(start, i - start);
                    if (i < len && line[i] == ',') i++;
                }
                result.Add(field);
            }
            return result;
        }
    }

    public class SsdeepClusterInfo
    {
        public int ClusterId;
        public int Size;
    }

    // Union-find (disjoint set) over file paths, connected by SsdeepMatch pairs.
    // Two files end up in the same cluster if there's a *chain* of above-
    // threshold matches between them, even if they don't match each other
    // directly - standard transitive grouping ("these are all variants of one
    // family"), not just "these two specific files happen to match."
    public static class SsdeepClusterer
    {
        public static Dictionary<string, SsdeepClusterInfo> BuildClusters(List<SsdeepMatch> matches, List<string> allPaths)
        {
            var parent = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in allPaths) parent[p] = p;

            foreach (var m in matches)
            {
                if (!parent.ContainsKey(m.FileA)) parent[m.FileA] = m.FileA;
                if (!parent.ContainsKey(m.FileB)) parent[m.FileB] = m.FileB;

                string rootA = Find(parent, m.FileA);
                string rootB = Find(parent, m.FileB);
                if (!rootA.Equals(rootB, StringComparison.OrdinalIgnoreCase))
                {
                    parent[rootA] = rootB;
                }
            }

            // Compact sequential IDs per distinct root, assigned in allPaths order
            // so results are stable/reproducible across runs given the same input.
            var rootToId = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var pathToRoot = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var sizeById = new Dictionary<int, int>();
            int nextId = 0;

            foreach (var p in allPaths)
            {
                string root = Find(parent, p);
                pathToRoot[p] = root;
                int id;
                if (!rootToId.TryGetValue(root, out id))
                {
                    id = nextId++;
                    rootToId[root] = id;
                }
            }

            foreach (var p in allPaths)
            {
                int id = rootToId[pathToRoot[p]];
                int count;
                sizeById.TryGetValue(id, out count);
                sizeById[id] = count + 1;
            }

            var result = new Dictionary<string, SsdeepClusterInfo>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in allPaths)
            {
                int id = rootToId[pathToRoot[p]];
                result[p] = new SsdeepClusterInfo { ClusterId = id, Size = sizeById[id] };
            }
            return result;
        }

        // Iterative (not recursive) with path compression - avoids any risk of
        // stack depth issues on a large, tangled cluster.
        private static string Find(Dictionary<string, string> parent, string x)
        {
            if (!parent.ContainsKey(x)) { parent[x] = x; return x; }

            string root = x;
            while (!parent[root].Equals(root, StringComparison.OrdinalIgnoreCase)) root = parent[root];

            string cur = x;
            while (!cur.Equals(root, StringComparison.OrdinalIgnoreCase))
            {
                string next = parent[cur];
                parent[cur] = root;
                cur = next;
            }
            return root;
        }
    }

    public class ImphashResult
    {
        public string Imphash;
        public string RichHash;
    }

    // Computes the import-table hash (imphash) and, best-effort, a Rich header
    // hash for a PE file already read into memory. Everything here is wrapped
    // so a malformed/truncated/non-PE input just yields a null result rather
    // than throwing - callers treat "no imphash" the same as "not a PE" or
    // "capa can't run on this", i.e. a normal, expected outcome, not an error.
    //
    // Imphash follows the widely-used algorithm (originally documented by
    // Mandiant): walk the import directory, build an ordered
    // "dllnamewithoutextension.functionname" list (lowercased; ordinal-only
    // imports become "ordNNNN"), join with commas, MD5 the resulting ASCII
    // string. Two files sharing an imphash linked the exact same APIs in the
    // exact same order - a signal that survives a repack/recompile changing
    // enough bytes to break ssdeep's fuzzy match.
    //
    // Rich header hash is a secondary, coarser toolchain fingerprint (MSVC-
    // built PEs only) - present only when the linker didn't strip it. Treated
    // as strictly best-effort here: if the "Rich"/"DanS" markers aren't found
    // exactly where expected, RichHash is left null rather than guessed at.
    public static class PeImportHasher
    {
        public static ImphashResult Compute(byte[] bytes)
        {
            var result = new ImphashResult();
            try { result.Imphash = ComputeImphash(bytes); } catch { result.Imphash = null; }
            try { result.RichHash = ComputeRichHash(bytes); } catch { result.RichHash = null; }
            if (result.Imphash == null && result.RichHash == null) return null;
            return result;
        }

        private static uint ReadU32(byte[] b, long off)
        {
            return (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));
        }

        private static ushort ReadU16(byte[] b, long off)
        {
            return (ushort)(b[off] | (b[off + 1] << 8));
        }

        private static string ReadAsciiZ(byte[] b, long off, int maxLen)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < maxLen; i++)
            {
                byte c = b[off + i];
                if (c == 0) break;
                sb.Append((char)c);
            }
            return sb.ToString();
        }

        private class Section { public uint VirtualAddress; public uint VirtualSize; public uint SizeOfRawData; public uint PointerToRawData; }

        private static long RvaToOffset(List<Section> sections, uint rva)
        {
            foreach (var s in sections)
            {
                uint span = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span)
                {
                    return s.PointerToRawData + (rva - s.VirtualAddress);
                }
            }
            return -1;
        }

        private static string ComputeImphash(byte[] b)
        {
            if (b.Length < 0x40) return null;
            if (b[0] != 'M' || b[1] != 'Z') return null;

            long peOffset = ReadU32(b, 0x3C);
            if (peOffset <= 0 || peOffset + 24 >= b.Length) return null;
            if (b[peOffset] != 'P' || b[peOffset + 1] != 'E' || b[peOffset + 2] != 0 || b[peOffset + 3] != 0) return null;

            long coffOffset = peOffset + 4;
            int numberOfSections = ReadU16(b, coffOffset + 2);
            int sizeOfOptionalHeader = ReadU16(b, coffOffset + 16);
            long optHeaderOffset = coffOffset + 20;
            if (optHeaderOffset + 2 >= b.Length || sizeOfOptionalHeader < 2) return null;

            ushort magic = ReadU16(b, optHeaderOffset);
            bool isPe32Plus = magic == 0x20B;
            if (magic != 0x10B && !isPe32Plus) return null; // not PE32 or PE32+ (e.g. ROM image) - unsupported

            int dataDirOffset = isPe32Plus ? 112 : 96;
            long importDirEntry = optHeaderOffset + dataDirOffset + (1 * 8); // DataDirectory[1] = Import Table
            if (importDirEntry + 8 > b.Length) return null;
            uint importRva = ReadU32(b, importDirEntry);
            if (importRva == 0) return null; // no imports (e.g. a pure resource DLL) - not an error

            long sectionTableOffset = optHeaderOffset + sizeOfOptionalHeader;
            var sections = new List<Section>();
            for (int i = 0; i < numberOfSections; i++)
            {
                long secOff = sectionTableOffset + (i * 40);
                if (secOff + 40 > b.Length) break;
                sections.Add(new Section
                {
                    VirtualSize = ReadU32(b, secOff + 8),
                    VirtualAddress = ReadU32(b, secOff + 12),
                    SizeOfRawData = ReadU32(b, secOff + 16),
                    PointerToRawData = ReadU32(b, secOff + 20)
                });
            }
            if (sections.Count == 0) return null;

            long importOffset = RvaToOffset(sections, importRva);
            if (importOffset < 0) return null;

            var parts = new List<string>();
            long descOff = importOffset;
            int guard = 0;
            while (guard++ < 1000) // sane upper bound on DLL count - never legitimately this high
            {
                if (descOff + 20 > b.Length) break;
                uint originalFirstThunk = ReadU32(b, descOff);
                uint nameRva = ReadU32(b, descOff + 12);
                uint firstThunk = ReadU32(b, descOff + 16);
                if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break; // null terminator entry

                long nameOff = RvaToOffset(sections, nameRva);
                if (nameOff < 0 || nameOff >= b.Length) { descOff += 20; continue; }
                string dllName = ReadAsciiZ(b, nameOff, 260).ToLowerInvariant();
                int dotIdx = dllName.LastIndexOf('.');
                if (dotIdx > 0) dllName = dllName.Substring(0, dotIdx);

                uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                long thunkOff = RvaToOffset(sections, thunkRva);
                if (thunkOff >= 0)
                {
                    int thunkGuard = 0;
                    long cur = thunkOff;
                    int thunkSize = isPe32Plus ? 8 : 4;
                    while (thunkGuard++ < 5000)
                    {
                        if (cur + thunkSize > b.Length) break;
                        ulong thunkVal = isPe32Plus
                            ? (ulong)ReadU32(b, cur) | ((ulong)ReadU32(b, cur + 4) << 32)
                            : ReadU32(b, cur);
                        if (thunkVal == 0) break;

                        ulong ordinalFlag = isPe32Plus ? 0x8000000000000000UL : 0x80000000UL;
                        string funcName;
                        if ((thunkVal & ordinalFlag) != 0)
                        {
                            funcName = "ord" + (thunkVal & 0xFFFF);
                        }
                        else
                        {
                            uint hintNameRva = (uint)(thunkVal & 0x7FFFFFFF);
                            long hintNameOff = RvaToOffset(sections, hintNameRva);
                            if (hintNameOff < 0 || hintNameOff + 2 >= b.Length) { cur += thunkSize; continue; }
                            funcName = ReadAsciiZ(b, hintNameOff + 2, 260).ToLowerInvariant();
                        }
                        parts.Add(dllName + "." + funcName);
                        cur += thunkSize;
                    }
                }
                descOff += 20;
            }

            if (parts.Count == 0) return null;
            string joined = string.Join(",", parts);
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.ASCII.GetBytes(joined));
                var sb = new StringBuilder(32);
                foreach (byte bb in hash) sb.Append(bb.ToString("x2"));
                return sb.ToString();
            }
        }

        // Best-effort: find "Rich", read the XOR key right after it, search
        // backward for the XOR-obfuscated "DanS" start marker, MD5 the decoded
        // bytes in between. Returns null on anything unexpected rather than
        // guessing - this is a secondary signal, not load-bearing like imphash.
        private static string ComputeRichHash(byte[] b)
        {
            if (b.Length < 0x80) return null;
            long peOffset = ReadU32(b, 0x3C);
            if (peOffset <= 0x40 || peOffset >= b.Length) return null;

            long richPos = -1;
            for (long i = 0x40; i + 4 <= peOffset; i++)
            {
                if (b[i] == 'R' && b[i + 1] == 'i' && b[i + 2] == 'c' && b[i + 3] == 'h') { richPos = i; break; }
            }
            if (richPos < 0 || richPos + 8 > b.Length) return null;

            uint key = ReadU32(b, richPos + 4);
            byte[] danS = { (byte)(0x44 ^ (key & 0xFF)), 0, 0, 0 }; // just first byte check, full check below

            long dansPos = -1;
            for (long i = richPos - 4; i >= 0x40; i -= 4)
            {
                uint candidate = ReadU32(b, i) ^ key;
                if (candidate == 0x536E6144) { dansPos = i; break; } // "DanS" little-endian as uint
            }
            if (dansPos < 0) return null;

            long start = dansPos + 16; // DanS (4) + 3 zero-padding DWORDs (12) precede the real @comp.id entries
            long end = richPos;
            if (start >= end) return null;

            var decoded = new byte[end - start];
            for (long i = start; i < end; i += 4)
            {
                uint val = ReadU32(b, i) ^ key;
                decoded[i - start] = (byte)val;
                if (i - start + 1 < decoded.Length) decoded[i - start + 1] = (byte)(val >> 8);
                if (i - start + 2 < decoded.Length) decoded[i - start + 2] = (byte)(val >> 16);
                if (i - start + 3 < decoded.Length) decoded[i - start + 3] = (byte)(val >> 24);
            }

            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(decoded);
                var sb = new StringBuilder(32);
                foreach (byte bb in hash) sb.Append(bb.ToString("x2"));
                return sb.ToString();
            }
        }
    }

    public class ImphashClusterInfo
    {
        public int ClusterId;
        public int Size;
    }

    // Much simpler than SsdeepClusterer - imphash is an exact string match, not
    // a fuzzy score, so this is a plain group-by rather than union-find. Only
    // groups of 2+ get a real cluster; files with a unique or missing imphash
    // get ClusterId -1.
    public static class ImphashClusterer
    {
        public static Dictionary<string, ImphashClusterInfo> BuildClusters(Dictionary<string, string> pathToImphash)
        {
            var groups = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in pathToImphash)
            {
                if (string.IsNullOrEmpty(kvp.Value)) continue;
                List<string> members;
                if (!groups.TryGetValue(kvp.Value, out members))
                {
                    members = new List<string>();
                    groups[kvp.Value] = members;
                }
                members.Add(kvp.Key);
            }

            var result = new Dictionary<string, ImphashClusterInfo>(StringComparer.OrdinalIgnoreCase);
            int nextId = 0;
            foreach (var kvp in groups)
            {
                if (kvp.Value.Count < 2) continue; // singleton imphash - not a cluster worth surfacing
                int id = nextId++;
                foreach (var path in kvp.Value)
                {
                    result[path] = new ImphashClusterInfo { ClusterId = id, Size = kvp.Value.Count };
                }
            }
            return result;
        }
    }
}
'@
        }

        # Icon.FromHandle(bitmap.GetHicon()) below creates a native HICON that
        # Icon.Dispose() does NOT release (per .NET docs, the caller owns handles
        # it passed into FromHandle) - without this, the window icon's HICON would
        # leak once per app launch. Guarded the same way as the block above so
        # re-running this script in an already-loaded pwsh session doesn't fail
        # with "type already exists".
        if (-not ('BinSifter.NativeIcon' -as [type])) {
        Add-Type -Namespace BinSifter -Name NativeIcon -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool DestroyIcon(System.IntPtr hIcon);
'@
        }

        # ================= Theme =================
        function Get-ThemePalette {
            param([bool]$IsDarkMode)

            if ($IsDarkMode) {
                return @{
                    WindowBack  = [System.Drawing.Color]::FromArgb(11, 19, 25)
                    SidebarBack = [System.Drawing.Color]::FromArgb(18, 30, 40)
                    SurfaceBack = [System.Drawing.Color]::FromArgb(14, 25, 32)
                    HeaderBack  = [System.Drawing.Color]::FromArgb(9, 16, 22)
                    Border      = [System.Drawing.Color]::FromArgb(49, 68, 80)
                    Fore        = [System.Drawing.Color]::FromArgb(228, 235, 240)
                    MutedFore   = [System.Drawing.Color]::FromArgb(164, 177, 187)
                    Accent      = [System.Drawing.Color]::FromArgb(31, 174, 255)
                    AccentFore  = [System.Drawing.Color]::White
                    Success     = [System.Drawing.Color]::FromArgb(83, 201, 91)
                    Warning     = [System.Drawing.Color]::FromArgb(247, 174, 28)
                    Danger      = [System.Drawing.Color]::FromArgb(242, 82, 91)
                    NavActive   = [System.Drawing.Color]::FromArgb(30, 52, 70)
                    ButtonBack  = [System.Drawing.Color]::FromArgb(25, 39, 49)
                }
            }

            return @{
                WindowBack  = [System.Drawing.Color]::FromArgb(244, 245, 247)
                SidebarBack = [System.Drawing.Color]::White
                SurfaceBack = [System.Drawing.Color]::White
                HeaderBack  = [System.Drawing.Color]::White
                Border      = [System.Drawing.Color]::FromArgb(220, 222, 226)
                Fore        = [System.Drawing.Color]::FromArgb(30, 32, 36)
                MutedFore   = [System.Drawing.Color]::FromArgb(110, 116, 124)
                Accent      = [System.Drawing.Color]::FromArgb(0, 120, 212)
                AccentFore  = [System.Drawing.Color]::White
                Success     = [System.Drawing.Color]::FromArgb(30, 160, 90)
                Warning     = [System.Drawing.Color]::FromArgb(210, 140, 20)
                Danger      = [System.Drawing.Color]::FromArgb(200, 60, 60)
                NavActive   = [System.Drawing.Color]::FromArgb(224, 238, 252)
                ButtonBack  = [System.Drawing.Color]::FromArgb(238, 239, 242)
            }
        }

        $theme = Get-ThemePalette -IsDarkMode $IsDarkMode

        # Consistent outline icon set modeled after the approved dashboard mockup.
        # Icons are drawn at runtime, so the application stays self-contained and
        # scales cleanly without relying on font-specific glyph alignment.
        function New-LineIconBitmap {
            param(
                [ValidateSet('gauge','list','chart','document','layers','database','file','target','check','cluster','users','user','percent','trend','history')]
                [string]$Name,
                [System.Drawing.Color]$Color
            )

            $bitmap = [System.Drawing.Bitmap]::new(64, 64, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            $pen = New-Object System.Drawing.Pen($Color, 4)
            $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
            $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
            $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
            try {
                $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
                switch ($Name) {
                    'gauge' {
                        $graphics.DrawArc($pen, 9, 11, 46, 46, 180, 180)
                        $graphics.DrawLine($pen, 12, 42, 52, 42)
                        $graphics.DrawLine($pen, 32, 36, 44, 22)
                        $graphics.DrawEllipse($pen, 29, 33, 6, 6)
                        $graphics.DrawLine($pen, 16, 35, 19, 31)
                        $graphics.DrawLine($pen, 24, 25, 26, 22)
                        $graphics.DrawLine($pen, 40, 25, 38, 22)
                    }
                    'list' {
                        foreach ($y in @(16, 32, 48)) {
                            $graphics.DrawEllipse($pen, 9, ($y - 3), 6, 6)
                            $graphics.DrawLine($pen, 23, $y, 54, $y)
                        }
                    }
                    'chart' {
                        $graphics.DrawLine($pen, 10, 53, 55, 53)
                        $graphics.DrawRectangle($pen, 14, 34, 8, 19)
                        $graphics.DrawRectangle($pen, 29, 22, 8, 31)
                        $graphics.DrawRectangle($pen, 44, 10, 8, 43)
                    }
                    { $_ -in @('document','file') } {
                        $graphics.DrawRectangle($pen, 15, 8, 34, 48)
                        $graphics.DrawLines($pen, [System.Drawing.Point[]]@(
                            (New-Object System.Drawing.Point(38, 8)),
                            (New-Object System.Drawing.Point(49, 19)),
                            (New-Object System.Drawing.Point(38, 19)),
                            (New-Object System.Drawing.Point(38, 8))
                        ))
                        $graphics.DrawLine($pen, 23, 31, 41, 31)
                        $graphics.DrawLine($pen, 23, 40, 41, 40)
                        $graphics.DrawLine($pen, 23, 49, 35, 49)
                    }
                    'layers' {
                        foreach ($offset in @(0, 11, 22)) {
                            $graphics.DrawPolygon($pen, [System.Drawing.Point[]]@(
                                (New-Object System.Drawing.Point(32, (10 + $offset))),
                                (New-Object System.Drawing.Point(52, (21 + $offset))),
                                (New-Object System.Drawing.Point(32, (32 + $offset))),
                                (New-Object System.Drawing.Point(12, (21 + $offset)))
                            ))
                        }
                    }
                    'database' {
                        $graphics.DrawEllipse($pen, 13, 9, 38, 16)
                        $graphics.DrawArc($pen, 13, 21, 38, 16, 0, 180)
                        $graphics.DrawArc($pen, 13, 36, 38, 16, 0, 180)
                        $graphics.DrawLine($pen, 13, 17, 13, 45)
                        $graphics.DrawLine($pen, 51, 17, 51, 45)
                        $graphics.DrawArc($pen, 13, 37, 38, 16, 0, 180)
                    }
                    'target' {
                        $graphics.DrawEllipse($pen, 10, 10, 44, 44)
                        $graphics.DrawEllipse($pen, 22, 22, 20, 20)
                        $graphics.DrawLine($pen, 32, 5, 32, 18)
                        $graphics.DrawLine($pen, 32, 46, 32, 59)
                        $graphics.DrawLine($pen, 5, 32, 18, 32)
                        $graphics.DrawLine($pen, 46, 32, 59, 32)
                    }
                    'check' {
                        $graphics.DrawEllipse($pen, 9, 9, 46, 46)
                        $graphics.DrawLines($pen, [System.Drawing.Point[]]@(
                            (New-Object System.Drawing.Point(19, 32)),
                            (New-Object System.Drawing.Point(28, 41)),
                            (New-Object System.Drawing.Point(46, 21))
                        ))
                    }
                    'cluster' {
                        $nodes = @(
                            @(32, 12), @(14, 28), @(50, 28), @(19, 49), @(45, 49), @(32, 32)
                        )
                        foreach ($pair in @(@(0,5),@(1,5),@(2,5),@(3,5),@(4,5))) {
                            $a = $nodes[$pair[0]]; $b = $nodes[$pair[1]]
                            $graphics.DrawLine($pen, $a[0], $a[1], $b[0], $b[1])
                        }
                        foreach ($node in $nodes) { $graphics.DrawEllipse($pen, ($node[0]-4), ($node[1]-4), 8, 8) }
                    }
                    'users' {
                        $graphics.DrawEllipse($pen, 24, 10, 16, 16)
                        $graphics.DrawEllipse($pen, 8, 18, 12, 12)
                        $graphics.DrawEllipse($pen, 44, 18, 12, 12)
                        $graphics.DrawArc($pen, 17, 28, 30, 26, 180, 180)
                        $graphics.DrawArc($pen, 3, 34, 20, 18, 180, 180)
                        $graphics.DrawArc($pen, 41, 34, 20, 18, 180, 180)
                    }
                    'user' {
                        $graphics.DrawEllipse($pen, 22, 10, 20, 20)
                        $graphics.DrawArc($pen, 12, 31, 40, 28, 180, 180)
                    }
                    'percent' {
                        $graphics.DrawEllipse($pen, 8, 8, 48, 48)
                        $graphics.DrawEllipse($pen, 19, 18, 7, 7)
                        $graphics.DrawEllipse($pen, 38, 39, 7, 7)
                        $graphics.DrawLine($pen, 21, 45, 44, 18)
                    }
                    'trend' {
                        $graphics.DrawLines($pen, [System.Drawing.Point[]]@(
                            (New-Object System.Drawing.Point(8, 48)),
                            (New-Object System.Drawing.Point(22, 32)),
                            (New-Object System.Drawing.Point(33, 41)),
                            (New-Object System.Drawing.Point(53, 17))
                        ))
                        $graphics.DrawLine($pen, 42, 17, 53, 17)
                        $graphics.DrawLine($pen, 53, 17, 53, 28)
                    }
                    'history' {
                        $graphics.DrawArc($pen, 10, 10, 44, 44, 45, 300)
                        $graphics.DrawLines($pen, [System.Drawing.Point[]]@(
                            (New-Object System.Drawing.Point(10, 13)),
                            (New-Object System.Drawing.Point(10, 25)),
                            (New-Object System.Drawing.Point(21, 22))
                        ))
                        $graphics.DrawLine($pen, 32, 21, 32, 34)
                        $graphics.DrawLine($pen, 32, 34, 42, 39)
                    }
                }
            }
            finally {
                $pen.Dispose()
                $graphics.Dispose()
            }
            return $bitmap
        }

        function New-ThemedButton {
            param([string]$Text, [int]$Width = 130, [int]$Height = 38, [switch]$Primary)

            $b = New-Object System.Windows.Forms.Button
            $b.Text = $Text
            $b.Size = New-Object System.Drawing.Size($Width, $Height)
            $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            if ($Primary) {
                $b.BackColor = $theme.Accent
                $b.ForeColor = $theme.AccentFore
                $b.FlatAppearance.BorderColor = $theme.Accent
            }
            else {
                $b.BackColor = $theme.ButtonBack
                $b.ForeColor = $theme.Fore
                $b.FlatAppearance.BorderColor = $theme.Border
            }
            return $b
        }

        # Blends two theme colors for the dashboard heat map's value-color scaling
        # - Success -> Warning -> Danger as magnitude increases, reusing the
        # theme's own palette instead of introducing new hardcoded colors. Defined
        # at this top level (not nested inside New-DashboardPage) so the refresh
        # timer, which lives outside that function, can call it by name too.
        function Merge-Color {
            param([System.Drawing.Color]$ColorA, [System.Drawing.Color]$ColorB, [double]$T)
            $t = [Math]::Max(0.0, [Math]::Min(1.0, $T))
            $r = [int]($ColorA.R + ($ColorB.R - $ColorA.R) * $t)
            $g = [int]($ColorA.G + ($ColorB.G - $ColorA.G) * $t)
            $b = [int]($ColorA.B + ($ColorB.B - $ColorA.B) * $t)
            return [System.Drawing.Color]::FromArgb($r, $g, $b)
        }
        function Get-HeatColor {
            param([double]$Intensity)
            $i = [Math]::Max(0.0, [Math]::Min(1.0, $Intensity))
            if ($i -le 0.5) { return Merge-Color $theme.Success $theme.Warning ($i / 0.5) }
            return Merge-Color $theme.Warning $theme.Danger (($i - 0.5) / 0.5)
        }

        function Import-ThemedLogo {
            param([string]$Path, [int]$Width)

            if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                return $null
            }

            $raw = [System.Drawing.Image]::FromFile($Path)
            $bmp = New-Object System.Drawing.Bitmap($raw)
            $raw.Dispose()

            $height = [int]([double]$bmp.Height / $bmp.Width * $Width)
            $box = New-Object System.Windows.Forms.PictureBox
            $box.Image = $bmp
            $box.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
            $box.Width = $Width
            $box.Height = $height
            return $box
        }

        # v1.3.0-alpha.2: on-demand "deep analysis" launcher helpers for the
        # Results-grid context menu (Sigcheck / Ghidra / x64dbg / x32dbg /
        # Speakeasy - ported selectively from proto2). Unlike the scan-pool's
        # own Invoke-ExternalTool (defined inside the worker/dispatcher
        # scriptblocks and not reachable from the UI thread), this copy runs
        # on the UI thread itself for single-file, analyst-initiated actions.
        # Kept deliberately synchronous (same tradeoff proto2 made) rather than
        # adding a second async/timer-poll pattern alongside the scan engine's -
        # bounded by TimeoutSeconds and paired with a wait cursor so it reads as
        # "busy," not "hung." Only Sigcheck and Speakeasy call this; Ghidra and
        # x64dbg/x32dbg are fire-and-forget launches with no output to capture.
        function Invoke-CapturedTool {
            param(
                [string]$Path,
                [string[]]$Arguments,
                [int]$TimeoutSeconds = 30
            )

            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName = $Path
            foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true

            $proc = [System.Diagnostics.Process]::new()
            $proc.StartInfo = $psi

            try {
                $null = $proc.Start()
                $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
                $stderrTask = $proc.StandardError.ReadToEndAsync()

                $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
                if (-not $exited) {
                    try { $proc.Kill($true) } catch { }
                    try { $null = $proc.WaitForExit(5000) } catch { }

                    $stdoutText = ''
                    $stderrText = ''
                    if ($stdoutTask.IsCompleted) { try { $stdoutText = $stdoutTask.GetAwaiter().GetResult() } catch { } }
                    if ($stderrTask.IsCompleted) { try { $stderrText = $stderrTask.GetAwaiter().GetResult() } catch { } }

                    $timeoutMessage = "Process timed out after $TimeoutSeconds seconds and was terminated."
                    if ($stderrText) { $timeoutMessage = "$timeoutMessage`r`n$stderrText" }
                    return [pscustomobject]@{
                        ExitCode = -1
                        TimedOut = $true
                        StdOut   = $stdoutText
                        StdErr   = $timeoutMessage
                    }
                }

                [pscustomobject]@{
                    ExitCode = $proc.ExitCode
                    TimedOut = $false
                    StdOut   = $stdoutTask.GetAwaiter().GetResult()
                    StdErr   = $stderrTask.GetAwaiter().GetResult()
                }
            }
            finally {
                $proc.Dispose()
            }
        }

        # Generic read-only report viewer for captured tool output (Sigcheck,
        # Speakeasy). Modal by design - these are quick "look at the answer,
        # close it" popups, not a panel meant to stay open alongside scanning.
        function Show-ToolReportWindow {
            param(
                [string]$Title,
                [string]$Content
            )

            $reportForm = New-Object System.Windows.Forms.Form
            $reportForm.Text = $Title
            $reportForm.Width = 860
            $reportForm.Height = 620
            $reportForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
            $reportForm.BackColor = $theme.WindowBack

            $txt = New-Object System.Windows.Forms.TextBox
            $txt.Multiline = $true
            $txt.ReadOnly = $true
            $txt.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
            $txt.WordWrap = $false
            $txt.Dock = [System.Windows.Forms.DockStyle]::Fill
            $txt.Font = New-Object System.Drawing.Font('Consolas', 9)
            $txt.BackColor = $theme.SurfaceBack
            $txt.ForeColor = $theme.Fore
            $txt.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
            $txt.Text = $Content

            $reportForm.Controls.Add($txt)
            $null = $reportForm.ShowDialog()
            $reportForm.Dispose()
        }

        # ================= Shared state =================
        # v1.3.0-alpha.2 settings consolidation: Settings asks for 6 things
        # (SrcDir, NsrlPath, YaraRules, CapaRules, ToolsDir, GhidraDir).
        # Everything else that used to be its own text field is now either
        # found by recursively searching ToolsDir/GhidraDir for a fixed
        # filename, or defaulted to a subfolder next to BinSifter's own
        # script file - created on first launch if missing. Every derived/
        # defaulted path stays exactly as blank-tolerant/graceful-skip as it
        # was before: a missing tool or a missing Attack/Blocklist file just
        # quietly disables that one feature, same as always - it's just no
        # longer something the analyst has to type in every time.
        $BinSifterRoot = if ($PSScriptRoot) { $PSScriptRoot }
            elseif ($PSCommandPath) { Split-Path -Parent $PSCommandPath }
            elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
            else { $null }
        if ([string]::IsNullOrWhiteSpace($BinSifterRoot)) {
            # $PSScriptRoot/$PSCommandPath/$MyInvocation.MyCommand.Path can all
            # come back empty depending on how the script is launched - notably,
            # some VS Code "Run and Debug" configurations for the PowerShell
            # extension don't populate these the same way a plain `pwsh -File`
            # invocation does. Everything below - default Reports/Attack/
            # Blocklist folders, the Settings cache file - is anchored to
            # $BinSifterRoot, so rather than hard-blocking startup, fall back to
            # the current working directory and tell the analyst where things
            # landed, so a debug-launched session still works instead of
            # silently surprising them later (this is what used to surface as
            # "Report directory is not writable: Cannot bind argument to 'Path'
            # because it is null" the first time Settings Save tried to
            # Join-Path against a null root).
            $BinSifterRoot = (Get-Location).Path
            $null = [System.Windows.Forms.MessageBox]::Show(
                "BinSifter couldn't determine its own script folder (this can happen when launching via VS Code's Run and Debug), so its default Reports/Attack/Blocklist folders and Settings cache will be created under the current folder instead:" + "`r`n`r`n" +
                $BinSifterRoot + "`r`n`r`n" +
                "To anchor these to the script's own folder instead, run the .ps1 file directly (double-click, right-click > Run with PowerShell, or `"pwsh -File path\to\script.ps1`").",
                'BinSifter', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        }

        # Maps each tool's Config key to the fixed filename BinSifter looks
        # for somewhere under ToolsDir. Single source of truth - both the
        # initial $Config build (via $form.Add_Shown, see bootstrap) and the
        # Settings Save handler call Set-ToolPathsFromDirectory against this
        # same table, so they can't drift out of sync. Ghidra's
        # analyzeHeadless.bat is deliberately NOT in this table - it's found
        # the same way (Find-ToolPath) but under its own separate directory
        # field, GhidraDir, rather than being mixed into the general tools
        # search - a Ghidra install can be large, and keeping it separate
        # means pointing BinSifter at the real, unmodified Ghidra install
        # root is enough; nothing needs to be copied or relocated for
        # analyzeHeadless.bat to still resolve the rest of its own install
        # correctly.
        $ToolFileNames = [ordered]@{
            YaraExe           = 'yara64.exe'
            CapaExe           = 'capa.exe'
            SsdeepExe         = 'ssdeep.exe'
            FlossExe          = 'floss.exe'
            DieExe            = 'die.exe'
            DieConsoleExe     = 'diec.exe'
            PEStudioExe       = 'pestudio.exe'
            CffExplorerExe    = 'CFF Explorer.exe'
            ResourceHackerExe = 'ResourceHacker.exe'
            SigcheckExe       = 'sigcheck.exe'
            X64dbgExe         = 'x64dbg.exe'
            X32dbgExe         = 'x32dbg.exe'
            SpeakeasyExe      = 'speakeasy.exe'
        }

        # FRED-style tool directories are routinely hierarchical (each tool
        # in its own subfolder), not flat - so this walks the whole tree
        # rather than assuming ToolsDir\<filename> directly. If more than one
        # copy of a filename turns up (e.g. a backup or an old version left
        # in a subfolder), the first match in sorted-path order wins and the
        # ambiguity is logged so it isn't a silent surprise. Can be slow on a
        # very large/network-mounted tree - callers are expected to show a
        # wait cursor around it (see Settings Save and $form.Add_Shown).
        function Find-ToolPath {
            param([string]$Directory, [string]$FileName)
            if (-not $Directory -or -not (Test-Path -LiteralPath $Directory -PathType Container)) { return '' }
            $found = $null
            try {
                $found = @(Get-ChildItem -LiteralPath $Directory -Filter $FileName -Recurse -File -ErrorAction SilentlyContinue)
            }
            catch { return '' }
            if (-not $found -or $found.Count -eq 0) { return '' }
            $sorted = @($found | Sort-Object -Property FullName)
            if ($sorted.Count -gt 1) {
                try { Add-Log "Found $($sorted.Count) copies of $FileName under $Directory - using $($sorted[0].FullName)" } catch { }
            }
            return $sorted[0].FullName
        }

        function Set-ToolPathsFromDirectory {
            param($Config, [string]$Directory)
            foreach ($key in $ToolFileNames.Keys) {
                $Config[$key] = Find-ToolPath -Directory $Directory -FileName $ToolFileNames[$key]
            }
        }

        $reportsDefaultDir = Join-Path $BinSifterRoot 'Reports'
        $attackDefaultPath = Join-Path $BinSifterRoot 'Attack\enterprise-attack.json'
        $blocklistDefaultPath = Join-Path $BinSifterRoot 'Blocklist\blocklist.csv'
        foreach ($defaultDir in @(
            $reportsDefaultDir,
            (Split-Path -Parent $attackDefaultPath),
            (Split-Path -Parent $blocklistDefaultPath)
        )) {
            if (-not (Test-Path -LiteralPath $defaultDir -PathType Container)) {
                try { $null = New-Item -Path $defaultDir -ItemType Directory -Force } catch { }
            }
        }

        # Settings-field caching: the 6 fields the analyst actually types in
        # tend to stay the same from one assessment to the next on a given
        # workstation, so a successful Settings Save writes them here, and
        # they're read back in as the starting values below. Purely a
        # convenience default - Save still re-validates everything, so a
        # stale cached path (e.g. a removable drive that isn't attached this
        # session) just shows up as invalid, same as if the analyst had typed
        # it wrong. Delete this file to reset to blank fields.
        $SettingsCachePath = Join-Path $BinSifterRoot '.bsifter-settings-cache.json'
        $cachedSettings = @{}
        if (Test-Path -LiteralPath $SettingsCachePath -PathType Leaf) {
            try {
                $rawCache = Get-Content -LiteralPath $SettingsCachePath -Raw -ErrorAction Stop
                $parsedCache = $rawCache | ConvertFrom-Json -ErrorAction Stop
                foreach ($prop in $parsedCache.PSObject.Properties) { $cachedSettings[$prop.Name] = [string]$prop.Value }
            }
            catch { $cachedSettings = @{} }
        }
        function Get-CachedSetting {
            param([string]$Key)
            if ($cachedSettings.ContainsKey($Key)) { return $cachedSettings[$Key] }
            return ''
        }

        $Config = @{
            SrcDir = Get-CachedSetting 'SrcDir'; NsrlPath = Get-CachedSetting 'NsrlPath'
            YaraRules = Get-CachedSetting 'YaraRules'; CapaRules = Get-CachedSetting 'CapaRules'
            ToolsDir = Get-CachedSetting 'ToolsDir'
            GhidraDir = Get-CachedSetting 'GhidraDir'
            # GhidraHeadlessExe is derived from GhidraDir (Find-ToolPath),
            # same as the $ToolFileNames-derived keys below - never cached or
            # set directly, always left blank here until resolved.
            GhidraHeadlessExe = ''
            YaraExe = ''; CapaExe = ''; SsdeepExe = ''; FlossExe = ''
            DieConsoleExe = ''; PEStudioExe = ''; DieExe = ''; CffExplorerExe = ''
            ResourceHackerExe = ''; SigcheckExe = ''
            X64dbgExe = ''; X32dbgExe = ''; SpeakeasyExe = ''
            # v1.3.0-alpha.2: no longer user-editable in Settings - defaulted
            # to a subfolder next to BinSifter itself (created above if
            # missing). Drop enterprise-attack.json / a blocklist CSV into the
            # Attack / Blocklist subfolders to enable those two features.
            ReportDirectory = $reportsDefaultDir
            AttackDataPath = $attackDefaultPath
            BlocklistPath = $blocklistDefaultPath
        }
        # ToolsDir's derived exe paths (YaraExe/CapaExe/etc.) and GhidraDir's
        # derived GhidraHeadlessExe are deliberately left blank here rather
        # than resolved immediately - a cached ToolsDir/GhidraDir could be a
        # large/hierarchical FRED tool tree, and Find-ToolPath's recursive
        # search shouldn't block the window from appearing at all. Resolved
        # once, right after the window is first shown - see $form.Add_Shown
        # in the bootstrap section at the bottom of this file.

        $FileRecords = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
        $UiDirtyQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        $UiSnapshots = @{}
        $UiTotals = @{
            Completed = 0; YaraHits = 0; CapaHits = 0; CapaScans = 0; NsrlMatches = 0
            Critical = 0; High = 0; Medium = 0; Low = 0; Unknown = 0
            # v1.3-proto1 enrichment-summary tile totals - tracked the same
            # incremental way as everything above (see the dirty-queue diff loop
            # in the refresh timer).
            ImphashClustered = 0; Unsigned = 0; KnownBad = 0; WithIocs = 0; Escalated = 0
        }

        $ScanControl = [hashtable]::Synchronized(@{
            IsRunning        = $false
            IsPaused         = $false
            StopRequested    = $false
            Completed        = $false
            TotalFiles       = 0
            FilesDiscovered  = $false
            OrderedPaths     = $null
            NsrlHashCount    = 0
            NsrlPreviewBusy  = $false
            Timer            = $null
            ReportPath       = $null
            ProcessRegistry  = $null
            NsrlPreviewHandle = $null
            # Set once by the dispatcher after the post-scan SSDEEP clustering pass
            # completes (see Start-ScanEngine) - a pscustomobject with NumClusters,
            # LargestClusterSize, LargestClusterId, Singletons, AvgScore,
            # FilesAbove85, PreviouslySeenClusters, TotalHashedFiles. $null until
            # the first scan's clustering pass finishes. The refresh timer just
            # displays this rather than recomputing cluster stats every tick.
            SsdeepMetrics    = $null
        })

        $LogQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        function Add-Log {
            param([string]$Message)
            $LogQueue.Enqueue("[$(Get-Date -Format 'HH:mm:ss')] $Message")
        }

        $EngineState = @{ Handle = $null }

        $ToolMetadata = [hashtable]::Synchronized(@{
            Yara = 'not configured'; Capa = 'not configured'
            Ssdeep = 'not configured'; NsrlDate = 'not configured'
        })
        $MetadataState = [hashtable]::Synchronized(@{ Handle = $null; Busy = $false })

        function Start-ToolMetadataRefresh {
            if ($MetadataState.Busy) { return }
            $oldHandle = $MetadataState.Handle
            if ($oldHandle -and -not $oldHandle.Disposed) {
                if (-not $oldHandle.Handle.IsCompleted) { return }
                try { $null = $oldHandle.PS.EndInvoke($oldHandle.Handle) } catch { }
                $oldHandle.PS.Dispose()
                $oldHandle.Runspace.Close()
                $oldHandle.Runspace.Dispose()
                $oldHandle.Disposed = $true
            }

            $MetadataState.Busy = $true
            $metadataRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $metadataRunspace.Open()
            $metadataPs = [System.Management.Automation.PowerShell]::Create()
            $metadataPs.Runspace = $metadataRunspace
            $null = $metadataPs.AddScript({
                param($YaraPath, $CapaPath, $SsdeepPath, $NsrlPath, $Metadata, $State)

                function Get-VersionText {
                    param([string]$Path, [string[]]$Arguments)
                    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'not configured' }
                    $proc = $null
                    try {
                        $psi = [System.Diagnostics.ProcessStartInfo]::new()
                        $psi.FileName = $Path
                        foreach ($arg in $Arguments) { $psi.ArgumentList.Add($arg) }
                        $psi.RedirectStandardOutput = $true
                        $psi.RedirectStandardError = $true
                        $psi.UseShellExecute = $false
                        $psi.CreateNoWindow = $true
                        $proc = [System.Diagnostics.Process]::new()
                        $proc.StartInfo = $psi
                        $null = $proc.Start()
                        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
                        $stderrTask = $proc.StandardError.ReadToEndAsync()
                        if (-not $proc.WaitForExit(3000)) {
                            try { $proc.Kill($true) } catch { }
                            try { $null = $proc.WaitForExit(2000) } catch { }
                            return 'version unavailable'
                        }
                        $stdout = if ($stdoutTask.IsCompleted) { $stdoutTask.GetAwaiter().GetResult() } else { '' }
                        $stderr = if ($stderrTask.IsCompleted) { $stderrTask.GetAwaiter().GetResult() } else { '' }
                        $text = "$stdout $stderr".Trim()
                        if (-not $text) { return 'version unavailable' }
                        return (($text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim())
                    }
                    catch { return 'version unavailable' }
                    finally { if ($proc) { $proc.Dispose() } }
                }

                try {
                    $Metadata.Yara = Get-VersionText -Path $YaraPath -Arguments @('--version')
                    $Metadata.Capa = Get-VersionText -Path $CapaPath -Arguments @('--version')
                    $Metadata.Ssdeep = Get-VersionText -Path $SsdeepPath -Arguments @('-V')
                    $Metadata.NsrlDate = if ($NsrlPath -and (Test-Path -LiteralPath $NsrlPath -PathType Leaf)) {
                        (Get-Item -LiteralPath $NsrlPath).LastWriteTime.ToString('yyyy-MM-dd')
                    } else { 'not configured' }
                }
                finally { $State.Busy = $false }
            })
            foreach ($argument in @(
                $Config.YaraExe, $Config.CapaExe, $Config.SsdeepExe, $Config.NsrlPath,
                $ToolMetadata, $MetadataState
            )) { $null = $metadataPs.AddArgument($argument) }
            $handle = $metadataPs.BeginInvoke()
            $MetadataState.Handle = [pscustomobject]@{
                PS = $metadataPs; Handle = $handle; Runspace = $metadataRunspace; Disposed = $false
            }
        }

        # Current Results-page filter, set by clicking a dashboard tile/bar/heat-map
        # cell (see Show-FilteredResults). Predicate is a scriptblock taking one
        # BinSifter.FileRecord and returning $true/$false; $null means "show every
        # row", same as before this feature existed. A hashtable (not two loose
        # variables) so functions can mutate it in place without needing $script:.
        $ResultsFilter = @{ Label = $null; Predicate = $null }

        # ================= Worker (runs per file inside the pool) =================
        $workerScriptBlock = {
            param(
                $FilePath, $FileRecords, $UiDirtyQueue, $ProcessRegistry, $KnownGoodHashes, $KnownBadHashes, $AttackDb,
                $YaraExe, $YaraRules, $CapaExe, $CapaRules, $SsdeepExe, $CapaReportsDir,
                $FlossExe, $FlossReportsDir, $DieConsoleExe, $DispositionHistory
            )

            function Publish-UiUpdate {
                if ($UiDirtyQueue) { $UiDirtyQueue.Enqueue($FilePath) }
            }

            function Get-SeverityRank {
                param([string]$Severity)
                switch ($Severity) {
                    'Critical' { 4 }
                    'High'     { 3 }
                    'Medium'   { 2 }
                    'Low'      { 1 }
                    default    { 0 }
                }
            }

            function Invoke-ExternalTool {
                param(
                    [string]$Path,
                    [string[]]$Arguments,
                    $ProcessRegistry,
                    [string]$RegistryKey,
                    [int]$TimeoutSeconds = 600
                )

                $psi = [System.Diagnostics.ProcessStartInfo]::new()
                $psi.FileName = $Path
                foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $psi.UseShellExecute = $false
                $psi.CreateNoWindow = $true

                $proc = [System.Diagnostics.Process]::new()
                $proc.StartInfo = $psi

                try {
                    $null = $proc.Start()
                    if ($ProcessRegistry -and $RegistryKey) { $ProcessRegistry[$RegistryKey] = $proc }

                    # ReadToEndAsync, not Register-ObjectEvent - the event-based approach
                    # queues its -Action onto PowerShell's own event loop rather than
                    # running synchronously, so nothing guarantees the queue has drained
                    # by the time WaitForExit returns. Confirmed by testing: the event
                    # version silently returned empty stdout/stderr for fast-exiting
                    # processes. Reading both streams as real .NET Tasks avoids both that
                    # race and the classic same-thread-ReadToEnd deadlock risk, since both
                    # streams drain concurrently regardless of which fills up first.
                    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
                    $stderrTask = $proc.StandardError.ReadToEndAsync()

                    $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
                    if (-not $exited) {
                        try { $proc.Kill($true) } catch { }
                        try { $null = $proc.WaitForExit(5000) } catch { }

                        $stdoutText = ''
                        $stderrText = ''
                        if ($stdoutTask.IsCompleted) {
                            try { $stdoutText = $stdoutTask.GetAwaiter().GetResult() } catch { }
                        }
                        if ($stderrTask.IsCompleted) {
                            try { $stderrText = $stderrTask.GetAwaiter().GetResult() } catch { }
                        }

                        $timeoutMessage = "Process timed out after $TimeoutSeconds seconds and was terminated."
                        if ($stderrText) { $timeoutMessage = "$timeoutMessage`r`n$stderrText" }
                        return [pscustomobject]@{
                            ExitCode = -1
                            TimedOut = $true
                            StdOut   = $stdoutText
                            StdErr   = $timeoutMessage
                        }
                    }

                    [pscustomobject]@{
                        ExitCode = $proc.ExitCode
                        TimedOut = $false
                        StdOut   = $stdoutTask.GetAwaiter().GetResult()
                        StdErr   = $stderrTask.GetAwaiter().GetResult()
                    }
                }
                finally {
                    if ($ProcessRegistry -and $RegistryKey) {
                        $removed = $null
                        $null = $ProcessRegistry.TryRemove($RegistryKey, [ref]$removed)
                    }
                    $proc.Dispose()
                }
            }

            $record = $FileRecords[$FilePath]
            $record.Status = 'Scanning'
            $record.Progress = 10
            Publish-UiUpdate

            try {
                $sha1Hasher = [System.Security.Cryptography.IncrementalHash]::CreateHash(
                    [System.Security.Cryptography.HashAlgorithmName]::SHA1)
                $md5Hasher = [System.Security.Cryptography.IncrementalHash]::CreateHash(
                    [System.Security.Cryptography.HashAlgorithmName]::MD5)

                # 4KB, not 512 bytes - a PE with a padded/oversized DOS stub can push
                # e_lfanew well past 512, and a large stub is itself a known evasion
                # trick worth not falling for. Comes from the same read loop already
                # hashing the file, so this costs no extra I/O.
                $header = [byte[]]::new(4096)
                $headerLength = 0
                $fileLength = 0L
                $bufferPool = [System.Buffers.ArrayPool[byte]]::Shared
                $buffer = $bufferPool.Rent(1MB)
                $stream = $null
                # Byte-frequency tally for Shannon entropy - filled in the same
                # read loop already hashing the file, so this costs no extra I/O.
                # The tally itself runs in C# (EntropyAnalyzer.AddCounts), not a
                # PowerShell loop, to keep this hot path fast per the same
                # reasoning as the compiled NSRL/CSV helpers above.
                $byteCounts = [long[]]::new(256)

                try {
                    $stream = [System.IO.File]::Open(
                        $FilePath, [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)

                    $fileLength = $stream.Length
                    while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        if ($headerLength -lt $header.Length) {
                            $copyLength = [Math]::Min($bytesRead, $header.Length - $headerLength)
                            [Array]::Copy($buffer, 0, $header, $headerLength, $copyLength)
                            $headerLength += $copyLength
                        }
                        $sha1Hasher.AppendData($buffer, 0, $bytesRead)
                        $md5Hasher.AppendData($buffer, 0, $bytesRead)
                        [BinSifter.EntropyAnalyzer]::AddCounts($byteCounts, $buffer, $bytesRead)
                    }

                    $sha1Bytes = $sha1Hasher.GetHashAndReset()
                    $sha1 = [Convert]::ToHexString($sha1Bytes)
                    $md5 = [Convert]::ToHexString($md5Hasher.GetHashAndReset())
                }
                finally {
                    if ($stream) { $stream.Dispose() }
                    $bufferPool.Return($buffer)
                    $sha1Hasher.Dispose(); $md5Hasher.Dispose()
                }

                $record.MD5 = $md5
                $record.SHA1 = $sha1

                # v1.3-proto1: apply any prior triage disposition for this exact
                # file (by SHA-1) before anything else runs, so a re-scan of the
                # same evidence set doesn't reset every analyst call back to
                # Untriaged.
                if ($DispositionHistory -and $DispositionHistory.ContainsKey($sha1)) {
                    $record.Disposition = $DispositionHistory[$sha1]
                }

                $record.Entropy = [BinSifter.EntropyAnalyzer]::ComputeEntropy($byteCounts, $fileLength)
                $record.Progress = 40

                # v1.3-proto1: Authenticode check, run unconditionally like entropy
                # (single cmdlet call against the file already on disk, no extra
                # read pass) - unlike ssdeep/yara/capa below, this still runs even
                # for NSRL-known files, since "signed" vs "unsigned" is meaningful
                # regardless of hash reputation.
                try {
                    $sigResult = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop
                    $record.SignatureStatus = $sigResult.Status.ToString()
                    if ($sigResult.SignerCertificate) {
                        $record.SignerName = $sigResult.SignerCertificate.Subject
                    }
                }
                catch {
                    $record.SignatureStatus = 'UnknownError'
                }
                Publish-UiUpdate

                $isKnownGood = $KnownGoodHashes.Contains([BinSifter.HashKey]::new($sha1Bytes))
                $record.NsrlMatch = $isKnownGood
                Publish-UiUpdate

                # v1.3-proto1: offline reputation check against an optional local
                # known-bad hash blocklist, mirroring the NSRL known-good check
                # just above but inverted. Matches against SHA1 or MD5, both
                # already computed for this file above - no extra hashing added.
                if ($KnownBadHashes) {
                    if ($KnownBadHashes.Contains($sha1) -or $KnownBadHashes.Contains($md5)) {
                        $record.ReputationStatus = 'KnownBad'
                        $record.ReputationSource = 'local-blocklist'
                    }
                    else {
                        $record.ReputationStatus = 'Clean'
                    }
                }
                Publish-UiUpdate

                if (-not $isKnownGood) {
                    # v1.3-proto1: imphash / rich-header hash. Needs the FULL file
                    # bytes - the import table can sit well past the 4KB header
                    # buffer already captured above, so this is a deliberate
                    # second read of the file. Gated to non-NSRL files and a 64MB
                    # size cap so it doesn't add meaningful I/O to a bulk scan of
                    # a mostly-known-good corpus (the common case - most of a
                    # disk image is legitimate OS/app binaries NSRL already
                    # resolved, which never reach this branch).
                    if ($headerLength -ge 2 -and $header[0] -eq 0x4D -and $header[1] -eq 0x5A -and $fileLength -gt 0 -and $fileLength -le 67108864) {
                        try {
                            $fullBytes = [System.IO.File]::ReadAllBytes($FilePath)
                            $impResult = [BinSifter.PeImportHasher]::Compute($fullBytes)
                            if ($impResult) {
                                $record.Imphash = $impResult.Imphash
                                $record.RichHash = $impResult.RichHash
                            }
                        }
                        catch {
                            # Best-effort - a parse failure just means no imphash for this file.
                        }
                        finally {
                            $fullBytes = $null
                        }
                    }

                    $ssdeepResult = Invoke-ExternalTool -Path $SsdeepExe -Arguments @($FilePath) `
                        -ProcessRegistry $ProcessRegistry -RegistryKey $FilePath
                    if ($ssdeepResult.ExitCode -ne 0) {
                        $detail = if ($ssdeepResult.StdErr) { $ssdeepResult.StdErr } else { $ssdeepResult.StdOut }
                        throw "ssdeep failed with exit code $($ssdeepResult.ExitCode): $detail"
                    }
                    $record.SSDEEP = $ssdeepResult.StdOut.Trim()
                    $record.Progress = 55
                    Publish-UiUpdate

                    # -m prints each matched rule's meta block, needed to read
                    # per-rule severity fields (score, tc_detection_factor, ...)
                    # and any MITRE ATT&CK reference URLs in that same metadata.
                    $yaraResult = Invoke-ExternalTool -Path $YaraExe -Arguments @('-m', $YaraRules, $FilePath) `
                        -ProcessRegistry $ProcessRegistry -RegistryKey $FilePath
                    if ($yaraResult.ExitCode -ne 0) {
                        $detail = if ($yaraResult.StdErr) { $yaraResult.StdErr } else { $yaraResult.StdOut }
                        throw "YARA failed with exit code $($yaraResult.ExitCode): $detail"
                    }
                    $yaraText = $yaraResult.StdOut.Trim()
                    $record.Progress = 70
                    Publish-UiUpdate

                    if (-not [string]::IsNullOrWhiteSpace($yaraText)) {
                        $yaraMatches = [BinSifter.YaraMetaParser]::Parse($yaraText)
                        # Keep YaraMatches as plain rule names (one per line), same
                        # shape as before -m was added, so existing CSV consumers
                        # and the grid's "YARA Hits" display don't see meta noise.
                        $record.YaraMatches = ($yaraMatches | ForEach-Object { $_.RuleName }) -join "`n"
                        $record.YaraHitCount = $yaraMatches.Count

                        $bestSeverity = 'Unknown'
                        $bestScore = -1
                        $attackHits = [System.Collections.Generic.List[string]]::new()
                        $attackSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

                        foreach ($ruleMatch in $yaraMatches) {
                            $sev = [BinSifter.SeverityScorer]::Resolve($ruleMatch.Meta)
                            if ((Get-SeverityRank $sev.Item1) -gt (Get-SeverityRank $bestSeverity)) {
                                $bestSeverity = $sev.Item1
                                $bestScore = $sev.Item2
                            }
                            if ($AttackDb) {
                                foreach ($technique in $AttackDb.Resolve($ruleMatch.Meta)) {
                                    if ($attackSeen.Add($technique.Id)) {
                                        $attackHits.Add("$($technique.Id) $($technique.Name) [$($technique.Tactic)]")
                                    }
                                }
                            }
                        }

                        $record.YaraSeverity = $bestSeverity
                        $record.YaraSeverityScore = $bestScore
                        $record.YaraAttackTechniques = if ($attackHits.Count -gt 0) { $attackHits -join '; ' } else { $null }

                        $extension = [System.IO.Path]::GetExtension($FilePath).ToLowerInvariant()
                        $isPE = $false
                        $isELF = $false

                        if ($headerLength -ge 64 -and $header[0] -eq 0x4D -and $header[1] -eq 0x5A) {
                            $peOffset = [BitConverter]::ToInt32($header, 0x3C)
                            if (
                                $peOffset -ge 0 -and ($peOffset + 4) -le $headerLength -and
                                $header[$peOffset] -eq 0x50 -and $header[$peOffset + 1] -eq 0x45 -and
                                $header[$peOffset + 2] -eq 0x00 -and $header[$peOffset + 3] -eq 0x00
                            ) {
                                $isPE = $true
                            }
                        }

                        if (
                            $headerLength -ge 4 -and $header[0] -eq 0x7F -and $header[1] -eq 0x45 -and
                            $header[2] -eq 0x4C -and $header[3] -eq 0x46
                        ) {
                            $isELF = $true
                        }

                        $isShellcode =
                            -not $isPE -and -not $isELF -and (
                                ($extension -in '.raw', '.bin' -and $fileLength -lt 200000) -or
                                (
                                    $extension -notin '.exe', '.dll', '.so', '.elf', '.bin', '.o', '.raw', '.dat' -and
                                    $fileLength -lt 100000
                                )
                            )

                        $record.CapaEligible = ($isPE -or $isELF -or $isShellcode)

                        # A file whose extension explicitly claims to be a native
                        # executable but whose magic bytes didn't validate as PE/ELF
                        # is excluded from both the PE/ELF branch AND the shellcode
                        # fallback (those extensions are on the fallback's exclusion
                        # list) - so it never reaches capa despite a YARA hit. That's
                        # a real analysis gap worth surfacing explicitly: could be a
                        # corrupted file, a truncated capture, or a deliberately
                        # header-stripped/anti-analysis binary.
                        $record.PossibleFalseNegative =
                            ($record.YaraHitCount -gt 0) -and (-not $record.CapaEligible) -and
                            ($extension -in '.exe', '.dll', '.so', '.elf')
                        Publish-UiUpdate

                        # Best-effort fallback for the PossibleFalseNegative case: capa
                        # can't analyze this file (no valid PE/ELF structure to parse),
                        # but floss's string extraction doesn't need one. Never allowed
                        # to fail the file's scan - if floss errors out or isn't
                        # configured, this is silently skipped, same as MITRE ATT&CK
                        # mapping being optional.
                        if ($record.PossibleFalseNegative -and $FlossExe -and (Test-Path -LiteralPath $FlossExe -PathType Leaf)) {
                            try {
                                $flossResult = Invoke-ExternalTool -Path $FlossExe -Arguments @('-j', $FilePath) `
                                    -ProcessRegistry $ProcessRegistry -RegistryKey $FilePath -TimeoutSeconds 300
                                if ($flossResult.ExitCode -eq 0) {
                                    $flossText = $flossResult.StdOut.Trim()
                                    if (-not [string]::IsNullOrWhiteSpace($flossText)) {
                                        try {
                                            $flossJson = $flossText | ConvertFrom-Json -ErrorAction Stop
                                            $stringCount = 0
                                            if ($flossJson.strings) {
                                                foreach ($category in @('static_strings', 'stack_strings', 'decoded_strings', 'tight_strings')) {
                                                    if ($flossJson.strings.PSObject.Properties.Name -contains $category) {
                                                        $stringCount += @($flossJson.strings.$category).Count
                                                    }
                                                }
                                            }
                                            $record.FlossStringCount = $stringCount

                                            # v1.3-proto1: mine the same FLOSS strings already
                                            # extracted above for IOC-shaped values (IPs, URLs,
                                            # domains, registry paths) instead of leaving them
                                            # unread in the JSON report - turns "floss ran" into
                                            # a short, scannable candidate-IOC list. Best-effort;
                                            # never allowed to affect FlossStringCount above.
                                            try {
                                                $allStrings = [System.Collections.Generic.List[string]]::new()
                                                if ($flossJson.strings) {
                                                    foreach ($category in @('static_strings', 'stack_strings', 'decoded_strings', 'tight_strings')) {
                                                        if ($flossJson.strings.PSObject.Properties.Name -contains $category) {
                                                            foreach ($entry in @($flossJson.strings.$category)) {
                                                                $sval = if ($entry.string) { $entry.string } else { "$entry" }
                                                                if ($sval) { $allStrings.Add($sval) }
                                                            }
                                                        }
                                                    }
                                                }

                                                $iocSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                                                $ipRegex = [regex]'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                                                $urlRegex = [regex]"\bhttps?://[^\s`"'<>]{4,200}"
                                                $domainRegex = [regex]'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|biz|info|xyz|top|club|online|site|tk|cc)\b'
                                                $regRegex = [regex]"\bHKEY_[A-Z_]+\\[^\s`"']{2,200}"

                                                foreach ($s in $allStrings) {
                                                    foreach ($m in $ipRegex.Matches($s)) { $null = $iocSet.Add($m.Value) }
                                                    foreach ($m in $urlRegex.Matches($s)) { $null = $iocSet.Add($m.Value) }
                                                    foreach ($m in $domainRegex.Matches($s)) { $null = $iocSet.Add($m.Value.ToLowerInvariant()) }
                                                    foreach ($m in $regRegex.Matches($s)) { $null = $iocSet.Add($m.Value) }
                                                }

                                                if ($iocSet.Count -gt 0) {
                                                    $record.IocCount = $iocSet.Count
                                                    # Capped so a pathological string blob can't balloon the CSV row.
                                                    $record.ExtractedIOCs = ($iocSet | Select-Object -First 50) -join '; '
                                                }
                                            }
                                            catch {
                                                # Best-effort - IOC mining never fails the file's scan.
                                            }
                                        }
                                        catch {
                                            $record.FlossStringCount = 0
                                        }

                                        if ($FlossReportsDir) {
                                            try {
                                                $flossReportPath = Join-Path $FlossReportsDir "$sha1.json"
                                                [System.IO.File]::WriteAllText($flossReportPath, $flossText)
                                            }
                                            catch {
                                                # A failed report write shouldn't fail the whole file's scan.
                                            }
                                        }
                                    }
                                }
                            }
                            catch {
                                # Best-effort fallback - floss issues never fail the file's scan.
                            }
                        }

                        # v1.3-proto1: DIE (Detect It Easy) console-mode packer/
                        # compiler detection. Gated to the same "ambiguous" files
                        # FLOSS targets (capa-ineligible) plus generally high-
                        # entropy files, rather than run on every file - this is
                        # another child process competing for the same throttled
                        # worker pool as yara/capa/ssdeep/floss, so it's bounded
                        # to files that actually need a second opinion on what
                        # they are, not run unconditionally across a whole batch.
                        if (($record.PossibleFalseNegative -or $record.Entropy -ge 7.2) -and $DieConsoleExe -and (Test-Path -LiteralPath $DieConsoleExe -PathType Leaf)) {
                            try {
                                $dieResult = Invoke-ExternalTool -Path $DieConsoleExe -Arguments @('-j', $FilePath) `
                                    -ProcessRegistry $ProcessRegistry -RegistryKey $FilePath -TimeoutSeconds 120
                                if ($dieResult.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($dieResult.StdOut)) {
                                    try {
                                        $dieJson = $dieResult.StdOut.Trim() | ConvertFrom-Json -ErrorAction Stop
                                        $packers = [System.Collections.Generic.List[string]]::new()
                                        $compilers = [System.Collections.Generic.List[string]]::new()
                                        foreach ($detect in @($dieJson.detects)) {
                                            foreach ($val in @($detect.values)) {
                                                if ($val.type -eq 'Packer') { $packers.Add($val.name) }
                                                elseif ($val.type -in 'Compiler', 'Linker') { $compilers.Add($val.name) }
                                            }
                                        }
                                        if ($packers.Count -gt 0) { $record.PackerDetected = (@($packers | Select-Object -Unique)) -join '; ' }
                                        if ($compilers.Count -gt 0) { $record.Compiler = (@($compilers | Select-Object -Unique)) -join '; ' }
                                    }
                                    catch {
                                        # Best-effort - malformed/unexpected DIE JSON just means no packer/compiler data for this file.
                                    }
                                }
                            }
                            catch {
                                # Best-effort - DIE issues never fail the file's scan.
                            }
                        }

                        if ($record.CapaEligible) {
                            $capaText = $null
                            $lastCapaError = $null

                            if ($isShellcode) {
                                # A raw/headerless blob has nothing for capa to auto-detect a
                                # format from - it needs -f sc32/sc64 told explicitly, and
                                # there's no reliable way to know the bitness up front. Try
                                # 32-bit first, then 64-bit, and keep whichever actually
                                # produced a detection; if both come back clean (0 rules),
                                # keep the first successful run's output so downstream code
                                # still sees valid (if empty) capa JSON rather than nothing.
                                foreach ($scFormat in @('sc32', 'sc64')) {
                                    $scResult = Invoke-ExternalTool -Path $CapaExe -Arguments @('-j', '-f', $scFormat, '-r', $CapaRules, $FilePath) `
                                        -ProcessRegistry $ProcessRegistry -RegistryKey $FilePath
                                    if ($scResult.ExitCode -ne 0) {
                                        $lastCapaError = if ($scResult.StdErr) { $scResult.StdErr } else { $scResult.StdOut }
                                        continue
                                    }

                                    $scText = $scResult.StdOut.Trim()
                                    $scRuleCount = 0
                                    if (-not [string]::IsNullOrWhiteSpace($scText)) {
                                        try {
                                            $scJson = $scText | ConvertFrom-Json -ErrorAction Stop
                                            if ($scJson.rules) { $scRuleCount = @($scJson.rules.PSObject.Properties).Count }
                                        }
                                        catch { $scRuleCount = 0 }
                                    }

                                    if (-not $capaText) {
                                        $capaText = $scText
                                        $record.CapaShellcodeFormat = $scFormat
                                    }
                                    if ($scRuleCount -gt 0) {
                                        $capaText = $scText
                                        $record.CapaShellcodeFormat = $scFormat
                                        break
                                    }
                                }

                                if (-not $capaText -and $lastCapaError) {
                                    throw "CAPA failed for both sc32 and sc64 shellcode formats: $lastCapaError"
                                }
                            }
                            else {
                                $capaResult = Invoke-ExternalTool -Path $CapaExe -Arguments @('-j', '-r', $CapaRules, $FilePath) `
                                    -ProcessRegistry $ProcessRegistry -RegistryKey $FilePath
                                if ($capaResult.ExitCode -ne 0) {
                                    $detail = if ($capaResult.StdErr) { $capaResult.StdErr } else { $capaResult.StdOut }
                                    throw "CAPA failed with exit code $($capaResult.ExitCode): $detail"
                                }
                                $capaText = $capaResult.StdOut.Trim()
                            }
                            $record.Progress = 90
                            Publish-UiUpdate

                            if (-not [string]::IsNullOrWhiteSpace($capaText)) {
                                $record.CAPAOutput = $capaText
                                try {
                                    $capaJson = $capaText | ConvertFrom-Json -ErrorAction Stop
                                    if ($capaJson.rules) {
                                        $record.CapaDetectionCount = @($capaJson.rules.PSObject.Properties).Count
                                    }
                                }
                                catch {
                                    $record.CapaDetectionCount = 0
                                }

                                if ($CapaReportsDir) {
                                    try {
                                        $reportPath = Join-Path $CapaReportsDir "$sha1.json"
                                        [System.IO.File]::WriteAllText($reportPath, $capaText)
                                    }
                                    catch {
                                        # A failed report write shouldn't fail the whole file's scan.
                                    }
                                }
                            }
                        }
                    }
                }

                $record.Status = 'Completed'
                $record.Progress = 100
                Publish-UiUpdate
            }
            catch {
                $record.Error = $_.Exception.Message
                $record.Status = 'Error'
                $record.Progress = 100
                Publish-UiUpdate
            }
        }

        # ================= Scan engine (background dispatcher, own runspace) =================
        function Start-ScanEngine {
            param($Config, [int]$ThrottleLimit, $FileRecords, $UiDirtyQueue, $ScanControl, $LogQueue, $WorkerScriptBlock)

            $dispatcherRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $dispatcherRunspace.Open()
            $dispatcherPs = [System.Management.Automation.PowerShell]::Create()
            $dispatcherPs.Runspace = $dispatcherRunspace

            $null = $dispatcherPs.AddScript({
                param($Config, $ThrottleLimit, $FileRecords, $UiDirtyQueue, $ScanControl, $LogQueue, $WorkerScriptBlock)

                function Add-Log2 {
                    param([string]$Message)
                    $LogQueue.Enqueue("[$(Get-Date -Format 'HH:mm:ss')] $Message")
                }

                # Same shape as the worker pool's Invoke-ExternalTool (see
                # $workerScriptBlock) - duplicated here rather than shared because the
                # dispatcher and the worker pool run in separate runspaces/scopes and
                # PowerShell functions don't cross that boundary. Needed here for the
                # post-scan SSDEEP clustering pass, which runs once in the dispatcher
                # after all workers finish, not per-file.
                function Invoke-ExternalTool {
                    param(
                        [string]$Path,
                        [string[]]$Arguments,
                        $ProcessRegistry,
                        [string]$RegistryKey,
                        [int]$TimeoutSeconds = 600
                    )

                    $psi = [System.Diagnostics.ProcessStartInfo]::new()
                    $psi.FileName = $Path
                    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
                    $psi.RedirectStandardOutput = $true
                    $psi.RedirectStandardError = $true
                    $psi.UseShellExecute = $false
                    $psi.CreateNoWindow = $true

                    $proc = [System.Diagnostics.Process]::new()
                    $proc.StartInfo = $psi

                    try {
                        $null = $proc.Start()
                        if ($ProcessRegistry -and $RegistryKey) { $ProcessRegistry[$RegistryKey] = $proc }

                        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
                        $stderrTask = $proc.StandardError.ReadToEndAsync()

                        $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
                        if (-not $exited) {
                            try { $proc.Kill($true) } catch { }
                            try { $null = $proc.WaitForExit(5000) } catch { }

                            $stdoutText = ''
                            $stderrText = ''
                            if ($stdoutTask.IsCompleted) {
                                try { $stdoutText = $stdoutTask.GetAwaiter().GetResult() } catch { }
                            }
                            if ($stderrTask.IsCompleted) {
                                try { $stderrText = $stderrTask.GetAwaiter().GetResult() } catch { }
                            }

                            $timeoutMessage = "Process timed out after $TimeoutSeconds seconds and was terminated."
                            if ($stderrText) { $timeoutMessage = "$timeoutMessage`r`n$stderrText" }
                            return [pscustomobject]@{
                                ExitCode = -1
                                TimedOut = $true
                                StdOut   = $stdoutText
                                StdErr   = $timeoutMessage
                            }
                        }

                        [pscustomobject]@{
                            ExitCode = $proc.ExitCode
                            TimedOut = $false
                            StdOut   = $stdoutTask.GetAwaiter().GetResult()
                            StdErr   = $stderrTask.GetAwaiter().GetResult()
                        }
                    }
                    finally {
                        if ($ProcessRegistry -and $RegistryKey) {
                            $removed = $null
                            $null = $ProcessRegistry.TryRemove($RegistryKey, [ref]$removed)
                        }
                        $proc.Dispose()
                    }
                }

                $processRegistry = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Diagnostics.Process]]::new()
                # Exposed so the UI thread (FormClosing) can kill in-flight tool
                # processes directly on shutdown instead of only hoping the dispatcher
                # notices StopRequested in time.
                $ScanControl.ProcessRegistry = $processRegistry

                try {
                    # NSRL RDS CSV: SHA-1,MD5,CRC32,FileName,FileSize,ProductCode,OpSystemCode,SpecialCode
                    # (no SHA-256 column, so matching is on SHA-1). Parsing/caching goes through
                    # the compiled BinSifter.NsrlLoader, not a PowerShell loop - see Add-Type above.
                    $sourceInfo = Get-Item -LiteralPath $Config.NsrlPath
                    # Cache lives under the report directory, not beside the NSRL source -
                    # NSRL reference sets are often on read-only/write-blocked evidentiary
                    # media, and a source-directory write failure used to abort the whole
                    # scan even though the NSRL data itself parsed fine. Named by a hash of
                    # the source path so multiple NSRL files can't collide on cache names.
                    $nsrlCacheDir = Join-Path $Config.ReportDirectory '.bsifter-nsrl-cache'
                    $null = New-Item -ItemType Directory -Path $nsrlCacheDir -Force -ErrorAction SilentlyContinue
                    $nsrlPathHash = [Convert]::ToHexString(
                        [System.Security.Cryptography.SHA256]::HashData(
                            [System.Text.Encoding]::UTF8.GetBytes($Config.NsrlPath.ToLowerInvariant())
                        )
                    ).Substring(0, 16)
                    $cacheName = "$([System.IO.Path]::GetFileNameWithoutExtension($Config.NsrlPath))_$nsrlPathHash.bsifter-cache"
                    $cachePath = Join-Path $nsrlCacheDir $cacheName
                    $tempCachePath = "$cachePath.tmp"
                    $cacheValid = $false

                    if (Test-Path -LiteralPath $cachePath -PathType Leaf) {
                        $headerStream = [System.IO.File]::OpenRead($cachePath)
                        try {
                            $headerBuf = [byte[]]::new(16)
                            if ($headerStream.Read($headerBuf, 0, 16) -eq 16) {
                                $cachedLength = [BitConverter]::ToInt64($headerBuf, 0)
                                $cachedTicks = [BitConverter]::ToInt64($headerBuf, 8)
                                if ($cachedLength -eq $sourceInfo.Length -and $cachedTicks -eq $sourceInfo.LastWriteTimeUtc.Ticks) {
                                    $cacheValid = $true
                                }
                            }
                        }
                        finally { $headerStream.Dispose() }
                    }

                    if ($cacheValid) {
                        Add-Log2 'Loading NSRL from cache (native loader, fast path)...'
                        $knownGoodHashes = [BinSifter.NsrlLoader]::LoadFromCache($cachePath, 16)
                    }
                    else {
                        Add-Log2 'Building NSRL cache from source CSV via native loader (first run against this file - subsequent runs will be fast)...'
                        $knownGoodHashes = [BinSifter.NsrlLoader]::BuildFromCsv($Config.NsrlPath, $tempCachePath)

                        try {
                            $finalStream = [System.IO.File]::Create($cachePath)
                            try {
                                $finalStream.Write([BitConverter]::GetBytes($sourceInfo.Length), 0, 8)
                                $finalStream.Write([BitConverter]::GetBytes($sourceInfo.LastWriteTimeUtc.Ticks), 0, 8)
                                $bodyStream = [System.IO.File]::OpenRead($tempCachePath)
                                try { $bodyStream.CopyTo($finalStream) } finally { $bodyStream.Dispose() }
                            }
                            finally { $finalStream.Dispose() }
                            Remove-Item -LiteralPath $tempCachePath -Force -ErrorAction SilentlyContinue
                            Add-Log2 "NSRL cache built: $cachePath"
                        }
                        catch {
                            Add-Log2 "Could not write NSRL cache, will re-parse next run: $($_.Exception.Message)"
                        }
                    }

                    $ScanControl.NsrlHashCount = $knownGoodHashes.Count
                    Add-Log2 "NSRL loaded: $($knownGoodHashes.Count) hashes."

                    # v1.3-proto1: optional local "known-bad" hash blocklist - same
                    # idea as the NSRL known-good check above but inverted.
                    # Deliberately simpler than NsrlLoader (plain HashSet[string],
                    # not the packed-binary/cached loader path) since blocklists
                    # are typically thousands to low-millions of entries, not
                    # NSRL's tens of millions - a full re-read each scan is cheap
                    # enough at that scale and avoids maintaining a second cache
                    # format.
                    #
                    # Two input shapes are supported, auto-detected per file:
                    #   1. Plain "one hash per line" (SHA1/MD5), optionally with
                    #      trailing CSV columns after the hash - the original
                    #      design here.
                    #   2. MalwareBazaar's own CSV export (both "recent" and
                    #      "full"): a banner of "#"-prefixed comment lines, then
                    #      a "#"-prefixed header row of quoted column names
                    #      (first_seen_utc,sha256_hash,md5_hash,sha1_hash,...),
                    #      then quoted/comma-separated data rows whose FIRST
                    #      field is a timestamp, not a hash - the original
                    #      "take the text before the first comma" logic would
                    #      have silently extracted timestamps instead of hashes
                    #      for this shape and loaded zero real entries. The
                    #      header row (itself "#"-prefixed, so it doesn't get
                    #      skipped as a no-op comment) is used to find the
                    #      sha1_hash/md5_hash column positions, so a reordered
                    #      future export still works rather than relying on a
                    #      hardcoded column index.
                    $knownBadHashes = $null
                    if (-not [string]::IsNullOrWhiteSpace($Config.BlocklistPath) -and
                        (Test-Path -LiteralPath $Config.BlocklistPath -PathType Leaf)) {
                        try {
                            Add-Log2 'Loading known-bad hash blocklist...'
                            $knownBadHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

                            $sha1ColIndex = -1
                            $md5ColIndex = -1
                            $headerChecked = $false
                            $quotedFieldSplit = '"\s*,\s*"'

                            foreach ($rawLine in [System.IO.File]::ReadLines($Config.BlocklistPath)) {
                                $trimmed = $rawLine.Trim()
                                if ($trimmed.Length -eq 0) { continue }

                                if ($trimmed.StartsWith('#')) {
                                    if (-not $headerChecked -and $trimmed -match '"sha1_hash"') {
                                        $headerFields = @(
                                            ($trimmed.TrimStart('#', ' ') -split $quotedFieldSplit) |
                                                ForEach-Object { $_.Trim('"', ' ') }
                                        )
                                        $sha1ColIndex = [array]::IndexOf($headerFields, 'sha1_hash')
                                        $md5ColIndex = [array]::IndexOf($headerFields, 'md5_hash')
                                        $headerChecked = $true
                                    }
                                    continue
                                }

                                if ($sha1ColIndex -ge 0) {
                                    # MalwareBazaar-shaped quoted CSV row - pull the
                                    # named column(s) rather than assuming position 0.
                                    $fields = @(($trimmed.Trim('"', ' ') -split $quotedFieldSplit))
                                    if ($sha1ColIndex -lt $fields.Count) {
                                        $val = $fields[$sha1ColIndex].Trim()
                                        if ($val.Length -eq 40) { $null = $knownBadHashes.Add($val) }
                                    }
                                    if ($md5ColIndex -ge 0 -and $md5ColIndex -lt $fields.Count) {
                                        $val = $fields[$md5ColIndex].Trim()
                                        if ($val.Length -eq 32) { $null = $knownBadHashes.Add($val) }
                                    }
                                }
                                else {
                                    # Plain "one hash per line" format, tolerating a
                                    # bare leading/trailing quote and trailing CSV
                                    # columns after the hash.
                                    $candidate = $trimmed
                                    $commaIdx = $candidate.IndexOf(',')
                                    if ($commaIdx -gt 0) { $candidate = $candidate.Substring(0, $commaIdx) }
                                    $candidate = $candidate.Trim('"', ' ')
                                    if ($candidate.Length -eq 40 -or $candidate.Length -eq 32) { $null = $knownBadHashes.Add($candidate) }
                                }
                            }
                            Add-Log2 "Blocklist loaded: $($knownBadHashes.Count) hash(es)."
                        }
                        catch {
                            Add-Log2 "Could not load blocklist, reputation checks disabled for this scan: $($_.Exception.Message)"
                            $knownBadHashes = $null
                        }
                    }
                    else {
                        Add-Log2 'No blocklist configured - reputation checks disabled for this scan.'
                    }

                    # v1.3-proto1: prior triage dispositions, persisted by SHA-1 so
                    # re-scanning the same files (or re-opening the same case
                    # directory later) keeps earlier Benign/Suspicious/Escalated
                    # calls instead of resetting everything to Untriaged. Written
                    # by the Results grid's disposition column handler (UI thread);
                    # read back here at the start of each scan.
                    $dispositionHistoryPath = Join-Path $Config.ReportDirectory '.bsifter-disposition-history.txt'
                    $dispositionHistory = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    if (Test-Path -LiteralPath $dispositionHistoryPath -PathType Leaf) {
                        try {
                            foreach ($line in [System.IO.File]::ReadAllLines($dispositionHistoryPath)) {
                                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                                $fields = $line.Split('|')
                                if ($fields.Count -ge 2 -and $fields[0].Trim().Length -eq 40) {
                                    $dispositionHistory[$fields[0].Trim()] = $fields[1].Trim()
                                }
                            }
                            Add-Log2 "Disposition history loaded: $($dispositionHistory.Count) prior call(s)."
                        }
                        catch {
                            Add-Log2 "Could not load disposition history: $($_.Exception.Message)"
                        }
                    }

                    # MITRE ATT&CK mapping is optional - a blank/missing path just
                    # disables TTP resolution for this scan rather than failing it.
                    $attackDb = $null
                    if (-not [string]::IsNullOrWhiteSpace($Config.AttackDataPath) -and
                        (Test-Path -LiteralPath $Config.AttackDataPath -PathType Leaf)) {
                        try {
                            Add-Log2 'Loading MITRE ATT&CK data...'
                            $attackDb = [BinSifter.AttackDb]::Load($Config.AttackDataPath)
                            Add-Log2 "MITRE ATT&CK data loaded: $($attackDb.TechniqueCount) techniques indexed."
                        }
                        catch {
                            Add-Log2 "Could not load MITRE ATT&CK data, TTP mapping disabled for this scan: $($_.Exception.Message)"
                            $attackDb = $null
                        }
                    }
                    else {
                        Add-Log2 'No MITRE ATT&CK data configured - TTP mapping disabled for this scan.'
                    }

                    if ($ScanControl.StopRequested) { throw 'stopped-before-enumeration' }

                    Add-Log2 'Enumerating target files...'
                    # Native walk instead of Get-ChildItem -Recurse - skips per-item pipeline overhead.
                    $enumResult = [BinSifter.FileScanner]::EnumerateFiles($Config.SrcDir)
                    $orderedPaths = $enumResult.Files

                    if ($enumResult.ErrorCount -gt 0) {
                        Add-Log2 "$($enumResult.ErrorCount) filesystem enumeration error(s) occurred."
                    }

                    $now = Get-Date
                    foreach ($path in $orderedPaths) {
                        $record = [BinSifter.FileRecord]::new()
                        $record.Path = $path
                        $record.Added = $now
                        $null = $FileRecords.TryAdd($path, $record)
                        $UiDirtyQueue.Enqueue($path)
                    }

                    $ScanControl.TotalFiles = $orderedPaths.Count
                    $ScanControl.OrderedPaths = $orderedPaths
                    $ScanControl.FilesDiscovered = $true
                    Add-Log2 "Target queue populated: $($orderedPaths.Count) files."

                    if ($orderedPaths.Count -eq 0) {
                        Add-Log2 'No files found - nothing to scan.'
                        throw 'nothing-to-scan'
                    }

                    $capaReportsDir = Join-Path $Config.ReportDirectory 'capa_reports'
                    $null = New-Item -ItemType Directory -Path $capaReportsDir -Force -ErrorAction SilentlyContinue

                    $flossReportsDir = Join-Path $Config.ReportDirectory 'floss_reports'
                    $null = New-Item -ItemType Directory -Path $flossReportsDir -Force -ErrorAction SilentlyContinue

                    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit, $iss, $Host)
                    $pool.Open()

                    # Close/Dispose lives in this finally so an unexpected exception
                    # mid-dispatch still releases the pool instead of leaking it.
                    try {
                    $queue = [System.Collections.Generic.Queue[string]]::new($orderedPaths)
                    $inFlight = [System.Collections.Generic.List[object]]::new()
                    $completedCount = 0
                    $nextMilestone = 50

                    while ($queue.Count -gt 0 -or $inFlight.Count -gt 0) {
                        if ($ScanControl.StopRequested) {
                            Add-Log2 'Stop requested - terminating in-flight tools and cancelling queued files...'
                            foreach ($proc in $processRegistry.Values) {
                                try { if (-not $proc.HasExited) { $proc.Kill($true) } } catch { }
                            }
                            while ($queue.Count -gt 0) {
                                $path = $queue.Dequeue()
                                $FileRecords[$path].Status = 'Cancelled'
                                $FileRecords[$path].Progress = 0
                                $UiDirtyQueue.Enqueue($path)
                            }
                            break
                        }

                        for ($i = $inFlight.Count - 1; $i -ge 0; $i--) {
                            $job = $inFlight[$i]
                            if ($job.Handle.IsCompleted) {
                                try { $null = $job.PS.EndInvoke($job.Handle) } catch { }
                                $job.PS.Dispose()
                                $inFlight.RemoveAt($i)
                                $completedCount++
                                if ($completedCount -ge $nextMilestone) {
                                    Add-Log2 "Progress: $completedCount / $($orderedPaths.Count) files processed."
                                    $nextMilestone += 50
                                }
                            }
                        }

                        if (-not $ScanControl.IsPaused -and $queue.Count -gt 0 -and $inFlight.Count -lt $ThrottleLimit) {
                            $path = $queue.Dequeue()
                            $workerPs = [powershell]::Create()
                            $workerPs.RunspacePool = $pool
                            $null = $workerPs.AddScript($WorkerScriptBlock)
                            $null = $workerPs.AddParameter('FilePath', $path)
                            $null = $workerPs.AddParameter('FileRecords', $FileRecords)
                            $null = $workerPs.AddParameter('UiDirtyQueue', $UiDirtyQueue)
                            $null = $workerPs.AddParameter('ProcessRegistry', $processRegistry)
                            $null = $workerPs.AddParameter('KnownGoodHashes', $knownGoodHashes)
                            $null = $workerPs.AddParameter('KnownBadHashes', $knownBadHashes)
                            $null = $workerPs.AddParameter('AttackDb', $attackDb)
                            $null = $workerPs.AddParameter('YaraExe', $Config.YaraExe)
                            $null = $workerPs.AddParameter('YaraRules', $Config.YaraRules)
                            $null = $workerPs.AddParameter('CapaExe', $Config.CapaExe)
                            $null = $workerPs.AddParameter('CapaRules', $Config.CapaRules)
                            $null = $workerPs.AddParameter('SsdeepExe', $Config.SsdeepExe)
                            $null = $workerPs.AddParameter('CapaReportsDir', $capaReportsDir)
                            $null = $workerPs.AddParameter('FlossExe', $Config.FlossExe)
                            $null = $workerPs.AddParameter('FlossReportsDir', $flossReportsDir)
                            $null = $workerPs.AddParameter('DieConsoleExe', $Config.DieConsoleExe)
                            $null = $workerPs.AddParameter('DispositionHistory', $dispositionHistory)
                            $handle = $workerPs.BeginInvoke()
                            $inFlight.Add([pscustomobject]@{ PS = $workerPs; Handle = $handle; Path = $path })
                        }
                        else {
                            Start-Sleep -Milliseconds 100
                        }
                    }

                    if ($ScanControl.StopRequested) {
                        # Drain whatever was in flight when Stop hit; force-remaining to Cancelled.
                        $deadline = (Get-Date).AddSeconds(5)
                        while ($inFlight.Count -gt 0 -and (Get-Date) -lt $deadline) {
                            for ($i = $inFlight.Count - 1; $i -ge 0; $i--) {
                                if ($inFlight[$i].Handle.IsCompleted) {
                                    try { $null = $inFlight[$i].PS.EndInvoke($inFlight[$i].Handle) } catch { }
                                    $inFlight[$i].PS.Dispose()
                                    $inFlight.RemoveAt($i)
                                }
                            }
                            if ($inFlight.Count -gt 0) { Start-Sleep -Milliseconds 100 }
                        }
                        foreach ($job in $inFlight) {
                            $rec = $FileRecords[$job.Path]
                            if ($rec.Status -eq 'Scanning') {
                                $rec.Status = 'Cancelled'
                                $UiDirtyQueue.Enqueue($job.Path)
                            }
                            try { $job.PS.Stop() } catch { }
                            $job.PS.Dispose()
                        }
                        Add-Log2 'Scan stopped.'
                    }
                    else {
                        Add-Log2 'Scan complete.'
                    }
                    }
                    finally {
                        $pool.Close()
                        $pool.Dispose()
                    }

                    # Export-Csv's per-property reflection gets slow at large row counts,
                    # so the typed records go straight to the compiled writer instead.
                    $recordList = [System.Collections.Generic.List[BinSifter.FileRecord]]::new($orderedPaths.Count)
                    foreach ($path in $orderedPaths) { $recordList.Add($FileRecords[$path]) }
                    $recordList = [System.Collections.Generic.List[BinSifter.FileRecord]]($recordList | Sort-Object -Property Path)

                    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'

                    # ================= SSDEEP fuzzy-hash clustering =================
                    # Every non-NSRL file already has an ssdeep signature from the per-
                    # file scan; nothing has read it back until now. This builds a
                    # combined signature-list file from those and re-hashes the same
                    # target files against it via `ssdeep -c -m`, which finds every
                    # pairwise match above threshold in one pass - i.e. clustering.
                    # (-m re-hashes FILES and compares to a known-signature file, and is
                    # the mode ssdeep documents as compatible with -c/CSV output; -k
                    # compares signature-to-signature without re-hashing, which would
                    # avoid the extra I/O, but its output format isn't documented as
                    # -c-compatible, so -m is the safer choice for a first pass.)
                    Add-Log2 'Building SSDEEP signature list for cluster comparison...'
                    # Declared here (not just inside the branch below) so later code - the
                    # v1.3-proto1 draft-YARA-rule generator - can safely check
                    # $recordsByCluster.Count even when clustering was skipped entirely
                    # (fewer than 2 hashed files, ssdeep.exe not configured, or an error
                    # below) without tripping Set-StrictMode on an unset variable.
                    $recordsByCluster = @{}
                    $ssdeepClusterThreshold = 40
                    try {
                        $sigLines = [System.Collections.Generic.List[string]]::new()
                        $sigLines.Add('ssdeep,1.1--blocksize:hash:hash,filename')
                        $ssdeepTargets = [System.Collections.Generic.List[string]]::new()

                        foreach ($r in $recordList) {
                            if ([string]::IsNullOrWhiteSpace($r.SSDEEP)) { continue }
                            $sigParts = $r.SSDEEP -split "`n", 2
                            if ($sigParts.Count -lt 2) { continue }
                            $dataLine = $sigParts[1].TrimEnd("`r")
                            if ([string]::IsNullOrWhiteSpace($dataLine)) { continue }
                            $sigLines.Add($dataLine)
                            $ssdeepTargets.Add($r.Path)
                        }

                        if ($ssdeepTargets.Count -ge 2 -and $Config.SsdeepExe -and (Test-Path -LiteralPath $Config.SsdeepExe -PathType Leaf)) {
                            $sigListPath = Join-Path $Config.ReportDirectory ".bsifter-ssdeep-siglist_$timestamp.txt"
                            [System.IO.File]::WriteAllLines($sigListPath, $sigLines)

                            # Command-line length is a real limit here (~32K chars total on
                            # Windows), so target files are matched in batches rather than
                            # all at once - keeps this working on large corpora instead of
                            # failing silently past some file count.
                            $ssdeepClusterThreshold = 40
                            $batchSize = 150
                            $matchesByPath = @{}
                            $allMatches = [System.Collections.Generic.List[BinSifter.SsdeepMatch]]::new()
                            $clusterFailed = $false

                            for ($batchStart = 0; $batchStart -lt $ssdeepTargets.Count; $batchStart += $batchSize) {
                                $batchEnd = [Math]::Min($batchStart + $batchSize, $ssdeepTargets.Count) - 1
                                $batchFiles = @($ssdeepTargets.GetRange($batchStart, $batchEnd - $batchStart + 1))

                                $clusterArgs = @('-c', '-m', $sigListPath, '-t', "$ssdeepClusterThreshold") + $batchFiles
                                $clusterResult = Invoke-ExternalTool -Path $Config.SsdeepExe -Arguments $clusterArgs `
                                    -ProcessRegistry $processRegistry -RegistryKey '__ssdeep-cluster__' -TimeoutSeconds 300

                                if ($clusterResult.ExitCode -ne 0 -and $clusterResult.ExitCode -ne 1) {
                                    $clusterFailed = $true
                                    continue
                                }
                                if ([string]::IsNullOrWhiteSpace($clusterResult.StdOut)) { continue }

                                foreach ($line in ($clusterResult.StdOut -split "`r?`n")) {
                                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                                    $match = [BinSifter.SsdeepMatchParser]::ParseLine($line)
                                    if (-not $match) { continue }
                                    if ($match.FileA -eq $match.FileB) { continue }

                                    $allMatches.Add($match)

                                    if (-not $matchesByPath.ContainsKey($match.FileA)) {
                                        $matchesByPath[$match.FileA] = [System.Collections.Generic.List[string]]::new()
                                    }
                                    $matchesByPath[$match.FileA].Add("$($match.FileB) ($($match.Score))")
                                }
                            }

                            $clusterRows = [System.Collections.Generic.List[string]]::new()
                            foreach ($r in $recordList) {
                                if ($matchesByPath.ContainsKey($r.Path)) {
                                    $uniqueMatches = @($matchesByPath[$r.Path] | Select-Object -Unique)
                                    $r.SsdeepMatches = $uniqueMatches -join '; '
                                    foreach ($m in $uniqueMatches) { $clusterRows.Add("$($r.Path),$m") }
                                }
                            }

                            if ($clusterRows.Count -gt 0) {
                                $clusterCsvPath = Join-Path $Config.ReportDirectory "ssdeep_clusters_$timestamp.csv"
                                $clusterCsvLines = [System.Collections.Generic.List[string]]::new()
                                $clusterCsvLines.Add('FileA,FileBAndScore')
                                $clusterCsvLines.AddRange($clusterRows)
                                [System.IO.File]::WriteAllLines($clusterCsvPath, $clusterCsvLines)
                                Add-Log2 "SSDEEP cluster matches saved: $clusterCsvPath ($($clusterRows.Count) related pairs found, threshold $ssdeepClusterThreshold)."
                            }
                            elseif ($clusterFailed) {
                                Add-Log2 'SSDEEP clustering encountered errors on one or more batches - see above for partial results.'
                            }
                            else {
                                Add-Log2 "No related files found above the SSDEEP similarity threshold ($ssdeepClusterThreshold)."
                            }

                            # ---- Connected-component clustering + dashboard heat-map metrics ----
                            # $matchesByPath above only records pairwise matches per file (for the
                            # CSV/grid display); it doesn't group files transitively. Real
                            # clustering - and everything the heat map shows - needs that, via
                            # union-find over every match found across all batches.
                            $clusterMap = [BinSifter.SsdeepClusterer]::BuildClusters($allMatches, $ssdeepTargets)

                            $highSimPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                            foreach ($m in $allMatches) {
                                if ($m.Score -ge 85) {
                                    $null = $highSimPaths.Add($m.FileA)
                                    $null = $highSimPaths.Add($m.FileB)
                                }
                            }

                            foreach ($r in $recordList) {
                                if ($clusterMap.ContainsKey($r.Path)) {
                                    $info = $clusterMap[$r.Path]
                                    $r.SsdeepClusterId = $info.ClusterId
                                    $r.SsdeepClusterSize = $info.Size
                                }
                                $r.SsdeepHasHighSimilarity = $highSimPaths.Contains($r.Path)
                            }

                            # Persisted "have we seen this before" history: a flat set of SHA-1
                            # hashes that have ever belonged to a size>=2 cluster in ANY prior run
                            # against this report directory. Loaded BEFORE this run's hashes are
                            # merged in, so a cluster only counts as previously-seen if it overlaps
                            # a run from before today, not itself. Lives next to the NSRL cache -
                            # same "per case folder" scoping.
                            $clusterHistoryPath = Join-Path $Config.ReportDirectory '.bsifter-ssdeep-cluster-history.txt'
                            $historyHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                            if (Test-Path -LiteralPath $clusterHistoryPath -PathType Leaf) {
                                foreach ($line in [System.IO.File]::ReadAllLines($clusterHistoryPath)) {
                                    if (-not [string]::IsNullOrWhiteSpace($line)) { $null = $historyHashes.Add($line.Trim()) }
                                }
                            }

                            $clusterSizes = @{}
                            $recordsByCluster = @{}
                            foreach ($r in $recordList) {
                                if ($r.SsdeepClusterId -ge 0 -and $r.SsdeepClusterSize -ge 2) {
                                    $clusterSizes[$r.SsdeepClusterId] = $r.SsdeepClusterSize
                                    if (-not $recordsByCluster.ContainsKey($r.SsdeepClusterId)) {
                                        $recordsByCluster[$r.SsdeepClusterId] = [System.Collections.Generic.List[BinSifter.FileRecord]]::new()
                                    }
                                    $recordsByCluster[$r.SsdeepClusterId].Add($r)
                                }
                            }

                            $numClusters = $clusterSizes.Count
                            $largestClusterId = -1
                            $largestClusterSize = 0
                            foreach ($kvp in $clusterSizes.GetEnumerator()) {
                                if ($kvp.Value -gt $largestClusterSize) {
                                    $largestClusterSize = $kvp.Value
                                    $largestClusterId = $kvp.Key
                                }
                            }

                            $singletons = @($recordList | Where-Object { $_.SsdeepClusterSize -eq 1 }).Count

                            $avgScore = 0.0
                            if ($allMatches.Count -gt 0) {
                                $scoreSum = 0.0
                                foreach ($m in $allMatches) { $scoreSum += $m.Score }
                                $avgScore = $scoreSum / $allMatches.Count
                            }

                            $filesAbove85 = $highSimPaths.Count

                            $previouslySeenClusterCount = 0
                            foreach ($clusterId in $clusterSizes.Keys) {
                                $seenBefore = $false
                                $memberRecords = $recordsByCluster[$clusterId]
                                foreach ($member in $memberRecords) {
                                    if ($member.SHA1 -and $historyHashes.Contains($member.SHA1)) {
                                        $seenBefore = $true
                                        break
                                    }
                                }
                                if ($seenBefore) {
                                    $previouslySeenClusterCount++
                                    foreach ($member in $memberRecords) { $member.SsdeepPreviouslySeen = $true }
                                }
                            }

                            # Only size>=2 clusters feed history - a singleton doesn't establish a
                            # "family" worth remembering across runs.
                            foreach ($r in $recordList) {
                                if ($r.SsdeepClusterSize -ge 2 -and $r.SHA1) { $null = $historyHashes.Add($r.SHA1) }
                            }
                            try {
                                [System.IO.File]::WriteAllLines($clusterHistoryPath, $historyHashes)
                            }
                            catch {
                                Add-Log2 "Could not update SSDEEP cluster history file: $($_.Exception.Message)"
                            }

                            $ScanControl.SsdeepMetrics = [pscustomobject]@{
                                NumClusters            = $numClusters
                                LargestClusterSize     = $largestClusterSize
                                LargestClusterId       = $largestClusterId
                                Singletons             = $singletons
                                AvgScore               = [Math]::Round($avgScore, 1)
                                FilesAbove85           = $filesAbove85
                                PreviouslySeenClusters = $previouslySeenClusterCount
                                TotalHashedFiles       = $ssdeepTargets.Count
                            }

                            Add-Log2 "SSDEEP clustering summary: $numClusters cluster(s), largest $largestClusterSize file(s), $singletons singleton(s), $previouslySeenClusterCount previously-seen cluster(s)."

                            Remove-Item -LiteralPath $sigListPath -Force -ErrorAction SilentlyContinue
                        }
                        else {
                            Add-Log2 'Skipping SSDEEP clustering - fewer than 2 hashed files, or ssdeep.exe not configured.'
                        }
                    }
                    catch {
                        Add-Log2 "SSDEEP clustering skipped due to error: $($_.Exception.Message)"
                    }

                    # ================= Imphash clustering (v1.3-proto1) =================
                    # Exact-match grouping (not fuzzy like ssdeep above) - files sharing an
                    # imphash linked the exact same API set in the exact same order, which
                    # survives a repack/recompile that would change ssdeep's fuzzy score.
                    # A second, independent clustering signal over the same batch.
                    try {
                        $pathToImphash = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                        foreach ($r in $recordList) {
                            if (-not [string]::IsNullOrWhiteSpace($r.Imphash)) { $pathToImphash[$r.Path] = $r.Imphash }
                        }
                        if ($pathToImphash.Count -ge 2) {
                            $imphashClusterMap = [BinSifter.ImphashClusterer]::BuildClusters($pathToImphash)
                            foreach ($r in $recordList) {
                                if ($imphashClusterMap.ContainsKey($r.Path)) {
                                    $iinfo = $imphashClusterMap[$r.Path]
                                    $r.ImphashClusterId = $iinfo.ClusterId
                                    $r.ImphashClusterSize = $iinfo.Size
                                    # ImphashClusterId/Size are only known after this
                                    # whole-batch pass, unlike the per-file fields the
                                    # dashboard's dirty-queue diffing normally reacts to
                                    # as each worker finishes - re-enqueue affected paths
                                    # now so the next refresh tick picks up the new
                                    # cluster membership via the same mechanism.
                                    $UiDirtyQueue.Enqueue($r.Path)
                                }
                            }
                            $imphashClusterCount = @($recordList | Where-Object { $_.ImphashClusterId -ge 0 } | ForEach-Object { $_.ImphashClusterId } | Select-Object -Unique).Count
                            if ($imphashClusterCount -gt 0) {
                                Add-Log2 "Imphash clustering summary: $imphashClusterCount cluster(s) among $($pathToImphash.Count) PE file(s) with a computed imphash."
                            }
                        }
                    }
                    catch {
                        Add-Log2 "Imphash clustering skipped due to error: $($_.Exception.Message)"
                    }

                    # ================= Draft YARA rule generation (v1.3-proto1) =================
                    # Best-effort, clearly-labeled-as-draft rules built from strings common to
                    # every member of a size>=2 SSDEEP cluster (only available for cluster
                    # members that went through the PossibleFalseNegative FLOSS fallback, or
                    # otherwise had FLOSS run - many won't, so this often has little or nothing
                    # to work with and that's expected, not a bug). Written to a folder for
                    # manual review before ever being folded into the real ruleset - never
                    # auto-imported into $Config.CapaRules/$Config.YaraRules by this app.
                    try {
                        if ($recordsByCluster -and $recordsByCluster.Count -gt 0) {
                            $generatedDir = Join-Path $Config.ReportDirectory 'generated_rules'
                            $null = New-Item -ItemType Directory -Path $generatedDir -Force -ErrorAction SilentlyContinue
                            $rulesWritten = 0

                            foreach ($clusterId in $recordsByCluster.Keys) {
                                $members = $recordsByCluster[$clusterId]
                                if ($members.Count -lt 2) { continue }

                                # Pull FLOSS static strings (if the report exists on disk for this
                                # member - not every cluster member necessarily went through FLOSS)
                                # per member, then intersect across all members that had any.
                                $perMemberStrings = [System.Collections.Generic.List[System.Collections.Generic.HashSet[string]]]::new()
                                foreach ($member in $members) {
                                    if (-not $member.SHA1) { continue }
                                    $flossReportPath = Join-Path $flossReportsDir "$($member.SHA1).json"
                                    if (-not (Test-Path -LiteralPath $flossReportPath -PathType Leaf)) { continue }
                                    try {
                                        $mj = Get-Content -LiteralPath $flossReportPath -Raw | ConvertFrom-Json -ErrorAction Stop
                                        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                                        if ($mj.strings -and $mj.strings.PSObject.Properties.Name -contains 'static_strings') {
                                            foreach ($entry in @($mj.strings.static_strings)) {
                                                $sval = if ($entry.string) { $entry.string } else { "$entry" }
                                                if ($sval -and $sval.Length -ge 8 -and $sval.Length -le 128) { $null = $set.Add($sval) }
                                            }
                                        }
                                        if ($set.Count -gt 0) { $perMemberStrings.Add($set) }
                                    }
                                    catch { }
                                }

                                $commonStrings = @()
                                if ($perMemberStrings.Count -ge 2) {
                                    $intersection = [System.Collections.Generic.HashSet[string]]::new($perMemberStrings[0], [System.StringComparer]::Ordinal)
                                    for ($si = 1; $si -lt $perMemberStrings.Count; $si++) { $intersection.IntersectWith($perMemberStrings[$si]) }
                                    $commonStrings = @($intersection | Select-Object -First 12)
                                }

                                $minSize = ($members | Measure-Object -Property @{Expression={ (Get-Item -LiteralPath $_.Path -ErrorAction SilentlyContinue).Length }} -Minimum).Minimum
                                $maxSize = ($members | Measure-Object -Property @{Expression={ (Get-Item -LiteralPath $_.Path -ErrorAction SilentlyContinue).Length }} -Maximum).Maximum
                                $sizeCondition = if ($minSize -and $maxSize) { "filesize >= $([Math]::Max(0, $minSize - 4096)) and filesize <= $($maxSize + 4096)" } else { $null }

                                $ruleName = "bsifter_ssdeep_cluster_${clusterId}_$timestamp" -replace '[^a-zA-Z0-9_]', '_'
                                $lines = [System.Collections.Generic.List[string]]::new()
                                $lines.Add("// AUTO-GENERATED DRAFT - review before use. BinSifter v1.3-proto1.")
                                $lines.Add("// Built from SSDEEP cluster $clusterId ($($members.Count) files, threshold $ssdeepClusterThreshold).")
                                $lines.Add("// Common-string basis: $($commonStrings.Count) string(s) shared across FLOSS-analyzed cluster members.")
                                $lines.Add("rule $ruleName")
                                $lines.Add('{')
                                $lines.Add('    meta:')
                                $lines.Add('        source = "BinSifter auto-generated - DRAFT, not reviewed"')
                                $lines.Add("        cluster_size = $($members.Count)")
                                $lines.Add("        generated = `"$timestamp`"")
                                if ($commonStrings.Count -gt 0) {
                                    $lines.Add('    strings:')
                                    for ($si = 0; $si -lt $commonStrings.Count; $si++) {
                                        $escaped = $commonStrings[$si].Replace('\', '\\').Replace('"', '\"')
                                        $lines.Add("        `$s$si = `"$escaped`"")
                                    }
                                    $lines.Add('    condition:')
                                    $cond = "uint16(0) == 0x5A4D and " + (if ($sizeCondition) { "$sizeCondition and " } else { '' }) + "(3 of them)"
                                    $lines.Add("        $cond")
                                }
                                else {
                                    # No shared strings found (no cluster member had a FLOSS report,
                                    # or nothing survived the intersection) - fall back to a filesize-
                                    # range-only skeleton that's explicitly flagged as needing manual
                                    # work rather than silently omitting the rule.
                                    $lines.Add('    condition:')
                                    $fallbackCond = "uint16(0) == 0x5A4D" + (if ($sizeCondition) { " and $sizeCondition" } else { '' })
                                    $lines.Add("        $fallbackCond // TODO: no common strings found - add real detection logic before use")
                                }
                                $lines.Add('}')

                                $ruleFilePath = Join-Path $generatedDir "$ruleName.yar"
                                [System.IO.File]::WriteAllLines($ruleFilePath, $lines)
                                $rulesWritten++
                            }

                            if ($rulesWritten -gt 0) {
                                Add-Log2 "Generated $rulesWritten draft YARA rule(s) from SSDEEP clusters - review under: $generatedDir"
                            }
                        }
                    }
                    catch {
                        Add-Log2 "Draft YARA rule generation skipped due to error: $($_.Exception.Message)"
                    }

                    $csvPath = Join-Path $Config.ReportDirectory "BinSifter_Triage_$timestamp.csv"
                    [BinSifter.CsvWriter]::WriteReport($csvPath, $recordList, 'full')
                    $ScanControl.ReportPath = $csvPath
                    Add-Log2 "Full report saved: $csvPath"

                    $suspiciousPath = Join-Path $Config.ReportDirectory "suspicious_unknown_$timestamp.csv"
                    [BinSifter.CsvWriter]::WriteReport($suspiciousPath, $recordList, 'suspicious')
                    Add-Log2 "Suspicious/unknown (non-NSRL) list saved: $suspiciousPath"

                    $yaraMatchesPath = Join-Path $Config.ReportDirectory "yara_matches_$timestamp.csv"
                    [BinSifter.CsvWriter]::WriteReport($yaraMatchesPath, $recordList, 'yara')
                    Add-Log2 "YARA matches list saved: $yaraMatchesPath"

                    $capaCompatiblePath = Join-Path $Config.ReportDirectory "capa_compatible_$timestamp.csv"
                    [BinSifter.CsvWriter]::WriteReport($capaCompatiblePath, $recordList, 'capa')
                    Add-Log2 "Capa-compatible list saved: $capaCompatiblePath"
                    Add-Log2 "Capa JSON reports saved under: $capaReportsDir"
                }
                catch {
                    if ($_.Exception.Message -notin @('stopped-before-enumeration', 'nothing-to-scan')) {
                        Add-Log2 "Scan engine error: $($_.Exception.Message)"
                    }
                }
                finally {
                    $ScanControl.IsRunning = $false
                    $ScanControl.Completed = $true
                }
            })

            $null = $dispatcherPs.AddArgument($Config)
            $null = $dispatcherPs.AddArgument($ThrottleLimit)
            $null = $dispatcherPs.AddArgument($FileRecords)
            $null = $dispatcherPs.AddArgument($UiDirtyQueue)
            $null = $dispatcherPs.AddArgument($ScanControl)
            $null = $dispatcherPs.AddArgument($LogQueue)
            $null = $dispatcherPs.AddArgument($WorkerScriptBlock)

            $handle = $dispatcherPs.BeginInvoke()
            return [pscustomobject]@{ PS = $dispatcherPs; Handle = $handle; Runspace = $dispatcherRunspace; Disposed = $false }
        }

        # ================= Main form shell =================
        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'BinSifter'
        $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
        $form.Size = New-Object System.Drawing.Size(1400, 900)
        $form.Font = New-Object System.Drawing.Font('Segoe UI', 10)
        $form.BackColor = $theme.WindowBack
        $form.ForeColor = $theme.Fore
        $form.MinimumSize = New-Object System.Drawing.Size(1200, 760)
        $windowIconBitmap = $null
        $windowIcon = $null
        $windowIconHandle = [IntPtr]::Zero
        if ($WindowIconPath -and (Test-Path -LiteralPath $WindowIconPath -PathType Leaf)) {
            try {
                $sourceIconImage = [System.Drawing.Image]::FromFile($WindowIconPath)
                try {
                    $windowIconBitmap = New-Object System.Drawing.Bitmap(64, 64)
                    $iconGraphics = [System.Drawing.Graphics]::FromImage($windowIconBitmap)
                    try {
                        $iconGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                        $iconGraphics.DrawImage($sourceIconImage, 0, 0, 64, 64)
                    }
                    finally { $iconGraphics.Dispose() }
                    # Older copies of the artwork used a solid backdrop; current
                    # copies already contain alpha. Only apply a color key when the
                    # corner is actually opaque, otherwise black subject outlines
                    # could be mistaken for the transparent corner's RGB value.
                    $cornerColor = $windowIconBitmap.GetPixel(0, 0)
                    if ($cornerColor.A -eq 255) {
                        $windowIconBitmap.MakeTransparent($cornerColor)
                    }
                    $windowIconHandle = $windowIconBitmap.GetHicon()
                    $windowIcon = [System.Drawing.Icon]::FromHandle($windowIconHandle)
                    $form.Icon = $windowIcon
                    $form.ShowIcon = $true
                }
                finally { $sourceIconImage.Dispose() }
            }
            catch {
                Add-Log "Window icon could not be loaded: $($_.Exception.Message)"
            }
        }

        $sidebar = New-Object System.Windows.Forms.Panel
        $sidebar.Dock = [System.Windows.Forms.DockStyle]::Left
        $sidebar.Width = 300
        $sidebar.BackColor = $theme.SidebarBack

        $sidebarLogo = Import-ThemedLogo -Path $LogoHorizontalPath -Width 275
        if ($sidebarLogo) {
            $sidebarLogo.Location = New-Object System.Drawing.Point(12, 18)
            $sidebar.Controls.Add($sidebarLogo)
        }

        $navPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $navPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $navPanel.WrapContents = $false
        $navPanel.Location = New-Object System.Drawing.Point(0, 150)
        $navPanel.Size = New-Object System.Drawing.Size(300, 600)
        $navPanel.BackColor = $theme.SidebarBack
        $sidebar.Controls.Add($navPanel)

        $topBar = New-Object System.Windows.Forms.Panel
        $topBar.Dock = [System.Windows.Forms.DockStyle]::Top
        $topBar.Height = 72
        $topBar.BackColor = $theme.HeaderBack

        $lblPageTitle = New-Object System.Windows.Forms.Label
        $lblPageTitle.AutoSize = $true
        $lblPageTitle.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
        $lblPageTitle.ForeColor = $theme.Fore
        $lblPageTitle.Location = New-Object System.Drawing.Point(28, 20)
        $topBar.Controls.Add($lblPageTitle)

        $lblStatusDot = New-Object System.Windows.Forms.Label
        $lblStatusDot.AutoSize = $true
        $lblStatusDot.Font = New-Object System.Drawing.Font('Segoe UI', 11)
        $lblStatusDot.Text = [char]0x25CF
        $lblStatusDot.ForeColor = $theme.Success
        $topBar.Controls.Add($lblStatusDot)

        $lblStatusText = New-Object System.Windows.Forms.Label
        $lblStatusText.AutoSize = $true
        $lblStatusText.Font = New-Object System.Drawing.Font('Segoe UI', 11.5)
        $lblStatusText.Text = 'Ready'
        $lblStatusText.ForeColor = $theme.Fore
        $topBar.Controls.Add($lblStatusText)

        $topStatusDivider = New-Object System.Windows.Forms.Panel
        $topStatusDivider.Size = New-Object System.Drawing.Size(1, 30)
        $topStatusDivider.BackColor = $theme.Border
        $topBar.Controls.Add($topStatusDivider)

        function New-TopBarButton {
            param([string]$Text, [int]$Width)
            $button = New-Object System.Windows.Forms.Button
            $button.Text = $Text
            $button.Size = New-Object System.Drawing.Size($Width, 44)
            $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $button.FlatAppearance.BorderSize = 0
            $button.BackColor = $theme.HeaderBack
            $button.ForeColor = $theme.Fore
            $button.Font = New-Object System.Drawing.Font('Segoe UI', 11.5)
            $button.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
            $button.Cursor = [System.Windows.Forms.Cursors]::Hand
            return $button
        }

        $btnTopSettings = New-TopBarButton -Text "$([char]0x2699)  Settings" -Width 126
        $btnTopHelp = New-TopBarButton -Text "$([char]0x003F)  Help" -Width 96
        $btnTopAbout = New-TopBarButton -Text "$([char]0x24D8)  About" -Width 106
        $topBar.Controls.Add($btnTopSettings)
        $topBar.Controls.Add($btnTopHelp)
        $topBar.Controls.Add($btnTopAbout)

        $statusBar = New-Object System.Windows.Forms.Panel
        $statusBar.Dock = [System.Windows.Forms.DockStyle]::Bottom
        $statusBar.Height = 40
        $statusBar.BackColor = $theme.HeaderBack

        $lblStatusBar = New-Object System.Windows.Forms.Label
        $lblStatusBar.AutoSize = $true
        $lblStatusBar.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $lblStatusBar.ForeColor = $theme.MutedFore
        $lblStatusBar.Location = New-Object System.Drawing.Point(24, 11)
        $lblStatusBar.Text = "BinSifter $AppVersion"
        $statusBar.Controls.Add($lblStatusBar)

        $content = New-Object System.Windows.Forms.Panel
        $content.Dock = [System.Windows.Forms.DockStyle]::Fill
        $content.BackColor = $theme.WindowBack
        $content.Padding = New-Object System.Windows.Forms.Padding(28, 24, 28, 24)

        $form.Controls.Add($content)
        $form.Controls.Add($topBar)
        $form.Controls.Add($sidebar)
        # Add the footer last so Dock=Bottom is calculated against the complete
        # window, not only the area remaining to the right of the sidebar.
        $form.Controls.Add($statusBar)

        function Move-TopBarControls {
            $lblStatusText.Location = New-Object System.Drawing.Point(($topBar.Width - $lblStatusText.Width - 24), 24)
            $lblStatusDot.Location = New-Object System.Drawing.Point(($lblStatusText.Left - $lblStatusDot.Width - 10), 25)
            $topStatusDivider.Location = New-Object System.Drawing.Point(($lblStatusDot.Left - 20), 21)
            $btnTopAbout.Location = New-Object System.Drawing.Point(($topStatusDivider.Left - $btnTopAbout.Width - 12), 14)
            $btnTopHelp.Location = New-Object System.Drawing.Point(($btnTopAbout.Left - $btnTopHelp.Width - 8), 14)
            $btnTopSettings.Location = New-Object System.Drawing.Point(($btnTopHelp.Left - $btnTopSettings.Width - 8), 14)
        }
        $topBar.Add_Resize({ Move-TopBarControls })

        # ================= Page: Dashboard =================
        function New-DashboardPage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.BackColor = $theme.WindowBack
            # The heat map row added below pushes total content past the window's
            # MinimumSize height, so this needs to scroll rather than clip.
            $page.AutoScroll = $true

            $tileRow = New-Object System.Windows.Forms.TableLayoutPanel
            $tileRow.Dock = [System.Windows.Forms.DockStyle]::Top
            $tileRow.Height = 150
            $tileRow.ColumnCount = 5
            $tileRow.RowCount = 1
            for ($i = 0; $i -lt 5; $i++) {
                $null = $tileRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 20)))
            }
            $page.Controls.Add($tileRow)

            function New-StatTile {
                param(
                    [string]$Caption,
                    [System.Drawing.Color]$AccentColor,
                    [string]$IconName = 'file',
                    [string]$Subtitle = '',
                    [switch]$Compact
                )

                $card = New-Object System.Windows.Forms.Panel
                $card.Margin = New-Object System.Windows.Forms.Padding(0, 0, 16, 0)
                $card.BackColor = $theme.SurfaceBack
                $card.Dock = [System.Windows.Forms.DockStyle]::Fill
                $card.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

                $lblCaption = New-Object System.Windows.Forms.Label
                $lblCaption.Text = $Caption
                $lblCaption.AutoSize = $true
                $lblCaption.Font = New-Object System.Drawing.Font('Segoe UI', 10)
                $lblCaption.ForeColor = $theme.MutedFore
                $lblCaption.Location = New-Object System.Drawing.Point(18, 14)
                $card.Controls.Add($lblCaption)

                $lblValue = New-Object System.Windows.Forms.Label
                $lblValue.Text = '0'
                $lblValue.AutoSize = $true
                $lblValue.ForeColor = $AccentColor
                $iconBox = New-Object System.Windows.Forms.PictureBox
                $iconBox.Image = New-LineIconBitmap -Name $IconName -Color $AccentColor
                $iconBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
                $iconBox.BackColor = [System.Drawing.Color]::Transparent
                if ($Compact) {
                    $lblCaption.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
                    $lblCaption.Location = New-Object System.Drawing.Point(10, 10)
                    $iconBox.Size = New-Object System.Drawing.Size(38, 38)
                    $iconBox.Location = New-Object System.Drawing.Point(10, 48)
                    $lblValue.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 23)
                    $lblValue.Location = New-Object System.Drawing.Point(54, 50)
                }
                else {
                    $iconBox.Size = New-Object System.Drawing.Size(48, 48)
                    $iconBox.Location = New-Object System.Drawing.Point(16, 47)
                    $lblValue.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 25)
                    $lblValue.Location = New-Object System.Drawing.Point(70, 48)

                    $lblSubtitle = New-Object System.Windows.Forms.Label
                    $lblSubtitle.Text = $Subtitle
                    $lblSubtitle.AutoSize = $true
                    $lblSubtitle.Font = New-Object System.Drawing.Font('Segoe UI', 8)
                    $lblSubtitle.ForeColor = $theme.MutedFore
                    $lblSubtitle.Location = New-Object System.Drawing.Point(72, 87)
                    $card.Controls.Add($lblSubtitle)
                }
                $card.Controls.Add($iconBox)
                $card.Controls.Add($lblValue)

                return [pscustomobject]@{ Card = $card; Value = $lblValue }
            }

            $tileFiles = New-StatTile -Caption 'Files Completed' -AccentColor $theme.Accent -IconName 'file' -Subtitle 'Total files processed'
            $tileYara = New-StatTile -Caption 'YARA Hits' -AccentColor $theme.Warning -IconName 'target' -Subtitle 'Matching rules found'
            $tileCapaScans = New-StatTile -Caption 'Capa Scans' -AccentColor $theme.Accent -IconName 'layers' -Subtitle 'Files analyzed'
            $tileCapa = New-StatTile -Caption 'Capa Rule Detections' -AccentColor $theme.Accent -IconName 'check' -Subtitle 'Capabilities identified'
            $tileNsrl = New-StatTile -Caption 'NSRL Matches' -AccentColor $theme.Accent -IconName 'database' -Subtitle 'Known file matches'

            $tileRow.Controls.Add($tileFiles.Card, 0, 0)
            $tileRow.Controls.Add($tileYara.Card, 1, 0)
            $tileRow.Controls.Add($tileCapaScans.Card, 2, 0)
            $tileRow.Controls.Add($tileCapa.Card, 3, 0)
            $tileRow.Controls.Add($tileNsrl.Card, 4, 0)
            # The final card has no trailing gutter, so this row and the chart
            # panels below share the exact same left/right boundaries.
            $tileNsrl.Card.Margin = New-Object System.Windows.Forms.Padding(0)

            # Wires a tile (its Card panel and every child label, so clicking the
            # number itself works too) to jump to Results filtered by Predicate.
            # Show-FilteredResults is defined later in the script, in the page-
            # wiring section - fine, since $handler only runs on click, by which
            # point the whole script (and every function in it) has already run
            # once and is available. GetNewClosure() is needed here because
            # $FilterLabel/$Predicate are this function's own parameters, and
            # without it the click handler would look them up fresh (and fail to
            # find them) at click time instead of using the values passed in now.
            function Add-DashboardTileClick {
                param($Tile, [string]$FilterLabel, [scriptblock]$Predicate)
                $handler = { Show-FilteredResults -FilterLabel $FilterLabel -Predicate $Predicate }.GetNewClosure()
                $Tile.Card.Cursor = [System.Windows.Forms.Cursors]::Hand
                $Tile.Card.Add_Click($handler)
                foreach ($ctrl in @($Tile.Card.Controls)) {
                    $ctrl.Cursor = [System.Windows.Forms.Cursors]::Hand
                    $ctrl.Add_Click($handler)
                }
            }

            Add-DashboardTileClick -Tile $tileYara -FilterLabel 'YARA Hits' `
                -Predicate { param($r) $r.YaraHitCount -gt 0 }
            Add-DashboardTileClick -Tile $tileCapaScans -FilterLabel 'Capa Scans' `
                -Predicate { param($r) $r.CapaEligible }
            Add-DashboardTileClick -Tile $tileCapa -FilterLabel 'Capa Rule Detections' `
                -Predicate { param($r) $r.CapaDetectionCount -gt 0 }
            Add-DashboardTileClick -Tile $tileNsrl -FilterLabel 'NSRL Matches' `
                -Predicate { param($r) $r.NsrlMatch }

            # Second row: worst-case YARA severity breakdown, one file counted
            # once under its highest-severity match, drawn as a small bar chart.
            # "Unknown" is a first-class bucket, not hidden - it means no matched
            # rule carried a recognizable severity field, which is itself worth
            # seeing rather than silently folding into another bucket.
            # There's no bundled charting control under PowerShell 7/.NET (the
            # classic System.Windows.Forms.DataVisualization chart is a .NET
            # Framework-only control), so this is drawn directly with GDI+ on a
            # plain Panel's Paint event - no extra dependency required.
            $severityChartOrder = @('Critical', 'High', 'Medium', 'Low', 'Unknown')
            $severityChartColors = [ordered]@{
                Critical = [System.Drawing.Color]::FromArgb(239, 68, 68)
                High     = [System.Drawing.Color]::FromArgb(245, 158, 11)
                Medium   = [System.Drawing.Color]::FromArgb(31, 174, 255)
                Low      = [System.Drawing.Color]::FromArgb(83, 201, 91)
                Unknown  = [System.Drawing.Color]::FromArgb(119, 129, 142)
            }
            $severityChartData = [ordered]@{
                Critical = 0; High = 0; Medium = 0; Low = 0; Unknown = 0
            }
            # Populated by the Paint handler below (one Rectangle per bar, using
            # the full column height rather than just the filled bar height, so a
            # short/zero bar is still a fair-sized click target) and read by the
            # MouseClick handler further down - both closures share this same
            # hashtable instance via GetNewClosure(), so mutations from Paint are
            # visible to the click handler without any extra plumbing.
            $severityBarRects = @{}

            $severityChartPanel = New-Object System.Windows.Forms.Panel
            $severityChartPanel.Dock = [System.Windows.Forms.DockStyle]::Top
            $severityChartPanel.Height = 220
            $severityChartPanel.Margin = New-Object System.Windows.Forms.Padding(0, 16, 0, 0)
            $severityChartPanel.BackColor = $theme.SurfaceBack
            $severityChartPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

            # GetNewClosure() snapshot-binds $severityChartData/$severityChartColors/
            # $theme/$severityChartOrder into this scriptblock. Without it, a bare
            # Paint handler resolves variable names against whatever scope is active
            # when WinForms actually fires the event (not this function's scope,
            # which is long gone by then), and would fail to find them.
            $severityPaintHandler = {
                param($senderCtrl, $e)
                $g = $e.Graphics
                $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

                $titleFont = New-Object System.Drawing.Font('Segoe UI', 10)
                $valueFont = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
                $captionFont = New-Object System.Drawing.Font('Segoe UI', 9)
                $axisFont = New-Object System.Drawing.Font('Segoe UI', 8)
                $foreBrush = New-Object System.Drawing.SolidBrush($theme.Fore)
                $mutedBrush = New-Object System.Drawing.SolidBrush($theme.MutedFore)
                $gridPen = New-Object System.Drawing.Pen($theme.Border, 1)
                $gridPen.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dot
                $axisPen = New-Object System.Drawing.Pen($theme.MutedFore, 1)

                try {
                    $g.DrawString('YARA Severity Breakdown', $titleFont, $mutedBrush, 18.0, 14.0)

                    $gap = 24
                    $barCount = $severityChartOrder.Count
                    $chartTop = 52
                    $chartBottom = $senderCtrl.Height - 34
                    $chartHeight = $chartBottom - $chartTop
                    $chartLeft = 48
                    $chartRight = $senderCtrl.Width - 16
                    $plotWidth = $chartRight - $chartLeft
                    $barWidth = [Math]::Max(20.0, ([double]($plotWidth - ($gap * ($barCount + 1))) / $barCount))

                    $maxVal = 1
                    foreach ($k in $severityChartOrder) { if ($severityChartData[$k] -gt $maxVal) { $maxVal = $severityChartData[$k] } }
                    $axisMax = [Math]::Max(10, [Math]::Ceiling($maxVal / 10.0) * 10)

                    # Mockup-style measured Y axis: five equal intervals, tick
                    # labels, and subtle dotted guide lines across the plot.
                    for ($tick = 0; $tick -le 5; $tick++) {
                        $tickValue = [int]($axisMax * $tick / 5.0)
                        $tickY = [float]($chartBottom - ($chartHeight * $tick / 5.0))
                        $g.DrawLine($gridPen, [float]$chartLeft, $tickY, [float]$chartRight, $tickY)
                        $g.DrawLine($axisPen, [float]($chartLeft - 5), $tickY, [float]$chartLeft, $tickY)
                        $tickText = "$tickValue"
                        $tickSize = $g.MeasureString($tickText, $axisFont)
                        $g.DrawString($tickText, $axisFont, $mutedBrush, [float]($chartLeft - $tickSize.Width - 8), [float]($tickY - ($tickSize.Height / 2)))
                    }
                    $g.DrawLine($axisPen, [float]$chartLeft, [float]$chartTop, [float]$chartLeft, [float]$chartBottom)

                    $x = [double]($chartLeft + $gap)
                    foreach ($key in $severityChartOrder) {
                        $val = $severityChartData[$key]
                        $barHeight = [double]$val / [double]$axisMax * $chartHeight
                        if ($val -gt 0 -and $barHeight -lt 3) { $barHeight = 3 }
                        $y = $chartBottom - $barHeight

                        $barBrush = New-Object System.Drawing.SolidBrush($severityChartColors[$key])
                        try { $g.FillRectangle($barBrush, [float]$x, [float]$y, [float]$barWidth, [float]$barHeight) }
                        finally { $barBrush.Dispose() }

                        $valStr = "$val"
                        $valSize = $g.MeasureString($valStr, $valueFont)
                        $g.DrawString($valStr, $valueFont, $foreBrush, [float]($x + ($barWidth - $valSize.Width) / 2), [float]($y - $valSize.Height - 2))

                        $capSize = $g.MeasureString($key, $captionFont)
                        $g.DrawString($key, $captionFont, $mutedBrush, [float]($x + ($barWidth - $capSize.Width) / 2), [float]($chartBottom + 6))

                        $severityBarRects[$key] = New-Object System.Drawing.Rectangle(
                            [int]$x, [int]$chartTop, [int][Math]::Ceiling($barWidth), [int]($chartBottom - $chartTop))

                        $x += $barWidth + $gap
                    }
                }
                finally {
                    $titleFont.Dispose(); $valueFont.Dispose(); $captionFont.Dispose(); $axisFont.Dispose()
                    $foreBrush.Dispose(); $mutedBrush.Dispose()
                    $gridPen.Dispose(); $axisPen.Dispose()
                }
            }.GetNewClosure()

            $severityChartPanel.Add_Paint($severityPaintHandler)
            $severityChartPanel.Add_Resize({ $severityChartPanel.Invalidate() }.GetNewClosure())
            $severityChartPanel.Cursor = [System.Windows.Forms.Cursors]::Hand

            # Hit-tests the click point against whichever bar rectangles the most
            # recent Paint pass computed, then jumps to Results filtered to that
            # severity bucket - same "worst matched-rule severity, only files that
            # actually had a YARA hit" definition the bars themselves count by.
            $severityClickHandler = {
                param($senderCtrl, $e)
                foreach ($key in $severityBarRects.Keys) {
                    if ($severityBarRects[$key].Contains($e.X, $e.Y)) {
                        $sevKey = $key
                        $sevPredicate = { param($r) $r.YaraHitCount -gt 0 -and $r.YaraSeverity -eq $sevKey }.GetNewClosure()
                        Show-FilteredResults -FilterLabel "YARA Severity: $sevKey" -Predicate $sevPredicate
                        return
                    }
                }
            }.GetNewClosure()
            $severityChartPanel.Add_MouseClick($severityClickHandler)

            # ================= SSDEEP cluster heat map =================
            # Six summary numbers from the post-scan clustering pass (see
            # Start-ScanEngine / $ScanControl.SsdeepMetrics), styled like the stat
            # tiles above but with the value's color scaled Success->Warning->
            # Danger by magnitude (relative to total ssdeep-hashed file count, or
            # 0-100 for the average-score tile) - the "heat" in heat map. Six
            # discrete cells rather than a literal pairwise NxN grid, which would
            # be unreadable/impractical to render for a few hundred files (a real
            # scan's cluster CSV can run into the thousands of pairwise rows).
            $heatMapTitle = New-Object System.Windows.Forms.Label
            $heatMapTitle.AutoSize = $true
            $heatMapTitle.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
            $heatMapTitle.ForeColor = $theme.Fore
            $heatMapTitle.Text = 'SSDEEP Cluster Heat Map'
            $heatMapTitle.Margin = New-Object System.Windows.Forms.Padding(0, 20, 0, 8)
            $heatMapTitle.Padding = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
            $heatMapTitle.Dock = [System.Windows.Forms.DockStyle]::Top

            $heatMapRow = New-Object System.Windows.Forms.TableLayoutPanel
            $heatMapRow.Dock = [System.Windows.Forms.DockStyle]::Top
            $heatMapRow.Height = 120
            $heatMapRow.ColumnCount = 6
            $heatMapRow.RowCount = 1
            for ($i = 0; $i -lt 6; $i++) {
                $null = $heatMapRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, (100.0 / 6))))
            }

            $heatClusters       = New-StatTile -Caption 'Similarity Clusters' -AccentColor $theme.Accent -IconName 'cluster' -Compact
            $heatLargest        = New-StatTile -Caption 'Largest Cluster' -AccentColor $theme.Accent -IconName 'users' -Compact
            $heatSingletons     = New-StatTile -Caption 'Singletons' -AccentColor $theme.Accent -IconName 'user' -Compact
            $heatAvgScore       = New-StatTile -Caption 'Avg. Similarity' -AccentColor $theme.Accent -IconName 'percent' -Compact
            $heatAbove85        = New-StatTile -Caption 'Files Above 85%' -AccentColor $theme.Accent -IconName 'trend' -Compact
            $heatPreviouslySeen = New-StatTile -Caption 'Previously Seen Clusters' -AccentColor $theme.Accent -IconName 'history' -Compact

            $heatMapRow.Controls.Add($heatClusters.Card, 0, 0)
            $heatMapRow.Controls.Add($heatLargest.Card, 1, 0)
            $heatMapRow.Controls.Add($heatSingletons.Card, 2, 0)
            $heatMapRow.Controls.Add($heatAvgScore.Card, 3, 0)
            $heatMapRow.Controls.Add($heatAbove85.Card, 4, 0)
            $heatMapRow.Controls.Add($heatPreviouslySeen.Card, 5, 0)
            $heatPreviouslySeen.Card.Margin = New-Object System.Windows.Forms.Padding(0)

            $ssdeepTip = New-Object System.Windows.Forms.ToolTip
            $ssdeepTip.SetToolTip($heatClusters.Card, 'Distinct similarity clusters found in the current scan.')
            $ssdeepTip.SetToolTip($heatPreviouslySeen.Card, 'Current clusters containing at least one file seen in a cluster during an earlier scan in this report directory.')

            # "Average Similarity" has no natural row subset of its own (it's a
            # property of the match set, not of individual files) - clicking it
            # shows the same "any file with at least one match" set as the
            # cluster-count tile, which is the closest honest equivalent.
            Add-DashboardTileClick -Tile $heatClusters -FilterLabel 'SSDEEP clusters (2+ files)' `
                -Predicate { param($r) $r.SsdeepClusterId -ge 0 -and $r.SsdeepClusterSize -ge 2 }
            Add-DashboardTileClick -Tile $heatLargest -FilterLabel 'Largest SSDEEP cluster' `
                -Predicate { param($r) $ScanControl.SsdeepMetrics -and $ScanControl.SsdeepMetrics.LargestClusterId -ge 0 -and $r.SsdeepClusterId -eq $ScanControl.SsdeepMetrics.LargestClusterId }
            Add-DashboardTileClick -Tile $heatSingletons -FilterLabel 'SSDEEP singletons' `
                -Predicate { param($r) $r.SsdeepClusterSize -eq 1 }
            Add-DashboardTileClick -Tile $heatAvgScore -FilterLabel 'Files with any SSDEEP match' `
                -Predicate { param($r) $r.SsdeepClusterId -ge 0 -and $r.SsdeepClusterSize -ge 2 }
            Add-DashboardTileClick -Tile $heatAbove85 -FilterLabel 'SSDEEP similarity >= 85%' `
                -Predicate { param($r) $r.SsdeepHasHighSimilarity }
            Add-DashboardTileClick -Tile $heatPreviouslySeen -FilterLabel 'Previously-seen SSDEEP clusters' `
                -Predicate { param($r) $r.SsdeepPreviouslySeen }

            $summaryPanel = New-Object System.Windows.Forms.Panel
            $summaryPanel.Dock = [System.Windows.Forms.DockStyle]::Top
            $summaryPanel.Height = 90
            $summaryPanel.Margin = New-Object System.Windows.Forms.Padding(0, 20, 0, 0)
            $summaryPanel.BackColor = $theme.SurfaceBack

            $lblSummary = New-Object System.Windows.Forms.Label
            $lblSummary.AutoSize = $true
            $lblSummary.Font = New-Object System.Drawing.Font('Segoe UI', 11)
            $lblSummary.ForeColor = $theme.Fore
            $lblSummary.Location = New-Object System.Drawing.Point(18, 16)
            $lblSummary.Text = "No scan running. Configure Settings, then start a scan from Scan Queue."
            $lblSummary.MaximumSize = New-Object System.Drawing.Size(900, 0)
            $summaryPanel.Controls.Add($lblSummary)

            $spacer = New-Object System.Windows.Forms.Panel
            $spacer.Dock = [System.Windows.Forms.DockStyle]::Top
            $spacer.Height = 32
            $spacer.BackColor = $theme.WindowBack

            $topToSsdeepSpacer = New-Object System.Windows.Forms.Panel
            $topToSsdeepSpacer.Dock = [System.Windows.Forms.DockStyle]::Top
            $topToSsdeepSpacer.Height = 28
            $topToSsdeepSpacer.BackColor = $theme.WindowBack

            # ================= v1.3-proto1 enrichment summary row =================
            # Same shape as the SSDEEP heat map row above (compact New-StatTile
            # cards in a TableLayoutPanel, click-to-filter via Add-DashboardTileClick)
            # for the new per-file signals: imphash clustering, Authenticode status,
            # blocklist reputation, extracted IOCs, and triage disposition. Placed
            # after the existing sections (added last, so it renders at the bottom)
            # rather than interleaved, to leave the dashboard's existing layout the
            # user already reviewed and approved untouched above the fold.
            $enrichmentTitle = New-Object System.Windows.Forms.Label
            $enrichmentTitle.AutoSize = $true
            $enrichmentTitle.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
            $enrichmentTitle.ForeColor = $theme.Fore
            $enrichmentTitle.Text = 'Enrichment Summary'
            $enrichmentTitle.Margin = New-Object System.Windows.Forms.Padding(0, 20, 0, 8)
            $enrichmentTitle.Padding = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
            $enrichmentTitle.Dock = [System.Windows.Forms.DockStyle]::Top

            $enrichmentRow = New-Object System.Windows.Forms.TableLayoutPanel
            $enrichmentRow.Dock = [System.Windows.Forms.DockStyle]::Top
            $enrichmentRow.Height = 120
            $enrichmentRow.ColumnCount = 5
            $enrichmentRow.RowCount = 1
            for ($i = 0; $i -lt 5; $i++) {
                $null = $enrichmentRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, (100.0 / 5))))
            }

            $tileImphash    = New-StatTile -Caption 'Imphash Clusters' -AccentColor $theme.Accent -IconName 'layers' -Compact
            $tileUnsigned   = New-StatTile -Caption 'Unsigned' -AccentColor $theme.Warning -IconName 'check' -Compact
            $tileKnownBad   = New-StatTile -Caption 'Known-Bad' -AccentColor $theme.Danger -IconName 'target' -Compact
            $tileIocs       = New-StatTile -Caption 'Files With IOCs' -AccentColor $theme.Accent -IconName 'document' -Compact
            $tileEscalated  = New-StatTile -Caption 'Escalated' -AccentColor $theme.Danger -IconName 'trend' -Compact

            $enrichmentRow.Controls.Add($tileImphash.Card, 0, 0)
            $enrichmentRow.Controls.Add($tileUnsigned.Card, 1, 0)
            $enrichmentRow.Controls.Add($tileKnownBad.Card, 2, 0)
            $enrichmentRow.Controls.Add($tileIocs.Card, 3, 0)
            $enrichmentRow.Controls.Add($tileEscalated.Card, 4, 0)
            $tileEscalated.Card.Margin = New-Object System.Windows.Forms.Padding(0)

            Add-DashboardTileClick -Tile $tileImphash -FilterLabel 'Imphash clusters (2+ files)' `
                -Predicate { param($r) $r.ImphashClusterId -ge 0 -and $r.ImphashClusterSize -ge 2 }
            Add-DashboardTileClick -Tile $tileUnsigned -FilterLabel 'Unsigned / invalid signature' `
                -Predicate { param($r) $r.SignatureStatus -and $r.SignatureStatus -ne 'Valid' }
            Add-DashboardTileClick -Tile $tileKnownBad -FilterLabel 'Known-bad (blocklist match)' `
                -Predicate { param($r) $r.ReputationStatus -eq 'KnownBad' }
            Add-DashboardTileClick -Tile $tileIocs -FilterLabel 'Files with extracted IOCs' `
                -Predicate { param($r) $r.IocCount -gt 0 }
            Add-DashboardTileClick -Tile $tileEscalated -FilterLabel 'Disposition: Escalated' `
                -Predicate { param($r) $r.Disposition -eq 'Escalated' }

            $page.Controls.Add($summaryPanel)
            $page.Controls.Add($severityChartPanel)
            $page.Controls.Add($spacer)
            $page.Controls.Add($heatMapRow)
            $page.Controls.Add($heatMapTitle)
            $page.Controls.Add($topToSsdeepSpacer)
            $page.Controls.Add($tileRow)
            $page.Controls.Add($enrichmentRow)
            $page.Controls.Add($enrichmentTitle)

            return [pscustomobject]@{
                Page = $page
                TileFiles = $tileFiles.Value
                TileYara = $tileYara.Value
                TileCapaScans = $tileCapaScans.Value
                TileCapa = $tileCapa.Value
                TileNsrl = $tileNsrl.Value
                SeverityChartData = $severityChartData
                SeverityChartPanel = $severityChartPanel
                LblSummary = $lblSummary
                HeatClusters = $heatClusters.Value
                HeatLargest = $heatLargest.Value
                HeatSingletons = $heatSingletons.Value
                HeatAvgScore = $heatAvgScore.Value
                HeatAbove85 = $heatAbove85.Value
                HeatPreviouslySeen = $heatPreviouslySeen.Value
                TileImphash = $tileImphash.Value
                TileUnsigned = $tileUnsigned.Value
                TileKnownBad = $tileKnownBad.Value
                TileIocs = $tileIocs.Value
                TileEscalated = $tileEscalated.Value
            }
        }

        # ================= Page: Scan Queue =================
        function New-ScanQueuePage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.BackColor = $theme.WindowBack

            $toolbar = New-Object System.Windows.Forms.FlowLayoutPanel
            $toolbar.Dock = [System.Windows.Forms.DockStyle]::Top
            $toolbar.Height = 50
            $toolbar.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
            $toolbar.BackColor = $theme.WindowBack

            $btnStart = New-ThemedButton -Text "$([char]0x25B6)  Start Scan" -Width 140 -Primary
            $btnPause = New-ThemedButton -Text "$([char]0x23F8)  Pause" -Width 110
            $btnStop = New-ThemedButton -Text "$([char]0x25A0)  Stop" -Width 110
            $btnClear = New-ThemedButton -Text "$([char]0x2715)  Clear Completed" -Width 165

            $btnPause.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
            $btnStop.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
            $btnClear.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)

            $toolbar.Controls.Add($btnStart)
            $toolbar.Controls.Add($btnPause)
            $toolbar.Controls.Add($btnStop)
            $toolbar.Controls.Add($btnClear)

            $lblSummary = New-Object System.Windows.Forms.Label
            $lblSummary.AutoSize = $true
            $lblSummary.Font = New-Object System.Drawing.Font('Segoe UI', 9)
            $lblSummary.ForeColor = $theme.MutedFore
            $lblSummary.Dock = [System.Windows.Forms.DockStyle]::Top
            $lblSummary.Padding = New-Object System.Windows.Forms.Padding(2, 8, 0, 8)
            $lblSummary.Text = 'No files queued.'

            $grid = New-Object System.Windows.Forms.DataGridView
            $grid.Dock = [System.Windows.Forms.DockStyle]::Fill
            $grid.AutoGenerateColumns = $false
            $grid.AllowUserToAddRows = $false
            $grid.AllowUserToDeleteRows = $false
            $grid.ReadOnly = $true
            $grid.RowHeadersVisible = $false
            $grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
            $grid.BackgroundColor = $theme.SurfaceBack
            $grid.GridColor = $theme.Border
            $grid.BorderStyle = [System.Windows.Forms.BorderStyle]::None
            $grid.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::AutoSize
            $grid.EnableHeadersVisualStyles = $false
            $grid.ColumnHeadersDefaultCellStyle.BackColor = $theme.SurfaceBack
            $grid.ColumnHeadersDefaultCellStyle.ForeColor = $theme.MutedFore
            $grid.ColumnHeadersHeight = 42
            $grid.RowTemplate.Height = 38
            $grid.DefaultCellStyle.BackColor = $theme.SurfaceBack
            $grid.DefaultCellStyle.ForeColor = $theme.Fore
            $grid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(6, 0, 6, 0)
            $grid.DefaultCellStyle.SelectionBackColor = $theme.NavActive
            $grid.DefaultCellStyle.SelectionForeColor = $theme.Fore

            $columnDefs = @(
                @{ Name = 'Path'; Header = 'File Path'; Width = 420 }
                @{ Name = 'Status'; Header = 'Status'; Width = 110 }
                @{ Name = 'Progress'; Header = 'Progress'; Width = 90 }
                @{ Name = 'YaraHits'; Header = 'YARA Hits'; Width = 90 }
                @{ Name = 'YaraSeverity'; Header = 'YARA Severity'; Width = 110 }
                @{ Name = 'CapaDetections'; Header = 'Capa Detections'; Width = 130 }
                @{ Name = 'PossibleFalseNegative'; Header = 'Poss. False Neg.'; Width = 120 }
                @{ Name = 'NsrlMatch'; Header = 'NSRL Match'; Width = 100 }
                @{ Name = 'Added'; Header = 'Added'; Width = 140 }
            )
            foreach ($colDef in $columnDefs) {
                $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
                $col.Name = $colDef.Name
                $col.HeaderText = $colDef.Header
                $col.Width = $colDef.Width
                $null = $grid.Columns.Add($col)
            }

            # Concept-style row glyphs and a real graphical progress track. These
            # are display-only handlers; the underlying cell values and scan state
            # remain unchanged.
            $grid.Add_CellFormatting({
                param($senderCtrl, $e)
                if ($e.RowIndex -lt 0) { return }
                $columnName = $senderCtrl.Columns[$e.ColumnIndex].Name
                if ($columnName -eq 'Path' -and $e.Value) {
                    $e.Value = "$([char]0x2699)  $($e.Value)"
                    $e.FormattingApplied = $true
                }
                elseif ($columnName -eq 'Status' -and $e.Value) {
                    switch ([string]$e.Value) {
                        'Completed' { $e.Value = "$([char]0x2714)  Completed"; $e.CellStyle.ForeColor = $theme.Success }
                        'Scanning'  { $e.Value = "$([char]0x25D4)  Scanning";  $e.CellStyle.ForeColor = $theme.Accent }
                        'Queued'    { $e.Value = "$([char]0x25F7)  Queued";    $e.CellStyle.ForeColor = $theme.MutedFore }
                        'Cancelled' { $e.Value = "$([char]0x2715)  Cancelled"; $e.CellStyle.ForeColor = $theme.Warning }
                        'Error'     { $e.Value = "$([char]0x26A0)  Error";     $e.CellStyle.ForeColor = $theme.Danger }
                    }
                    $e.FormattingApplied = $true
                }
                elseif ($columnName -eq 'YaraHits' -and [int]$e.Value -gt 0) {
                    $e.CellStyle.ForeColor = $theme.Warning
                }
                elseif ($columnName -eq 'CapaDetections' -and [int]$e.Value -gt 0) {
                    $e.CellStyle.ForeColor = $theme.Accent
                }
                elseif ($columnName -eq 'NsrlMatch' -and [string]$e.Value -eq 'Yes') {
                    $e.CellStyle.ForeColor = $theme.Accent
                }
            })

            $grid.Add_CellPainting({
                param($senderCtrl, $e)
                if ($e.RowIndex -lt 0 -or $senderCtrl.Columns[$e.ColumnIndex].Name -ne 'Progress') { return }
                $e.PaintBackground($e.ClipBounds, $true)
                $raw = [string]$senderCtrl.Rows[$e.RowIndex].Cells['Progress'].Value
                $percent = 0
                if ($raw -match '(\d+)') { $percent = [Math]::Max(0, [Math]::Min(100, [int]$Matches[1])) }

                $track = New-Object System.Drawing.Rectangle($e.CellBounds.X + 8, $e.CellBounds.Y + 12, [Math]::Max(10, $e.CellBounds.Width - 42), 12)
                $trackBrush = New-Object System.Drawing.SolidBrush($theme.ButtonBack)
                $fillBrush = New-Object System.Drawing.SolidBrush($theme.Accent)
                try {
                    $e.Graphics.FillRectangle($trackBrush, $track)
                    if ($percent -gt 0) {
                        $fill = New-Object System.Drawing.Rectangle($track.X, $track.Y, [int]($track.Width * $percent / 100.0), $track.Height)
                        $e.Graphics.FillRectangle($fillBrush, $fill)
                    }
                    $textRect = New-Object System.Drawing.Rectangle($track.Right + 5, $e.CellBounds.Y, 38, $e.CellBounds.Height)
                    [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, "$percent%", $senderCtrl.Font, $textRect, $theme.Fore, [System.Windows.Forms.TextFormatFlags]::VerticalCenter)
                }
                finally {
                    $trackBrush.Dispose()
                    $fillBrush.Dispose()
                }
                $e.Handled = $true
            })

            $page.Controls.Add($grid)
            $page.Controls.Add($lblSummary)
            $page.Controls.Add($toolbar)

            return [pscustomobject]@{
                Page = $page; Grid = $grid; LblSummary = $lblSummary
                BtnStart = $btnStart; BtnPause = $btnPause; BtnStop = $btnStop; BtnClear = $btnClear
                RowIndexByPath = @{}
            }
        }

        # ================= Page: Results =================
        function New-ResultsPage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.BackColor = $theme.WindowBack

            $toolbar = New-Object System.Windows.Forms.FlowLayoutPanel
            $toolbar.Dock = [System.Windows.Forms.DockStyle]::Top
            $toolbar.Height = 50
            $toolbar.BackColor = $theme.WindowBack

            $txtFilter = New-Object System.Windows.Forms.TextBox
            $txtFilter.Width = 320
            $txtFilter.Height = 32
            $txtFilter.Font = New-Object System.Drawing.Font('Segoe UI', 10)
            $txtFilter.BackColor = $theme.SurfaceBack
            $txtFilter.ForeColor = $theme.Fore
            $txtFilter.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

            $btnOpenFolder = New-ThemedButton -Text 'Open Report Folder' -Width 170
            $btnOpenFolder.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
            $btnRefresh = New-ThemedButton -Text 'Refresh' -Width 100
            $btnRefresh.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)

            $toolbar.Controls.Add($txtFilter)
            $toolbar.Controls.Add($btnOpenFolder)
            $toolbar.Controls.Add($btnRefresh)

            # Shown only while a dashboard tile/bar/heat-map click has narrowed the
            # grid to a specific subset (see Show-FilteredResults) - the free-text
            # search above still layers on top of whatever rows are loaded here.
            $filterBar = New-Object System.Windows.Forms.Panel
            $filterBar.Dock = [System.Windows.Forms.DockStyle]::Top
            $filterBar.Height = 34
            $filterBar.BackColor = $theme.SurfaceBack
            $filterBar.Visible = $false

            $lblFilter = New-Object System.Windows.Forms.Label
            $lblFilter.AutoSize = $true
            $lblFilter.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
            $lblFilter.ForeColor = $theme.Accent
            $lblFilter.Location = New-Object System.Drawing.Point(12, 8)
            $filterBar.Controls.Add($lblFilter)

            $btnClearFilter = New-ThemedButton -Text 'Clear Filter' -Width 100 -Height 24
            $btnClearFilter.Location = New-Object System.Drawing.Point(500, 4)
            $filterBar.Controls.Add($btnClearFilter)

            $grid = New-Object System.Windows.Forms.DataGridView
            $grid.Dock = [System.Windows.Forms.DockStyle]::Fill
            $grid.AutoGenerateColumns = $false
            $grid.AllowUserToAddRows = $false
            $grid.AllowUserToDeleteRows = $false
            $grid.ReadOnly = $true
            $grid.RowHeadersVisible = $false
            $grid.BackgroundColor = $theme.SurfaceBack
            $grid.GridColor = $theme.Border
            $grid.BorderStyle = [System.Windows.Forms.BorderStyle]::None
            $grid.EnableHeadersVisualStyles = $false
            $grid.ColumnHeadersDefaultCellStyle.BackColor = $theme.SurfaceBack
            $grid.ColumnHeadersDefaultCellStyle.ForeColor = $theme.MutedFore
            $grid.DefaultCellStyle.BackColor = $theme.SurfaceBack
            $grid.DefaultCellStyle.ForeColor = $theme.Fore
            # Grid-level ReadOnly is left false so the Disposition column (added
            # below) can be edited in place - every other column is marked
            # ReadOnly individually instead, since a grid-level ReadOnly=true
            # would override any per-column setting and make Disposition
            # uneditable too.
            $grid.ReadOnly = $false
            $grid.EditMode = [System.Windows.Forms.DataGridViewEditMode]::EditOnKeystrokeOrF2

            $resultColumns = @(
                @{ Name = 'Path'; Header = 'File Path'; Width = 320 }
                @{ Name = 'Status'; Header = 'Status'; Width = 90 }
                @{ Name = 'SHA1'; Header = 'SHA-1'; Width = 220 }
                @{ Name = 'NsrlMatch'; Header = 'NSRL'; Width = 60 }
                @{ Name = 'YaraHits'; Header = 'YARA Hits'; Width = 80 }
                @{ Name = 'YaraSeverity'; Header = 'YARA Severity'; Width = 100 }
                @{ Name = 'AttackTechniques'; Header = 'MITRE ATT&CK'; Width = 260 }
                @{ Name = 'CapaDetections'; Header = 'Capa Detections'; Width = 110 }
                @{ Name = 'CapaShellcodeFormat'; Header = 'Capa SC Format'; Width = 90 }
                @{ Name = 'PossibleFalseNegative'; Header = 'Poss. False Neg.'; Width = 110 }
                @{ Name = 'Entropy'; Header = 'Entropy'; Width = 70 }
                @{ Name = 'FlossStringCount'; Header = 'FLOSS Strings'; Width = 90 }
                @{ Name = 'SsdeepMatches'; Header = 'SSDEEP Matches'; Width = 220 }
                @{ Name = 'PackerDetected'; Header = 'Packer (DIE)'; Width = 120 }
                @{ Name = 'Compiler'; Header = 'Compiler (DIE)'; Width = 140 }
                @{ Name = 'Imphash'; Header = 'Imphash'; Width = 110 }
                @{ Name = 'SignatureStatus'; Header = 'Signature'; Width = 100 }
                @{ Name = 'SignerName'; Header = 'Signer'; Width = 180 }
                @{ Name = 'IocCount'; Header = 'IOCs'; Width = 60 }
                @{ Name = 'ExtractedIOCs'; Header = 'Extracted IOCs'; Width = 240 }
                @{ Name = 'ReputationStatus'; Header = 'Reputation'; Width = 90 }
                @{ Name = 'Error'; Header = 'Error'; Width = 200 }
            )
            foreach ($colDef in $resultColumns) {
                $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
                $col.Name = $colDef.Name
                $col.HeaderText = $colDef.Header
                $col.Width = $colDef.Width
                $col.ReadOnly = $true
                $null = $grid.Columns.Add($col)
            }

            # Disposition (v1.3-proto1) is the one editable column - an in-grid
            # dropdown rather than a separate dialog, so tagging a row during
            # bulk triage doesn't interrupt scanning through the rest of the list.
            $dispositionCol = New-Object System.Windows.Forms.DataGridViewComboBoxColumn
            $dispositionCol.Name = 'Disposition'
            $dispositionCol.HeaderText = 'Disposition'
            $dispositionCol.Width = 120
            $dispositionCol.ReadOnly = $false
            $dispositionCol.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $null = $dispositionCol.Items.AddRange(@('Untriaged', 'Benign', 'Suspicious', 'Escalated'))
            $null = $grid.Columns.Add($dispositionCol)

            # Right-click a row to select it before the context menu opens, so
            # "Open in PE Studio" etc. always act on the row under the cursor
            # rather than whatever was last left-clicked.
            $grid.Add_CellMouseDown({
                param($senderCtrl, $e)
                if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right -and $e.RowIndex -ge 0) {
                    $senderCtrl.ClearSelection()
                    $senderCtrl.Rows[$e.RowIndex].Selected = $true
                    $senderCtrl.CurrentCell = $senderCtrl.Rows[$e.RowIndex].Cells[0]
                }
            })

            # v1.3-proto1 quick-launch menu (Feature 1). Each item's Enabled state
            # and label are refreshed on every Opening event rather than fixed at
            # construction time, since the configured tool paths can change later
            # via Settings without the app restarting.
            $launchMenu = New-Object System.Windows.Forms.ContextMenuStrip
            $launchTools = @(
                @{ ConfigKey = 'PEStudioExe'; Label = 'Open in PE Studio' }
                @{ ConfigKey = 'DieExe'; Label = 'Open in DIE' }
                # CFF Explorer's command-line argument is reserved for its own
                # Lua ".cff" scripting engine (NTCore's docs: passing a .cff
                # script runs it headlessly, no window at all) - passing an
                # arbitrary PE path there is silently ignored, confirmed
                # against this FRED's install: the app opens but the flagged
                # file never loads, every time, for every file tried. Unlike
                # the other quick-launch tools, it can't be made to auto-load
                # the file, so launch it plain and copy the path to the
                # clipboard instead - one paste into File > Open beats a
                # zero-step promise that doesn't actually work.
                @{ ConfigKey = 'CffExplorerExe'; Label = 'Open in CFF Explorer (copies path to clipboard)'; CopyPathInsteadOfArg = $true }
                @{ ConfigKey = 'ResourceHackerExe'; Label = 'Open in Resource Hacker' }
                # v1.3.0-alpha.2: debuggers get the same simple launch treatment
                # as the tools above, plus a Confirm prompt (checked in the
                # shared click handler below) since loading a live sample into
                # a debugger warrants a beat of caution that a static viewer
                # like PE Studio doesn't.
                @{ ConfigKey = 'X64dbgExe'; Label = 'Open in x64dbg'; Confirm = 'This opens the selected binary in x64dbg. Continue only in an isolated analysis environment.' }
                @{ ConfigKey = 'X32dbgExe'; Label = 'Open in x32dbg'; Confirm = 'This opens the selected binary in x32dbg. Continue only in an isolated analysis environment.' }
            )
            $launchMenuItems = @{}
            foreach ($tool in $launchTools) {
                $item = New-Object System.Windows.Forms.ToolStripMenuItem
                $item.Text = $tool.Label
                # Carry the whole tool def (not just the config key) so the
                # shared click handler below can read .Confirm without relying
                # on loop-variable closure capture.
                $item.Tag = $tool
                $item.Add_Click({
                    $tool = $this.Tag
                    $configKey = $tool.ConfigKey
                    if ($grid.SelectedRows.Count -eq 0) { return }
                    $targetPath = $grid.SelectedRows[0].Cells['Path'].Value
                    $exePath = $Config[$configKey]
                    if ([string]::IsNullOrWhiteSpace($exePath) -or -not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
                        $expectedFileName = $ToolFileNames[$configKey]
                        $msg = if ($Config.ToolsDir) {
                            "$expectedFileName was not found in your configured tools directory:`r`n$($Config.ToolsDir)"
                        } else {
                            "Configure a tools directory in Settings first (Settings > Path to tools), then place $expectedFileName in it."
                        }
                        [System.Windows.Forms.MessageBox]::Show(
                            $grid.FindForm(), $msg, 'BinSifter',
                            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                        return
                    }
                    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) { return }
                    if ($tool.Confirm) {
                        $confirmResult = [System.Windows.Forms.MessageBox]::Show(
                            $grid.FindForm(), $tool.Confirm, 'BinSifter',
                            [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
                        if ($confirmResult -ne [System.Windows.Forms.DialogResult]::Yes) { return }
                    }
                    try {
                        if ($tool.CopyPathInsteadOfArg) {
                            Start-Process -FilePath $exePath
                            [System.Windows.Forms.Clipboard]::SetText($targetPath)
                        }
                        else {
                            Start-Process -FilePath $exePath -ArgumentList "`"$targetPath`""
                        }
                    }
                    catch {
                        [System.Windows.Forms.MessageBox]::Show(
                            $grid.FindForm(), "Could not launch: $($_.Exception.Message)", 'BinSifter',
                            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                    }
                }.GetNewClosure())
                $null = $launchMenu.Items.Add($item)
                $launchMenuItems[$tool.ConfigKey] = $item
            }

            # v1.3.0-alpha.2 "deep analysis" group - selectively ported from
            # proto2 (Ghidra headless, Sigcheck, Speakeasy). Kept as its own
            # separated block below the simple launch-tools group rather than
            # folded into $launchTools, since each of these needs meaningfully
            # different logic (project-directory construction, captured
            # output + report viewer) instead of a bare Start-Process.
            $null = $launchMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

            $ghidraItem = New-Object System.Windows.Forms.ToolStripMenuItem
            $ghidraItem.Text = 'Send to Ghidra (headless analysis)'
            $ghidraItem.Add_Click({
                if ($grid.SelectedRows.Count -eq 0) { return }
                $targetPath = $grid.SelectedRows[0].Cells['Path'].Value
                $ghidraExe = $Config.GhidraHeadlessExe
                if ([string]::IsNullOrWhiteSpace($ghidraExe) -or -not (Test-Path -LiteralPath $ghidraExe -PathType Leaf)) {
                    $msg = if ($Config.GhidraDir) {
                        "analyzeHeadless.bat was not found under your configured Ghidra directory:`r`n$($Config.GhidraDir)"
                    } else {
                        "Configure the path to Ghidra in Settings first (Settings > Path to Ghidra)."
                    }
                    [System.Windows.Forms.MessageBox]::Show(
                        $grid.FindForm(), $msg, 'BinSifter',
                        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                    return
                }
                if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) { return }
                if ([string]::IsNullOrWhiteSpace($Config.ReportDirectory)) {
                    [System.Windows.Forms.MessageBox]::Show(
                        $grid.FindForm(), "Configure a Report Directory in Settings first - Ghidra projects are stored under it.", 'BinSifter',
                        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                    return
                }
                try {
                    $ghidraProjectsDir = Join-Path $Config.ReportDirectory 'ghidra_projects'
                    if (-not (Test-Path -LiteralPath $ghidraProjectsDir -PathType Container)) {
                        $null = New-Item -Path $ghidraProjectsDir -ItemType Directory -Force
                    }
                    # TryGetValue, not a bare indexer - $FileRecords is a
                    # ConcurrentDictionary, whose indexer throws
                    # KeyNotFoundException on a miss rather than returning
                    # $null (unlike a plain Hashtable). A miss is unlikely but
                    # not impossible (e.g. a stale Results row from before the
                    # most recent $FileRecords.Clear()) - fall back to a
                    # filename-based project name instead of an error dialog.
                    $record = $null
                    $hasRecord = $FileRecords.TryGetValue($targetPath, [ref]$record)
                    $projectName = if ($hasRecord -and $record.SHA1) { "BinSifter_$($record.SHA1)" } else { "BinSifter_$([IO.Path]::GetFileNameWithoutExtension($targetPath))" }
                    # Fire-and-forget, same as the other quick-launch tools -
                    # headless analysis can run for minutes, and Ghidra is
                    # purely static (no execution risk), so there's nothing to
                    # wait on or warn about. Note: this process isn't tracked
                    # in a registry, so it won't be force-closed if BinSifter
                    # exits first - harmless for a read-only analysis run, but
                    # worth knowing if you close BinSifter mid-analysis.
                    Start-Process -FilePath $ghidraExe -ArgumentList @(
                        "`"$ghidraProjectsDir`"", "`"$projectName`"",
                        '-import', "`"$targetPath`"",
                        '-overwrite', '-analysisTimeoutPerFile', '300'
                    )
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        $grid.FindForm(), "Could not launch Ghidra: $($_.Exception.Message)", 'BinSifter',
                        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                }
            }.GetNewClosure())
            $null = $launchMenu.Items.Add($ghidraItem)

            $sigcheckItem = New-Object System.Windows.Forms.ToolStripMenuItem
            $sigcheckItem.Text = 'Verify signature and provenance (Sigcheck)'
            $sigcheckItem.Add_Click({
                if ($grid.SelectedRows.Count -eq 0) { return }
                $targetPath = $grid.SelectedRows[0].Cells['Path'].Value
                $sigcheckExe = $Config.SigcheckExe
                if ([string]::IsNullOrWhiteSpace($sigcheckExe) -or -not (Test-Path -LiteralPath $sigcheckExe -PathType Leaf)) {
                    $msg = if ($Config.ToolsDir) {
                        "sigcheck.exe was not found in your configured tools directory:`r`n$($Config.ToolsDir)"
                    } else {
                        "Configure a tools directory in Settings first (Settings > Path to tools), then place sigcheck.exe in it."
                    }
                    [System.Windows.Forms.MessageBox]::Show(
                        $grid.FindForm(), $msg, 'BinSifter',
                        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                    return
                }
                if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) { return }
                $grid.FindForm().Cursor = [System.Windows.Forms.Cursors]::WaitCursor
                try {
                    # -nobanner/-accepteula: no interactive EULA prompt on
                    # first run. -a: extended details (Publisher/Product/
                    # Description). -h: hashes. Deliberately no -vt (VirusTotal
                    # lookup) - that's a network call with its own ToS, out of
                    # scope for what was asked here.
                    $result = Invoke-CapturedTool -Path $sigcheckExe -Arguments @('-nobanner', '-accepteula', '-a', '-h', $targetPath) -TimeoutSeconds 30
                    $body = if ($result.TimedOut) { $result.StdErr } else { "$($result.StdOut)`r`n$($result.StdErr)".Trim() }
                    if ([string]::IsNullOrWhiteSpace($body)) { $body = '(no output)' }
                    Show-ToolReportWindow -Title "Sigcheck - $(Split-Path -Leaf $targetPath)" -Content $body
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        $grid.FindForm(), "Could not run Sigcheck: $($_.Exception.Message)", 'BinSifter',
                        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                }
                finally {
                    $grid.FindForm().Cursor = [System.Windows.Forms.Cursors]::Default
                }
            }.GetNewClosure())
            $null = $launchMenu.Items.Add($sigcheckItem)

            $speakeasyItem = New-Object System.Windows.Forms.ToolStripMenuItem
            $speakeasyItem.Text = 'Run isolated Speakeasy emulation'
            $speakeasyItem.Add_Click({
                if ($grid.SelectedRows.Count -eq 0) { return }
                $targetPath = $grid.SelectedRows[0].Cells['Path'].Value
                $speakeasyExe = $Config.SpeakeasyExe
                if ([string]::IsNullOrWhiteSpace($speakeasyExe) -or -not (Test-Path -LiteralPath $speakeasyExe -PathType Leaf)) {
                    $msg = if ($Config.ToolsDir) {
                        "speakeasy.exe was not found in your configured tools directory:`r`n$($Config.ToolsDir)"
                    } else {
                        "Configure a tools directory in Settings first (Settings > Path to tools), then place speakeasy.exe in it."
                    }
                    [System.Windows.Forms.MessageBox]::Show(
                        $grid.FindForm(), $msg, 'BinSifter',
                        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                    return
                }
                if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) { return }
                $confirmResult = [System.Windows.Forms.MessageBox]::Show(
                    $grid.FindForm(), "This emulates the selected binary's code. Emulation must be performed in an isolated analysis environment. Continue?", 'BinSifter',
                    [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
                if ($confirmResult -ne [System.Windows.Forms.DialogResult]::Yes) { return }
                $grid.FindForm().Cursor = [System.Windows.Forms.Cursors]::WaitCursor
                try {
                    # Longer timeout than Sigcheck - emulation of a nontrivial
                    # sample routinely runs well past 30s; a 30s cap (proto2's
                    # blanket default for every captured tool) would make this
                    # look broken on anything but the smallest samples.
                    $result = Invoke-CapturedTool -Path $speakeasyExe -Arguments @('-t', $targetPath, '-o', 'json') -TimeoutSeconds 120
                    $rawBody = if ($result.TimedOut) { $result.StdErr } else { "$($result.StdOut)`r`n$($result.StdErr)".Trim() }
                    if ([string]::IsNullOrWhiteSpace($rawBody)) { $rawBody = '(no output)' }

                    # Best-effort JSON summary on top of the raw dump - same
                    # graceful-degradation pattern used for capa/FLOSS JSON
                    # elsewhere in this file: try to parse, fall back to raw
                    # text untouched if the shape doesn't match what's expected.
                    $summaryLines = $null
                    if (-not $result.TimedOut) {
                        try {
                            $parsed = $result.StdOut | ConvertFrom-Json -ErrorAction Stop
                            $apiCalls = @($parsed.apis).Count
                            $netIndicators = @($parsed.network) | ForEach-Object { $_ } | Select-Object -Unique
                            $fileOps = @($parsed.file_access).Count
                            $summaryLines = @(
                                "Speakeasy emulation summary for $(Split-Path -Leaf $targetPath)"
                                "API calls observed: $apiCalls"
                                "File operations observed: $fileOps"
                                "Network indicators: $(if ($netIndicators.Count -gt 0) { $netIndicators -join ', ' } else { '(none observed)' })"
                                ''
                                '--- Raw output ---'
                            )
                        }
                        catch { $summaryLines = $null }
                    }
                    $body = if ($summaryLines) { ($summaryLines -join "`r`n") + "`r`n" + $rawBody } else { $rawBody }
                    Show-ToolReportWindow -Title "Speakeasy - $(Split-Path -Leaf $targetPath)" -Content $body
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        $grid.FindForm(), "Could not run Speakeasy: $($_.Exception.Message)", 'BinSifter',
                        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                }
                finally {
                    $grid.FindForm().Cursor = [System.Windows.Forms.Cursors]::Default
                }
            }.GetNewClosure())
            $null = $launchMenu.Items.Add($speakeasyItem)

            $launchMenu.Add_Opening({
                if ($grid.SelectedRows.Count -eq 0) { $_.Cancel = $true; return }
                foreach ($tool in $launchTools) {
                    $configured = -not [string]::IsNullOrWhiteSpace($Config[$tool.ConfigKey])
                    $launchMenuItems[$tool.ConfigKey].Enabled = $configured
                    $launchMenuItems[$tool.ConfigKey].Text = if ($configured) { $tool.Label } else { "$($tool.Label) (not configured)" }
                }
                $ghidraItem.Enabled = -not [string]::IsNullOrWhiteSpace($Config.GhidraHeadlessExe)
                $sigcheckItem.Enabled = -not [string]::IsNullOrWhiteSpace($Config.SigcheckExe)
                $speakeasyItem.Enabled = -not [string]::IsNullOrWhiteSpace($Config.SpeakeasyExe)
            }.GetNewClosure())
            $grid.ContextMenuStrip = $launchMenu

            $page.Controls.Add($grid)
            $page.Controls.Add($filterBar)
            $page.Controls.Add($toolbar)

            return [pscustomobject]@{
                Page = $page; Grid = $grid; TxtFilter = $txtFilter; BtnOpenFolder = $btnOpenFolder; BtnRefresh = $btnRefresh
                FilterBar = $filterBar; LblFilter = $lblFilter; BtnClearFilter = $btnClearFilter
            }
        }

        # ================= Page: Settings =================
        function New-SettingsPage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.AutoScroll = $true
            $page.BackColor = $theme.WindowBack

            $layout = New-Object System.Windows.Forms.TableLayoutPanel
            $layout.ColumnCount = 3
            $layout.AutoSize = $true
            $layout.Dock = [System.Windows.Forms.DockStyle]::Top
            $null = $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
            $null = $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
            $null = $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))

            # v1.3.0-alpha.2: consolidated down to 5 fields. Report output,
            # MITRE ATT&CK data, the known-bad blocklist, and every individual
            # tool exe are no longer separate fields here - see the Help page
            # field guide for the default locations and expected filenames.
            $fieldDefs = @(
                @{ Key = 'SrcDir'; Label = 'Path to binaries to scan'; Type = 'Directory' }
                @{ Key = 'NsrlPath'; Label = 'NSRL text file path'; Type = 'File'; Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*' }
                @{ Key = 'YaraRules'; Label = 'Path to YARA rules'; Type = 'File'; Filter = 'YARA rules (*.yar;*.yara)|*.yar;*.yara|All files (*.*)|*.*' }
                @{ Key = 'CapaRules'; Label = 'Path to capa rules'; Type = 'Directory' }
                @{ Key = 'ToolsDir'; Label = 'Path to tools'; Type = 'Directory' }
                @{ Key = 'GhidraDir'; Label = 'Path to Ghidra - optional'; Type = 'Directory' }
            )

            $fieldBoxes = @{}
            $rowIndex = 0
            foreach ($fieldDef in $fieldDefs) {
                $lbl = New-Object System.Windows.Forms.Label
                $lbl.Text = $fieldDef.Label
                $lbl.AutoSize = $true
                $lbl.Anchor = [System.Windows.Forms.AnchorStyles]::Left
                $lbl.Margin = New-Object System.Windows.Forms.Padding(3, 12, 12, 3)
                $lbl.ForeColor = $theme.Fore

                $txt = New-Object System.Windows.Forms.TextBox
                $txt.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
                $txt.Width = 620
                $txt.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 3)
                $txt.BackColor = $theme.SurfaceBack
                $txt.ForeColor = $theme.Fore
                $txt.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

                $btn = New-ThemedButton -Text 'Browse...' -Width 100 -Height 30
                # Carry both the field def and textbox on the button itself - looking
                # $txt up later via an outer hashtable depended on this function's
                # scope still being alive, which isn't guaranteed after it returns.
                $btn.Tag = [pscustomobject]@{ Def = $fieldDef; TextBox = $txt }

                $btn.Add_Click({
                    $tag = $this.Tag
                    $def = $tag.Def
                    $targetTextBox = $tag.TextBox

                    if ($def.Type -eq 'Directory') {
                        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
                        if ($targetTextBox.Text -and (Test-Path -LiteralPath $targetTextBox.Text -PathType Container)) {
                            $dialog.SelectedPath = $targetTextBox.Text
                        }
                        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                            $targetTextBox.Text = $dialog.SelectedPath
                        }
                    }
                    else {
                        $dialog = New-Object System.Windows.Forms.OpenFileDialog
                        $dialog.Filter = $def.Filter
                        $dialog.CheckFileExists = $true
                        if ($targetTextBox.Text -and (Test-Path -LiteralPath $targetTextBox.Text -PathType Leaf)) {
                            $dialog.InitialDirectory = Split-Path -LiteralPath $targetTextBox.Text -Parent
                            $dialog.FileName = Split-Path -LiteralPath $targetTextBox.Text -Leaf
                        }
                        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                            $targetTextBox.Text = $dialog.FileName
                        }
                    }
                })

                $fieldBoxes[$fieldDef.Key] = $txt

                $null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
                $layout.Controls.Add($lbl, 0, $rowIndex)
                $layout.Controls.Add($txt, 1, $rowIndex)
                $layout.Controls.Add($btn, 2, $rowIndex)
                $rowIndex++
            }

            $btnSave = New-ThemedButton -Text 'Save Settings' -Width 160 -Primary
            $btnSave.Margin = New-Object System.Windows.Forms.Padding(3, 20, 0, 0)

            $lblStatus = New-Object System.Windows.Forms.Label
            $lblStatus.AutoSize = $true
            $lblStatus.Font = New-Object System.Drawing.Font('Segoe UI', 9)
            $lblStatus.Margin = New-Object System.Windows.Forms.Padding(3, 28, 0, 0)
            $lblStatus.ForeColor = $theme.MutedFore
            $lblStatus.Text = ''

            $null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
            $layout.Controls.Add($btnSave, 1, $rowIndex)
            $rowIndex++
            $null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
            $layout.Controls.Add($lblStatus, 1, $rowIndex)

            $page.Controls.Add($layout)

            return [pscustomobject]@{ Page = $page; Fields = $fieldBoxes; BtnSave = $btnSave; LblStatus = $lblStatus }
        }

        # ================= Page: YARA Rules =================
        function New-YaraRulesPage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.BackColor = $theme.WindowBack

            $topRow = New-Object System.Windows.Forms.FlowLayoutPanel
            $topRow.Dock = [System.Windows.Forms.DockStyle]::Top
            $topRow.Height = 50
            $topRow.BackColor = $theme.WindowBack

            $lblPath = New-Object System.Windows.Forms.Label
            $lblPath.AutoSize = $true
            $lblPath.Font = New-Object System.Drawing.Font('Segoe UI', 9)
            $lblPath.ForeColor = $theme.MutedFore
            $lblPath.Margin = New-Object System.Windows.Forms.Padding(3, 10, 12, 0)
            $lblPath.Text = 'No rules file configured.'

            $btnBrowse = New-ThemedButton -Text 'Browse...' -Width 110
            $btnReload = New-ThemedButton -Text 'Reload' -Width 110
            $btnReload.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
            $btnSave = New-ThemedButton -Text 'Save Changes' -Width 140 -Primary
            $btnSave.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)

            $topRow.Controls.Add($lblPath)
            $topRow.Controls.Add($btnBrowse)
            $topRow.Controls.Add($btnReload)
            $topRow.Controls.Add($btnSave)

            $txtContent = New-Object System.Windows.Forms.TextBox
            $txtContent.Multiline = $true
            $txtContent.Dock = [System.Windows.Forms.DockStyle]::Fill
            $txtContent.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
            $txtContent.WordWrap = $false
            $txtContent.Font = New-Object System.Drawing.Font('Consolas', 10)
            $txtContent.BackColor = $theme.SurfaceBack
            $txtContent.ForeColor = $theme.Fore
            $txtContent.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

            $page.Controls.Add($txtContent)
            $page.Controls.Add($topRow)

            return [pscustomobject]@{ Page = $page; LblPath = $lblPath; BtnBrowse = $btnBrowse; BtnReload = $btnReload; BtnSave = $btnSave; TxtContent = $txtContent }
        }

        # ================= Page: Capa Rules =================
        function New-CapaRulesPage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.BackColor = $theme.WindowBack

            $topRow = New-Object System.Windows.Forms.FlowLayoutPanel
            $topRow.Dock = [System.Windows.Forms.DockStyle]::Top
            $topRow.Height = 50
            $topRow.BackColor = $theme.WindowBack

            $lblPath = New-Object System.Windows.Forms.Label
            $lblPath.AutoSize = $true
            $lblPath.Font = New-Object System.Drawing.Font('Segoe UI', 9)
            $lblPath.ForeColor = $theme.MutedFore
            $lblPath.Margin = New-Object System.Windows.Forms.Padding(3, 10, 12, 0)
            $lblPath.Text = 'No rules directory configured.'

            $btnBrowse = New-ThemedButton -Text 'Browse...' -Width 110
            $btnOpenFolder = New-ThemedButton -Text 'Open Folder' -Width 130
            $btnOpenFolder.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
            $btnRefresh = New-ThemedButton -Text 'Refresh' -Width 100
            $btnRefresh.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)

            $topRow.Controls.Add($lblPath)
            $topRow.Controls.Add($btnBrowse)
            $topRow.Controls.Add($btnOpenFolder)
            $topRow.Controls.Add($btnRefresh)

            $list = New-Object System.Windows.Forms.ListBox
            $list.Dock = [System.Windows.Forms.DockStyle]::Fill
            $list.Font = New-Object System.Drawing.Font('Consolas', 10)
            $list.BackColor = $theme.SurfaceBack
            $list.ForeColor = $theme.Fore
            $list.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

            $page.Controls.Add($list)
            $page.Controls.Add($topRow)

            return [pscustomobject]@{ Page = $page; LblPath = $lblPath; BtnBrowse = $btnBrowse; BtnOpenFolder = $btnOpenFolder; BtnRefresh = $btnRefresh; List = $list }
        }

        # ================= Page: NSRL =================
        function New-NsrlPage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.BackColor = $theme.WindowBack

            $topRow = New-Object System.Windows.Forms.FlowLayoutPanel
            $topRow.Dock = [System.Windows.Forms.DockStyle]::Top
            $topRow.Height = 50
            $topRow.BackColor = $theme.WindowBack

            $lblPath = New-Object System.Windows.Forms.Label
            $lblPath.AutoSize = $true
            $lblPath.Font = New-Object System.Drawing.Font('Segoe UI', 9)
            $lblPath.ForeColor = $theme.MutedFore
            $lblPath.Margin = New-Object System.Windows.Forms.Padding(3, 10, 12, 0)
            $lblPath.Text = 'No NSRL file configured.'

            $btnBrowse = New-ThemedButton -Text 'Browse...' -Width 110
            $btnReloadPreview = New-ThemedButton -Text 'Reload Now' -Width 130
            $btnReloadPreview.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)

            $topRow.Controls.Add($lblPath)
            $topRow.Controls.Add($btnBrowse)
            $topRow.Controls.Add($btnReloadPreview)

            $lblCount = New-Object System.Windows.Forms.Label
            $lblCount.AutoSize = $true
            $lblCount.Font = New-Object System.Drawing.Font('Segoe UI', 28, [System.Drawing.FontStyle]::Bold)
            $lblCount.ForeColor = $theme.Accent
            $lblCount.Location = New-Object System.Drawing.Point(4, 70)
            $lblCount.Text = '0'

            $lblCountCaption = New-Object System.Windows.Forms.Label
            $lblCountCaption.AutoSize = $true
            $lblCountCaption.Font = New-Object System.Drawing.Font('Segoe UI', 10)
            $lblCountCaption.ForeColor = $theme.MutedFore
            $lblCountCaption.Location = New-Object System.Drawing.Point(6, 130)
            $lblCountCaption.Text = 'known-good hashes loaded'

            $page.Controls.Add($lblCountCaption)
            $page.Controls.Add($lblCount)
            $page.Controls.Add($topRow)

            return [pscustomobject]@{ Page = $page; LblPath = $lblPath; BtnBrowse = $btnBrowse; BtnReloadPreview = $btnReloadPreview; LblCount = $lblCount }
        }

        # ================= Page: Logs =================
        function New-LogsPage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.BackColor = $theme.WindowBack

            $topRow = New-Object System.Windows.Forms.FlowLayoutPanel
            $topRow.Dock = [System.Windows.Forms.DockStyle]::Top
            $topRow.Height = 50
            $topRow.BackColor = $theme.WindowBack

            $btnClear = New-ThemedButton -Text 'Clear Logs' -Width 120
            $topRow.Controls.Add($btnClear)

            $txtLog = New-Object System.Windows.Forms.TextBox
            $txtLog.Multiline = $true
            $txtLog.ReadOnly = $true
            $txtLog.Dock = [System.Windows.Forms.DockStyle]::Fill
            $txtLog.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
            $txtLog.Font = New-Object System.Drawing.Font('Consolas', 10)
            $txtLog.BackColor = $theme.SurfaceBack
            $txtLog.ForeColor = $theme.Fore
            $txtLog.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

            $page.Controls.Add($txtLog)
            $page.Controls.Add($topRow)

            return [pscustomobject]@{ Page = $page; TxtLog = $txtLog; BtnClear = $btnClear }
        }

        # ================= Page: Help =================
        function New-HelpPage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.BackColor = $theme.WindowBack

            $help = New-Object System.Windows.Forms.RichTextBox
            $help.Dock = [System.Windows.Forms.DockStyle]::Fill
            $help.ReadOnly = $true
            $help.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
            $help.BackColor = $theme.SurfaceBack
            $help.ForeColor = $theme.Fore
            $help.Font = New-Object System.Drawing.Font('Segoe UI', 10)
            $help.DetectUrls = $false
            $help.WordWrap = $true
            $help.Text = @'
BIN SIFTER FIELD GUIDE

BinSifter is meant for fast, repeatable triage of a directory full of files. It does not replace reverse engineering or a full malware-analysis workflow. Its job is to reduce a large collection into smaller, useful groups: known-good files, files that matched YARA, files that CAPA could analyze, files with notable capabilities, and files that resemble one another through SSDEEP.

BEFORE THE FIRST SCAN

Open Settings and fill in the required paths:

• Source Directory — the folder BinSifter will walk recursively.
• NSRL Path — an NSRL RDS hash file whose first CSV field is SHA-1.
• YARA Rules — the rule file YARA will apply.
• CAPA Rules — the CAPA rules directory.
• Path to tools — one folder containing every other external program BinSifter uses, searched recursively. See PATH TO TOOLS below for the full list.
• Path to Ghidra — optional, your Ghidra install root. BinSifter finds analyzeHeadless.bat inside it automatically. See PATH TO TOOLS below for why this one is separate.

Everything beyond these fields — where reports are written, MITRE ATT&CK data, the known-bad hash blocklist — is a fixed default location next to the BinSifter script itself. You don't type these in; you just place the right file in the right folder. See DEFAULT LOCATIONS below.

All Settings fields are remembered between launches: once Settings saves successfully, BinSifter writes them to a small cache file next to the script (.bsifter-settings-cache.json) and pre-fills them the next time you open BinSifter. Handy since these tend to stay the same from one assessment to the next on a given workstation. A cached value that's no longer valid (e.g. a removable drive that isn't attached this session) just shows up as invalid on Save, same as if you'd typed it wrong - nothing breaks. Delete the cache file to reset every field to blank.

PATH TO TOOLS

Point "Path to tools" at one folder containing all of the following, by exact filename (Windows filenames are case-insensitive, so exact capitalization doesn't matter). BinSifter searches the whole folder tree under it, not just the top level - a hierarchical layout (each tool in its own subfolder, as is common on FRED-style workstations) is expected and fine. If more than one copy of a filename turns up somewhere in the tree, BinSifter picks one (logged on the Logs page so it isn't a silent surprise) - keep only one copy of each tool under this folder if that matters for your case.

Only the first three are required — everything else is optional, and a missing file just quietly disables the one feature that depends on it (its Results-grid right-click entry shows as "not configured"):

• yara64.exe — required. YARA engine.
• capa.exe — required. CAPA capability detection.
• ssdeep.exe — required. Fuzzy hashing and post-scan clustering.
• floss.exe — optional. String-extraction fallback for YARA hits CAPA can't analyze.
• die.exe — optional. Detect It Easy (GUI) — quick-launch from Results.
• diec.exe — optional. Detect It Easy (console mode) — automated packer/compiler ID during scanning, for ambiguous files.
• pestudio.exe — optional. Quick-launch from Results.
• CFF Explorer.exe — optional. Quick-launch from Results, though unlike the other tools here it can't be made to auto-load the flagged file (its command line is reserved for its own Lua scripting engine) - launching it copies the file's path to the clipboard instead, ready to paste into File > Open.
• ResourceHacker.exe — optional. Quick-launch from Results.
• sigcheck.exe — optional. Sysinternals Sigcheck — on-demand signature/provenance dump from Results.
• x64dbg.exe and x32dbg.exe — optional, two separate entries. Debugger launch from Results — pick whichever matches the target's bitness.
• speakeasy.exe — optional. Isolated code emulation, on-demand from Results.

Ghidra isn't in this folder's search - it has its own "Path to Ghidra" field instead (see BEFORE THE FIRST SCAN above). Point it at your Ghidra install root (e.g. D:\ghidra_11.x) and BinSifter locates analyzeHeadless.bat inside it the same recursive way, without needing anything copied, moved, or symlinked - the real install stays exactly where it is.

Settings Save specifically checks that yara64.exe, capa.exe, and ssdeep.exe can be found somewhere under "Path to tools" before it lets you save — BinSifter can't scan without them. Every other tool on the list, and Ghidra, is only checked at the moment you try to use it. A large or network-mounted folder can take a few seconds to search; BinSifter shows a wait cursor during Save and again once at startup (see the note in DEFAULT LOCATIONS about cached values) rather than freezing silently.

DEFAULT LOCATIONS

BinSifter creates these folders next to its own script file automatically, the first time it runs, if they don't already exist. None of them are set in Settings:

• Reports\ — where CSV reports, CAPA/FLOSS JSON, caches, generated YARA rule drafts, Ghidra projects, and SSDEEP history are written. Always this folder, per BinSifter install.
• Attack\ — drop enterprise-attack.json here (as Attack\enterprise-attack.json) to enable MITRE ATT&CK technique enrichment on YARA hits. Leave the folder empty to skip that enrichment.
• Blocklist\ — drop a known-bad hash CSV/TXT here (as Blocklist\blocklist.csv, one SHA-1/MD5 per line or a MalwareBazaar-style export) to enable the offline reputation check. Leave the folder empty to skip that check.

If Settings loads with a cached "Path to tools" or "Path to Ghidra" already filled in, BinSifter re-searches them once, right after the window first appears, so the footer's tool-version display and the Results-grid quick actions are ready without needing to revisit and re-save Settings every launch.

RESULTS-GRID QUICK ACTIONS

Right-click any row in Results for two groups of on-demand actions, all driven by the tools directory above:

• Quick-launch (no confirmation): PE Studio, DIE, CFF Explorer, Resource Hacker, Ghidra headless analysis, and Sigcheck. These are read-only inspection tools or, for Ghidra, a purely static analysis run — nothing here executes the selected file.
• Confirmation required: x64dbg, x32dbg, and Speakeasy. These are execution-adjacent (loading into a debugger or emulating code), so BinSifter asks you to confirm you're working in an isolated analysis environment before launching.

Sigcheck and Speakeasy show their output in a popup report window; Ghidra and the debuggers just launch the external tool directly.

STARTING A SCAN

Open Scan Queue and select Start Scan. BinSifter loads or builds the NSRL cache, walks the source directory, creates one queue record per file, and sends files to a bounded worker pool.

Pause stops new files from being dispatched. Files already running are allowed to finish.

Stop terminates registered external tools, cancels work still in the queue, and gives active workers a short period to close. A stopped run still writes the reports it can produce from the records collected so far.

Clear Completed removes finished, failed, and cancelled rows from the on-screen queue. It does not delete reports or source files.

WHAT HAPPENS TO EACH FILE

Each file is read once to calculate SHA-1 and MD5. A small header sample is retained for format checks.

1. SHA-1 is checked against NSRL.
2. A known-good NSRL match skips SSDEEP, YARA, and CAPA.
3. An unknown file receives an SSDEEP fuzzy hash.
4. YARA runs and records matching rules, severity metadata, and ATT&CK references when available.
5. CAPA runs only after a YARA hit and only when the file appears suitable for CAPA analysis.
6. Optional FLOSS analysis can provide a fallback for suspicious files CAPA cannot accept.

An error on one file is recorded in that file's row and report. It does not stop the rest of the scan.

USING THE DASHBOARD

The top counters summarize completed files, YARA hits, CAPA scan attempts, CAPA rule detections, and NSRL matches.

The YARA Severity Breakdown counts each YARA-positive file once under its highest recognized severity. "Unknown" means the matched rule did not provide severity metadata BinSifter could recognize.

The SSDEEP Cluster Heat Map summarizes relationships in the current batch:

• Similarity Clusters — connected groups containing two or more related files.
• Largest Cluster — number of files in the largest current group.
• Singletons — hashed files that did not join a multi-file cluster.
• Average Similarity — average score across the pairwise matches returned by SSDEEP.
• Files Above 85% — files participating in at least one high-similarity match.
• Previously Seen Clusters — current clusters containing a SHA-1 that belonged to a cluster in an earlier run using this report directory.

The two cluster counters are deliberately different. "Similarity Clusters" describes everything found now; "Previously Seen Clusters" is the subset that overlaps earlier work.

Dashboard counters, YARA severity bars, and SSDEEP cells are clickable. Selecting one opens Results with the corresponding filter already applied.

RESULTS AND REPORTS

Results shows the detailed in-memory record for each file. Use the filter box to narrow by path. A dashboard selection adds a named result filter; clear that filter when you want the full set again.

The report directory receives:

• A full triage CSV.
• A suspicious/unknown CSV excluding NSRL matches.
• A YARA-matches CSV.
• A CAPA-compatible CSV.
• Per-file CAPA JSON where CAPA returned output.
• Optional FLOSS output.
• SSDEEP pair/cluster reports and the persistent cluster-history file.

The source directory is read for analysis only. BinSifter does not quarantine, rename, repair, or delete evidence.

YARA, CAPA, NSRL, AND LOG PAGES

YARA Rules lets you inspect, reload, and edit the configured rule file. Saving changes writes directly to that file, so keep source control or a backup for production rules.

CAPA Rules lists the configured rule directory and makes it easy to open that location.

NSRL shows the configured reference file and loaded hash count. Reload Now checks the existing cache when possible; the first load of a new or changed NSRL file can take longer.

Logs is the first place to look when a tool exits unexpectedly, a directory cannot be read, or a report cannot be written. The footer also shows the detected YARA, CAPA, and SSDEEP versions plus the NSRL file date.

PRACTICAL NOTES

Treat a YARA hit as a lead, not a verdict. Review the rule name, severity, file context, CAPA capabilities, strings, and cluster relationships together.

NSRL means "known to the reference set," not automatically safe in every context. Likewise, a file with no YARA hit is not automatically benign.

If CAPA or SSDEEP versions show as unavailable, confirm yara64.exe/capa.exe/ssdeep.exe are actually present in your configured tools directory (Settings > Path to tools) and try the program's version command from a PowerShell prompt.

For repeatable case work, preserve the report directory (Reports\ next to BinSifter itself) and record the BinSifter/tool versions shown in the footer.
'@

            $page.Controls.Add($help)
            return [pscustomobject]@{ Page = $page; Content = $help }
        }

        # ================= Page: About =================
        function New-AboutPage {
            $page = New-Object System.Windows.Forms.Panel
            $page.Dock = [System.Windows.Forms.DockStyle]::Fill
            $page.BackColor = $theme.WindowBack

            $aboutLogo = Import-ThemedLogo -Path $LogoHorizontalPath -Width 320
            if ($aboutLogo) {
                $aboutLogo.Location = New-Object System.Drawing.Point(4, 10)
                $page.Controls.Add($aboutLogo)
            }

            $lblVersion = New-Object System.Windows.Forms.Label
            $lblVersion.AutoSize = $true
            $lblVersion.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
            $lblVersion.ForeColor = $theme.Fore
            $lblVersion.Location = New-Object System.Drawing.Point(6, 155)
            $lblVersion.Text = "BinSifter $AppVersion"

            $lblDesc = New-Object System.Windows.Forms.Label
            $lblDesc.AutoSize = $true
            $lblDesc.Font = New-Object System.Drawing.Font('Segoe UI', 10)
            $lblDesc.ForeColor = $theme.MutedFore
            $lblDesc.Location = New-Object System.Drawing.Point(6, 190)
            $lblDesc.MaximumSize = New-Object System.Drawing.Size(700, 0)
            $lblDesc.Text = "BinSifter is a bounded-parallel binary triage tool. It hashes each file once (SHA-1/MD5), filters known-good files against an NSRL hash set, and runs YARA and CAPA against the remaining files to surface suspicious matches and identified capabilities."

            $lblTools = New-Object System.Windows.Forms.Label
            $lblTools.AutoSize = $true
            $lblTools.Font = New-Object System.Drawing.Font('Segoe UI', 10)
            $lblTools.ForeColor = $theme.MutedFore
            $lblTools.Location = New-Object System.Drawing.Point(6, 256)
            $lblTools.Text = "Integrates: YARA, CAPA, ssdeep (+ post-scan clustering), FLOSS (optional), NSRL RDS"

            $page.Controls.Add($lblVersion)
            $page.Controls.Add($lblDesc)
            $page.Controls.Add($lblTools)

            return [pscustomobject]@{ Page = $page }
        }

        # ================= Assemble pages + nav =================
        $dashboard = New-DashboardPage
        $scanQueue = New-ScanQueuePage
        $results = New-ResultsPage
        $settings = New-SettingsPage
        $yaraPage = New-YaraRulesPage
        $capaPage = New-CapaRulesPage
        $nsrlPage = New-NsrlPage
        $logsPage = New-LogsPage
        $helpPage = New-HelpPage
        $aboutPage = New-AboutPage

        $pageMap = [ordered]@{
            'Dashboard'  = $dashboard.Page
            'Scan Queue' = $scanQueue.Page
            'Results'    = $results.Page
            'YARA Rules' = $yaraPage.Page
            'Capa Rules' = $capaPage.Page
            'NSRL'       = $nsrlPage.Page
            'Settings'   = $settings.Page
            'Logs'       = $logsPage.Page
            'Help'       = $helpPage.Page
            'About'      = $aboutPage.Page
        }

        foreach ($key in $pageMap.Keys) {
            $pageMap[$key].Visible = $false
            $content.Controls.Add($pageMap[$key])
        }

        $navIconNames = @{
            'Dashboard' = 'gauge'
            'Scan Queue' = 'list'
            'Results' = 'chart'
            'YARA Rules' = 'document'
            'Capa Rules' = 'layers'
            'NSRL' = 'database'
            'Logs' = 'document'
        }

        $navButtons = @{}
        $navLabels = @{}
        $navIconBoxes = @{}
        $navIconImages = @{}
        foreach ($key in @('Dashboard', 'Scan Queue', 'Results', 'YARA Rules', 'Capa Rules', 'NSRL', 'Logs')) {
            $navBtn = New-Object System.Windows.Forms.Button
            $navBtn.Text = ''
            $navBtn.Width = 300
            $navBtn.Height = 48
            $navBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $navBtn.FlatAppearance.BorderSize = 0
            $navBtn.BackColor = $theme.SidebarBack
            $navBtn.ForeColor = $theme.Fore
            $navBtn.Tag = $key
            $navBtn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 2)
            $navBtn.Add_Click({ Show-Page -Name $this.Tag })

            $navIcon = New-Object System.Windows.Forms.PictureBox
            $navIconImages[$key] = @{
                Normal = New-LineIconBitmap -Name $navIconNames[$key] -Color $theme.MutedFore
                Active = New-LineIconBitmap -Name $navIconNames[$key] -Color $theme.Accent
            }
            $navIcon.Image = $navIconImages[$key].Normal
            $navIcon.Size = New-Object System.Drawing.Size(30, 30)
            $navIcon.Location = New-Object System.Drawing.Point(22, 9)
            $navIcon.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
            $navIcon.BackColor = [System.Drawing.Color]::Transparent
            $navIcon.Tag = $key
            $navIcon.Cursor = [System.Windows.Forms.Cursors]::Hand
            $navIcon.Add_Click({ Show-Page -Name $this.Tag })

            $navLabel = New-Object System.Windows.Forms.Label
            $navLabel.Text = $key
            $navLabel.AutoSize = $false
            $navLabel.Location = New-Object System.Drawing.Point(72, 0)
            $navLabel.Size = New-Object System.Drawing.Size(210, 48)
            $navLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
            $navLabel.Font = New-Object System.Drawing.Font('Segoe UI', 10.5)
            $navLabel.ForeColor = $theme.Fore
            $navLabel.BackColor = [System.Drawing.Color]::Transparent
            $navLabel.Tag = $key
            $navLabel.Cursor = [System.Windows.Forms.Cursors]::Hand
            $navLabel.Add_Click({ Show-Page -Name $this.Tag })

            $navBtn.Controls.Add($navIcon)
            $navBtn.Controls.Add($navLabel)
            $navPanel.Controls.Add($navBtn)
            $navButtons[$key] = $navBtn
            $navLabels[$key] = $navLabel
            $navIconBoxes[$key] = $navIcon
        }

        function Show-Page {
            param([string]$Name)
            foreach ($key in $pageMap.Keys) {
                $pageMap[$key].Visible = ($key -eq $Name)
                if ($navButtons.ContainsKey($key)) {
                    $navButtons[$key].BackColor = if ($key -eq $Name) { $theme.NavActive } else { $theme.SidebarBack }
                    $navButtons[$key].ForeColor = if ($key -eq $Name) { $theme.Accent } else { $theme.Fore }
                    $navLabels[$key].ForeColor = if ($key -eq $Name) { $theme.Accent } else { $theme.Fore }
                    $navIconBoxes[$key].Image = if ($key -eq $Name) { $navIconImages[$key].Active } else { $navIconImages[$key].Normal }
                }
            }
            $lblPageTitle.Text = if ($Name -eq 'Dashboard') { '' } else { $Name }

            if ($Name -eq 'Results') { Update-ResultsGrid }
            if ($Name -eq 'Capa Rules') { Update-CapaRulesList }
            if ($Name -eq 'YARA Rules') { Update-YaraRulesContent }
        }

        $btnTopSettings.Add_Click({ Show-Page -Name 'Settings' })
        $btnTopHelp.Add_Click({ Show-Page -Name 'Help' })
        $btnTopAbout.Add_Click({ Show-Page -Name 'About' })

        # ================= Settings page wiring =================
        foreach ($key in $Config.Keys) {
            if ($settings.Fields.ContainsKey($key)) { $settings.Fields[$key].Text = $Config[$key] }
        }

        $settings.BtnSave.Add_Click({
            $invalid = [System.Collections.Generic.List[string]]::new()
            $candidate = @{}

            $checks = @(
                @{ Key = 'SrcDir'; Type = 'Container' }
                @{ Key = 'NsrlPath'; Type = 'Leaf' }
                @{ Key = 'YaraRules'; Type = 'Leaf' }
                @{ Key = 'CapaRules'; Type = 'Container' }
                @{ Key = 'ToolsDir'; Type = 'Container' }
            )

            foreach ($check in $checks) {
                $value = $settings.Fields[$check.Key].Text.Trim()
                if (-not $value -or -not (Test-Path -LiteralPath $value -PathType $check.Type)) {
                    $invalid.Add($check.Key)
                }
                else {
                    $candidate[$check.Key] = (Resolve-Path -LiteralPath $value).Path
                }
            }

            # GhidraDir is the one remaining optional field (blank disables
            # the feature, same graceful-skip pattern as everything derived
            # from ToolsDir) - handled separately from $checks since "blank"
            # has to mean something different from "invalid" here. It's kept
            # as its own directory field rather than folded into ToolsDir's
            # search so a Ghidra install can just be pointed at directly,
            # unmodified, in its normal install location - analyzeHeadless.bat
            # is then located inside it below, same recursive-search approach
            # as everything under ToolsDir.
            $ghidraValue = $settings.Fields['GhidraDir'].Text.Trim()
            if ([string]::IsNullOrWhiteSpace($ghidraValue)) {
                $candidate['GhidraDir'] = ''
            }
            elseif (Test-Path -LiteralPath $ghidraValue -PathType Container) {
                $candidate['GhidraDir'] = (Resolve-Path -LiteralPath $ghidraValue).Path
            }
            else {
                $invalid.Add('GhidraDir')
            }

            # ToolsDir existing isn't enough on its own - BinSifter can't scan
            # at all without YARA/capa/ssdeep specifically, so those 3 have to
            # actually be found somewhere under it. Everything else derived
            # from ToolsDir (FLOSS, DIE, PE Studio, the debuggers, Sigcheck,
            # Speakeasy, ...) stays optional/graceful-skip, same as before -
            # only these three block Save. Recursive, not a flat Join-Path -
            # FRED tool directories are routinely hierarchical (each tool in
            # its own subfolder), so a same-level-only check would wrongly
            # reject a perfectly good tools directory. This can take a moment
            # on a large tree, hence the wait cursor.
            if ($candidate.ContainsKey('ToolsDir')) {
                $settings.Page.FindForm().Cursor = [System.Windows.Forms.Cursors]::WaitCursor
                try {
                    $requiredToolFiles = @('yara64.exe', 'capa.exe', 'ssdeep.exe')
                    foreach ($fileName in $requiredToolFiles) {
                        if (-not (Find-ToolPath -Directory $candidate['ToolsDir'] -FileName $fileName)) {
                            $invalid.Add("ToolsDir (missing $fileName)")
                        }
                    }
                }
                finally {
                    $settings.Page.FindForm().Cursor = [System.Windows.Forms.Cursors]::Default
                }
            }

            if ($invalid.Count -gt 0) {
                $settings.LblStatus.ForeColor = $theme.Danger
                $settings.LblStatus.Text = "Invalid or missing: $($invalid -join ', ')"
                return
            }

            # Existence isn't the same as write access - catching a read-only report
            # folder here beats finding out only after a multi-hour scan finishes.
            # ReportDirectory is a fixed default now (see $Config construction),
            # not part of $candidate, so probe the live $Config value directly.
            try {
                $probePath = Join-Path $Config.ReportDirectory ".bsifter-write-test-$([Guid]::NewGuid().ToString('N')).tmp"
                [System.IO.File]::WriteAllText($probePath, 'test')
                Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
            }
            catch {
                $settings.LblStatus.ForeColor = $theme.Danger
                $settings.LblStatus.Text = "Report directory is not writable: $($_.Exception.Message)"
                return
            }

            foreach ($key in $candidate.Keys) { $Config[$key] = $candidate[$key] }
            $settings.Page.FindForm().Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            try {
                Set-ToolPathsFromDirectory -Config $Config -Directory $Config.ToolsDir
                $Config.GhidraHeadlessExe = Find-ToolPath -Directory $Config.GhidraDir -FileName 'analyzeHeadless.bat'
            }
            finally {
                $settings.Page.FindForm().Cursor = [System.Windows.Forms.Cursors]::Default
            }
            $settings.LblStatus.ForeColor = $theme.Success
            $settings.LblStatus.Text = 'Settings saved.'
            Add-Log 'Settings saved.'

            # Cache the 6 raw fields (not the derived tool exe paths - those
            # are re-resolved from ToolsDir/GhidraDir every time, so caching
            # them too would just risk drifting stale) so next launch starts
            # from the same values, since these tend not to change assessment
            # to assessment on a given workstation. Best-effort - a read-only
            # BinSifter install directory just means caching silently doesn't
            # happen, not a Save failure.
            try {
                $cachePayload = @{}
                # Matches the Settings page's field list exactly (SrcDir/
                # NsrlPath/YaraRules/CapaRules/ToolsDir from $checks, plus
                # GhidraDir) - not read from $fieldDefs, since that array is
                # local to New-SettingsPage's own scope and isn't reachable
                # from this handler.
                foreach ($cacheKey in (@($checks.Key) + 'GhidraDir')) { $cachePayload[$cacheKey] = $Config[$cacheKey] }
                $cachePayload | ConvertTo-Json | Set-Content -LiteralPath $SettingsCachePath -Encoding UTF8 -ErrorAction Stop
            }
            catch { Add-Log "Could not cache Settings values: $($_.Exception.Message)" }

            $yaraPage.LblPath.Text = $Config.YaraRules
            $capaPage.LblPath.Text = $Config.CapaRules
            $nsrlPage.LblPath.Text = $Config.NsrlPath
            Update-YaraRulesContent
            Update-CapaRulesList
            Start-ToolMetadataRefresh
        })

        # ================= Scan Queue wiring =================
        $scanQueue.BtnStart.Add_Click({
            if ($ScanControl.IsRunning) { return }

            $missing = @()
            # ReportDirectory is always populated (fixed default, see $Config
            # construction) and YaraExe/CapaExe/SsdeepExe are only blank when
            # ToolsDir itself was never set - checking ToolsDir directly here
            # is equivalent and matches what the Settings page now shows.
            foreach ($key in @('SrcDir', 'NsrlPath', 'YaraRules', 'CapaRules', 'ToolsDir')) {
                if ([string]::IsNullOrWhiteSpace($Config[$key])) { $missing += $key }
            }
            if ($missing.Count -gt 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    $form, "Configure Settings before starting a scan.", 'BinSifter',
                    [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                Show-Page -Name 'Settings'
                return
            }

            $FileRecords.Clear()
            $dirtyPath = $null
            while ($UiDirtyQueue.TryDequeue([ref]$dirtyPath)) { }
            $UiSnapshots.Clear()
            foreach ($metricKey in @($UiTotals.Keys)) { $UiTotals[$metricKey] = 0 }
            $scanQueue.Grid.Rows.Clear()
            $scanQueue.RowIndexByPath.Clear()
            $ScanControl.IsRunning = $true
            $ScanControl.IsPaused = $false
            $ScanControl.StopRequested = $false
            $ScanControl.Completed = $false
            $ScanControl.FilesDiscovered = $false
            $ScanControl.TotalFiles = 0
            $ScanControl.OrderedPaths = $null
            $ScanControl.Timer = [System.Diagnostics.Stopwatch]::StartNew()
            $scanQueue.BtnPause.Text = "$([char]0x23F8)  Pause"
            Start-ToolMetadataRefresh

            Add-Log 'Scan starting...'
            $EngineState.Handle = Start-ScanEngine -Config $Config -ThrottleLimit $ThrottleLimit `
                -FileRecords $FileRecords -UiDirtyQueue $UiDirtyQueue -ScanControl $ScanControl `
                -LogQueue $LogQueue -WorkerScriptBlock $workerScriptBlock
        })

        $scanQueue.BtnPause.Add_Click({
            if (-not $ScanControl.IsRunning) { return }
            $ScanControl.IsPaused = -not $ScanControl.IsPaused
            $scanQueue.BtnPause.Text = if ($ScanControl.IsPaused) { "$([char]0x25B6)  Resume" } else { "$([char]0x23F8)  Pause" }
            Add-Log $(if ($ScanControl.IsPaused) { 'Scan paused.' } else { 'Scan resumed.' })
        })

        $scanQueue.BtnStop.Add_Click({
            if (-not $ScanControl.IsRunning) { return }
            $ScanControl.StopRequested = $true
            Add-Log 'Stop requested.'
        })

        $scanQueue.BtnClear.Add_Click({
            $toRemove = @($scanQueue.RowIndexByPath.Keys | Where-Object {
                $FileRecords.ContainsKey($_) -and $FileRecords[$_].Status -in @('Completed', 'Error', 'Cancelled')
            } | ForEach-Object {
                [pscustomobject]@{ Path = $_; RowIndex = $scanQueue.RowIndexByPath[$_] }
            } | Sort-Object RowIndex -Descending)
            foreach ($item in $toRemove) {
                if ($item.RowIndex -lt $scanQueue.Grid.Rows.Count) {
                    $scanQueue.Grid.Rows.RemoveAt($item.RowIndex)
                }
                $scanQueue.RowIndexByPath.Remove($item.Path)
            }
            # Re-index remaining rows after removal.
            $newIndex = @{}
            for ($i = 0; $i -lt $scanQueue.Grid.Rows.Count; $i++) {
                $p = $scanQueue.Grid.Rows[$i].Cells['Path'].Value
                $newIndex[$p] = $i
            }
            $scanQueue.RowIndexByPath.Clear()
            foreach ($k in $newIndex.Keys) { $scanQueue.RowIndexByPath[$k] = $newIndex[$k] }
        })

        # ================= Results page wiring =================
        function Update-ResultsGrid {
            $results.Grid.Rows.Clear()
            $predicate = $ResultsFilter.Predicate
            $matchCount = 0
            foreach ($kvp in $FileRecords.GetEnumerator() | Sort-Object { $_.Value.Path }) {
                $r = $kvp.Value
                if ($predicate -and -not (& $predicate $r)) { continue }
                $matchCount++
                $null = $results.Grid.Rows.Add(
                    $r.Path, $r.Status, $r.SHA1, $(if ($r.NsrlMatch) { 'Yes' } else { 'No' }),
                    $r.YaraHitCount, $r.YaraSeverity, $r.YaraAttackTechniques, $r.CapaDetectionCount,
                    $r.CapaShellcodeFormat,
                    $(if ($r.PossibleFalseNegative) { 'Yes' } else { 'No' }),
                    $(if ($r.Entropy -ge 0) { $r.Entropy.ToString('F2') } else { '' }),
                    $(if ($r.FlossStringCount -ge 0) { $r.FlossStringCount } else { '' }),
                    $r.SsdeepMatches,
                    $r.PackerDetected, $r.Compiler, $r.Imphash,
                    $r.SignatureStatus, $r.SignerName,
                    $(if ($r.IocCount -gt 0) { $r.IocCount } else { '' }),
                    $r.ExtractedIOCs, $r.ReputationStatus,
                    $r.Error,
                    $r.Disposition
                )
            }

            if ($ResultsFilter.Label) {
                $results.LblFilter.Text = "Filtered: $($ResultsFilter.Label)  -  $matchCount file(s)"
                $results.FilterBar.Visible = $true
            }
            else {
                $results.FilterBar.Visible = $false
            }
        }

        # v1.3-proto1: persists one Disposition call to the per-case history file
        # (SHA1|Disposition per line), read back by Start-ScanEngine's dispatcher
        # at the start of the next scan. Rewrites the whole file rather than
        # appending - simple and safe at the scale this is meant for (thousands
        # of entries, not millions), same tradeoff the SSDEEP cluster history
        # file already makes.
        function Save-DispositionEntry {
            param([string]$Sha1, [string]$Disposition)
            if (-not $Sha1 -or -not $Config.ReportDirectory -or -not (Test-Path -LiteralPath $Config.ReportDirectory -PathType Container)) { return }
            $historyPath = Join-Path $Config.ReportDirectory '.bsifter-disposition-history.txt'
            $entries = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            if (Test-Path -LiteralPath $historyPath -PathType Leaf) {
                try {
                    foreach ($line in [System.IO.File]::ReadAllLines($historyPath)) {
                        if ([string]::IsNullOrWhiteSpace($line)) { continue }
                        $fields = $line.Split('|')
                        if ($fields.Count -ge 2) { $entries[$fields[0].Trim()] = $fields[1].Trim() }
                    }
                }
                catch { }
            }
            $entries[$Sha1] = $Disposition
            try {
                $lines = foreach ($kvp in $entries.GetEnumerator()) { "$($kvp.Key)|$($kvp.Value)" }
                [System.IO.File]::WriteAllLines($historyPath, $lines)
            }
            catch {
                Add-Log "Could not save disposition history: $($_.Exception.Message)"
            }
        }

        # Combo-box cells only mark the grid "dirty" on selection, not commit the
        # value - forcing the commit immediately (rather than waiting for the
        # user to click elsewhere) is what makes a single dropdown pick feel like
        # a real single-click action instead of needing an extra click to "confirm" it.
        $results.Grid.Add_CurrentCellDirtyStateChanged({
            if ($results.Grid.IsCurrentCellDirty -and $results.Grid.CurrentCell.OwningColumn.Name -eq 'Disposition') {
                $results.Grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
            }
        })

        $results.Grid.Add_CellValueChanged({
            param($senderCtrl, $e)
            if ($e.RowIndex -lt 0 -or $e.ColumnIndex -lt 0) { return }
            $col = $senderCtrl.Columns[$e.ColumnIndex]
            if ($col.Name -ne 'Disposition') { return }
            $row = $senderCtrl.Rows[$e.RowIndex]
            $path = $row.Cells['Path'].Value
            $newDisposition = $row.Cells['Disposition'].Value
            if (-not $path -or -not $newDisposition) { return }
            if (-not $FileRecords.ContainsKey($path)) { return }
            $rec = $FileRecords[$path]
            $rec.Disposition = $newDisposition
            if ($rec.SHA1) { Save-DispositionEntry -Sha1 $rec.SHA1 -Disposition $newDisposition }
            # A disposition edit happens on the UI thread, not inside a worker, so
            # it never goes through the worker's own Publish-UiUpdate calls -
            # enqueue it directly so the dashboard's "Escalated" tile (dirty-queue
            # diffed, same as every other enrichment tile) picks up the change on
            # the next 750ms tick instead of only after some unrelated re-scan.
            if ($UiDirtyQueue) { $UiDirtyQueue.Enqueue($path) }
        })

        # Called from a dashboard tile/severity-bar/heat-map-cell click to jump to
        # Results pre-narrowed to just the rows behind that number. Predicate takes
        # one BinSifter.FileRecord and returns $true/$false; $null clears back to
        # showing everything (same as clicking Clear Filter).
        function Show-FilteredResults {
            param([string]$FilterLabel, [scriptblock]$Predicate)
            $ResultsFilter.Label = $FilterLabel
            $ResultsFilter.Predicate = $Predicate
            Show-Page -Name 'Results'
        }

        $results.BtnClearFilter.Add_Click({
            $ResultsFilter.Label = $null
            $ResultsFilter.Predicate = $null
            Update-ResultsGrid
        })

        $results.BtnRefresh.Add_Click({ Update-ResultsGrid })

        $results.BtnOpenFolder.Add_Click({
            if ($Config.ReportDirectory -and (Test-Path -LiteralPath $Config.ReportDirectory)) {
                Start-Process -FilePath $Config.ReportDirectory
            }
        })

        # Debounced so a large result set doesn't re-walk every row on every keystroke -
        # the timer restarts on each change and only applies the filter once typing pauses.
        $filterDebounceTimer = New-Object System.Windows.Forms.Timer
        $filterDebounceTimer.Interval = 300
        $filterDebounceTimer.Add_Tick({
            $filterDebounceTimer.Stop()
            $needle = $results.TxtFilter.Text
            foreach ($row in $results.Grid.Rows) {
                if ([string]::IsNullOrWhiteSpace($needle)) {
                    $row.Visible = $true
                }
                else {
                    $row.Visible = ("$($row.Cells['Path'].Value)" -like "*$needle*")
                }
            }
        })

        $results.TxtFilter.Add_TextChanged({
            $filterDebounceTimer.Stop()
            $filterDebounceTimer.Start()
        })

        # ================= YARA Rules page wiring =================
        function Update-YaraRulesContent {
            if ($Config.YaraRules -and (Test-Path -LiteralPath $Config.YaraRules -PathType Leaf)) {
                $yaraPage.LblPath.Text = $Config.YaraRules
                try {
                    $yaraPage.TxtContent.Text = [System.IO.File]::ReadAllText($Config.YaraRules)
                }
                catch {
                    $yaraPage.TxtContent.Text = "Could not read file: $($_.Exception.Message)"
                }
            }
            else {
                $yaraPage.LblPath.Text = 'No rules file configured.'
                $yaraPage.TxtContent.Text = ''
            }
        }

        $yaraPage.BtnBrowse.Add_Click({
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Filter = 'YARA rules (*.yar;*.yara)|*.yar;*.yara|All files (*.*)|*.*'
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $Config.YaraRules = $dialog.FileName
                $settings.Fields['YaraRules'].Text = $dialog.FileName
                Update-YaraRulesContent
            }
        })
        $yaraPage.BtnReload.Add_Click({ Update-YaraRulesContent })
        $yaraPage.BtnSave.Add_Click({
            if (-not $Config.YaraRules) { return }
            try {
                [System.IO.File]::WriteAllText($Config.YaraRules, $yaraPage.TxtContent.Text)
                Add-Log "YARA rules file saved: $($Config.YaraRules)"
                [System.Windows.Forms.MessageBox]::Show($form, 'Saved.', 'BinSifter') | Out-Null
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show($form, "Save failed: $($_.Exception.Message)", 'BinSifter', `
                    [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            }
        })

        # ================= Capa Rules page wiring =================
        function Update-CapaRulesList {
            $capaPage.List.Items.Clear()
            if ($Config.CapaRules -and (Test-Path -LiteralPath $Config.CapaRules -PathType Container)) {
                $capaPage.LblPath.Text = $Config.CapaRules
                $files = @(Get-ChildItem -LiteralPath $Config.CapaRules -Recurse -File -Include '*.yml', '*.yaml', '*.json' -ErrorAction SilentlyContinue)
                foreach ($f in $files) { $null = $capaPage.List.Items.Add($f.FullName) }
                if ($files.Count -eq 0) { $null = $capaPage.List.Items.Add('(no rule files found)') }
            }
            else {
                $capaPage.LblPath.Text = 'No rules directory configured.'
            }
        }

        $capaPage.BtnBrowse.Add_Click({
            $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $Config.CapaRules = $dialog.SelectedPath
                $settings.Fields['CapaRules'].Text = $dialog.SelectedPath
                Update-CapaRulesList
            }
        })
        $capaPage.BtnRefresh.Add_Click({ Update-CapaRulesList })
        $capaPage.BtnOpenFolder.Add_Click({
            if ($Config.CapaRules -and (Test-Path -LiteralPath $Config.CapaRules)) {
                Start-Process -FilePath $Config.CapaRules
            }
        })

        # ================= NSRL page wiring =================
        $nsrlPage.BtnBrowse.Add_Click({
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $Config.NsrlPath = $dialog.FileName
                $settings.Fields['NsrlPath'].Text = $dialog.FileName
                $nsrlPage.LblPath.Text = $dialog.FileName
            }
        })

        $nsrlPage.BtnReloadPreview.Add_Click({
            if (-not $Config.NsrlPath -or -not (Test-Path -LiteralPath $Config.NsrlPath -PathType Leaf)) {
                [System.Windows.Forms.MessageBox]::Show($form, 'Configure a valid NSRL file first.', 'BinSifter') | Out-Null
                return
            }
            if ($ScanControl.NsrlPreviewBusy) { return }
            $previousPreview = $ScanControl.NsrlPreviewHandle
            if ($previousPreview -and -not $previousPreview.Disposed) {
                if (-not $previousPreview.Handle.IsCompleted) { return }
                try { $null = $previousPreview.PS.EndInvoke($previousPreview.Handle) } catch { }
                $previousPreview.PS.Dispose()
                $previousPreview.Runspace.Close()
                $previousPreview.Runspace.Dispose()
                $previousPreview.Disposed = $true
            }
            $ScanControl.NsrlPreviewBusy = $true
            Add-Log 'Reloading NSRL preview...'

            $previewRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $previewRunspace.Open()
            $previewPs = [System.Management.Automation.PowerShell]::Create()
            $previewPs.Runspace = $previewRunspace
            $null = $previewPs.AddScript({
                param($NsrlPath, $ReportDirectory, $ScanControl, $LogQueue)

                try {
                    $count = 0
                    $usedCache = $false

                    # Same cache location/naming as the real scan engine, so this button
                    # actually reflects what a scan would use instead of always missing.
                    if ($ReportDirectory -and (Test-Path -LiteralPath $ReportDirectory -PathType Container)) {
                        $nsrlCacheDir = Join-Path $ReportDirectory '.bsifter-nsrl-cache'
                        $nsrlPathHash = [Convert]::ToHexString(
                            [System.Security.Cryptography.SHA256]::HashData(
                                [System.Text.Encoding]::UTF8.GetBytes($NsrlPath.ToLowerInvariant())
                            )
                        ).Substring(0, 16)
                        $cacheName = "$([System.IO.Path]::GetFileNameWithoutExtension($NsrlPath))_$nsrlPathHash.bsifter-cache"
                        $cachePath = Join-Path $nsrlCacheDir $cacheName

                        if (Test-Path -LiteralPath $cachePath -PathType Leaf) {
                            $sourceInfo = Get-Item -LiteralPath $NsrlPath
                            $cacheStream = [System.IO.File]::OpenRead($cachePath)
                            try {
                                $headerBuf = [byte[]]::new(16)
                                if ($cacheStream.Read($headerBuf, 0, 16) -eq 16) {
                                    $cachedLength = [BitConverter]::ToInt64($headerBuf, 0)
                                    $cachedTicks = [BitConverter]::ToInt64($headerBuf, 8)
                                    if ($cachedLength -eq $sourceInfo.Length -and $cachedTicks -eq $sourceInfo.LastWriteTimeUtc.Ticks) {
                                        $count = [Math]::Floor(($cacheStream.Length - 16) / 20)
                                        $usedCache = $true
                                    }
                                }
                            }
                            finally { $cacheStream.Dispose() }
                        }
                    }

                    if (-not $usedCache) {
                        # No cache yet, so this still walks the whole CSV once - only happens
                        # when asked for directly; a real scan builds the cache after this.
                        $count = [BinSifter.NsrlLoader]::CountRows($NsrlPath)
                    }

                    $ScanControl.NsrlHashCount = $count
                    $LogQueue.Enqueue("[$(Get-Date -Format 'HH:mm:ss')] NSRL preview reloaded: $count hashes$(if ($usedCache) { ' (from cache)' }).")
                }
                catch {
                    $LogQueue.Enqueue("[$(Get-Date -Format 'HH:mm:ss')] NSRL preview failed: $($_.Exception.Message)")
                }
                finally {
                    # Always clear the busy flag, even on failure - otherwise the button
                    # silently stops doing anything for the rest of the session.
                    $ScanControl.NsrlPreviewBusy = $false
                }
            })
            $null = $previewPs.AddArgument($Config.NsrlPath)
            $null = $previewPs.AddArgument($Config.ReportDirectory)
            $null = $previewPs.AddArgument($ScanControl)
            $null = $previewPs.AddArgument($LogQueue)
            $handle = $previewPs.BeginInvoke()
            $ScanControl.NsrlPreviewHandle = [pscustomobject]@{
                PS = $previewPs; Handle = $handle; Runspace = $previewRunspace; Disposed = $false
            }
        })

        # ================= Logs page wiring =================
        $logsPage.BtnClear.Add_Click({ $logsPage.TxtLog.Clear() })

        # ================= Refresh timer =================
        $refreshTimer = New-Object System.Windows.Forms.Timer
        $refreshTimer.Interval = 750

        $refreshTimer.Add_Tick({
            # Drain logs
            $line = $null
            $appended = $false
            while ($LogQueue.TryDequeue([ref]$line)) {
                $logsPage.TxtLog.AppendText("$line`r`n")
                $appended = $true
            }
            if ($appended) {
                $logsPage.TxtLog.SelectionStart = $logsPage.TxtLog.TextLength
                $logsPage.TxtLog.ScrollToCaret()
            }

            # Populate scan queue rows once files are discovered. SuspendLayout keeps
            # the grid from recalculating/redrawing on every single Rows.Add call -
            # without it, a large file count can freeze the UI for several seconds.
            if ($ScanControl.FilesDiscovered -and $scanQueue.Grid.Rows.Count -eq 0 -and $ScanControl.OrderedPaths) {
                $scanQueue.Grid.SuspendLayout()
                try {
                    foreach ($path in $ScanControl.OrderedPaths) {
                        $r = $FileRecords[$path]
                        $rowIdx = $scanQueue.Grid.Rows.Add($path, $r.Status, "$($r.Progress)%", $r.YaraHitCount, $r.YaraSeverity, $r.CapaDetectionCount, $(if ($r.PossibleFalseNegative) { 'Yes' } else { 'No' }), $(if ($r.NsrlMatch) { 'Yes' } else { 'No' }), $r.Added.ToString('g'))
                        $scanQueue.RowIndexByPath[$path] = $rowIdx
                    }
                }
                finally {
                    $scanQueue.Grid.ResumeLayout()
                }
            }

            # Drain only records whose workers reported a state change. Each
            # record's previous contribution is subtracted before its new
            # contribution is added, keeping dashboard totals incremental and
            # avoiding a full record/grid rewrite every 750 ms.
            $dirtyPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $dirtyPath = $null
            while ($UiDirtyQueue.TryDequeue([ref]$dirtyPath)) {
                if ($dirtyPath) { $null = $dirtyPaths.Add($dirtyPath) }
            }

            foreach ($path in $dirtyPaths) {
                if (-not $FileRecords.ContainsKey($path)) { continue }
                $r = $FileRecords[$path]
                $previous = if ($UiSnapshots.ContainsKey($path)) { $UiSnapshots[$path] } else { $null }
                if ($previous) {
                    foreach ($metricKey in @('Completed','YaraHits','CapaHits','CapaScans','NsrlMatches','Critical','High','Medium','Low','Unknown','ImphashClustered','Unsigned','KnownBad','WithIocs','Escalated')) {
                        $UiTotals[$metricKey] -= $previous[$metricKey]
                    }
                }

                $snapshot = @{
                    Completed = [int]($r.Status -eq 'Completed')
                    YaraHits = [int]$r.YaraHitCount
                    CapaHits = [int]$r.CapaDetectionCount
                    CapaScans = [int][bool]$r.CapaEligible
                    NsrlMatches = [int][bool]$r.NsrlMatch
                    Critical = 0; High = 0; Medium = 0; Low = 0; Unknown = 0
                    # v1.3-proto1 - same subtract/re-add pattern as everything above.
                    # ImphashClustered reflects the post-scan clustering pass (the
                    # dispatcher re-enqueues every clustered path once that pass
                    # finishes, same as any other per-file state change).
                    ImphashClustered = [int]($r.ImphashClusterId -ge 0 -and $r.ImphashClusterSize -ge 2)
                    Unsigned = [int]($r.SignatureStatus -and $r.SignatureStatus -ne 'Valid')
                    KnownBad = [int]($r.ReputationStatus -eq 'KnownBad')
                    WithIocs = [int]($r.IocCount -gt 0)
                    Escalated = [int]($r.Disposition -eq 'Escalated')
                }
                if ($r.YaraHitCount -gt 0) {
                    $severityKey = if ($r.YaraSeverity -in @('Critical','High','Medium','Low')) { $r.YaraSeverity } else { 'Unknown' }
                    $snapshot[$severityKey] = 1
                }
                foreach ($metricKey in @('Completed','YaraHits','CapaHits','CapaScans','NsrlMatches','Critical','High','Medium','Low','Unknown','ImphashClustered','Unsigned','KnownBad','WithIocs','Escalated')) {
                    $UiTotals[$metricKey] += $snapshot[$metricKey]
                }
                $UiSnapshots[$path] = $snapshot

                if ($scanQueue.RowIndexByPath.ContainsKey($path)) {
                    $rowIdx = $scanQueue.RowIndexByPath[$path]
                    if ($rowIdx -lt $scanQueue.Grid.Rows.Count) {
                        $row = $scanQueue.Grid.Rows[$rowIdx]
                        $row.Cells['Status'].Value = $r.Status
                        $row.Cells['Progress'].Value = "$($r.Progress)%"
                        $row.Cells['YaraHits'].Value = $r.YaraHitCount
                        $row.Cells['YaraSeverity'].Value = $r.YaraSeverity
                        $row.Cells['CapaDetections'].Value = $r.CapaDetectionCount
                        $row.Cells['PossibleFalseNegative'].Value = $(if ($r.PossibleFalseNegative) { 'Yes' } else { 'No' })
                        $row.Cells['NsrlMatch'].Value = $(if ($r.NsrlMatch) { 'Yes' } else { 'No' })
                    }
                }
            }

            $completedCount = $UiTotals.Completed
            $dashboard.TileFiles.Text = "$completedCount"
            $dashboard.TileYara.Text = "$($UiTotals.YaraHits)"
            $dashboard.TileCapaScans.Text = "$($UiTotals.CapaScans)"
            $dashboard.TileCapa.Text = "$($UiTotals.CapaHits)"
            $dashboard.TileNsrl.Text = "$($UiTotals.NsrlMatches)"
            $dashboard.TileImphash.Text = "$($UiTotals.ImphashClustered)"
            $dashboard.TileUnsigned.Text = "$($UiTotals.Unsigned)"
            $dashboard.TileKnownBad.Text = "$($UiTotals.KnownBad)"
            $dashboard.TileIocs.Text = "$($UiTotals.WithIocs)"
            $dashboard.TileEscalated.Text = "$($UiTotals.Escalated)"
            if ($dirtyPaths.Count -gt 0) {
                $dashboard.SeverityChartData['Critical'] = $UiTotals.Critical
                $dashboard.SeverityChartData['High'] = $UiTotals.High
                $dashboard.SeverityChartData['Medium'] = $UiTotals.Medium
                $dashboard.SeverityChartData['Low'] = $UiTotals.Low
                $dashboard.SeverityChartData['Unknown'] = $UiTotals.Unknown
                $dashboard.SeverityChartPanel.Invalidate()
            }

            # SSDEEP heat map - computed once by the dispatcher after clustering
            # finishes (see Start-ScanEngine), not recomputed every tick like the
            # counters above. This just displays whatever's currently there.
            $sm = $ScanControl.SsdeepMetrics
            if ($sm) {
                $denom = [Math]::Max(1, $sm.TotalHashedFiles)

                $dashboard.HeatClusters.Text = "$($sm.NumClusters)"
                $dashboard.HeatClusters.ForeColor = Get-HeatColor ($sm.NumClusters / $denom)

                $dashboard.HeatLargest.Text = "$($sm.LargestClusterSize)"
                $dashboard.HeatLargest.ForeColor = Get-HeatColor ($sm.LargestClusterSize / $denom)

                $dashboard.HeatSingletons.Text = "$($sm.Singletons)"
                $dashboard.HeatSingletons.ForeColor = Get-HeatColor ($sm.Singletons / $denom)

                $dashboard.HeatAvgScore.Text = "$($sm.AvgScore)"
                $dashboard.HeatAvgScore.ForeColor = Get-HeatColor ($sm.AvgScore / 100.0)

                $dashboard.HeatAbove85.Text = "$($sm.FilesAbove85)"
                $dashboard.HeatAbove85.ForeColor = Get-HeatColor ($sm.FilesAbove85 / $denom)

                $dashboard.HeatPreviouslySeen.Text = "$($sm.PreviouslySeenClusters)"
                $dashboard.HeatPreviouslySeen.ForeColor = Get-HeatColor ($sm.PreviouslySeenClusters / $denom)
            }

            if ($ScanControl.IsRunning) {
                $elapsed = if ($ScanControl.Timer) { $ScanControl.Timer.Elapsed } else { [TimeSpan]::Zero }
                $dashboard.LblSummary.Text = "Scanning: $completedCount / $($ScanControl.TotalFiles) files - elapsed $($elapsed.ToString('hh\:mm\:ss'))"
                $scanQueue.LblSummary.Text = "$($ScanControl.TotalFiles) files total - $completedCount completed - elapsed $($elapsed.ToString('hh\:mm\:ss'))"
            }
            elseif ($ScanControl.Completed) {
                $dashboard.LblSummary.Text = "Last scan finished: $completedCount / $($ScanControl.TotalFiles) files completed."
                $scanQueue.LblSummary.Text = "Scan finished. $completedCount / $($ScanControl.TotalFiles) files completed."
            }

            # Release the dispatcher's own runspace/PowerShell instance once it's done -
            # otherwise each Start Scan click leaks another one, since only the handle
            # (not the resources behind it) gets overwritten on the next run.
            if ($ScanControl.Completed -and $EngineState.Handle -and -not $EngineState.Handle.Disposed) {
                try { $null = $EngineState.Handle.PS.EndInvoke($EngineState.Handle.Handle) } catch { }
                $EngineState.Handle.PS.Dispose()
                $EngineState.Handle.Runspace.Close()
                $EngineState.Handle.Runspace.Dispose()
                $EngineState.Handle.Disposed = $true
            }

            # Same cleanup for the NSRL preview's one-off background runspace.
            $previewHandle = $ScanControl.NsrlPreviewHandle
            if ($previewHandle -and -not $previewHandle.Disposed -and $previewHandle.Handle.IsCompleted) {
                try { $null = $previewHandle.PS.EndInvoke($previewHandle.Handle) } catch { }
                $previewHandle.PS.Dispose()
                $previewHandle.Runspace.Close()
                $previewHandle.Runspace.Dispose()
                $previewHandle.Disposed = $true
            }

            $metadataHandle = $MetadataState.Handle
            if ($metadataHandle -and -not $metadataHandle.Disposed -and $metadataHandle.Handle.IsCompleted) {
                try { $null = $metadataHandle.PS.EndInvoke($metadataHandle.Handle) } catch { }
                $metadataHandle.PS.Dispose()
                $metadataHandle.Runspace.Close()
                $metadataHandle.Runspace.Dispose()
                $metadataHandle.Disposed = $true
            }

            # Status dot + button enablement
            if ($ScanControl.IsRunning -and $ScanControl.IsPaused) {
                $lblStatusText.Text = 'Paused'
                $lblStatusDot.ForeColor = $theme.Warning
            }
            elseif ($ScanControl.IsRunning) {
                $lblStatusText.Text = 'Scanning'
                $lblStatusDot.ForeColor = $theme.Accent
            }
            else {
                $lblStatusText.Text = 'Ready'
                $lblStatusDot.ForeColor = $theme.Success
            }
            Move-TopBarControls

            $scanQueue.BtnStart.Enabled = -not $ScanControl.IsRunning
            $scanQueue.BtnPause.Enabled = $ScanControl.IsRunning
            $scanQueue.BtnStop.Enabled = $ScanControl.IsRunning

            if ($ScanControl.NsrlHashCount -gt 0) {
                $nsrlPage.LblCount.Text = "$($ScanControl.NsrlHashCount)"
            }

            $statusBits = @(
                "Engine: $AppVersion"
                "YARA: $($ToolMetadata.Yara)"
                "Capa: $($ToolMetadata.Capa)"
                "SSDEEP: $($ToolMetadata.Ssdeep)"
                "NSRL: $($ToolMetadata.NsrlDate)"
            )
            $lblStatusBar.Text = $statusBits -join '   |   '
        })

        $form.Add_FormClosing({
            if ($ScanControl.IsRunning) {
                $ScanControl.StopRequested = $true

                # Kill in-flight tool processes directly rather than only hoping the
                # dispatcher notices StopRequested before this process tears down -
                # the dispatcher runs on a background thread that doesn't keep the
                # process alive, so external tools could otherwise be orphaned.
                if ($ScanControl.ProcessRegistry) {
                    foreach ($proc in $ScanControl.ProcessRegistry.Values) {
                        try { if (-not $proc.HasExited) { $proc.Kill($true) } } catch { }
                    }
                }

                $deadline = (Get-Date).AddSeconds(5)
                while (-not $ScanControl.Completed -and (Get-Date) -lt $deadline) {
                    [System.Windows.Forms.Application]::DoEvents()
                    Start-Sleep -Milliseconds 100
                }
            }
            $refreshTimer.Stop()
            $filterDebounceTimer.Stop()

            $previewHandle = $ScanControl.NsrlPreviewHandle
            if ($previewHandle -and -not $previewHandle.Disposed) {
                if (-not $previewHandle.Handle.IsCompleted) {
                    try { $previewHandle.PS.Stop() } catch { }
                }
                try { $null = $previewHandle.PS.EndInvoke($previewHandle.Handle) } catch { }
                $previewHandle.PS.Dispose()
                $previewHandle.Runspace.Close()
                $previewHandle.Runspace.Dispose()
                $previewHandle.Disposed = $true
                $ScanControl.NsrlPreviewBusy = $false
            }

            $metadataHandle = $MetadataState.Handle
            if ($metadataHandle -and -not $metadataHandle.Disposed) {
                if (-not $metadataHandle.Handle.IsCompleted) {
                    try { $metadataHandle.PS.Stop() } catch { }
                }
                try { $null = $metadataHandle.PS.EndInvoke($metadataHandle.Handle) } catch { }
                $metadataHandle.PS.Dispose()
                $metadataHandle.Runspace.Close()
                $metadataHandle.Runspace.Dispose()
                $metadataHandle.Disposed = $true
                $MetadataState.Busy = $false
            }
            if ($windowIcon) { $windowIcon.Dispose() }
            if ($windowIconBitmap) { $windowIconBitmap.Dispose() }
            # Icon.Dispose() above frees the Icon wrapper but not the native HICON
            # GetHicon() allocated - release that separately or it leaks for the
            # life of the process (harmless since it's one handle and the process
            # is exiting anyway, but cheap to do correctly).
            if ($windowIconHandle -ne [IntPtr]::Zero) { [BinSifter.NativeIcon]::DestroyIcon($windowIconHandle) | Out-Null }
        })

        $form.Add_Shown({
            Move-TopBarControls
            # Resolve a cached ToolsDir/GhidraDir's derived tool paths now
            # that the window is actually on screen, rather than blocking
            # startup before the first paint - a hierarchical FRED tool tree
            # (or a full Ghidra install) can take a moment to walk
            # recursively (see Find-ToolPath / where $Config is built).
            if ($Config.ToolsDir -or $Config.GhidraDir) {
                $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
                try {
                    if ($Config.ToolsDir) {
                        Set-ToolPathsFromDirectory -Config $Config -Directory $Config.ToolsDir
                        Add-Log "Resolved tools from cached tools directory: $($Config.ToolsDir)"
                    }
                    if ($Config.GhidraDir) {
                        $Config.GhidraHeadlessExe = Find-ToolPath -Directory $Config.GhidraDir -FileName 'analyzeHeadless.bat'
                        Add-Log "Resolved Ghidra from cached Ghidra directory: $($Config.GhidraDir)"
                    }
                    Start-ToolMetadataRefresh
                }
                finally {
                    $form.Cursor = [System.Windows.Forms.Cursors]::Default
                }
            }
        })

        Show-Page -Name 'Dashboard'
        $refreshTimer.Start()
        [System.Windows.Forms.Application]::Run($form)
    })

    try {
        $ps.Invoke()
        if ($ps.HadErrors) {
            $ps.Streams.Error | ForEach-Object { Write-Warning $_.Exception.Message }
        }
    }
    finally {
        $ps.Dispose()
        $runspace.Close()
        $runspace.Dispose()
    }
}

# ================= Bootstrap =================
# Bump this on every new version file - it's the only place the displayed
# version number needs to change now (status bar + About page both read it).
$AppVersion = 'v1.3.0-alpha.2'
$isDarkMode = Test-SystemDarkMode
$threadLimit = [Math]::Min(16, [Math]::Max(2, [Environment]::ProcessorCount * 2))
$logoHorizontal = if ($isDarkMode) {
    Join-Path $PSScriptRoot 'BinSifter-Logo-Horizontal-Dark.png'
}
else {
    Join-Path $PSScriptRoot 'BinSifter-Logo-Horizontal.png'
}
$windowIconPath = Join-Path $PSScriptRoot 'BinSifter-WindowIcon.png'

Show-MainWindow -IsDarkMode $isDarkMode -LogoHorizontalPath $logoHorizontal -WindowIconPath $windowIconPath -ThrottleLimit $threadLimit -AppVersion $AppVersion

Write-Host '[+] BinSifter closed.' -ForegroundColor Green
