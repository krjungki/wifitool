// 이벤트 로그와 분석 결과를 무결성 manifest가 있는 로컬 ZIP으로 수집한다.
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WifiTool.Core;

namespace WifiTool.Windows;

public sealed record PackageEntry(string Path, long Size, string Sha256);

public sealed record PackageManifest(
    string SchemaVersion,
    string ToolVersion,
    string CollectionId,
    DateTimeOffset CollectedAt,
    DateTimeOffset RequestedFrom,
    DateTimeOffset RequestedTo,
    string DisplayTimeZone,
    IReadOnlyList<PackageEntry> Files,
    IReadOnlyList<ChannelStatus> Channels,
    bool Partial);

public sealed record PackageCreationResult(string Path, PackageManifest Manifest);

public sealed class DiagnosticPackageService
{
    public const int MaxEntries = 64;
    public const long MaxUncompressedBytes = 512L * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public PackageCreationResult Create(
        string destination,
        DateTimeOffset from,
        DateTimeOffset to,
        IEnumerable<string> channels,
        IReadOnlyList<TimelineEntry> timeline,
        IReadOnlyList<WifiProfileSnapshot> profiles,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        if (File.Exists(destination)) throw new IOException("기존 ZIP을 덮어쓰지 않습니다.");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(destination))!);
        var collectionId = Guid.NewGuid().ToString("N");
        var workspace = Path.Combine(Path.GetTempPath(), "WifiTool", collectionId);
        var pending = destination + ".partial";
        Directory.CreateDirectory(workspace);

        try
        {
            var statuses = ExportChannels(workspace, from, to, channels, cancellationToken);
            WriteProfiles(workspace, profiles, cancellationToken);
            WriteTimeline(workspace, timeline, cancellationToken);
            WriteInventory(workspace, cancellationToken);
            File.WriteAllText(Path.Combine(workspace, "collection-status.json"), JsonSerializer.Serialize(statuses, JsonOptions), new UTF8Encoding(false));

            var files = EnumerateEntries(workspace);
            var manifest = new PackageManifest(
                "1.0",
                Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "unknown",
                collectionId,
                DateTimeOffset.UtcNow,
                from.ToUniversalTime(),
                to.ToUniversalTime(),
                TimeZoneInfo.Local.Id,
                files,
                statuses,
                statuses.Any(item => item.Status is not ("available" or "empty")));
            File.WriteAllText(Path.Combine(workspace, "manifest.json"), JsonSerializer.Serialize(manifest, JsonOptions), new UTF8Encoding(false));

            if (File.Exists(pending)) File.Delete(pending);
            ZipFile.CreateFromDirectory(workspace, pending, CompressionLevel.Optimal, false);
            File.Move(pending, destination, false);
            return new PackageCreationResult(destination, manifest);
        }
        finally
        {
            if (File.Exists(pending)) File.Delete(pending);
            if (Directory.Exists(workspace)) Directory.Delete(workspace, true);
        }
    }

    public PackageManifest Validate(string packagePath)
    {
        using var archive = ZipFile.OpenRead(packagePath);
        if (archive.Entries.Count is 0 or > MaxEntries) throw new InvalidDataException("ZIP 파일 수 제한을 벗어났습니다.");
        var totalSize = archive.Entries.Sum(entry => entry.Length);
        if (totalSize > MaxUncompressedBytes) throw new InvalidDataException("ZIP 해제 크기 제한을 벗어났습니다.");
        foreach (var entry in archive.Entries)
        {
            ValidateEntryName(entry.FullName);
            var unixFileType = (entry.ExternalAttributes >> 16) & 0xF000;
            var windowsAttributes = entry.ExternalAttributes & 0xFFFF;
            if (unixFileType == 0xA000 || (windowsAttributes & (int)FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("ZIP link 항목은 허용하지 않습니다.");
            if (entry.CompressedLength > 0 && entry.Length / Math.Max(1, entry.CompressedLength) > 200)
                throw new InvalidDataException("비정상적인 압축비를 가진 항목이 있습니다.");
        }

        var manifestEntry = archive.GetEntry("manifest.json") ?? throw new InvalidDataException("manifest.json이 없습니다.");
        PackageManifest manifest;
        using (var stream = manifestEntry.Open())
        {
            manifest = JsonSerializer.Deserialize<PackageManifest>(stream)
                ?? throw new InvalidDataException("manifest.json을 해석할 수 없습니다.");
        }
        if (manifest.SchemaVersion != "1.0" || string.IsNullOrWhiteSpace(manifest.CollectionId))
            throw new InvalidDataException("지원하지 않거나 불완전한 manifest schema입니다.");

        foreach (var expected in manifest.Files)
        {
            ValidateEntryName(expected.Path);
            var actual = archive.GetEntry(expected.Path) ?? throw new InvalidDataException($"필수 항목이 없습니다: {expected.Path}");
            if (actual.Length != expected.Size) throw new InvalidDataException($"크기가 일치하지 않습니다: {expected.Path}");
            using var stream = actual.Open();
            var hash = Convert.ToHexString(SHA256.HashData(stream));
            if (!hash.Equals(expected.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"SHA-256이 일치하지 않습니다: {expected.Path}");
        }

        return manifest;
    }

    private static List<ChannelStatus> ExportChannels(
        string workspace,
        DateTimeOffset from,
        DateTimeOffset to,
        IEnumerable<string> channels,
        CancellationToken cancellationToken)
    {
        var result = new List<ChannelStatus>();
        var eventDirectory = Directory.CreateDirectory(Path.Combine(workspace, "events"));
        using var session = new EventLogSession();
        var start = from.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
        var end = to.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
        var query = $"*[System[TimeCreated[@SystemTime&gt;='{start}' and @SystemTime&lt;='{end}']]]";
        var index = 0;

        foreach (var channel in channels.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var target = Path.Combine(eventDirectory.FullName, $"channel-{++index:D2}.evtx");
            try
            {
                session.ExportLog(channel, PathType.LogName, query, target);
                result.Add(new ChannelStatus(channel, "available", 0, Path.GetFileName(target)));
            }
            catch (UnauthorizedAccessException exception)
            {
                result.Add(new ChannelStatus(channel, "denied", 0, exception.Message));
            }
            catch (EventLogNotFoundException exception)
            {
                result.Add(new ChannelStatus(channel, "not-found", 0, exception.Message));
            }
            catch (EventLogException exception)
            {
                result.Add(new ChannelStatus(channel, "error", 0, exception.Message));
            }
        }
        return result;
    }

    private static void WriteProfiles(string workspace, IReadOnlyList<WifiProfileSnapshot> profiles, CancellationToken cancellationToken)
    {
        if (profiles.Count == 0) return;
        var directory = Directory.CreateDirectory(Path.Combine(workspace, "profiles"));
        for (var index = 0; index < profiles.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var profile = profiles[index];
            if (profile.SanitizedXml is null || profile.ExportBlockedReason is not null) continue;
            File.WriteAllText(Path.Combine(directory.FullName, $"profile-{index + 1:D2}.xml"), profile.SanitizedXml, new UTF8Encoding(false));
        }
    }

    private static void WriteTimeline(string workspace, IReadOnlyList<TimelineEntry> timeline, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        File.WriteAllText(Path.Combine(workspace, "timeline.json"), JsonSerializer.Serialize(timeline, JsonOptions), new UTF8Encoding(false));
        var csv = new StringBuilder("timestamp,stage,account,ssid,outcome,evidence,summary\r\n");
        foreach (var item in timeline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            csv.AppendLine(string.Join(',', CsvValue.Escape(item.Timestamp.ToString("o")), CsvValue.Escape(item.Stage), CsvValue.Escape(item.Account), CsvValue.Escape(item.Ssid), CsvValue.Escape(item.Outcome.ToString()), CsvValue.Escape(item.Evidence.ToString()), CsvValue.Escape(item.Summary)));
        }
        File.WriteAllText(Path.Combine(workspace, "timeline.csv"), csv.ToString(), new UTF8Encoding(false));
    }

    private static void WriteInventory(string workspace, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var inventory = new
        {
            Machine = Environment.MachineName,
            OS = Environment.OSVersion.VersionString,
            Architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
            CapturedAt = DateTimeOffset.UtcNow
        };
        File.WriteAllText(Path.Combine(workspace, "inventory.json"), JsonSerializer.Serialize(inventory, JsonOptions), new UTF8Encoding(false));
    }

    private static List<PackageEntry> EnumerateEntries(string workspace) =>
        Directory.EnumerateFiles(workspace, "*", SearchOption.AllDirectories)
            .Select(path => new PackageEntry(
                Path.GetRelativePath(workspace, path).Replace('\\', '/'),
                new FileInfo(path).Length,
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))))
            .OrderBy(item => item.Path, StringComparer.Ordinal)
            .ToList();

    private static void ValidateEntryName(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || Path.IsPathRooted(path) || path.Contains("..", StringComparison.Ordinal) || path.Contains('\\'))
            throw new InvalidDataException("안전하지 않은 ZIP 항목 경로입니다.");
    }
}

public static class CsvValue
{
    public static string Escape(string? value)
    {
        value ??= string.Empty;
        if (value.Length > 0 && "=+-@\t\r".Contains(value[0])) value = "'" + value;
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }
}