// 진단 ZIP의 경로·크기·hash 검증이 위험 입력을 거부하는지 검증한다.
using System.IO.Compression;
using System.Text.Json;
using WifiTool.Windows;

namespace WifiTool.Tests;

public sealed class DiagnosticPackageTests
{
    [Fact]
    public void CollectionChannelsIncludeSecurityOnlyWhenSelected()
    {
        Assert.DoesNotContain("Security", DiagnosticPackageService.BuildEventChannels(false));
        Assert.Contains("Security", DiagnosticPackageService.BuildEventChannels(true));
    }

    [Fact]
    public void RangeQueryUsesDirectXPathOperators()
    {
        var from = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var query = DiagnosticPackageService.BuildRangeQuery(from, from.AddHours(1));

        Assert.Contains("@SystemTime>='2026-09-08T00:00:00.0000000+00:00'", query);
        Assert.Contains("@SystemTime<='2026-09-08T01:00:00.0000000+00:00'", query);
        Assert.DoesNotContain("&gt;", query, StringComparison.Ordinal);
        Assert.DoesNotContain("&lt;", query, StringComparison.Ordinal);
    }

    [Fact]
    public void CollectionPackageIncludesSanitizedWifiProfileAndManifestCounts()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wifitool-test-{Guid.NewGuid():N}.zip");
        var profile = new WifiTool.Core.WifiProfileSnapshot(
            "interface", "adapter", "profile", "CORP-WIFI", "AllUser", DateTimeOffset.UtcNow,
            new Dictionary<string, string>(), "<WLANProfile><name>profile</name></WLANProfile>", null);
        try
        {
            var result = new DiagnosticPackageService().Create(
                path, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow,
                [], [], [profile], true);

            Assert.True(result.Manifest.WifiProfilesRequested);
            Assert.Equal(1, result.Manifest.ProfilesFound);
            Assert.Equal(1, result.Manifest.ProfilesExported);
            Assert.Contains(result.Manifest.Channels, item => item.Channel == "Wi-Fi profiles" && item.Status == "available");
            using var archive = ZipFile.OpenRead(path);
            Assert.NotNull(archive.GetEntry("profiles/profile-01.xml"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void CollectionPackageSupportsManyManagedWifiProfiles()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wifitool-test-{Guid.NewGuid():N}.zip");
        var profiles = Enumerable.Range(1, 70)
            .Select(index => new WifiTool.Core.WifiProfileSnapshot(
                $"interface-{index}", "adapter", $"profile-{index}", $"SSID-{index}", "AllUser", DateTimeOffset.UtcNow,
                new Dictionary<string, string>(), $"<WLANProfile><name>profile-{index}</name></WLANProfile>", null))
            .ToList();
        try
        {
            var result = new DiagnosticPackageService().Create(
                path, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow,
                [], [], profiles, true);

            Assert.Equal(70, result.Manifest.ProfilesExported);
            Assert.Equal(result.Manifest.CollectionId, new DiagnosticPackageService().Validate(path).CollectionId);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ProfileCollectionErrorMarksPackagePartialWithoutBlockingZip()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wifitool-test-{Guid.NewGuid():N}.zip");
        try
        {
            var result = new DiagnosticPackageService().Create(
                path, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow,
                [], [], [], true, "profile access denied");

            Assert.True(result.Manifest.Partial);
            Assert.Contains(result.Manifest.Channels, item => item.Channel == "Wi-Fi profiles" && item.Status == "error");
            Assert.True(File.Exists(path));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void T12_ValidatesManifestHashAndRejectsTampering()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wifitool-test-{Guid.NewGuid():N}.zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                Write(archive, "timeline.json", "[]");
                var manifest = new PackageManifest("1.0", "0.1.0", "test", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, "UTC",
                    [new PackageEntry("timeline.json", 2, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("[]"u8.ToArray())))], [], false);
                Write(archive, "manifest.json", JsonSerializer.Serialize(manifest));
            }
            var service = new DiagnosticPackageService();
            Assert.Equal("test", service.Validate(path).CollectionId);

            using (var archive = ZipFile.Open(path, ZipArchiveMode.Update))
            {
                archive.GetEntry("timeline.json")!.Delete();
                Write(archive, "timeline.json", "[1]");
            }
            Assert.Throws<InvalidDataException>(() => service.Validate(path));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void T12_RejectsTraversalEntry()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wifitool-test-{Guid.NewGuid():N}.zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create)) Write(archive, "../escape.txt", "x");
            Assert.Throws<InvalidDataException>(() => new DiagnosticPackageService().Validate(path));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void T12_RejectsSymbolicLinkEntry()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wifitool-test-{Guid.NewGuid():N}.zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry("link");
                entry.ExternalAttributes = 0xA000 << 16;
            }
            Assert.Throws<InvalidDataException>(() => new DiagnosticPackageService().Validate(path));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void T12_RejectsLargeHighCompressionEntry()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wifitool-test-{Guid.NewGuid():N}.zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry("large-zeroes.bin", CompressionLevel.SmallestSize);
                using var stream = entry.Open();
                stream.Write(new byte[2 * 1024 * 1024]);
            }
            Assert.Throws<InvalidDataException>(() => new DiagnosticPackageService().Validate(path));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Theory]
    [InlineData("=cmd|' /C calc'!A0")]
    [InlineData("+SUM(1,1)")]
    [InlineData("-10+20")]
    [InlineData("@SUM(1,1)")]
    public void T11_PrefixesCsvFormulaValues(string value)
    {
        Assert.StartsWith("\"'", CsvValue.Escape(value));
    }

    private static void Write(ZipArchive archive, string name, string content)
    {
        var entry = archive.CreateEntry(name);
        using var writer = new StreamWriter(entry.Open());
        writer.Write(content);
    }
}