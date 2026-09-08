// 진단 ZIP의 경로·크기·hash 검증이 위험 입력을 거부하는지 검증한다.
using System.IO.Compression;
using System.Text.Json;
using WifiTool.Windows;

namespace WifiTool.Tests;

public sealed class DiagnosticPackageTests
{
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