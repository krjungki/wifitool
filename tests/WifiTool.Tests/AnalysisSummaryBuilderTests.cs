// 로그 채널 부재와 Intel payload 복원을 진단 요약에 정확히 표시하는지 검증한다.
using WifiTool.Core;

namespace WifiTool.Tests;

public sealed class AnalysisSummaryBuilderTests
{
    [Fact]
    public void ReportsMissingOperationalAndSecurityCoverageWithoutClaimingRootCause()
    {
        var time = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var events = new[]
        {
            new NormalizedEvent("synthetic", "System", "Netwtw14", 7021, 1, time, null, null, null, "CORP-WIFI", null, null, null, null, null, null, "<Event/>", new Dictionary<string, string>()) { Bssid = "00:11:22:33:44:55" },
            new NormalizedEvent("synthetic", "System", "Netwtw10", 5002, 2, time.AddSeconds(1), null, null, null, null, null, null, null, null, null, null, "<Event/>", new Dictionary<string, string>())
        };
        var timeline = new TimelineBuilder().Build(events, TimeSpan.FromMinutes(5));

        var overview = new AnalysisSummaryBuilder().Build(events, timeline);

        Assert.Contains(overview.Findings, item => item.Contains("WLAN-AutoConfig/Operational"));
        Assert.Contains(overview.Findings, item => item.Contains("Security 로그"));
        Assert.Contains(overview.Findings, item => item.Contains("binary payload"));
        Assert.Contains(overview.Findings, item => item.Contains("단정하지 않습니다"));
        Assert.Equal(1, overview.DistinctSsidCount);
        Assert.Equal(1, overview.WifiFailedCount);
    }
}