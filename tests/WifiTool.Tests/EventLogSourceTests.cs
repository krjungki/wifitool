// 존재하지 않는 EVTX 입력이 사건 없음이 아닌 coverage 오류로 남는지 검증한다.
using WifiTool.Windows;

namespace WifiTool.Tests;

public sealed class EventLogSourceTests
{
    [Fact]
    public void LiveQueryUsesDirectXPathComparisonOperator()
    {
        var now = DateTimeOffset.Parse("2026-09-08T00:01:00Z");

        var query = EventLogSource.BuildRecentQuery(now.AddMinutes(-1), now);

        Assert.Equal("*[System[TimeCreated[timediff(@SystemTime) <= 60000]]]", query);
        Assert.DoesNotContain("&lt;", query, StringComparison.Ordinal);
    }

    [Fact]
    public void T06_ReportsMissingEvtxAsCoverageFailure()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.evtx");

        var result = new EventLogSource().ReadFiles([missing]);

        Assert.Empty(result.Events);
        Assert.Single(result.Channels);
        Assert.NotEqual("empty", result.Channels[0].Status);
        Assert.NotEqual("available", result.Channels[0].Status);
    }
}