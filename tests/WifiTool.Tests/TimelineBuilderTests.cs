// 부팅·로그온·무선 사건의 상관분석이 관측과 추론을 구분하는지 검증한다.
using WifiTool.Core;

namespace WifiTool.Tests;

public sealed class TimelineBuilderTests
{
    private readonly TimelineBuilder _builder = new();

    [Fact]
    public void T01_SeparatesBootLogonAndUserWifiEvidence()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(12, "Microsoft-Windows-Kernel-General", "System", start),
            Event(8001, "Microsoft-Windows-WLAN-AutoConfig", "System", start.AddSeconds(20), ssid: "corp"),
            Event(4624, "Microsoft-Windows-Security-Auditing", "Security", start.AddSeconds(30), account: "CONTOSO\\user", logonType: "2"),
            Event(11001, "Microsoft-Windows-WLAN-AutoConfig", "Microsoft-Windows-WLAN-AutoConfig/Operational", start.AddSeconds(40), ssid: "corp", account: "CONTOSO\\user")
        ], TimeSpan.FromMinutes(5));

        Assert.Equal(4, timeline.Count);
        Assert.Null(timeline[1].SinceLogon);
        Assert.Equal(TimeSpan.FromSeconds(10), timeline[3].SinceLogon);
        Assert.Equal(EvidenceLevel.Inferred, timeline[3].Evidence);
    }

    [Fact]
    public void T02_DoesNotCallElapsedTimeAuthenticationDuration()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(7001, "Microsoft-Windows-Winlogon", "System", start),
            Event(8001, "Microsoft-Windows-WLAN-AutoConfig", "System", start.AddSeconds(130), ssid: "corp")
        ], TimeSpan.FromMinutes(5));

        Assert.Equal(TimeSpan.FromSeconds(130), timeline[1].SinceLogon);
        Assert.Null(timeline[1].Account);
        Assert.Contains("실제 EAP 인증 소요시간", timeline[1].Details);
    }

    [Fact]
    public void T03_PreservesFailureAndFallbackSuccess()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(8002, "Microsoft-Windows-WLAN-AutoConfig", "System", start, ssid: "corp"),
            Event(8001, "Microsoft-Windows-WLAN-AutoConfig", "System", start.AddSeconds(4), ssid: "guest")
        ], TimeSpan.FromMinutes(5));

        Assert.Equal([Outcome.Failed, Outcome.Succeeded], timeline.Select(item => item.Outcome));
        Assert.Equal(["corp", "guest"], timeline.Select(item => item.Ssid));
    }

    [Fact]
    public void T05_KeepsDnsFailureSeparateFromWifiSuccess()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(7001, "Microsoft-Windows-Winlogon", "System", start),
            Event(8015, "Microsoft-Windows-DNS-Client", "System", start.AddSeconds(2)),
            Event(8001, "Microsoft-Windows-WLAN-AutoConfig", "System", start.AddSeconds(4))
        ], TimeSpan.FromMinutes(5));

        Assert.Equal(TimelineKind.DependentServiceFailure, timeline[1].Kind);
        Assert.Equal("DNS 처리 실패", timeline[1].Stage);
        Assert.Equal(Outcome.Failed, timeline[1].Outcome);
        Assert.Equal(Outcome.Succeeded, timeline[2].Outcome);
    }

    [Fact]
    public void T07_IgnoresNonInteractiveNetworkLogon()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(4624, "Microsoft-Windows-Security-Auditing", "Security", start, logonType: "3"),
            Event(8001, "Microsoft-Windows-WLAN-AutoConfig", "System", start.AddSeconds(5))
        ], TimeSpan.FromMinutes(5));

        Assert.Single(timeline);
        Assert.Null(timeline[0].SinceLogon);
    }

    [Fact]
    public void T09_DoesNotCorrelateAcrossBoot()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(7001, "Microsoft-Windows-Winlogon", "System", start),
            Event(12, "Microsoft-Windows-Kernel-General", "System", start.AddMinutes(1)),
            Event(8001, "Microsoft-Windows-WLAN-AutoConfig", "System", start.AddMinutes(2))
        ], TimeSpan.FromMinutes(5));

        Assert.Null(timeline[^1].SinceLogon);
    }

    [Fact]
    public void T04_UsesProviderMetadataMeaningForSecurityEvents()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(11004, "Microsoft-Windows-WLAN-AutoConfig", "Microsoft-Windows-WLAN-AutoConfig/Operational", start),
            Event(11006, "Microsoft-Windows-WLAN-AutoConfig", "Microsoft-Windows-WLAN-AutoConfig/Operational", start.AddSeconds(1))
        ], TimeSpan.FromMinutes(5));

        Assert.Equal(Outcome.Unknown, timeline[0].Outcome);
        Assert.Equal("무선 보안 중지", timeline[0].Stage);
        Assert.Equal(Outcome.Failed, timeline[1].Outcome);
        Assert.Equal("무선 보안 실패", timeline[1].Stage);
    }

    [Fact]
    public void T08_SortsOutOfOrderInputByUtcTimestamp()
    {
        var start = DateTimeOffset.Parse("2026-11-01T01:00:00-07:00");
        var timeline = _builder.Build([
            Event(8001, "Microsoft-Windows-WLAN-AutoConfig", "System", start.AddMinutes(1)),
            Event(12, "Microsoft-Windows-Kernel-General", "System", start)
        ], TimeSpan.FromMinutes(5));

        Assert.Equal(TimelineKind.Boot, timeline[0].Kind);
        Assert.True(timeline[0].Timestamp.UtcDateTime < timeline[1].Timestamp.UtcDateTime);
    }

    [Fact]
    public void IncludesIntelConnectionAndRoamWithBssidContext()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var connected = Event(7021, "Netwtw14", "System", start, ssid: "CORP-WIFI") with
        {
            Bssid = "00:11:22:33:44:55"
        };
        var roamed = Event(7003, "Netwtw14", "System", start.AddSeconds(10), ssid: "CORP-WIFI") with
        {
            Bssid = "00:11:22:33:44:66",
            PreviousBssid = "00:11:22:33:44:55"
        };

        var timeline = _builder.Build([connected, roamed], TimeSpan.FromMinutes(5));

        Assert.Equal(TimelineKind.WifiConnected, timeline[0].Kind);
        Assert.Equal("00:11:22:33:44:55", timeline[0].Bssid);
        Assert.Equal(TimelineKind.WifiRoamed, timeline[1].Kind);
        Assert.Equal("00:11:22:33:44:55", timeline[1].PreviousBssid);
        Assert.Equal("00:11:22:33:44:66", timeline[1].Bssid);
    }

    [Fact]
    public void DependentServiceFailureRequiresMatchingProviderNotOnlyEventId()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(7001, "Microsoft-Windows-Winlogon", "System", start),
            Event(8194, "VSS", "Application", start.AddMilliseconds(500)),
            Event(8194, "Group Policy Registry", "Application", start.AddSeconds(1)),
            Event(8015, "Unrelated-Provider", "System", start.AddSeconds(2)),
            Event(8015, "Microsoft-Windows-DNS-Client", "System", start.AddSeconds(3))
        ], TimeSpan.FromMinutes(5));

        Assert.Equal(3, timeline.Count);
        Assert.All(timeline.Skip(1), item => Assert.Equal(TimelineKind.DependentServiceFailure, item.Kind));
    }

    [Fact]
    public void DependentFailuresAreOnlyIncludedBeforeWifiConnectsAfterLogon()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(7001, "Microsoft-Windows-Winlogon", "System", start),
            Event(1129, "Microsoft-Windows-GroupPolicy", "System", start.AddSeconds(5)),
            Event(7021, "Netwtw14", "System", start.AddSeconds(10), ssid: "CORP-WIFI"),
            Event(5719, "NETLOGON", "System", start.AddSeconds(20))
        ], TimeSpan.FromMinutes(5));

        Assert.Contains(timeline, item => item.Stage == "그룹 정책 네트워크 대기 실패");
        Assert.DoesNotContain(timeline, item => item.Stage == "도메인 컨트롤러 연결 실패");
    }

    [Fact]
    public void IncludesBootShutdownSleepResumeAndUnexpectedShutdown()
    {
        var start = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
        var timeline = _builder.Build([
            Event(12, "Microsoft-Windows-Kernel-General", "System", start),
            Event(42, "Microsoft-Windows-Kernel-Power", "System", start.AddMinutes(1)),
            Event(107, "Microsoft-Windows-Kernel-Power", "System", start.AddMinutes(2)),
            Event(13, "Microsoft-Windows-Kernel-General", "System", start.AddMinutes(3)),
            Event(41, "Microsoft-Windows-Kernel-Power", "System", start.AddMinutes(4)),
            Event(6008, "EventLog", "System", start.AddMinutes(5))
        ], TimeSpan.FromMinutes(5));

        Assert.Equal([
            TimelineKind.Boot,
            TimelineKind.Sleep,
            TimelineKind.Resume,
            TimelineKind.Shutdown,
            TimelineKind.UnexpectedShutdown,
            TimelineKind.UnexpectedShutdown
        ], timeline.Select(item => item.Kind));
    }

    private static NormalizedEvent Event(int id, string provider, string channel, DateTimeOffset time, string? ssid = null, string? account = null, string? logonType = null) =>
        new("synthetic", channel, provider, id, id, time, null, null, null, ssid, account, null, null, logonType, null, null, "<Event />", new Dictionary<string, string>());
}