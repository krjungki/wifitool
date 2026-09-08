// 수집 범위와 타임라인을 바탕으로 과장 없는 진단 요약을 만든다.
namespace WifiTool.Core;

public sealed record AnalysisOverview(
    int BootCount,
    int LogonCount,
    int WifiConnectedCount,
    int WifiFailedCount,
    int WifiRoamedCount,
    int DistinctSsidCount,
    IReadOnlyList<string> Findings);

public sealed class AnalysisSummaryBuilder
{
    public AnalysisOverview Build(IReadOnlyList<NormalizedEvent> events, IReadOnlyList<TimelineEntry> timeline)
    {
        var findings = new List<string>();
        var hasWlanOperational = events.Any(item => item.Channel.Equals("Microsoft-Windows-WLAN-AutoConfig/Operational", StringComparison.OrdinalIgnoreCase));
        var hasSecurity = events.Any(item => item.Channel.Equals("Security", StringComparison.OrdinalIgnoreCase));
        var intelWifi = events.Count(item => item.Provider.StartsWith("Netwtw", StringComparison.OrdinalIgnoreCase) && item.Ssid is not null);
        var unsupportedDriverFailures = events.Count(item =>
            item.Provider.StartsWith("Netwtw", StringComparison.OrdinalIgnoreCase) &&
            item.EventId is 5002 or 5010 && string.IsNullOrWhiteSpace(item.Message));
        var distinctSsid = events.Where(item => item.Ssid is not null).Select(item => item.Ssid).Distinct(StringComparer.Ordinal).Count();

        if (!hasWlanOperational)
        {
            findings.Add("WLAN-AutoConfig/Operational 로그가 없습니다. 802.1X 인증 시작·종료·실패 이유는 이 입력만으로 확정할 수 없습니다.");
        }
        if (!hasSecurity)
        {
            findings.Add("Security 로그가 없습니다. 사용자 로그온은 Winlogon 신호와 SID까지만 관측하며 로그인 입력 시작 시각과 상세 실패 상태는 확인할 수 없습니다.");
        }
        if (intelWifi > 0)
        {
            findings.Add($"Intel 무선 드라이버 binary payload에서 SSID/BSSID가 있는 연결·로밍 사건 {intelWifi:N0}건과 고유 SSID {distinctSsid:N0}개를 복원했습니다.");
        }
        if (unsupportedDriverFailures > 0)
        {
            findings.Add($"Intel 드라이버 오류 {unsupportedDriverFailures:N0}건은 provider message resource가 없어 Event ID와 원본 근거만 확인됩니다. 이를 802.1X 실패 원인으로 단정하지 않습니다.");
        }
        if (timeline.Any(item => item.Kind == TimelineKind.DependentServiceFailure))
        {
            findings.Add("로그온 후 Wi-Fi 연결 전 구간의 DNS·NETLOGON·Group Policy 실패만 종속 서비스 실패로 표시합니다. 각 사건은 유형별로 구분되며 Wi-Fi 근본 원인으로 자동 판정하지 않습니다.");
        }

        return new AnalysisOverview(
            timeline.Count(item => item.Kind == TimelineKind.Boot),
            timeline.Count(item => item.Kind == TimelineKind.Logon),
            timeline.Count(item => item.Kind == TimelineKind.WifiConnected),
            timeline.Count(item => item.Kind == TimelineKind.WifiFailed),
            timeline.Count(item => item.Kind == TimelineKind.WifiRoamed),
            distinctSsid,
            findings);
    }
}