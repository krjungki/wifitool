// 정규화 이벤트를 원본 근거가 연결된 보수적 타임라인으로 변환한다.
namespace WifiTool.Core;

public sealed class TimelineBuilder
{
    private static readonly HashSet<int> LogonSuccessEvents = [4624, 7001];
    private static readonly HashSet<int> LogonFailureEvents = [4625];
    public IReadOnlyList<TimelineEntry> Build(IEnumerable<NormalizedEvent> source, TimeSpan correlationWindow)
    {
        var events = source.OrderBy(item => item.Timestamp).ThenBy(item => item.RecordId).ToList();
        var output = new List<TimelineEntry>(events.Count);
        DateTimeOffset? lastInteractiveLogon = null;
        DateTimeOffset? lastBoot = null;
        DateTimeOffset? lastWifiConnected = null;

        foreach (var item in events)
        {
            var systemState = ClassifySystemState(item);
            if (systemState is not null)
            {
                var (kind, stage, outcome, details) = systemState.Value;
                if (kind is TimelineKind.Boot or TimelineKind.UnexpectedShutdown)
                {
                    lastInteractiveLogon = null;
                    lastWifiConnected = null;
                }
                if (kind == TimelineKind.Boot) lastBoot = item.Timestamp;
                output.Add(Create(item, kind, stage, outcome, EvidenceLevel.Observed, details));
                continue;
            }

            if (LogonFailureEvents.Contains(item.EventId) && IsSecurity(item))
            {
                output.Add(Create(item, TimelineKind.LogonFailure, "로그온 실패", Outcome.Failed, EvidenceLevel.Observed, FailureSummary(item)));
                continue;
            }

            if (LogonSuccessEvents.Contains(item.EventId) && IsInteractiveLogon(item))
            {
                lastInteractiveLogon = item.Timestamp;
                var description = item.EventId == 4624
                    ? "대화형 로그온 성공이 관측되었습니다. 자격 증명 입력 시작 시각은 아닙니다."
                    : "Winlogon 로그온 신호가 관측되었습니다. Security 로그가 없으면 계정과 성공 세부 정보는 제한됩니다.";
                output.Add(Create(item, TimelineKind.Logon, "사용자 로그온", Outcome.Succeeded, EvidenceLevel.Observed, description));
                continue;
            }

            var wifiKind = ClassifyWifi(item);
            if (wifiKind is not null)
            {
                var (kind, stage, outcome) = wifiKind.Value;
                TimeSpan? sinceLogon = null;
                var evidence = EvidenceLevel.Observed;
                var details = item.Message ?? (item.Provider.StartsWith("Netwtw", StringComparison.OrdinalIgnoreCase) && item.EventId is 5002 or 5010
                    ? "Intel 무선 드라이버 오류가 관측됐지만 이 PC에 provider message resource가 없어 상세 설명을 렌더링할 수 없습니다. Event ID와 원본 XML을 확인하십시오."
                    : "원본 XML에서 사건이 관측되었습니다.");

                if (lastInteractiveLogon is not null && item.Timestamp >= lastInteractiveLogon)
                {
                    var elapsed = item.Timestamp - lastInteractiveLogon.Value;
                    if (elapsed <= correlationWindow && (lastBoot is null || item.Timestamp >= lastBoot))
                    {
                        sinceLogon = elapsed;
                        evidence = EvidenceLevel.Inferred;
                        details += " 로그온 후 시간 인접성만 확인했으며 실제 EAP 인증 소요시간이나 인증 계정을 뜻하지 않습니다.";
                    }
                }

                output.Add(Create(item, kind, stage, outcome, evidence, details, sinceLogon));
                if (kind is TimelineKind.WifiConnected or TimelineKind.WifiRoamed && outcome == Outcome.Succeeded)
                {
                    lastWifiConnected = item.Timestamp;
                }
                continue;
            }

            var dependentFailure = ClassifyDependentServiceFailure(item);
            if (dependentFailure is not null && lastInteractiveLogon is not null)
            {
                var elapsed = item.Timestamp - lastInteractiveLogon.Value;
                var noWifiSinceLogon = lastWifiConnected is null || lastWifiConnected < lastInteractiveLogon;
                if (elapsed >= TimeSpan.Zero && elapsed <= correlationWindow && noWifiSinceLogon)
                {
                    var (stage, details) = dependentFailure.Value;
                    output.Add(Create(item, TimelineKind.DependentServiceFailure, stage, Outcome.Failed, EvidenceLevel.Inferred,
                        details + " 로그온 후 Wi-Fi 연결 전 구간에서 관측됐으나 Wi-Fi가 원인이라는 뜻은 아닙니다.", elapsed));
                }
            }
        }

        return output;
    }

    private static bool IsSecurity(NormalizedEvent item) =>
        item.Channel.Equals("Security", StringComparison.OrdinalIgnoreCase) ||
        item.Provider.Contains("Security-Auditing", StringComparison.OrdinalIgnoreCase);

    private static bool IsInteractiveLogon(NormalizedEvent item)
    {
        if (item.EventId == 7001)
        {
            return item.Provider.Contains("Winlogon", StringComparison.OrdinalIgnoreCase);
        }

        if (!IsSecurity(item))
        {
            return false;
        }

        return item.LogonType is "2" or "7" or "10" or "11";
    }

    private static (TimelineKind Kind, string Stage, Outcome Outcome, string Details)? ClassifySystemState(NormalizedEvent item)
    {
        if (item.Provider.Contains("Kernel-General", StringComparison.OrdinalIgnoreCase))
        {
            if (item.EventId == 12) return (TimelineKind.Boot, "PC 부팅/재부팅", Outcome.Succeeded, "Windows 커널 시작이 기록됐습니다. 이 이벤트만으로 전원 켜기와 재시작을 구분하지 않습니다.");
            if (item.EventId == 13) return (TimelineKind.Shutdown, "OS 종료", Outcome.Succeeded, "Windows 커널 종료가 기록됐습니다.");
        }
        if (item.Provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase))
        {
            if (item.EventId == 41) return (TimelineKind.UnexpectedShutdown, "비정상 종료 후 재시작", Outcome.Failed, "정상 종료 절차 없이 다시 시작된 상태가 기록됐습니다.");
            if (item.EventId == 42) return (TimelineKind.Sleep, "절전 진입", Outcome.Succeeded, "시스템 절전 진입이 기록됐습니다.");
            if (item.EventId == 107) return (TimelineKind.Resume, "절전 복귀", Outcome.Succeeded, "시스템 절전 복귀가 기록됐습니다.");
            if (item.EventId == 109) return (TimelineKind.Shutdown, "종료/재시작 시작", Outcome.Unknown, "커널 전원 관리자가 종료 또는 재시작 절차를 시작했습니다.");
        }
        if (item.Provider.Contains("Power-Troubleshooter", StringComparison.OrdinalIgnoreCase) && item.EventId == 1)
            return (TimelineKind.Resume, "절전 복귀 완료", Outcome.Succeeded, "Power Troubleshooter가 절전 복귀를 기록했습니다.");
        if (item.Provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase) && item.EventId == 6008)
            return (TimelineKind.UnexpectedShutdown, "예기치 않은 이전 종료", Outcome.Failed, "Event Log가 이전 시스템 종료가 예상되지 않았음을 기록했습니다.");
        return null;
    }

    private static (string Stage, string Details)? ClassifyDependentServiceFailure(NormalizedEvent item)
    {
        if (item.Provider.Equals("NETLOGON", StringComparison.OrdinalIgnoreCase) && item.EventId == 5719)
            return ("도메인 컨트롤러 연결 실패", "NETLOGON이 도메인 컨트롤러 연결 실패를 기록했습니다.");
        if (item.Provider.Contains("DNS-Client", StringComparison.OrdinalIgnoreCase) && item.EventId is 8015 or 8020)
            return ("DNS 처리 실패", "DNS Client가 이름 확인 또는 등록 실패를 기록했습니다.");
        if (item.Provider.Contains("GroupPolicy", StringComparison.OrdinalIgnoreCase) ||
            item.Provider.Contains("Group Policy", StringComparison.OrdinalIgnoreCase))
        {
            return item.EventId switch
            {
                1055 => ("그룹 정책 DC 확인 실패", "Group Policy가 도메인 컨트롤러 이름 확인 실패를 기록했습니다."),
                1085 => ("그룹 정책 확장 적용 실패", "Group Policy 확장 처리 실패가 기록됐습니다."),
                1129 => ("그룹 정책 네트워크 대기 실패", "Group Policy가 도메인 네트워크 연결을 확보하지 못했습니다."),
                8194 => ("그룹 정책 CSE 처리 실패", "Group Policy Client-Side Extension 처리 실패가 기록됐습니다."),
                _ => null
            };
        }
        return null;
    }

    private static (TimelineKind Kind, string Stage, Outcome Outcome)? ClassifyWifi(NormalizedEvent item)
    {
        if (item.Provider.StartsWith("Netwtw", StringComparison.OrdinalIgnoreCase))
        {
            return item.EventId switch
            {
                7021 => (TimelineKind.WifiConnected, "Intel Wi-Fi 연결/재연결", Outcome.Succeeded),
                7003 => (TimelineKind.WifiRoamed, "Intel AP 로밍", Outcome.Succeeded),
                5002 or 5010 => (TimelineKind.WifiFailed, "Intel 무선 드라이버 오류", Outcome.Failed),
                _ => null
            };
        }

        if (!item.Provider.Contains("WLAN-AutoConfig", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return item.EventId switch
        {
            8000 => (TimelineKind.WifiAttempt, "Wi-Fi 연결 시도", Outcome.InProgress),
            8001 => (TimelineKind.WifiConnected, "Wi-Fi 연결 성공", Outcome.Succeeded),
            8002 => (TimelineKind.WifiFailed, "Wi-Fi 연결 실패", Outcome.Failed),
            8003 => (TimelineKind.WifiDisconnected, "Wi-Fi 연결 해제", Outcome.Unknown),
            11000 => (TimelineKind.WifiAttempt, "무선 결합 시작", Outcome.InProgress),
            11001 => (TimelineKind.Information, "무선 결합 성공", Outcome.Succeeded),
            11002 => (TimelineKind.WifiFailed, "무선 결합 실패", Outcome.Failed),
            11003 or 11007 or 11010 => (TimelineKind.WifiAttempt, "무선 보안 시작", Outcome.InProgress),
            11004 => (TimelineKind.Information, "무선 보안 중지", Outcome.Unknown),
            11005 or 11008 => (TimelineKind.Information, "무선 보안 성공", Outcome.Succeeded),
            11006 or 11009 => (TimelineKind.WifiFailed, "무선 보안 실패", Outcome.Failed),
            4000 => (TimelineKind.Information, "WLAN AutoConfig 시작", Outcome.Succeeded),
            4001 => (TimelineKind.Information, "WLAN AutoConfig 중지", Outcome.Unknown),
            10001 => (TimelineKind.Information, "WLAN 확장 모듈 로드", Outcome.Succeeded),
            10002 => (TimelineKind.Information, "WLAN 확장 모듈 중지", Outcome.Unknown),
            _ => null
        };
    }

    private static string FailureSummary(NormalizedEvent item)
    {
        var status = item.Data.GetValueOrDefault("Status") ?? item.ReasonCode;
        var subStatus = item.Data.GetValueOrDefault("SubStatus");
        return $"Windows 로그온 실패가 기록되었습니다. Status={status ?? "미상"}, SubStatus={subStatus ?? "미상"}.";
    }

    private static TimelineEntry Create(
        NormalizedEvent item,
        TimelineKind kind,
        string stage,
        Outcome outcome,
        EvidenceLevel evidence,
        string details,
        TimeSpan? sinceLogon = null) =>
        new TimelineEntry(
            $"{item.SourceId}:{item.RecordId?.ToString() ?? item.Timestamp.UtcTicks.ToString()}",
            item.Timestamp,
            kind,
            stage,
            item.Account,
            item.Ssid ?? item.ProfileName,
            outcome,
            evidence,
            item.Message ?? $"{item.Provider} {item.EventId}",
            details,
            [item.SourceId],
            sinceLogon)
        {
            Bssid = item.Bssid,
            PreviousBssid = item.PreviousBssid
        };
}