// Wi-Fi 진단 이벤트와 파생 타임라인의 공통 데이터 계약을 정의한다.
namespace WifiTool.Core;

public enum EvidenceLevel
{
    Observed,
    Inferred,
    Unknown
}

public enum TimelineKind
{
    Boot,
    Shutdown,
    Sleep,
    Resume,
    UnexpectedShutdown,
    Logon,
    LogonFailure,
    WifiAttempt,
    WifiConnected,
    WifiFailed,
    WifiDisconnected,
    WifiRoamed,
    DependentServiceFailure,
    Information
}

public enum Outcome
{
    Succeeded,
    Failed,
    InProgress,
    Unknown
}

public sealed record NormalizedEvent(
    string SourceId,
    string Channel,
    string Provider,
    int EventId,
    long? RecordId,
    DateTimeOffset Timestamp,
    string? ActivityId,
    string? InterfaceId,
    string? ProfileName,
    string? Ssid,
    string? Account,
    string? SubjectSid,
    string? LogonId,
    string? LogonType,
    string? ReasonCode,
    string? Message,
    string RawXml,
    IReadOnlyDictionary<string, string> Data)
{
    public string? Bssid { get; init; }
    public string? PreviousBssid { get; init; }
}

public sealed record TimelineEntry(
    string Id,
    DateTimeOffset Timestamp,
    TimelineKind Kind,
    string Stage,
    string? Account,
    string? Ssid,
    Outcome Outcome,
    EvidenceLevel Evidence,
    string Summary,
    string Details,
    IReadOnlyList<string> SourceIds,
    TimeSpan? SinceLogon = null)
{
    public string? Bssid { get; init; }
    public string? PreviousBssid { get; init; }
}

public sealed record ChannelStatus(
    string Channel,
    string Status,
    int RecordCount,
    string? Details = null);

public sealed record EventReadResult(
    IReadOnlyList<NormalizedEvent> Events,
    IReadOnlyList<ChannelStatus> Channels);

public sealed record WifiProfileSnapshot(
    string InterfaceId,
    string InterfaceDescription,
    string ProfileName,
    string? Ssid,
    string Scope,
    DateTimeOffset CapturedAt,
    IReadOnlyDictionary<string, string> Settings,
    string? SanitizedXml,
    string? ExportBlockedReason);