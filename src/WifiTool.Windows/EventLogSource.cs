// Windows 이벤트 로그와 EVTX 파일을 동일한 XML 기반 모델로 읽는다.
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Security;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using WifiTool.Core;

namespace WifiTool.Windows;

public sealed class EventLogSource
{
    public EventReadResult ReadLive(IEnumerable<string> channels, DateTimeOffset from, CancellationToken cancellationToken = default)
    {
        var events = new List<NormalizedEvent>();
        var statuses = new List<ChannelStatus>();
        var query = BuildRecentQuery(from, DateTimeOffset.UtcNow);

        foreach (var channel in channels.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadTarget(channel, PathType.LogName, query, events, statuses, cancellationToken);
        }

        return new EventReadResult(events.OrderBy(item => item.Timestamp).ToList(), statuses);
    }

    public static string BuildRecentQuery(DateTimeOffset from, DateTimeOffset now)
    {
        var milliseconds = Math.Max(0L, (long)(now.ToUniversalTime() - from.ToUniversalTime()).TotalMilliseconds);
        return $"*[System[TimeCreated[timediff(@SystemTime) <= {milliseconds.ToString(CultureInfo.InvariantCulture)}]]]";
    }

    public EventReadResult ReadFiles(IEnumerable<string> paths, CancellationToken cancellationToken = default)
    {
        var events = new List<NormalizedEvent>();
        var statuses = new List<ChannelStatus>();

        foreach (var path in paths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadTarget(Path.GetFullPath(path), PathType.FilePath, "*", events, statuses, cancellationToken);
        }

        return new EventReadResult(events.OrderBy(item => item.Timestamp).ToList(), statuses);
    }

    private static void ReadTarget(
        string target,
        PathType pathType,
        string queryText,
        List<NormalizedEvent> events,
        List<ChannelStatus> statuses,
        CancellationToken cancellationToken)
    {
        var count = 0;
        var parseErrors = 0;
        try
        {
            var query = new EventLogQuery(target, pathType, queryText)
            {
                ReverseDirection = false,
                TolerateQueryErrors = false
            };
            using var reader = new EventLogReader(query);
            while (reader.ReadEvent() is { } record)
            {
                using (record)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        var description = ShouldRenderDescription(record.ProviderName, record.Id)
                            ? TryFormatDescription(record)
                            : null;
                        events.Add(EventXmlNormalizer.Normalize(record.ToXml(), target, description));
                        count++;
                    }
                    catch (Exception exception) when (exception is FormatException or XmlException)
                    {
                        parseErrors++;
                    }
                }
            }

            var status = parseErrors > 0 ? "partial" : count == 0 ? "empty" : "available";
            var details = parseErrors > 0 ? $"{parseErrors}개 레코드를 정규화하지 못했습니다." : null;
            statuses.Add(new ChannelStatus(target, status, count, details));
        }
        catch (UnauthorizedAccessException exception)
        {
            statuses.Add(new ChannelStatus(target, "denied", count, exception.Message));
        }
        catch (EventLogNotFoundException exception)
        {
            statuses.Add(new ChannelStatus(target, "not-found", count, exception.Message));
        }
        catch (EventLogException exception)
        {
            statuses.Add(new ChannelStatus(target, "error", count, exception.Message));
        }
        catch (SecurityException exception)
        {
            statuses.Add(new ChannelStatus(target, "denied", count, exception.Message));
        }
    }

    private static bool ShouldRenderDescription(string? provider, int eventId) =>
        provider is not null &&
        (provider.StartsWith("Netwtw", StringComparison.OrdinalIgnoreCase) ||
         provider.Contains("WLAN-AutoConfig", StringComparison.OrdinalIgnoreCase) ||
         provider.Contains("Winlogon", StringComparison.OrdinalIgnoreCase) ||
         provider.Contains("GroupPolicy", StringComparison.OrdinalIgnoreCase) ||
         provider.Contains("Group Policy", StringComparison.OrdinalIgnoreCase) ||
         provider.Contains("DNS-Client", StringComparison.OrdinalIgnoreCase) ||
         provider.Equals("NETLOGON", StringComparison.OrdinalIgnoreCase)) &&
        eventId is 5002 or 5010 or 7001 or 8002 or
            1055 or 1085 or 1129 or 5719 or 8015 or 8020 or 8194 or
            11002 or 11006 or 11009;

    private static string? TryFormatDescription(EventRecord record)
    {
        try { return record.FormatDescription(); }
        catch (EventLogException) { return null; }
    }
}

public static class EventXmlNormalizer
{
    private static readonly XNamespace EventNs = "http://schemas.microsoft.com/win/2004/08/events/event";

    public static NormalizedEvent Normalize(string xml, string sourceId, string? renderedDescription = null)
    {
        var document = XDocument.Parse(xml, LoadOptions.PreserveWhitespace);
        var root = document.Root ?? throw new FormatException("이벤트 XML 루트가 없습니다.");
        var system = root.Element(EventNs + "System") ?? throw new FormatException("이벤트 System 요소가 없습니다.");
        var provider = system.Element(EventNs + "Provider");
        var data = ReadData(root);
        var providerName = provider?.Attribute("Name")?.Value ?? "Unknown";
        DecodeIntelWifiPayload(providerName, system.Element(EventNs + "EventID")?.Value, root, data);
        var timestampText = system.Element(EventNs + "TimeCreated")?.Attribute("SystemTime")?.Value
            ?? throw new FormatException("이벤트 시각이 없습니다.");
        var timestamp = DateTimeOffset.Parse(timestampText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        var activity = system.Element(EventNs + "Correlation");

        return new NormalizedEvent(
            sourceId,
            system.Element(EventNs + "Channel")?.Value ?? "Unknown",
            providerName,
            int.Parse(system.Element(EventNs + "EventID")?.Value ?? "0", CultureInfo.InvariantCulture),
            TryLong(system.Element(EventNs + "EventRecordID")?.Value),
            timestamp.ToUniversalTime(),
            activity?.Attribute("ActivityID")?.Value,
            First(data, "InterfaceGuid", "InterfaceId", "Interface GUID"),
            First(data, "ProfileName", "Profile Name", "Profile"),
            First(data, "SSID", "Ssid", "SSIDName", "NetworkSsid"),
            Account(data),
            First(data, "TargetUserSid", "SubjectUserSid", "UserSid"),
            First(data, "TargetLogonId", "SubjectLogonId", "LogonId"),
            First(data, "LogonType"),
            First(data, "ReasonCode", "Reason", "Status"),
            First(data, "FailureReason", "Message", "ErrorMessage") ?? renderedDescription,
            xml,
            data)
        {
            Bssid = First(data, "BSSID", "Bssid"),
            PreviousBssid = First(data, "PreviousBSSID", "PreviousBssid")
        };
    }

    private static Dictionary<string, string> ReadData(XElement root)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var index = 0;
        foreach (var item in root.Descendants(EventNs + "Data"))
        {
            var key = item.Attribute("Name")?.Value ?? $"Data{index++}";
            result[key] = item.Value;
        }

        foreach (var item in root.Descendants().Where(item => item.Name.Namespace != EventNs && !item.HasElements))
        {
            result.TryAdd(item.Name.LocalName, item.Value);
        }

        return result;
    }

    private static string? Account(IReadOnlyDictionary<string, string> data)
    {
        var domain = First(data, "TargetDomainName", "SubjectDomainName", "Domain");
        var user = First(data, "TargetUserName", "SubjectUserName", "UserName", "User");
        if (user is not null)
        {
            return string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}";
        }
        return First(data, "UserSid", "TargetUserSid", "SubjectUserSid");
    }

    private static void DecodeIntelWifiPayload(string provider, string? eventIdText, XElement root, Dictionary<string, string> data)
    {
        if (!provider.StartsWith("Netwtw", StringComparison.OrdinalIgnoreCase) ||
            !int.TryParse(eventIdText, out var eventId) || eventId is not (7021 or 7003))
        {
            return;
        }

        var binaryText = root.Descendants(EventNs + "Binary").FirstOrDefault()?.Value;
        if (string.IsNullOrWhiteSpace(binaryText) || binaryText.Length % 2 != 0) return;
        byte[] payload;
        try { payload = Convert.FromHexString(binaryText); }
        catch (FormatException) { return; }
        if (payload.Length < 88) return;

        var bssid = FormatMac(payload.AsSpan(48, 6));
        var ssid = DecodeSsid(payload.AsSpan(56, Math.Min(32, payload.Length - 56)));
        if (bssid is not null) data["BSSID"] = bssid;
        if (ssid is not null) data["SSID"] = ssid;

        if (eventId == 7003 && payload.Length >= 94)
        {
            var previous = FormatMac(payload.AsSpan(88, 6));
            if (previous is not null) data["PreviousBSSID"] = previous;
        }
    }

    private static string? FormatMac(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 6 || bytes.ToArray().All(value => value == 0)) return null;
        return string.Join(':', bytes.ToArray().Select(value => value.ToString("X2", CultureInfo.InvariantCulture)));
    }

    private static string? DecodeSsid(ReadOnlySpan<byte> bytes)
    {
        var length = bytes.IndexOf((byte)0);
        if (length < 0) length = bytes.Length;
        if (length == 0) return null;
        var value = bytes[..length].ToArray();
        try
        {
            var utf8 = new UTF8Encoding(false, true).GetString(value);
            return utf8.All(character => !char.IsControl(character)) ? utf8 : Convert.ToHexString(value);
        }
        catch (DecoderFallbackException)
        {
            return Convert.ToHexString(value);
        }
    }

    private static string? First(IReadOnlyDictionary<string, string> data, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)) return value;
        }
        return null;
    }

    private static long? TryLong(string? value) => long.TryParse(value, out var result) ? result : null;
}