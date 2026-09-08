// 언어에 의존하지 않는 named event XML 필드 정규화를 검증한다.
using WifiTool.Windows;

namespace WifiTool.Tests;

public sealed class EventXmlNormalizerTests
{
    [Fact]
    public void DecodesIntelConnectionSsidAndBssidFromBinaryPayload()
    {
        var payload = new byte[168];
        new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }.CopyTo(payload, 48);
        "CORP-WIFI"u8.CopyTo(payload.AsSpan(56));
        var xml = IntelEventXml(7021, payload);

        var item = EventXmlNormalizer.Normalize(xml, "synthetic.evtx");

        Assert.Equal("CORP-WIFI", item.Ssid);
        Assert.Equal("00:11:22:33:44:55", item.Bssid);
    }

    [Fact]
    public void DecodesIntelRoamPreviousBssidFromBinaryPayload()
    {
        var payload = new byte[112];
        new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x66 }.CopyTo(payload, 48);
        "CORP-WIFI"u8.CopyTo(payload.AsSpan(56));
        new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }.CopyTo(payload, 88);
        var xml = IntelEventXml(7003, payload);

        var item = EventXmlNormalizer.Normalize(xml, "synthetic.evtx");

        Assert.Equal("00:11:22:33:44:66", item.Bssid);
        Assert.Equal("00:11:22:33:44:55", item.PreviousBssid);
    }

    [Fact]
    public void UsesWinlogonUserSidAsAccountWhenNameIsUnavailable()
    {
        const string xml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System><Provider Name="Microsoft-Windows-Winlogon"/><EventID>7001</EventID><TimeCreated SystemTime="2026-09-08T00:00:00Z"/><Channel>System</Channel></System>
              <EventData><Data Name="TSId">1</Data><Data Name="UserSid">S-1-5-21-1-2-3-1001</Data></EventData>
            </Event>
            """;

        var item = EventXmlNormalizer.Normalize(xml, "synthetic.evtx");

        Assert.Equal("S-1-5-21-1-2-3-1001", item.Account);
    }

    [Fact]
    public void KeepsRenderedDescriptionWhenXmlHasNoMessageField()
    {
        var xml = IntelEventXml(5002, new byte[96]);

        var item = EventXmlNormalizer.Normalize(xml, "synthetic.evtx", "Wireless driver reported an error.");

        Assert.Equal("Wireless driver reported an error.", item.Message);
    }

    [Fact]
    public void T04_PreservesRawUnknownReasonCode()
    {
        const string xml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System><Provider Name="Microsoft-Windows-WLAN-AutoConfig"/><EventID>8002</EventID><TimeCreated SystemTime="2026-09-08T00:00:00Z"/><EventRecordID>42</EventRecordID><Channel>System</Channel></System>
              <EventData><Data Name="SSID">corp</Data><Data Name="ReasonCode">0xDEADBEEF</Data></EventData>
            </Event>
            """;

        var item = EventXmlNormalizer.Normalize(xml, "synthetic.evtx");

        Assert.Equal("0xDEADBEEF", item.ReasonCode);
        Assert.Equal("corp", item.Ssid);
        Assert.Contains("0xDEADBEEF", item.RawXml);
    }

        private static string IntelEventXml(int eventId, byte[] payload) => $"""
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System><Provider Name="Netwtw14"/><EventID>{eventId}</EventID><TimeCreated SystemTime="2026-09-08T00:00:00Z"/><Channel>System</Channel></System>
                    <EventData><Binary>{Convert.ToHexString(payload)}</Binary></EventData>
                </Event>
                """;
}