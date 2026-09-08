// 무선 프로필 XML 파서가 SSID와 SSO 값을 읽고 비밀을 제거하는지 검증한다.
using WifiTool.Windows;

namespace WifiTool.Tests;

public sealed class ProfileParserTests
{
    [Fact]
    public void T10_FindsSsidDifferentFromProfileNameAndRemovesSecrets()
    {
        const string xml = """
            <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
              <name>Friendly profile</name>
              <SSIDConfig><SSID><name>한글-SSID</name></SSID><nonBroadcast>true</nonBroadcast></SSIDConfig>
              <MSM><security><authEncryption><authentication>WPA2</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>
              <sharedKey><keyMaterial>do-not-export</keyMaterial></sharedKey></security></MSM>
              <OneX xmlns="http://www.microsoft.com/networking/OneX/v1"><authMode>machineOrUser</authMode><singleSignOn><type>postLogon</type><maxDelay>10</maxDelay></singleSignOn></OneX>
            </WLANProfile>
            """;

        var result = WifiProfileParser.ParseAndSanitize(xml);

        Assert.Equal("한글-SSID", result.Ssid);
        Assert.Equal("postLogon", result.Settings["singleSignOnType"]);
        Assert.DoesNotContain("keyMaterial", result.SanitizedXml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("do-not-export", result.SanitizedXml);
    }

    [Fact]
    public void T10_BlocksMalformedOrDtdXml()
    {
        var malformed = WifiProfileParser.ParseAndSanitize("<profile>");
        var dtd = WifiProfileParser.ParseAndSanitize("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]><foo>&xxe;</foo>");

        Assert.Null(malformed.SanitizedXml);
        Assert.NotNull(malformed.ExportBlockedReason);
        Assert.Null(dtd.SanitizedXml);
        Assert.NotNull(dtd.ExportBlockedReason);
    }

    [Fact]
    public void T10_BlocksUnknownExtensionNamespaceFromXmlExport()
    {
        const string xml = """
            <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
              <name>profile</name><SSIDConfig><SSID><name>corp</name></SSID></SSIDConfig>
              <vendor:Secret xmlns:vendor="https://example.invalid/vendor">opaque</vendor:Secret>
            </WLANProfile>
            """;

        var result = WifiProfileParser.ParseAndSanitize(xml);

        Assert.Equal("corp", result.Ssid);
        Assert.Null(result.SanitizedXml);
        Assert.Contains("namespace", result.ExportBlockedReason);
    }
}