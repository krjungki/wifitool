// Native WLAN API로 인터페이스와 프로필을 읽고 비밀 필드를 제거한다.
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Xml;
using System.Xml.Linq;
using WifiTool.Core;

namespace WifiTool.Windows;

public sealed class NativeWifiProfileSource
{
    public IReadOnlyList<WifiProfileSnapshot> ReadProfiles(string? ssid = null)
    {
        EnsureWindows();
        var result = new List<WifiProfileSnapshot>();
        ThrowIfError(NativeMethods.WlanOpenHandle(2, IntPtr.Zero, out _, out var handle));
        try
        {
            ThrowIfError(NativeMethods.WlanEnumInterfaces(handle, IntPtr.Zero, out var interfaceListPointer));
            try
            {
                foreach (var adapter in ReadInterfaces(interfaceListPointer))
                {
                    result.AddRange(ReadProfiles(handle, adapter, ssid));
                }
            }
            finally
            {
                NativeMethods.WlanFreeMemory(interfaceListPointer);
            }
        }
        finally
        {
            NativeMethods.WlanCloseHandle(handle, IntPtr.Zero);
        }

        return result;
    }

    private static IEnumerable<WifiProfileSnapshot> ReadProfiles(IntPtr handle, WlanInterfaceInfo adapter, string? ssidFilter)
    {
        ThrowIfError(NativeMethods.WlanGetProfileList(handle, ref adapter.InterfaceGuid, IntPtr.Zero, out var profileListPointer));
        try
        {
            var header = Marshal.PtrToStructure<WlanListHeader>(profileListPointer);
            var itemPointer = IntPtr.Add(profileListPointer, Marshal.SizeOf<WlanListHeader>());
            var itemSize = Marshal.SizeOf<WlanProfileInfo>();
            for (var index = 0; index < header.Count; index++)
            {
                var profile = Marshal.PtrToStructure<WlanProfileInfo>(IntPtr.Add(itemPointer, index * itemSize));
                uint flags = 0;
                var access = 0u;
                var code = NativeMethods.WlanGetProfile(handle, ref adapter.InterfaceGuid, profile.Name, IntPtr.Zero, out var xmlPointer, ref flags, out access);
                if (code != 0) continue;

                try
                {
                    var rawXml = Marshal.PtrToStringUni(xmlPointer) ?? string.Empty;
                    var parsed = WifiProfileParser.ParseAndSanitize(rawXml);
                    if (!string.IsNullOrWhiteSpace(ssidFilter) && !string.Equals(parsed.Ssid, ssidFilter, StringComparison.Ordinal)) continue;
                    yield return new WifiProfileSnapshot(
                        adapter.InterfaceGuid.ToString("D"),
                        adapter.Description,
                        profile.Name,
                        parsed.Ssid,
                        (flags & 1) != 0 ? "GroupPolicy" : (flags & 2) != 0 ? "PerUser" : "AllUser",
                        DateTimeOffset.UtcNow,
                        parsed.Settings,
                        parsed.SanitizedXml,
                        parsed.ExportBlockedReason);
                }
                finally
                {
                    NativeMethods.WlanFreeMemory(xmlPointer);
                }
            }
        }
        finally
        {
            NativeMethods.WlanFreeMemory(profileListPointer);
        }
    }

    private static IEnumerable<WlanInterfaceInfo> ReadInterfaces(IntPtr pointer)
    {
        var header = Marshal.PtrToStructure<WlanListHeader>(pointer);
        var itemPointer = IntPtr.Add(pointer, Marshal.SizeOf<WlanListHeader>());
        var itemSize = Marshal.SizeOf<WlanInterfaceInfo>();
        for (var index = 0; index < header.Count; index++)
        {
            yield return Marshal.PtrToStructure<WlanInterfaceInfo>(IntPtr.Add(itemPointer, index * itemSize));
        }
    }

    private static void ThrowIfError(uint code)
    {
        if (code != 0) throw new Win32Exception((int)code);
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native WLAN은 Windows에서만 사용할 수 있습니다.");
    }
}

public static class WifiProfileParser
{
    private static readonly string[] SensitiveNames = ["keyMaterial", "Password", "password", "Credentials", "credential"];
    private static readonly HashSet<string> KnownNamespaces = new(StringComparer.Ordinal)
    {
        "http://www.microsoft.com/networking/WLAN/profile/v1",
        "http://www.microsoft.com/networking/WLAN/profile/v2",
        "http://www.microsoft.com/networking/WLAN/profile/v3",
        "http://www.microsoft.com/networking/WLAN/profile/v4",
        "http://www.microsoft.com/networking/OneX/v1",
        "http://www.microsoft.com/provisioning/EapHostConfig",
        "http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1",
        "http://www.microsoft.com/provisioning/EapCommon",
        "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1",
        "http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1",
        "http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1",
        "http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2",
        "http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3"
    };

    public static (string? Ssid, Dictionary<string, string> Settings, string? SanitizedXml, string? ExportBlockedReason) ParseAndSanitize(string xml)
    {
        try
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var textReader = new StringReader(xml);
            using var reader = XmlReader.Create(textReader, settings);
            var document = XDocument.Load(reader, LoadOptions.PreserveWhitespace);
            var unknownNamespaces = (document.Root?.DescendantsAndSelf() ?? [])
                .Select(item => item.Name.NamespaceName)
                .Where(item => !string.IsNullOrEmpty(item) && !KnownNamespaces.Contains(item))
                .Distinct(StringComparer.Ordinal)
                .ToList();
            foreach (var element in document.Descendants().Where(item => SensitiveNames.Any(name => item.Name.LocalName.Contains(name, StringComparison.OrdinalIgnoreCase))).ToList())
            {
                element.Remove();
            }

            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            Add(values, document, "connectionMode");
            Add(values, document, "autoSwitch");
            Add(values, document, "nonBroadcast");
            Add(values, document, "authentication");
            Add(values, document, "encryption");
            Add(values, document, "useOneX");
            Add(values, document, "authMode");
            Add(values, document, "type", "singleSignOnType", ancestor: "singleSignOn");
            Add(values, document, "maxDelay");
            Add(values, document, "maxAuthFailures");
            Add(values, document, "UseWinLogonCredentials");
            Add(values, document, "PerformServerValidation");
            var ssid = document.Descendants().FirstOrDefault(item => item.Name.LocalName == "SSID")?
                .Elements().FirstOrDefault(item => item.Name.LocalName == "name")?.Value;
            ssid ??= document.Descendants().FirstOrDefault(item => item.Name.LocalName == "SSID")?
                .Elements().FirstOrDefault(item => item.Name.LocalName == "hex")?.Value;
            if (unknownNamespaces.Count > 0)
            {
                return (ssid, values, null, $"검증되지 않은 프로필 확장 namespace가 있어 XML 내보내기를 차단했습니다: {string.Join(", ", unknownNamespaces)}");
            }
            return (ssid, values, document.ToString(SaveOptions.DisableFormatting), null);
        }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException)
        {
            return (null, new Dictionary<string, string>(), null, $"프로필 XML을 안전하게 해석할 수 없습니다: {exception.Message}");
        }
    }

    private static void Add(Dictionary<string, string> values, XDocument document, string localName, string? key = null, string? ancestor = null)
    {
        var element = document.Descendants().FirstOrDefault(item =>
            item.Name.LocalName == localName &&
            (ancestor is null || item.Ancestors().Any(parent => parent.Name.LocalName == ancestor)));
        values[key ?? localName] = string.IsNullOrWhiteSpace(element?.Value) ? "NotConfigured" : element.Value;
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct WlanListHeader
{
    public int Count;
    public int Index;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WlanInterfaceInfo
{
    public Guid InterfaceGuid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Description;
    public int State;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WlanProfileInfo
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Name;
    public uint Flags;
}

internal static partial class NativeMethods
{
    [LibraryImport("wlanapi.dll")]
    internal static partial uint WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr clientHandle);

    [LibraryImport("wlanapi.dll")]
    internal static partial uint WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    [LibraryImport("wlanapi.dll")]
    internal static partial uint WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [LibraryImport("wlanapi.dll")]
    internal static partial uint WlanGetProfileList(IntPtr clientHandle, ref Guid interfaceGuid, IntPtr reserved, out IntPtr profileList);

    [LibraryImport("wlanapi.dll", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial uint WlanGetProfile(IntPtr clientHandle, ref Guid interfaceGuid, string profileName, IntPtr reserved, out IntPtr profileXml, ref uint flags, out uint grantedAccess);

    [LibraryImport("wlanapi.dll")]
    internal static partial void WlanFreeMemory(IntPtr memory);
}