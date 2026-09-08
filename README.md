# wifitool

Windows Wi-Fi 접속 문제를 부팅, 로그온, 무선 연결, 인증 관련 사건의 타임라인으로 분석하는 .NET WPF 도구입니다.

## 주요 기능

- 현재 PC 이벤트 로그와 여러 EVTX 파일 분석
- 부팅, 종료, 비정상 종료, 절전, 복귀 상태 분리
- 사용자 로그온과 Wi-Fi 연결 사이의 시간 관계 표시
- Intel Netwtw10/14 이벤트에서 SSID, BSSID, AP 로밍 복원
- WLAN 연결·결합·보안 단계와 실패 코드 표시
- 로그온 후 Wi-Fi 연결 전 DNS, NETLOGON, Group Policy 실패 분류
- SSID에 해당하는 Wi-Fi 프로필 조회와 비밀 필드 제거 XML 추출
- 이벤트, 프로필, 분석 결과를 무결성 manifest가 있는 ZIP으로 수집

분석 결과는 `Observed`, `Inferred`, `Unknown`으로 근거 수준을 구분합니다. 시간상 인접한 사건만으로 Wi-Fi 또는 802.1X 실패 원인을 확정하지 않습니다.

## 다운로드 및 실행

[Releases](https://github.com/krjungki/wifitool/releases)에서 `WifiTool.exe`를 내려받아 실행합니다. .NET 런타임이 포함된 Windows x64 단일 실행 파일입니다.

EVTX 파일을 인수로 전달하면 시작과 함께 분석합니다.

```powershell
.\WifiTool.exe C:\Logs\Application.evtx C:\Logs\System.evtx
```

일부 이벤트 채널과 Wi-Fi 프로필은 Windows 정책에 따라 관리자 권한이 필요할 수 있습니다. 앱은 자동 승격하거나 로그·프로필 설정을 변경하지 않습니다.

## Platform Support

| OS | Status | Architecture | Runtime | Artifact | Verification |
|---|---|---|---|---|---|
| Windows 11 | supported | x64 | .NET 10 self-contained | single-file EXE | 자동 테스트, publish, 버전·창·스크롤·EVTX 분석 smoke |
| Windows 10 / Server | not-targeted | - | - | 제공하지 않음 | 이번 릴리스 범위 밖 |
| macOS | unsupported | - | WPF 실행 불가 | 제공하지 않음 | Windows Event Log 및 Native WLAN API 의존 |
| Linux | unsupported | - | WPF 실행 불가 | 제공하지 않음 | Windows Event Log 및 Native WLAN API 의존 |

## 빌드 및 테스트

.NET 10 SDK와 Windows 11 x64가 필요합니다.

```powershell
dotnet restore WifiTool.sln
dotnet build WifiTool.sln -c Release --no-restore
dotnet test tests/WifiTool.Tests/WifiTool.Tests.csproj -c Release
dotnet publish src/WifiTool.App/WifiTool.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -o dist/wifitool-win-x64
```

이벤트 의미와 지원 범위는 [이벤트 매핑](docs/event-map.md), 검증 항목은 [테스트 계획](docs/test-plan.md), 변경 내역은 [history](docs/history.md)를 참고하십시오.

## 의존성

- Microsoft .NET 10
- `System.Diagnostics.EventLog` 10.0.0, MIT
- 테스트: xUnit 2.9.3, Microsoft.NET.Test.Sdk 17.14.1, coverlet.collector 6.0.4

## 개인정보와 한계

EVTX와 수집 ZIP에는 계정, 호스트명, SSID, BSSID 등 민감정보가 포함될 수 있습니다. 수집 파일은 자동 업로드되지 않으며 사용자가 지정한 로컬 경로에만 저장됩니다. 실제 로그와 프로필을 issue나 공개 저장소에 첨부하기 전에 반드시 검토하십시오.

WLAN-AutoConfig/Operational, Security 또는 EAP 관련 로그가 없으면 인증 계정과 실패 이유를 확정할 수 없습니다. 현재 프로필 설정이 과거 사건 당시에도 같았다고 가정하지 않습니다.