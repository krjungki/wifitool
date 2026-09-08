# 이벤트 및 API 매핑

확인일: 2026-09-08
대상: Windows 11 x64, .NET SDK 10.0.400

이 문서는 도구가 의미를 부여하는 사건과 그 근거를 고정합니다. 이벤트가 이 표에 없거나 provider/version이 다르면 원본 XML을 보존하되 자동 원인 판정을 하지 않습니다.

## WLAN-AutoConfig

현재 OS의 `Microsoft-Windows-WLAN-AutoConfig` provider metadata를 `ProviderMetadata.Events`와 `wevtutil gp ... /f:xml`로 확인했습니다.

| ID | Task / Opcode | 도구 표시 | 결과 |
|---|---|---|---|
| 8000 | ACM connection start | Wi-Fi 연결 시도 | InProgress |
| 8001 | ACM connection succeed | Wi-Fi 연결 성공 | Succeeded |
| 8002 | ACM connection fail | Wi-Fi 연결 실패 | Failed |
| 8003 | ACM disconnected | Wi-Fi 연결 해제 | Unknown |
| 11000 | MSM association start | 무선 결합 시작 | InProgress |
| 11001 | MSM association success | 무선 결합 성공 | Succeeded, 전체 연결 완료 아님 |
| 11002 | MSM association failure | 무선 결합 실패 | Failed |
| 11003 / 11010 | MSM security start | 무선 보안 시작 | InProgress |
| 11004 | MSM security stop | 무선 보안 중지 | Unknown, 실패 아님 |
| 11005 | MSM security success | 무선 보안 성공 | Succeeded |
| 11006 | MSM security failure | 무선 보안 실패 | Failed |
| 11007 / 11008 / 11009 | IHV security start/success/failure | IHV 보안 단계 | 각 opcode 결과 |

전체 연결 성공은 8001로 표시합니다. 11001과 11005는 각각 결합과 보안 하위 단계의 성공입니다. 메시지 문자열은 표시용 보조 정보이며 파싱 계약이 아닙니다.

## Windows 세션과 보조 사건

| Provider / ID | 사용 | 한계 |
|---|---|---|
| Kernel-General 12 | OS 시작 기준점 | fast startup·resume을 단독으로 구분하지 않음 |
| Power-Troubleshooter 1 / 107 | 절전 복귀 후보 | provider와 함께 일치할 때만 사용 |
| Security 4624 | 대화형 로그온 성공 관측 | LogonType 2, 7, 10, 11만 UI 세션으로 분류. 자격 증명 입력 시작 시각 아님 |
| Security 4625 | 로그온 실패와 Status/SubStatus | 감사 미설정·권한 거부·기록 없음 구분 필요 |
| Winlogon 7001 | Security가 없을 때 로그온 대용 신호 | 실제 인증 계정과 시작 시각을 증명하지 않음 |
| DNS 8015/8020, NETLOGON 5719, GroupPolicy 1055/1085/1129, CSE 8194 | 연결 공백의 보조 타임라인 | Wi-Fi 근본 원인으로 자동 승격하지 않음 |

## Intel Netwtw System 이벤트

일부 수집본에는 WLAN-AutoConfig/Operational 연결 이벤트가 없고 Intel 드라이버가 System 채널에 binary payload로 연결 상태를 남깁니다. Netwtw10/Netwtw14의 관측된 payload 형식은 다음과 같이 처리합니다.

| ID | 의미 | payload |
|---|---|---|
| 7021 | 연결 또는 재연결 관측 | byte 48부터 BSSID 6바이트, byte 56부터 최대 32바이트 SSID |
| 7003 | AP 로밍 관측 | byte 48부터 새 BSSID, byte 56부터 SSID, byte 88부터 이전 BSSID |
| 5002 / 5010 | Intel 무선 드라이버 오류 | provider message resource가 있으면 설명을 표시하고, 없으면 Event ID와 원본 XML만 근거로 유지 |

SSID는 null 종단 UTF-8을 우선 사용하고 유효하지 않으면 hex로 표시합니다. BSSID/SSID offset은 첨부 fixture의 Netwtw10/14 1,207건과 기존 분석 결과에서 대조했습니다. 다른 provider/version 또는 길이가 짧은 payload에는 적용하지 않습니다.

Event ID만으로 사건을 분류하지 않습니다. 예를 들어 Application의 VSS 8194는 Group Policy CSE 8194와 관계없으므로 provider가 Group Policy 계열일 때만 종속 서비스 실패로 포함합니다. DNS·NETLOGON·Group Policy 실패는 사용자 로그온 이후 아직 Wi-Fi 연결이 관측되지 않은 상관 창에서만 타임라인에 표시하며, Wi-Fi 원인으로 단정하지 않습니다.

## API 전제

| API | 확인한 계약 | 구현 |
|---|---|---|
| `EventLogQuery(path, PathType, query)` | active log와 log file을 모두 대상으로 지원 | live는 `LogName`, EVTX는 `FilePath`; record XML을 named field로 정규화 |
| `EventLogSession.ExportLog` | query 결과를 EVTX로 내보냄; message text는 포함하지 않음 | 채널별 파일과 상태를 manifest에 기록 |
| `WlanEnumInterfaces` | 로컬 WLAN interface 목록과 GUID 반환 | 반환 메모리를 `WlanFreeMemory`로 해제 |
| `WlanGetProfileList` | 인터페이스별 profile name과 우선순위 반환 | profile name을 SSID로 간주하지 않음 |
| `WlanGetProfile` | profile XML과 scope flag 반환 | `WLAN_PROFILE_GET_PLAINTEXT_KEY` 미사용; 반환된 key/credential 노드 제거 |

## 공식 출처

- [EventLogQuery constructors](https://learn.microsoft.com/dotnet/api/system.diagnostics.eventing.reader.eventlogquery.-ctor?view=net-10.0)
- [EventLogSession.ExportLog](https://learn.microsoft.com/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.exportlog?view=net-10.0)
- [WlanGetProfile](https://learn.microsoft.com/windows/win32/api/wlanapi/nf-wlanapi-wlangetprofile)
- [WlanGetProfileList](https://learn.microsoft.com/windows/win32/api/wlanapi/nf-wlanapi-wlangetprofilelist)
- [singleSignOn element](https://learn.microsoft.com/windows/win32/nativewifi/onexschema-singlesignon-onex-element)
- [Single-file deployment](https://learn.microsoft.com/dotnet/core/deploying/single-file/overview)

## 미검증 또는 환경 의존

- 기업별 EAP provider와 vendor 확장 필드.
- 실제 Security 로그 권한과 감사 정책.
- 실제 기업 802.1X 실패에서 WLAN/EAP 이벤트의 완결성.
- Windows 위치 개인정보 설정에 따른 WLAN API 제한.
- 현재 프로필이 과거 사건 당시에도 동일했다는 가정.
- Netwtw 외 제조사와 향후 Intel provider version의 binary payload 형식.