# 테스트 계획

## 자동 테스트

```powershell
dotnet test tests/WifiTool.Tests/WifiTool.Tests.csproj -c Release
```

| Fixture | 검증 |
|---|---|
| T01 | 부팅 전 연결과 사용자 로그온 후 연결의 분리 |
| T02 | 로그온→연결 간격을 EAP 인증 시간으로 오인하지 않음 |
| T03 | 대상 SSID 실패와 다른 SSID 성공을 모두 보존 |
| T04 | 미등록 reason code 보존, security stop과 failure 구분 |
| T05 | Wi-Fi 성공 뒤 DNS 실패를 별도 계층으로 표시 |
| T07 | network logon을 interactive logon으로 상관하지 않음 |
| T09 | 재부팅을 넘어 로그온과 연결을 짝짓지 않음 |
| T10 | profile name과 SSID 분리, key/credential 제거, DTD 차단 |
| T12 | ZIP round-trip, traversal·hash 변조 거부 |
| Intel binary | 7021 SSID/BSSID, 7003 이전/새 BSSID, 짧은 payload 안전 무시 |
| Coverage summary | WLAN Operational/Security 부재와 원인 비단정 표시 |
| Provider guard | VSS 8194를 Group Policy 영향으로 오인하지 않음 |

합성 fixture에는 고객명, 실제 계정, 실제 SSID, 원본 EVTX를 사용하지 않습니다.

## 실제 Windows smoke

1. EXE를 일반 권한으로 실행하고 주 창 제목에 버전을 확인한다.
2. `로컬 로그 읽기`를 누르고 채널별 available/empty/denied/not-found/error 상태를 확인한다.
3. 타임라인에서 8001 전체 연결 성공과 11001 결합 성공이 다른 단계로 보이는지 확인한다.
4. `프로필 조회`를 명시적으로 누르고 SSID/profile/interface/scope를 확인한다.
5. 저장된 XML에서 `keyMaterial`, password, credential 문자열이 없는지 검사한다.
6. `최근 24시간 ZIP 저장` 후 같은 ZIP을 다시 열어 hash 검증과 타임라인 일치를 확인한다.
7. 관리자 권한이 필요한 채널은 자동 승격 없이 제한 상태로 보이는지 확인한다.
8. 1366x768, 1920x1080 및 100/150/200% 배율에서 표, 상세, 버튼이 겹치지 않는지 확인한다.

2026-09-08 실행 결과: Windows 11 Enterprise 10.0.26200 x64에서 `--version`, 주 창 생성/정상 종료, 900x580 초기 화면 캡처는 PASS. 버튼 2~7은 민감정보 접근 동의 전이므로 미실행이다.

2026-09-08 private 첨부 EVTX 회귀: Application/System 118,121건을 약 10초에 처리해 타임라인 1,656건을 생성했다. SSID/BSSID 1,207건과 고유 SSID 23개가 복원됐고 부팅 46, 로그온 40, 연결 669, 실패 3, 로밍 538건이 UI 상단과 집계 probe에서 일치했다. 시스템 상태 탭은 부팅 46, 종료 절차 84, 절전 10, 복귀 19, 비정상 종료 증거 8건을 표시했다. 기존 일반 네트워크 영향 567건은 로그온 후 Wi-Fi 연결 전 종속 서비스 실패 49건(DNS 10, GPO CSE 9, GPO 네트워크 9, GPO 확장 16, DC 연결 5)으로 축소했다. 각 DataGrid `Loaded` 시점에 고정 하단 scrollbar를 연결하고 star 열을 고정 폭으로 교체했다. 타임라인에서 scrollbar 값 `0→902.29`, DataGrid horizontal scroll percent `0→100` 동기화와 오른쪽 끝 열 표시를 확인했다. private 원본·경로·계정·SSID/BSSID 값은 테스트 fixture나 문서에 복제하지 않았다.

실제 계정/SSID가 화면과 ZIP에 나타날 수 있으므로 smoke 산출물은 repository에 저장하지 않습니다.

## 릴리스 차단 조건

- source test 또는 publish 실패.
- 패키지 EXE가 시작되지 않음.
- 프로필에 비밀 필드가 남음.
- 손상·hash 불일치 ZIP을 열어 줌.
- 로그 누락을 사건 없음 또는 성공으로 표시함.
- 지원 OS에서 actual-OS smoke 미완료.