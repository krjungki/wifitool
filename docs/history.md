# 변경 이력

## 0.1.0-rc - 2026-09-08

- .NET 10 WPF 기반 Windows Wi-Fi 현장 점검 도구 최초 구현.
- live log와 복수 EVTX의 XML 기반 정규화 및 부팅·로그온·Wi-Fi 타임라인 추가.
- WLAN 전체 연결, association, security 단계를 provider metadata에 맞춰 구분.
- SSID별 Native WLAN 프로필 조회와 key/credential 제거 XML 처리 추가.
- hash manifest가 있는 EVTX/프로필/타임라인 ZIP 생성과 fail-closed 재열기 추가.
- 합성 회귀 테스트와 self-contained `win-x64` single-file 배포 구성.
- 자동 테스트 30/30, 패키지 버전/창/초기 UI smoke와 AppDev gate 통과.
- 실제 로컬 로그, 프로필, 수집 ZIP workflow는 민감정보 접근 동의 전이므로 release 차단 상태.
- 로컬 이벤트 시간 XPath의 `&lt;=` literal token으로 조회가 실패하던 결함을 직접 `<=` 연산자로 수정. 실제 System/WLAN 채널 reader가 available/empty 상태를 정상 반환하는지 확인.
- WLAN Operational이 없는 System EVTX를 위해 Netwtw10/14 7021·7003 binary payload의 SSID/BSSID/이전 BSSID 복원을 추가.
- Intel 연결·로밍·드라이버 오류, WLAN 서비스 사건, provider-aware DNS/NETLOGON/Group Policy 영향을 타임라인에 추가하고 VSS 8194 오탐을 제거.
- 채널 부재와 판정 한계를 설명하는 진단 요약 탭, BSSID 열·상세·검색, EVTX command-line 자동 열기를 추가.
- private 첨부 fixture 118,121건에서 SSID/BSSID 1,207건, 고유 SSID 23개, 부팅 46·로그온 40·연결 669·실패 3·로밍 538건을 확인. 원본과 식별자는 앱 소스·테스트에 포함하지 않음.
- DataGrid 내부 스크롤에 의존하지 않고 각 그리드 아래에 고정 18px 가로 스크롤을 배치해 내부 오프셋과 동기화. UI Automation에서 타임라인 스크롤이 offscreen=false/enabled=true인지 확인.
- 선택되지 않은 탭은 시작 시 visual tree가 없어 scrollbar bridge가 연결되지 않던 결함을 각 DataGrid `Loaded` 시점 연결로 수정. star 열이 horizontal extent를 0으로 만들던 문제도 고정 폭 열로 교체해 해결.
- 첨부 타임라인에서 scrollbar 값 `0→902.29`, DataGrid horizontal scroll percent `0→100` 동기화와 오른쪽 끝 열 표시를 확인.

## 0.1.0 - 2026-09-08

- 공개 저장소 `krjungki/wifitool`의 `main`에 commit `f0cce061c12390cf6777ab50ed2c9c0dc44dc0f3` push.
- annotated tag 및 GitHub Release `v0.1.0` 게시.
- self-contained Windows x64 `WifiTool.exe`와 `SHA256SUMS.txt` 첨부.
- 공개 다운로드 EXE 139,830,864 bytes, SHA-256 `2053dd7fabb2551023eb05bbdff0fe6c59935ca18660a4c215d4dbafb1c3e7d8`, `--version=0.1.0` 검증.
- GitHub Actions의 main/tag push build가 모두 성공.

## 0.1.1 - 2026-09-08

- 수집 탭에 기본 해제된 `Security 로그 포함` checkbox 추가.
- 기본 활성화된 `Wi-Fi 프로필 포함`과 선택적 SSID 입력 추가. ZIP 저장 시 Native WLAN에서 프로필을 자동 조회.
- profile name과 SSID를 구분하고 keyMaterial/credential 제거를 통과한 XML만 `profiles/`에 저장.
- Security 권한 거부나 프로필 조회 실패가 전체 ZIP 생성을 막지 않도록 partial 상태와 manifest 수치로 보존.
- EVTX export range XPath의 XML entity 오류를 직접 비교 연산자로 수정.
- 관리형 프로필 70개 환경을 위해 ZIP 파일 수 상한을 2,048로 조정하고 1MB 이상 고압축 항목 차단은 유지.
- 자동 테스트 36/36 통과. 실제 smoke에서 프로필 70개 발견, 69개 안전 XML export, Security 일반 권한 거부 상태, ZIP round-trip 검증.
- 의미 없는 `네트워크 영향` 단계를 제거. 로그온 후 Wi-Fi 연결 전 상관 창에 있는 DNS·NETLOGON·Group Policy 실패 49건만 유형별 종속 서비스 실패로 표시.

버전 SSOT는 `src/WifiTool.App/WifiTool.App.csproj`입니다.