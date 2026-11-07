# Windows About

`ciip_windows_2026.ps1` v0.2.0은 2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드의 Windows Server W-01~W-64를 대상으로 한다. 설정·정책·운영 증거를 수집하고 자동 판정 가능한 조건을 비교한다. 운영 승인·실효성·최신성 판단이 필요한 항목에는 수동 확인 내용을 남긴다.

## 실행

작성 기준은 64-bit Windows Server와 Windows PowerShell 5.1이다. 관리자 PowerShell에서 실행한다. 권한이 부족해 조회하지 못한 항목은 `ERROR`로 기록될 수 있다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ciip_windows_2026.ps1
```

사용자 설정은 Script 상단의 `param(...)`에서 한 번에 관리한다. 각 Parameter의 설명과 적용값은 `-ShowConfig`로 확인한다. 입력 방법은 [Windows 변수](WINDOWS_VARIABLES.md)에 정리했다. 파일 확장자는 PowerShell Script인 `.ps1`을 사용한다.

## 코드 구성

`ciip_windows_2026.ps1`이 직접 수정하고 배포하는 단일 원본이다. 별도의 분할 소스나 빌드 Script는 사용하지 않는다. 기능은 파일 내부의 구역으로 구분한다.

| 파일 내부 구역 | 담당 |
|---|---|
| 상단 설정·Catalog | 사용자 입력·설명·내부 상태·공식 Metadata |
| `core` | 공통 결과·masking·Timeout·입력 검증·실행·보고서 |
| `platform` | CIM·Registry·서비스·정책·ACL 조회 |
| `accounts` | 계정·그룹 조회와 W-01~W-15 |
| `services` | FTP·DNS·SNMP 공통 처리와 W-16~W-37 |
| `patches` | Patch·백신 정보 공통 처리와 W-38~W-39 |
| `logging` | W-40~W-43 |
| `security` | W-44~W-64 |

각 항목은 `Test-WindowsW01`~`Test-WindowsW64`의 독립 함수다. 실행부는 ID를 확인하고 해당 함수를 호출한다. 조회·판정이 겹치는 부분은 공통 함수를 사용한다. 개별 항목은 결과 Record 하나를 반환하며, 처리되지 않은 예외나 결과 계약 위반은 해당 항목의 `ERROR`가 된다.

코드는 4 Spaces, PowerShell의 `Verb-Noun` 함수명, PascalCase Parameter, camelCase 지역 변수, UTF-8 BOM·CRLF를 사용한다. Script 자체의 외부 Module 파일은 필요하지 않지만, IIS·DNS 등 설치 기능의 조회 API 제공 여부에 따라 해당 항목의 수집 범위가 달라진다.

## 결과

실행별 결과 폴더에 `result.json`과 `report.txt`를 저장한다. 항목번호·제목·상중하 위험도·판정·핵심 근거·수동 확인 내용·오류·점검 이유·미조치 위험을 포함한다. 요약에는 상태별 개수, 선택·완료 항목 수, 미선택 항목, 취약 항목의 가중합을 기록한다.

근거 문자열은 24,000자에서 일괄 절단하지 않는다. W-16·W-22·W-42·W-58은 조회한 정상·위반 값과 대상별 조회 오류를 함께 보존하며, 일부 조회에 실패해도 이미 확인한 취약 조건은 `VULNERABLE`로 보고한다. 확인된 위반 없이 조회 실패만 있으면 `ERROR`다.

| Status | 의미 |
|---|---|
| `GOOD` | 조회한 범위에서 가이드의 구현된 판정 조건 충족 |
| `VULNERABLE` | 확인한 설정이 가이드 또는 명시한 승인 정책의 조건 미충족 |
| `MANUAL` | 증거는 확보했으나 정책·적용 범위·실효성 등을 추가 확인해야 함 |
| `NOT_APPLICABLE` | 역할·가입 상태 등 확인한 근거에 따라 해당 없음 |
| `ERROR` | 조회·해석·실행 실패 또는 결과 계약 위반 |

가중합은 `VULNERABLE` 항목만 상3·중2·하1로 더한다. `MANUAL`·`ERROR`·미선택 항목은 양호에 포함하지 않는다. Exit Code는 정상 완료 `0`, 초기 설정·실행 실패 `2`, 항목 오류 포함 `3`, 중단을 기록한 경우 `130`이다. `0`은 모든 항목이 양호하다는 뜻이 아니다.

## 주요 판정·수집 범위

| 항목 | 현재 처리 |
|---|---|
| W-06 관리자 | 승인 SID가 입력되면 인원수·중첩 그룹 판단보다 먼저 대조한다. 한 명이어도 미승인이면 `VULNERABLE`이며, 승인된 중첩 그룹의 실제 구성원은 추가 확인한다. |
| W-21·22·24 FTP | IIS FTP가 비실행이면 알려진 FTP 서비스·프로세스와 21·990 수신 포트도 확인한다. 다른 Provider 증거나 조회 실패가 있으면 `MANUAL`이며, 이름 변경·비표준 포트는 탐지 범위 밖이다. |
| W-24 FTP IP 제한 | IIS `Microsoft.Web.Administration` API로 사이트별 `system.ftpServer/security/ipSecurity`의 유효 상속 설정을 조회한다. `allowUnlisted`와 주소·마스크·허용/차단 규칙을 기록하며, 규칙 없이 미등록 주소를 허용하면 `VULNERABLE`이다. 조회 실패·주소 승인·하위 URL 범위는 추가 확인한다. |
| W-25 DNS 영역 전송 | `SecureSecondaries`와 `SecondaryServers`를 수집한다. 권한 있는 영역에서 전체 서버 전송 허용은 `VULNERABLE`, 조회한 대상 영역이 모두 전송 차단이면 `GOOD`이다. 제한된 대상의 승인 여부·미제공 설정값은 `MANUAL`이다. |
| W-30 SNMP | public/private 외에도 영문·숫자 조합과 길이를 검사한다. 특수문자 포함 시 8자 이상, 미포함 시 10자 이상이 기준이다. 원문 대신 길이·문자 종류·기준 충족 여부를 기록한다. |
| W-37·62 실행 명령 | 예약 작업의 실행파일·인수·작업 경로와 시작 프로그램의 Command를 수집한다. 인식한 민감 인수만 가리고 나머지 명령은 보존한다. 구형 예약 작업 API는 AT 작업만 조회한다. |

## 호환·예외·민감정보

- 계정·그룹은 SID, 서비스는 Service Name, 감사 정책은 고정 Key·GUID·Mask를 사용한다. 한글 표시 이름과 상태 문장을 기준으로 판정하지 않는다.
- 조회 실패와 서비스 비실행을 구분한다. 전체 서비스 목록이 정상 조회된 뒤에만 미존재·중지를 판정하며, 일시 중지·전환 상태는 미사용으로 단정하지 않는다.
- DC의 계정·그룹, Domain·FGPP 정책, 중첩 그룹, 미로드 Profile, 다른 Provider·설정 상속은 해당 항목에 한계를 명시한다. Domain 계정을 대량 열거하거나 사용자 Hive를 강제로 Load하지 않는다.
- Patch·OS Build·백신의 최신성, 조직 승인, 설정의 전체 실효성은 고정 Version 숫자만으로 확정하지 않는다.
- 계정명·SID·경로·권한은 결과에 남긴다. 비밀번호·Hash·Token·Community 등은 수집을 제한하거나 `xxx`로 masking한다. SAM 내용·자동 로그인 비밀번호는 읽지 않는다. 임의의 모든 비밀 형식을 완전하게 식별하는 기능은 아니다.
- 시스템 설정 변경·자동 조치·영구 환경변수 저장을 수행하지 않는다. 결과 폴더와 임시 수집 파일을 생성하며, 임시 파일은 종료 시 제거한다.

OS Version·Server 역할·설치 기능·Provider에 따라 수정 또는 추가 확인이 필요할 수 있다.

## 검토 범위와 참조

항목별 판정과 수집 범위는 현재 단일 Script를 기준으로 한다. 조직 승인·다른 Provider·복잡한 적용 조건은 결과의 수동 확인 내용을 함께 검토한다.

공식 근거: [KISA 2026 상세가이드](https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000127&nttId=71928&menuNo=205021).

Windows PowerShell 5.1에서 구문 검사와 메모리 기반 핵심 함수 검사를 수행했다. 관리자 승인, FTP·DNS·SNMP 판정, 대상별 오류·근거 보존, 명령 masking, JSON 변환과 FTP XML 수집을 확인했다. 실제 Windows Server의 전체 실행과 IIS·DNS 등 설치 기능 API의 실서버 동작은 미검증이다.
