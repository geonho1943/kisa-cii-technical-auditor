# Windows 변수

`ciip_windows_2026.ps1` v0.2.0 기준. 사용자 입력은 파일 상단의 `param(...)`에 모두 모여 있다. 아래 설명은 사용자 입력과 공유 상태를 대상으로 하며, 함수 안에서 사용하는 반복문 변수·임시 값은 해당 함수의 Local Scope에 둔다.

## 사용자 입력

기본값을 수정하거나 실행 시 Parameter로 지정한다. 비밀번호·Hash를 입력하는 Parameter는 없다.

| Parameter | Type | 기본값 | 용도·미입력 처리 |
|---|---|---|---|
| `OutputDirectory` | `string` | Script 폴더 아래 `audit-results` | 결과 위치. 실행마다 접근을 제한한 하위 폴더를 생성한다. 상대 경로를 직접 지정하면 현재 작업 폴더 기준이다. |
| `CheckIds` | `string[]` | `@('ALL')` | `@('W-01', 'W-02')`처럼 점검 ID를 지정한다. `ALL`과 개별 ID 혼용은 오류다. 미선택 항목은 결과에 기록한다. |
| `CommandTimeoutSeconds` | `int` | `20` | 외부 명령의 Timeout. 허용 범위 1~300초. 초과·실패를 서비스 미사용으로 해석하지 않는다. |
| `CimTimeoutSeconds` | `int` | `15` | CIM의 `OperationTimeoutSec`. 허용 범위 1~120초. 모든 Windows Cmdlet에 일괄 적용되는 제한은 아니다. |
| `ApprovedAccountSids` | `string[]` | `@()` | W-03의 승인 로컬 계정 SID 전체 목록. 미입력은 `MANUAL`. 입력한 목록 밖의 계정은 `VULNERABLE`이다. |
| `ApprovedAdminSids` | `string[]` | `@()` | W-06의 승인 관리자 구성원 SID. 입력 시 인원수·중첩 그룹 판단 전에 대조하여 미승인 구성원은 `VULNERABLE`. 미입력이고 직접 사용자 1명이면 수량 기준으로 `GOOD`, 2명 이상이면 `MANUAL`. 중첩 그룹의 실제 구성원은 별도 확인한다. |
| `ApprovedRemoteDesktopSids` | `string[]` | `@()` | W-14의 승인 Remote Desktop Users 구성원 SID. 미입력은 `MANUAL`. 목록과 일치해도 실제 Allow/Deny 권한·중첩 그룹은 수동 확인한다. |
| `UnnecessaryServices` | `string[]` | `@()` | W-18에서 업무상 불필요하다고 확정한 Service Name. 미입력은 실행 목록을 수집하고 `MANUAL`. DisplayName은 사용하지 않는다. |
| `RequiredServices` | `string[]` | `@()` | 업무상 필요한 Service Name. 예: `@('W3SVC', 'SNMP')`. W-19·W-29의 필요성 판단에 사용하며, 관련 보안 항목 전체를 면제하지 않는다. |
| `ApprovedTimeSources` | `string[]` | `@()` | W-41의 승인 NTP 이름·IP. 명시적 NTP 설정이 목록을 벗어나면 불일치를 보고한다. 실제 동기화·Domain 시간 계층은 별도 확인한다. |
| `RequiredAuditSettings` | `hashtable` | `@{}` | W-40의 고급 감사 `Subcategory GUID = Mask`. `1`은 성공, `2`는 실패, `3`은 둘 다. 미입력 시 기본 감사 정책과 유효 적용 조건을 대조하거나 `MANUAL`로 남긴다. 일부 GUID 일치만으로 전체 감사를 `GOOD`으로 단정하지 않는다. |
| `BannerMarkers` | `string[]` | `@()` | W-57 경고 본문에 포함돼야 하는 승인 문자열. Literal·대소문자 구분으로 비교한다. 미입력 시 제목·본문의 공란 여부를 검사한다. |
| `ShowConfig` | `switch` | 지정 안 함 | 입력 형식을 검증하고 설정값·설명만 출력한 뒤 종료한다. OS 점검·결과 폴더 생성은 수행하지 않는다. |
| `ValidateConfig` | `switch` | 지정 안 함 | 동일한 입력 형식 검증과 설정 설명 후 종료한다. 승인 목록의 업무적 완전성까지 검증하는 기능은 아니다. |

설정과 설명 확인:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ciip_windows_2026.ps1 -ShowConfig
```

## 입력 기준

- SID 배열에는 이름 대신 `S-1-...` 형태의 실제 SID를 넣는다. 결과에는 확인한 계정 이름과 SID를 함께 남긴다.
- 서비스 배열에는 언어별 DisplayName 대신 `Win32_Service.Name`을 넣는다.
- 승인 목록을 입력하기 전에 범위가 완전한지 확인한다. 일부 계정만 입력하면 나머지 계정은 미승인으로 판단된다.
- 점검 ID의 가이드 기준값은 내부 점검 로직에 둔다. 사용자 승인 목록과 가이드의 수치 기준을 혼합하지 않는다.

## 내부 공유 상태

아래 값은 Script Scope에서만 사용한다. 사용자 입력 구역에서 직접 수정하지 않는다.

| 변수 | 역할 |
|---|---|
| `$script:Config` | 상단 Parameter의 실행 시점 값. 함수가 공통으로 참조한다. |
| `$script:ConfigDescriptions` | Parameter의 `HelpMessage`. 설정 출력에 사용한다. |
| `$script:Catalog` | W-01~W-64의 제목·위험도·점검 이유·미조치 위험. |
| `$script:ToolVersion` | Script 버전 `0.2.0`. 결과 파일에 기록한다. |
| `$script:RegistryPaths` | 공통 LSA·System Policy·LanmanServer·Terminal Policy 경로. |
| `$script:Os`, `$script:Computer` | OS·Build·Server 역할·Domain 가입 여부. |
| `$script:ServiceRecords`, `$script:AccountRecords` | 서비스·로컬 계정의 조회 Cache. |
| `$script:FtpRuntime` | IIS FTP 비실행 시 알려진 FTP 서비스·프로세스·21/990 수신 포트와 조회 오류를 재사용하는 Cache. |
| `$script:ServiceError`, `$script:AccountError` | 조회 실패 Cache. 실패 이후 빈 목록을 미설치·양호로 재사용하지 않는다. |
| `$script:SecPolicy`, `$script:PolicyError` | `secedit` 정책 Export의 해석 결과와 실패 상태. |
| `$script:NativeProcesses` | 실행 중인 외부 명령 추적. Timeout·종료 시 정리한다. |
| `$script:OutputPath` | 현재 실행의 결과 폴더. |
| `$script:WorkDirectory` | 임시 수집 폴더. 실행 종료 시 제거한다. |

환경변수·Registry에 설정값을 영구 저장하지 않는다. 별도 PowerShell Process 실행을 기준으로 하며 Dot-sourcing은 차단한다. 정상 종료 시 임시 폴더와 Cache를 정리하고, Process가 종료되면 실행 변수가 해제된다. 강제 종료·전원 중단은 정리 코드를 실행하지 못할 수 있다. Memory 덮어쓰기·Swap·Dump 삭제는 수행하지 않는다.
