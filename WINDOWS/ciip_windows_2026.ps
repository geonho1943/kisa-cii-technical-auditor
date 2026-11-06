#Requires -Version 5.1
<#
2026 주요정보통신기반시설 Windows Server W-01~W-64 점검.
실행: powershell.exe -NoProfile -File .\ciip_windows_2026.ps1
설정: 아래 param 구역만 수정. -ShowConfig로 설명과 적용값 확인.
설정 변경/자동 조치/영구 환경변수 저장 없음.
Version·의존환경에 따라 수정 또는 추가 확인이 필요할 수 있음.
#>
[CmdletBinding()]
param(
    # ================= 사용자 설정: 모든 입력값을 이 구역에서 정의 =================
    [Parameter(HelpMessage = '결과 폴더. Script 위치 아래가 기본값. 실행마다 접근 제한 하위 폴더 생성')]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'audit-results'),

    [Parameter(HelpMessage = 'ALL 또는 W-01,W-02 등의 배열. 미선택 항목은 결과에 별도 기록')]
    [string[]]$CheckIds = @('ALL'),

    [Parameter(HelpMessage = '외부 명령 제한 시간(초), 1~300. Timeout은 ERROR이며 안전/미사용으로 처리하지 않음')]
    [ValidateRange(1, 300)]
    [int]$CommandTimeoutSeconds = 20,

    [Parameter(HelpMessage = 'CIM 조회 제한 시간(초), 1~120')]
    [ValidateRange(1, 120)]
    [int]$CimTimeoutSeconds = 15,

    [Parameter(HelpMessage = 'W-03 승인 로컬 계정 SID 배열. 미입력 시 불필요 계정 여부 MANUAL. 계정 이름은 결과에 표시')]
    [string[]]$ApprovedAccountSids = @(),

    [Parameter(HelpMessage = 'W-06 승인 관리자 SID 배열. 구성원 2명 이상이고 목록이 없으면 MANUAL')]
    [string[]]$ApprovedAdminSids = @(),

    [Parameter(HelpMessage = 'W-14 승인 Remote Desktop Users 구성원 SID 배열. 미입력 시 MANUAL')]
    [string[]]$ApprovedRemoteDesktopSids = @(),

    [Parameter(HelpMessage = 'W-18 업무상 불필요하다고 확정한 서비스의 Service Name 배열. DisplayName 아님. 예: TlntSvr')]
    [string[]]$UnnecessaryServices = @(),

    [Parameter(HelpMessage = '업무상 필요한 Service Name 배열. 예: W3SVC,SNMP. 모든 항목을 자동 면제하지 않음')]
    [string[]]$RequiredServices = @(),

    [Parameter(HelpMessage = 'W-41 승인 시간 서버/Pool 이름 또는 IP. Domain 계층 동기화는 별도 확인')]
    [string[]]$ApprovedTimeSources = @(),

    [Parameter(HelpMessage = 'W-40 고급 감사 Subcategory GUID=Mask. 1=성공,2=실패,3=둘 다. 미입력 시 기본 정책 대조 또는 MANUAL')]
    [hashtable]$RequiredAuditSettings = @{},

    [Parameter(HelpMessage = 'W-57 승인 경고 문구의 필수 문자열 배열. 미입력 시 제목/본문 존재 조건으로 검사')]
    [string[]]$BannerMarkers = @(),

    [Parameter(HelpMessage = '비민감 설정의 이름·값·설명만 출력하고 종료')]
    [switch]$ShowConfig,

    [Parameter(HelpMessage = '입력 형식만 확인하고 종료. 조직 정책의 승인·완전성까지 검증하는 기능은 아님')]
    [switch]$ValidateConfig
    # ============================ 사용자 설정 끝 ============================
)

if ($MyInvocation.InvocationName -eq '.') {
    throw 'Dot-sourcing 대신 powershell.exe -NoProfile -File로 별도 Process에서 실행하십시오.'
}
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# 내부 상태는 Script Scope에만 존재한다. 비밀번호·Hash를 입력받지 않는다.
$script:Config = @{}
$script:ConfigDescriptions = @{}
foreach ($parameterName in $MyInvocation.MyCommand.Parameters.Keys) {
    $descriptions = @($MyInvocation.MyCommand.Parameters[$parameterName].Attributes |
        Where-Object { $_ -is [Management.Automation.ParameterAttribute] -and $_.HelpMessage })
    if ($descriptions.Count -eq 0) {
        continue
    }
    $script:Config[$parameterName] = Get-Variable -Name $parameterName -ValueOnly
    $script:ConfigDescriptions[$parameterName] = ($descriptions | ForEach-Object { $_.HelpMessage }) -join ' '
}
$script:WorkDirectory = $null
$script:OutputPath = $null
$script:Os = $null
$script:Computer = $null
$script:ServiceRecords = $null
$script:AccountRecords = $null
$script:ServiceError = $null
$script:FtpRuntime = $null
$script:AccountError = $null
$script:SecPolicy = $null
$script:PolicyError = $null
$script:NativeProcesses = New-Object 'System.Collections.Generic.List[System.Diagnostics.Process]'
$script:Catalog = @{}

$script:ToolVersion = '0.2.0'

$script:RegistryPaths = @{
    Lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    SystemPolicy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    LanmanServer = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    TerminalPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
}
# ID/위험도/제목은 공식 2026 가이드 기준. 목적·위험은 자체 요약.
$catalogText = @'
W-01|상|Administrator 계정 이름 변경 등 보안성 강화|기본 관리자 계정의 직접 식별과 인증 위험을 줄임|인증정보 추측·탈취가 최고 권한 침해로 연결
W-02|상|Guest 계정 비활성화|공용 Guest 인증 경로 제한|불특정 사용자의 계정·자원 접근
W-03|상|불필요한 계정 제거|승인한 계정만 유지|방치 계정이 침입·권한 유지 경로로 사용
W-04|상|계정 잠금 임계값 설정|반복 인증 실패를 제한|무차별 대입으로 계정 인증정보 탐색
W-05|상|해독 가능한 암호화를 사용하여 암호 저장 해제|복구 가능한 비밀번호 저장을 제한|저장소 침해 시 원문 비밀번호 복구 위험
W-06|상|관리자 그룹에 최소한의 사용자 포함|불필요한 관리 권한 제한|승인되지 않은 계정의 최고 권한 행사
W-07|중|Everyone 사용 권한을 익명 사용자에 적용|익명 사용자의 Everyone 권한 상속 제한|익명 접근으로 자원 권한 확대
W-08|중|계정 잠금 기간 설정|반복 공격의 재시도 간격 제한|잠금이 빠르게 풀려 인증 공격이 지속
W-09|상|비밀번호 관리 정책 설정|길이·복잡성·기간·이력 정책 확인|추측·재사용·장기 노출 비밀번호로 계정 탈취
W-10|중|마지막 사용자 이름 표시 안 함|로그온 화면의 계정 정보 노출 제한|공격자가 유효 계정을 쉽게 식별
W-11|중|로컬 로그온 허용|대화형 로컬 로그온 권한 최소화|불필요한 계정이 서버 Session을 획득
W-12|중|익명 SID/이름 변환 허용 해제|익명 계정·SID 열거 제한|유효 사용자와 그룹 정보 수집
W-13|중|콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한|빈 비밀번호 계정의 Network 접근 제한|비밀번호 없는 계정으로 원격 접근
W-14|중|원격터미널 접속 가능한 사용자 그룹 제한|원격 Session을 승인 사용자로 제한|불필요한 계정의 원격 접속
W-15|상|사용자 개인키 사용 시 암호 입력|개인키 사용을 사용자 인증으로 보호|Session 접근자가 개인키를 무단 사용
W-16|상|공유 권한 및 사용자 그룹 설정|공유에 대한 불특정 사용자 접근 제한|공유 파일 무단 열람·변조
W-17|상|하드디스크 기본 공유 제거|불필요한 관리 공유 노출 제한|관리 공유를 이용한 접근·확장 경로 노출
W-18|상|불필요한 서비스 제거|업무상 불필요한 실행 기능 최소화|취약 서비스와 불필요한 Port 공격면 노출
W-19|상|불필요한 IIS 서비스 구동 점검|업무 필요성 없는 Web 서비스 제한|불필요한 Web 기능과 취약점 노출
W-20|상|NetBIOS 바인딩 서비스 구동 점검|불필요한 NetBIOS 통신 경로 제한|이름·공유 정보 수집과 공격면 확대
W-21|상|암호화되지 않는 FTP 서비스 비활성화|평문 FTP 인증·전송 제한|계정정보·데이터 도청
W-22|상|FTP 디렉토리 접근권한 설정|FTP Home의 불특정 사용자 권한 제한|전송 파일 무단 열람·변조
W-23|상|공유 서비스에 대한 익명 접근 제한 설정|익명 공유·FTP 인증을 제한|비인가 데이터 열람·업로드
W-24|상|FTP 접근 제어 설정|FTP 접속 Host를 승인 범위로 제한|불필요한 외부 파일 전송 접근
W-25|상|DNS Zone Transfer 설정|Zone 복제를 승인 서버로 제한|내부 DNS·Network 구조 전체 노출
W-26|상|RDS(Remote Data Services)제거|구형 IIS RDS 공격 경로 확인|구형 원격 Data 기능의 취약점 악용
W-27|상|최신 Windows OS Build 버전 적용|지원 Build·업데이트 절차 확인|알려진 OS 취약점이 미조치로 유지
W-28|중|터미널 서비스 암호화 수준 설정|RDP 통신 암호화 수준 확보|원격 Session 통신 내용 노출
W-29|중|불필요한 SNMP 서비스 구동 점검|SNMP 운용 필요성과 인증 확인|관리 정보·설정 Interface 노출
W-30|중|SNMP Community String 복잡성 설정|기본 Community 사용 제한|기본 문자열로 관리 정보 접근
W-31|중|SNMP Access Control 설정|관리 패킷의 Source 제한|비인가 Host의 관리 정보 조회·변경
W-32|중|DNS 서비스 구동 점검|DNS 동적 Update 정책 제한|비인가 DNS Record 변경
W-33|하|HTTP/FTP/SMTP 배너 차단|제품·Version 정보 노출 제한|취약점에 맞는 공격 대상 식별
W-34|중|Telnet 서비스 비활성화|Telnet 미사용 또는 NTLM 인증 확인|평문 인증정보 노출·취약 원격 접근
W-35|중|불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거|사용하지 않는 Data 연결 정의 정리|불필요한 DB 연결·설정 정보 노출
W-36|중|원격터미널 접속 타임아웃 설정|유휴 RDP Session 종료|방치된 Session의 비인가 사용
W-37|중|예약된 작업에 의심스러운 명령이 등록되어 있는지 점검|예약 작업의 정당성 검토|예약 실행을 통한 권한 유지·악성 명령 실행
W-38|상|주기적 보안 패치 및 벤더 권고사항 적용|패치 정책·권고 검토·적용 기록 확인|알려진 취약점이 장기간 미조치
W-39|상|백신 프로그램 업데이트|백신 엔진·Signature 갱신 확인|새 악성 코드에 대한 탐지 공백
W-40|중|정책에 따른 시스템 로깅 설정|책임 추적에 필요한 감사 기록 확보|침해 탐지·행위 추적·사고 분석 곤란
W-41|중|NTP 및 시각 동기화 설정|승인 시간 Source와 동기화|로그 시간 신뢰 저하·시간 의존 인증 오류
W-42|하|이벤트 로그 관리 설정|이벤트 로그 용량·보존 기간 확보|필요한 감사 기록이 조기 덮어쓰기됨
W-43|중|이벤트 로그 파일 접근 통제 설정|불특정 사용자의 감사 정보 접근 제한|로그 유출·변조·흔적 삭제
W-44|상|원격으로 액세스할 수 있는 레지스트리 경로|불필요한 Remote Registry 운용 제한|원격 설정 조회·변경 공격면 노출
W-45|상|백신 프로그램 설치|악성 코드 방어 제품 설치 확인|악성 코드 실행·감염의 탐지 공백
W-46|상|SAM 파일 접근 통제 설정|계정 인증정보 저장소의 ACL 보호|인증정보 탈취·계정 저장소 변조
W-47|하|화면 보호기 설정|유휴 사용자 Session을 잠금|방치된 화면과 Session을 비인가 사용
W-48|상|로그온하지 않고 시스템 종료 허용|미인증 시스템 종료 제한|인증 없이 서비스 운영 중단
W-49|상|원격 시스템에서 강제로 시스템 종료|원격 종료 권한 최소화|비인가 서비스 중단
W-50|상|보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료|감사 저장 실패 시 종료 정책 확인|로그 장애를 이용한 서비스 중단
W-51|상|SAM 계정과 공유의 익명 열거 허용 안 함|익명 계정·공유 열거 제한|내부 사용자·공유 자원 정보 수집
W-52|상|Autologon 기능 제어|비밀번호 입력 없는 자동 로그인 제한|재부팅·물리 접근 시 계정 Session 획득
W-53|상|이동식 미디어 포맷 및 꺼내기 허용|Media 관리 권한 최소화|비인가 Media 조작·정보 유출
W-54|중|Dos 공격 방어 레지스트리 설정|가이드의 TCP/IP 방어 설정 확인|Network 자원 소모·서비스 중단
W-55|중|사용자가 프린터 드라이버를 설치할 수 없게 함|비관리자 Driver 설치 제한|악성·취약 Driver를 통한 권한 상승
W-56|중|SMB 세션 중단 관리 설정|만료·유휴 SMB Session 정리|불필요한 Session 누적과 자원 소모
W-57|하|로그온 시 경고 메시지 설정|접근 제한과 사용 책임을 고지|비인가 사용 금지·감사 고지 누락
W-58|중|사용자별 홈 디렉터리 권한 설정|사용자 Home의 Everyone 권한 제한|사용자 데이터 무단 열람·변조
W-59|중|LAN Manager 인증 수준|구형 LM·NTLM 응답 제한|약한 인증 응답에 대한 공격
W-60|중|보안 채널 데이터 디지털 암호화 또는 서명|Domain 보안 채널 보호|인증 트래픽 위조·Replay·중간자 공격
W-61|중|파일 및 디렉토리 보호|ACL을 지원하는 파일시스템 사용|파일별 접근 권한 통제 미흡
W-62|중|시작 프로그램 목록 분석|자동 실행 항목의 정당성 검토|부팅·로그인 시 악성 코드 실행
W-63|중|도메인 컨트롤러-사용자의 시간 동기화|Kerberos 시간 오차 정책 확인|시간 차이로 인한 인증 장애·Replay 방어 약화
W-64|중|윈도우 방화벽 설정|Windows Firewall 유효 정책 활성화|불필요한 Network 접근 경로 노출
'@
foreach ($line in ($catalogText -split '\r?\n')) {
    $parts = $line -split '\|', 5
    if ($parts.Count -eq 5) {
        $script:Catalog[$parts[0]] = @{ Title = $parts[2]; Severity = $parts[1]; Purpose = $parts[3]; Risk = $parts[4] }
    }
}
Remove-Variable -Name catalogText, line, parts -ErrorAction SilentlyContinue

#region core

# Windows core

function Protect-AuditText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [string]) {
        $text = $Value
    }
    else {
        $text = ConvertTo-Json -InputObject $Value -Depth 6 -Compress
    }
    $text = [regex]::Replace($text, '\$([A-Za-z0-9-]+)\$[^\s:"]+', '[hash:$1:xxx]')
    $text = [regex]::Replace($text, '(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[private key:xxx]')
    $text = [regex]::Replace($text, '(?i)((?:\bpassword|\bpasswd|\btoken|\bsecret|\bauthorization|\bcommunity|\bntlmhash|\bpasswordhash)\s*"?\s*[=:]\s*)("(?:\\.|[^"\\])*"|[^\s,;}\]]+)', '$1[xxx]')
    $text = [regex]::Replace($text, '(?i)\b[0-9a-f]{32}:[0-9a-f]{32}\b', '[LM:xxx]:[NTLM:xxx]')
    return $text
}

function Protect-AuditCommand {
    param([AllowNull()][string]$Command)
    # JSON 변환 전에 인수 값만 가린다. 실행파일·일반 옵션·작업 경로는 보존한다.
    $value = '(?:"(?:\\.|[^"\\])*"|''[^'']*''|[^\s;&|]+)'
    $option = '(?i)((?<![\w])(?:--?|/)(?:password|passwd|pwd|token|secret|authorization|community|ntlmhash|passwordhash)(?:\s*[=:]\s*|\s+))'
    $text = [regex]::Replace([string]$Command, '(?i)(\bauthorization\s*:\s*(?:Bearer|Basic)\s+)[^\s"'';]+', '$1[xxx]')
    $text = [regex]::Replace($text, $option + $value, '$1[xxx]')
    $assignment = '(?i)((?:\bpassword|\bpasswd|\bpwd|\btoken|\bsecret|\bcommunity|\bntlmhash|\bpasswordhash)\s*[=:]\s*)'
    $text = [regex]::Replace($text, $assignment + $value, '$1[xxx]')
    $text = [regex]::Replace($text, '(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@', '$1[xxx]@')
    return Protect-AuditText $text
}

function New-AuditResult {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [ValidateSet('GOOD', 'VULNERABLE', 'MANUAL', 'NOT_APPLICABLE', 'ERROR')][string]$Status,
        [string]$Summary,
        [AllowNull()][object]$Evidence = '',
        [string]$ManualAction = '',
        [string]$ErrorCode = ''
    )
    $metadata = $script:Catalog[$Id]
    if ($Status -eq 'GOOD' -and $Id -in @('W-04', 'W-05', 'W-08', 'W-09') -and
        $null -ne $script:Computer -and $script:Computer.PartOfDomain) {
        $Status = 'MANUAL'
        $ManualAction = '로컬 SAM 정책 확인 완료. Domain 계정 정책·Fine-Grained Password Policy·GPO 적용 범위 별도 확인'
    }
    return [pscustomobject][ordered]@{
        id = $Id
        title = $metadata.Title
        severity = $metadata.Severity
        status = $Status
        summary = Protect-AuditText $Summary
        evidence = Protect-AuditText $Evidence
        manual_action = Protect-AuditText $ManualAction
        error_code = $ErrorCode
        purpose = $metadata.Purpose
        risk = $metadata.Risk
    }
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)
    # Windows CommandLineToArgvW quoting; no cmd.exe, Invoke-Expression or eval.
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * ($slashes * 2 + 1)))
            [void]$builder.Append('"')
        }
        else {
            if ($slashes) {
                [void]$builder.Append(('\' * $slashes))
            }
            [void]$builder.Append($character)
        }
        $slashes = 0
    }
    if ($slashes) {
        [void]$builder.Append(('\' * ($slashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-AuditNativeCommand {
    param(
        [string]$Name,
        [string[]]$Arguments
    )
    $executable = Join-Path $script:Os.SystemDirectory $Name
    if (-not [IO.File]::Exists($executable)) {
        throw "필수 실행파일 없음: $Name"
    }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $executable
    $start.Arguments = (($Arguments | ForEach-Object {
        ConvertTo-NativeArgument $_
    }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Console]::OutputEncoding
    $start.StandardErrorEncoding = [Console]::OutputEncoding
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    [void]$script:NativeProcesses.Add($process)
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($script:Config.CommandTimeoutSeconds * 1000)) {
            try {
                $process.Kill()
            }
            catch {
                Write-Verbose 'Timeout Process 종료 실패'
            }
            throw "명령 Timeout: $Name"
        }
        return [pscustomobject]@{
            Code = $process.ExitCode
            Stdout = $stdoutTask.GetAwaiter().GetResult()
            Stderr = $stderrTask.GetAwaiter().GetResult()
        }
    }
    finally {
        [void]$script:NativeProcesses.Remove($process)
        $process.Dispose()
    }
}

function New-PrivateAuditDirectory {
    param([string]$Path)
    if ([IO.Directory]::Exists($Path)) {
        throw "이미 존재하는 실행 폴더: $Path"
    }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $sids = @('S-1-5-18', 'S-1-5-32-544', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    foreach ($sidValue in ($sids | Select-Object -Unique)) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inheritance, $propagation, 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    $directory = New-Object IO.DirectoryInfo($Path)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [IO.FileSystemAclExtensions]::Create($directory, $acl)
    }
    else {
        $directory.Create($acl)
    }
    return $directory.FullName
}

function Test-RegistryRule {
    param(
        [string]$Id,
        [string]$Path,
        [string]$Name,
        [string[]]$Allowed
    )
    $setting = Get-RegistrySetting -Path $Path -Name $Name
    if ($setting.State -eq 'MISSING') {
        return New-AuditResult $Id MANUAL '명시적 Registry 값 없음; 유효 기본값·정책 확인 필요' "$Path\$Name" 'OS Version·GPO·Vendor 기본값 확인; 없음=0으로 가정하지 않음'
    }
    $value = [string]$setting.Value
    if ($value -in $Allowed) {
        return New-AuditResult $Id GOOD '명시적 설정이 가이드 값과 일치' "$Path\$Name=$value"
    }
    return New-AuditResult $Id VULNERABLE '명시적 설정이 가이드 조건 미충족' "$Path\$Name=$value"
}

function Test-SecurityPolicyRule {
    param(
        [string]$Id,
        [string]$Name,
        [int]$Minimum,
        [int]$Maximum
    )
    $policy = Get-SecurityPolicy
    if (-not $policy.ContainsKey($Name)) {
        return New-AuditResult $Id MANUAL '보안 정책 값이 Export에 없음' $Name '적용 GPO·Domain/Local 정책과 실제 기본값 확인'
    }
    $number = 0
    if (-not [int]::TryParse($policy[$Name], [ref]$number)) {
        throw "보안 정책 숫자 Parsing 실패: $Name"
    }
    if ($number -ge $Minimum -and $number -le $Maximum) {
        return New-AuditResult $Id GOOD '보안 정책 수치가 가이드 범위 내' "$Name=$number"
    }
    return New-AuditResult $Id VULNERABLE '보안 정책 수치가 가이드 범위 밖' "$Name=$number"
}

function Get-InactiveServiceResult {
    param(
        [string]$Id,
        [string]$Name
    )
    $state = Get-ServiceState $Name
    if ($state -in @('STOPPED', 'ABSENT')) {
        return New-AuditResult $Id GOOD '정상 조회된 전체 서비스 목록에서 비실행 확인' "$Name=$state"
    }
    if ($state -eq 'UNKNOWN') {
        throw "서비스 상태 미확정: $Name"
    }
    return $null
}

function Write-AuditReport {
    param(
        [object[]]$Results,
        [string[]]$Selected,
        [string[]]$NotSelected,
        [bool]$Interrupted
    )
    $counts = [ordered]@{
        GOOD=0
        VULNERABLE=0
        MANUAL=0
        NOT_APPLICABLE=0
        ERROR=0
    }
    $weighted = 0
    foreach ($result in $Results) {
        $counts[$result.status]++
        if ($result.status -eq 'VULNERABLE') {
            switch ($result.severity) {
                '상' {
                    $weighted += 3
                } '중' {
                    $weighted += 2
                } '하' {
                    $weighted += 1
                }
            }
        }
    }
    $report = [ordered]@{
        schema_version='1.0'
        tool_version=$script:ToolVersion
        guide_version='2026'
        platform='windows'
        generated_at=[DateTime]::UtcNow.ToString('o')
        os=@{
            Caption=$script:Os.Caption
            Version=$script:Os.Version
            Build=$script:Os.BuildNumber
        }
        domain_role=$script:Computer.DomainRole
        domain_joined=$script:Computer.PartOfDomain
        scope='현재 Server의 machine/local SAM; Domain/FGPP/미로드 Profile/외부 Provider는 항목별 한계 참조'
        selected_count=$Selected.Count
        completed_count=$Results.Count
        interrupted=$Interrupted
        not_selected=$NotSelected
        counts=$counts
        weighted_vulnerable_score=$weighted
        items=$Results
    }
    $encoding = New-Object Text.UTF8Encoding($false)
    $json = ConvertTo-Json -InputObject $report -Depth 12
    [IO.File]::WriteAllText((Join-Path $script:OutputPath 'result.json'), $json, $encoding)
    $builder = New-Object Text.StringBuilder
    [void]$builder.AppendLine("CIIP Audit Windows $($script:ToolVersion) / Guide 2026")
    [void]$builder.AppendLine("OS: $($script:Os.Caption) Build=$($script:Os.BuildNumber)")
    [void]$builder.AppendLine("완료 $($Results.Count)/$($Selected.Count) / 상태 $(ConvertTo-Json $counts -Compress)")
    [void]$builder.AppendLine("취약 가중합: $weighted (상3/중2/하1; 수동/오류/미실행은 양호에 포함하지 않음)")
    foreach ($result in $Results) {
        [void]$builder.AppendLine("`r`n[$($result.id)] $($result.title) ($($result.severity)) — $($result.status)")
        [void]$builder.AppendLine("결과: $($result.summary)`r`n근거: $($result.evidence)")
        [void]$builder.AppendLine("수동 확인: $($result.manual_action)`r`n오류: $($result.error_code)")
        [void]$builder.AppendLine("점검 이유: $($result.purpose)`r`n미조치 위험: $($result.risk)")
    }
    [void]$builder.AppendLine("`r`n미선택: $($NotSelected -join ',')")
    [IO.File]::WriteAllText((Join-Path $script:OutputPath 'report.txt'), $builder.ToString(), $encoding)
}

function Invoke-WindowsAuditCheck {
    param([string]$Id)

    if (-not $script:Catalog.ContainsKey($Id)) {
        throw "구현되지 않은 항목 ID: $Id"
    }
    if ([int]$script:Computer.DomainRole -ge 4 -and $Id -in @('W-01','W-02','W-03','W-06','W-14')) {
        return New-AuditResult $Id MANUAL 'DC는 Domain 계정·그룹을 별도 범위로 검사해야 함' "DomainRole=$($script:Computer.DomainRole)" 'AD 유효 정책·승인 계정/그룹 확인'
    }
    $functionName = 'Test-WindowsW{0}' -f $Id.Substring(2)
    & $functionName
}

function Show-AuditConfiguration {
    Write-Host '사용자 설정 (공란 정책은 임의 추정하지 않습니다):'
    foreach ($name in ($script:Config.Keys | Sort-Object)) {
        $value = $script:Config[$name]
        if ($null -eq $value -or ($value -is [array] -and $value.Count -eq 0)) {
            $rendered = '(미입력)'
        }
        else {
            $rendered = Protect-AuditText $value
        }
        $help = $script:ConfigDescriptions[$name]
        Write-Host ("  {0} = {1}" -f $name, $rendered)
        Write-Host ("    {0}" -f $help)
    }
}

function Invoke-WindowsAudit {
    try {
        foreach ($sidValue in @($script:Config.ApprovedAccountSids) + @($script:Config.ApprovedAdminSids) + @($script:Config.ApprovedRemoteDesktopSids)) {
            if ($sidValue -notmatch '^S-\d+(?:-\d+)+$') {
                throw "SID 형식 오류: $sidValue"
            }
        }
        foreach ($key in $script:Config.RequiredAuditSettings.Keys) {
            $parsedGuid = [guid]::Empty
            if (-not [guid]::TryParse([string]$key,[ref]$parsedGuid)) {
                throw "감사 GUID 형식 오류: $key"
            }
            if ([int]$script:Config.RequiredAuditSettings[$key] -lt 1 -or [int]$script:Config.RequiredAuditSettings[$key] -gt 3) {
                throw '감사 Mask는 1~3 필요'
            }
        }
        $allIds = @(1..64 | ForEach-Object {
            'W-{0:00}' -f $_
        })
        if ($script:Config.CheckIds.Count -eq 0) {
            throw 'CheckIds가 비어 있음'
        }
        if ($script:Config.CheckIds -contains 'ALL') {
            if ($script:Config.CheckIds.Count -ne 1) {
                throw 'ALL과 개별 항목을 함께 지정하지 마십시오.'
            }
            $selected = $allIds
        }
        else {
            $selected = @($script:Config.CheckIds | Select-Object -Unique)
            foreach ($id in $selected) {
                if ($id -notin $allIds) {
                    throw "항목 ID 오류: $id"
                }
            }
        }
        $notSelected = @($allIds | Where-Object {
            $_ -notin $selected
        })
        Show-AuditConfiguration

        if ($script:Config.ShowConfig -or $script:Config.ValidateConfig) {
            return 0
        }
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
            throw 'Windows Server에서 실행하십시오.'
        }
        if ([IntPtr]::Size -ne 8) {
            throw '64-bit Windows PowerShell에서 실행하십시오. 32-bit Registry View로 판정하지 않습니다.'
        }
        $script:Os = Get-AuditCimInstance -ClassName Win32_OperatingSystem -Property @('Caption','Version','BuildNumber','ProductType','WindowsDirectory','SystemDirectory')
        $script:Computer = Get-AuditCimInstance -ClassName Win32_ComputerSystem -Property @('DomainRole','PartOfDomain')
        if ([int]$script:Os.ProductType -eq 1) {
            throw 'Windows Client용이 아닌 Windows Server용 점검 Script입니다.'
        }
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning '관리자 권한이 아닙니다. 조회 실패 항목은 ERROR로 기록됩니다.'
        }
        $base = [IO.Path]::GetFullPath($script:Config.OutputDirectory)
        if (-not [IO.Directory]::Exists($base)) {
            [void][IO.Directory]::CreateDirectory($base)
        }
        $script:OutputPath = New-PrivateAuditDirectory (Join-Path $base ('audit.' + [guid]::NewGuid().ToString('N')))
        $script:WorkDirectory = New-PrivateAuditDirectory (Join-Path $script:OutputPath ('.work.' + [guid]::NewGuid().ToString('N')))
        $results = New-Object 'System.Collections.Generic.List[object]'
        $interrupted = $false
        try {
            foreach ($id in $selected) {
                try {
                    $item = @(Invoke-WindowsAuditCheck $id)
                    if ($item.Count -ne 1 -or $null -eq $item[0] -or $item[0].id -ne $id) {
                        throw '항목 결과는 일치하는 Record 1개여야 함'
                    }
                    [void]$results.Add($item[0])
                }
                catch {
                    [void]$results.Add((New-AuditResult $id ERROR '항목 조회/실행 실패' $_.Exception.Message '권한·명령·Provider·설정 형식·Timeout 확인' 'CHECK_FAILED'))
                }
                Write-Host "$id $($results[$results.Count - 1].status)"
            }
        }
        finally {
            $interrupted = $results.Count -lt $selected.Count
            Write-AuditReport -Results @($results.ToArray()) -Selected $selected -NotSelected $notSelected -Interrupted $interrupted
        }
        Write-Host "완료: $script:OutputPath\result.json / report.txt"
        if ($interrupted) {
            return 130
        }
        if (@($results | Where-Object status -eq 'ERROR').Count -gt 0) {
            return 3
        }
        return 0
    }
    catch {
        Write-Error -Message (Protect-AuditText $_.Exception.Message) -ErrorAction Continue
        return 2
    }
    finally {
        foreach ($process in @($script:NativeProcesses.ToArray())) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                }
            }
            catch {
                Write-Verbose 'Process 정리 예외'
            }
            $process.Dispose()
        }
        $script:NativeProcesses.Clear()
        if ($script:WorkDirectory -and [IO.Directory]::Exists($script:WorkDirectory)) {
            try {
                [IO.Directory]::Delete($script:WorkDirectory, $true)
            }
            catch {
                Write-Warning '임시 작업 폴더를 제거하지 못했습니다. 접근 권한을 유지하고 직접 확인하십시오.'
            }
        }
        $script:SecPolicy = $null
        $script:AccountRecords = $null
        $script:ServiceRecords = $null
    }
}

#endregion

#region platform

# Windows platform

function Get-AuditCimInstance {
    param(
        [string]$ClassName,
        [string]$Filter = '',
        [string[]]$Property = @(),
        [string]$Namespace = 'root/cimv2'
    )
    $arguments = @{
        ClassName = $ClassName
        Namespace = $Namespace
        OperationTimeoutSec = $script:Config.CimTimeoutSeconds
        ErrorAction = 'Stop'
    }
    if ($Filter) {
        $arguments.Filter = $Filter
    }
    if ($Property.Count -gt 0) {
        $arguments.Property = $Property
    }
    Get-CimInstance @arguments
}

function Get-RegistrySetting {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($Name -notin $key.GetValueNames()) {
            return [pscustomobject]@{
                State = 'MISSING'
                Value = $null
            }
        }
        return [pscustomobject]@{
            State = 'OK'
            Value = $key.GetValue($Name)
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return [pscustomobject]@{
            State = 'MISSING'
            Value = $null
        }
    }
}

function Get-SecurityPolicy {
    if ($null -ne $script:SecPolicy) {
        return $script:SecPolicy
    }
    if ($null -ne $script:PolicyError) {
        throw $script:PolicyError
    }
    $path = Join-Path $script:WorkDirectory 'security-policy.inf'
    try {
        $logPath = Join-Path $script:WorkDirectory 'secedit.log'
        $native = Invoke-AuditNativeCommand -Name 'secedit.exe' -Arguments @('/export', '/mergedpolicy', '/cfg', $path, '/log', $logPath, '/quiet')
        if ($native.Code -ne 0 -or -not [IO.File]::Exists($path)) {
            throw "secedit export 실패(code=$($native.Code)): $(Protect-AuditText $native.Stderr)"
        }
        $policy = @{}
        foreach ($line in [IO.File]::ReadAllLines($path)) {
            if ($line -match '^\s*([^;\[=]+?)\s*=\s*(.*?)\s*$') {
                $policy[$Matches[1].Trim()] = $Matches[2]
            }
        }
        if ($policy.Count -eq 0) {
            throw '보안 정책 Parsing 결과가 비어 있음'
        }
        $script:SecPolicy = $policy
        return $policy
    }
    catch {
        $script:PolicyError = $_.Exception.Message
        throw
    }
    finally {
        if ([IO.File]::Exists($path)) {
            [IO.File]::Delete($path)
        }
    }
}

function Get-ServiceSnapshot {
    if ($null -ne $script:ServiceError) {
        throw $script:ServiceError
    }
    if ($null -eq $script:ServiceRecords) {
        try {
            $records = @(Get-AuditCimInstance -ClassName Win32_Service -Property @('Name', 'State', 'StartMode'))
            if ($records.Count -eq 0) {
                throw 'Service 목록 조회 결과가 비어 있음'
            }
            $script:ServiceRecords = $records
        }
        catch {
            $script:ServiceError = $_.Exception.Message
            throw
        }
    }
    return $script:ServiceRecords
}

function Get-ServiceState {
    param([string]$Name)
    $matches = @(Get-ServiceSnapshot | Where-Object {
        $_.Name -eq $Name
    })
    if ($matches.Count -eq 0) {
        return 'ABSENT'
    }
    if (@($matches | Where-Object {
        $_.State -eq 'Running'
    }).Count -gt 0) {
        return 'RUNNING'
    }
    if (@($matches | Where-Object {
        $_.State -ne 'Stopped'
    }).Count -gt 0) {
        return 'UNKNOWN'
    }
    return 'STOPPED'
}

function Get-AllowAceSnapshot {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        [pscustomobject]@{
            Sid = $sid
            Rights = [string]$ace.FileSystemRights
            Inherited = $ace.IsInherited
        }
    }
}

#endregion

#region accounts

# Windows accounts

function Get-LocalAccountSnapshot {
    if ([int]$script:Computer.DomainRole -ge 4) {
        throw 'DC의 Domain 계정을 로컬 SAM 목록으로 열거하지 않습니다.'
    }
    if ($null -ne $script:AccountError) {
        throw $script:AccountError
    }
    if ($null -eq $script:AccountRecords) {
        try {
            $records = @(Get-AuditCimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -Property @('SID', 'Name', 'Disabled', 'LocalAccount'))
            if ($records.Count -eq 0) {
                throw '로컬 계정 목록 조회 결과가 비어 있음'
            }
            $script:AccountRecords = $records
        }
        catch {
            $script:AccountError = $_.Exception.Message
            throw
        }
    }
    return $script:AccountRecords
}

function Get-GroupMembersBySid {
    param([string]$Sid)
    $groups = @(Get-AuditCimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='$Sid'")
    if ($groups.Count -ne 1) {
        throw "로컬 그룹 SID 조회 실패: $Sid"
    }
    $arguments = @{
        InputObject = $groups[0]
        Association = 'Win32_GroupUser'
        OperationTimeoutSec = $script:Config.CimTimeoutSeconds
        ErrorAction = 'Stop'
    }
    foreach ($member in (Get-CimAssociatedInstance @arguments)) {
        [pscustomobject]@{
            Name = $member.Name
            SID = $member.SID
            Class = $member.CimClass.CimClassName
        }
    }
}

# W-01
function Test-WindowsW01 {
    $id = 'W-01'
    $accounts = @(Get-LocalAccountSnapshot | Where-Object {
        $_.SID -match '-500$'
    })
    if ($accounts.Count -ne 1) {
        throw 'RID 500 관리자 계정을 식별하지 못함'
    }
    $account = $accounts[0]
    if ($account.Name -ne 'Administrator') {
        return New-AuditResult $id GOOD '기본 관리자 계정 이름 변경 확인' ($account | Select-Object Name, SID, Disabled)
    }
    return New-AuditResult $id MANUAL '기본 이름 유지; 강화된 비밀번호 적용 여부 확인 필요' ($account | Select-Object Name, SID, Disabled) '가이드의 이름 변경/강화 비밀번호 조건을 확인. 이름만으로 취약 단정하지 않음'
}

# W-02
function Test-WindowsW02 {
    $id = 'W-02'
    $accounts = @(Get-LocalAccountSnapshot | Where-Object {
        $_.SID -match '-501$'
    })
    if ($accounts.Count -ne 1) {
        throw 'RID 501 Guest 계정을 식별하지 못함'
    }
    if ($accounts[0].Disabled) {
        return New-AuditResult $id GOOD 'Guest 비활성 확인' ($accounts[0] | Select-Object Name, SID, Disabled)
    }
    return New-AuditResult $id VULNERABLE 'Guest 활성 상태' ($accounts[0] | Select-Object Name, SID, Disabled)
}

# W-03
function Test-WindowsW03 {
    $id = 'W-03'
    $accounts = @(Get-LocalAccountSnapshot | Select-Object Name, SID, Disabled)
    if ($script:Config.ApprovedAccountSids.Count -eq 0) {
        return New-AuditResult $id MANUAL '불필요 계정 여부는 승인 목록 필요' $accounts '상단 ApprovedAccountSids에 승인 전체 계정 SID 지정'
    }
    $unexpected = @($accounts | Where-Object {
        $_.SID -notin $script:Config.ApprovedAccountSids
    })
    if ($unexpected.Count -gt 0) {
        return New-AuditResult $id VULNERABLE '입력한 승인 목록 밖의 계정' $unexpected 'Disabled 계정도 삭제/유지 필요성을 검토'
    }
    return New-AuditResult $id GOOD '로컬 계정이 승인 목록에 포함' $accounts
}

# W-04
function Test-WindowsW04 {
    $id = 'W-04'
    return Test-SecurityPolicyRule $id 'LockoutBadCount' 1 5
}

# W-05
function Test-WindowsW05 {
    $id = 'W-05'
    return Test-SecurityPolicyRule $id 'ClearTextPassword' 0 0
}

# W-06
function Test-WindowsW06 {
    $id = 'W-06'
    $members = @(Get-GroupMembersBySid 'S-1-5-32-544')
    if ($members.Count -eq 0) {
        throw '관리자 그룹의 유효 구성원을 확인하지 못함'
    }
    if ($script:Config.ApprovedAdminSids.Count -gt 0) {
        $unexpected = @($members | Where-Object { $_.SID -notin $script:Config.ApprovedAdminSids })
        if ($unexpected.Count) {
            return New-AuditResult $id VULNERABLE '미승인 관리자 구성원' @{
                Members=$members
                Unapproved=$unexpected
            }
        }
    }
    if (@($members | Where-Object {
        $_.Class -eq 'Win32_Group'
    }).Count) {
        return New-AuditResult $id MANUAL '관리자 그룹에 중첩 그룹 포함' $members 'Domain/중첩 그룹의 유효 사용자 범위와 승인 목록을 검토'
    }
    if ($members.Count -le 1) {
        return New-AuditResult $id GOOD '관리자 그룹 구성원 1명 이하' $members
    }
    if ($script:Config.ApprovedAdminSids.Count -eq 0) {
        return New-AuditResult $id MANUAL '관리자 구성원 2명 이상: 필요성 확인 필요' $members '숫자만으로 취약 단정하지 않고 승인 목록 대조'
    }
    return New-AuditResult $id GOOD '관리자 구성원 승인 목록과 일치' $members
}

# W-07
function Test-WindowsW07 {
    $id = 'W-07'
    return Test-RegistryRule $id $script:RegistryPaths.Lsa 'EveryoneIncludesAnonymous' @('0')
}

# W-08
function Test-WindowsW08 {
    $id = 'W-08'
    $policy = Get-SecurityPolicy
    $evidence = @{}
    foreach ($key in @('LockoutDuration', 'ResetLockoutCount')) {
        if (-not $policy.ContainsKey($key)) {
            return New-AuditResult $id MANUAL '잠금 기간의 유효 설정 확인 필요' $evidence $key
        }
        $value = 0
        if (-not [int]::TryParse($policy[$key], [ref]$value)) {
            throw "잠금 기간 Parsing 실패: $key"
        }
        $evidence[$key] = $value
        if ($value -lt 60) {
            return New-AuditResult $id VULNERABLE '잠금/초기화 기간 60분 기준 미충족' $evidence '0=관리자 해제 등의 정책 의미와 운영상 승인 예외 별도 검토'
        }
    }
    return New-AuditResult $id GOOD '잠금 및 초기화 기간 60분 이상' $evidence
}

# W-09
function Test-WindowsW09 {
    $id = 'W-09'
    $policy = Get-SecurityPolicy
    $rules = @{
        PasswordComplexity = @(1,1)
        MinimumPasswordLength = @(8,65535)
        MaximumPasswordAge = @(1,90)
        MinimumPasswordAge = @(1,65535)
        PasswordHistorySize = @(4,65535)
    }
    $evidence = @{}
    $bad = @()
    $missing = @()
    foreach ($key in $rules.Keys) {
        if (-not $policy.ContainsKey($key)) {
            $missing += $key
            continue
        }
        $value = 0
        if (-not [int]::TryParse($policy[$key], [ref]$value)) {
            throw "비밀번호 정책 Parsing 실패: $key"
        }
        $evidence[$key] = $value
        if ($value -lt $rules[$key][0] -or $value -gt $rules[$key][1]) {
            $bad += $key
        }
    }
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE '비밀번호 정책 기준 미충족' @{
            Values = $evidence
            Failed = $bad
            Missing = $missing
        }
    }
    if ($missing.Count) {
        return New-AuditResult $id MANUAL '비밀번호 정책 일부 값 미확정' @{
            Values = $evidence
            Missing = $missing
        } '적용 GPO와 계정 범위 확인'
    }
    return New-AuditResult $id GOOD '비밀번호 복잡성·길이·기간·기억 기준 충족' $evidence
}

# W-10
function Test-WindowsW10 {
    $id = 'W-10'
    return Test-RegistryRule $id $script:RegistryPaths.SystemPolicy 'DontDisplayLastUserName' @('1')
}

# W-11
function Test-WindowsW11 {
    $id = 'W-11'
    $policy = Get-SecurityPolicy
    if (-not $policy.ContainsKey('SeInteractiveLogonRight')) {
        return New-AuditResult $id MANUAL '로컬 로그온 권한 미확정' '' '유효 사용자 권한 할당 확인'
    }
    $sids = @($policy.SeInteractiveLogonRight -split ',' | ForEach-Object {
        $_.Trim().TrimStart('*')
    } | Where-Object {
        $_
    })
    return New-AuditResult $id MANUAL '로컬 로그온 허용 대상 수집' $sids 'Administrators SID S-1-5-32-544 및 실제 IIS IUSR 계정 여부·Server 역할별 필요성 확인'
}

# W-12
function Test-WindowsW12 {
    $id = 'W-12'
    return Test-SecurityPolicyRule $id 'LSAAnonymousNameLookup' 0 0
}

# W-13
function Test-WindowsW13 {
    $id = 'W-13'
    return Test-RegistryRule $id $script:RegistryPaths.Lsa 'LimitBlankPasswordUse' @('1')
}

# W-14
function Test-WindowsW14 {
    $id = 'W-14'
    $members = @(Get-GroupMembersBySid 'S-1-5-32-555')
    if ($script:Config.ApprovedRemoteDesktopSids.Count -eq 0) {
        return New-AuditResult $id MANUAL '원격 접속 그룹의 승인 정책 확인 필요' $members 'RDP 사용 여부·별도 계정·SeRemoteInteractiveLogonRight·중첩 그룹 확인'
    }
    $bad = @($members | Where-Object {
        $_.SID -notin $script:Config.ApprovedRemoteDesktopSids
    })
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE 'RDP 그룹의 미승인 구성원' $bad
    }
    return New-AuditResult $id MANUAL 'RDP 직접 구성원은 승인 목록과 일치' $members 'Allow/Deny 권한 할당·관리자 우회·중첩 그룹의 실제 접속 범위 확인'
}

# W-15
function Test-WindowsW15 {
    $id = 'W-15'
    return Test-RegistryRule $id 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' 'ForceKeyProtection' @('2')
}

#endregion

#region services

# Windows services

function Get-InactiveFtpResult {
    param([string]$Id)
    $state = Get-ServiceState 'FTPSVC'
    if ($state -eq 'RUNNING') { return $null }
    if ($state -eq 'UNKNOWN') { throw 'IIS FTP 서비스 상태 미확정' }
    if ($null -eq $script:FtpRuntime) {
        $data = @{ IisState=$state; Services=@(); Processes=@(); Listeners=@(); Errors=@() }
        $data.Services = @(Get-ServiceSnapshot | Where-Object {
            $_.Name -ne 'FTPSVC' -and $_.Name -match 'ftp|filezilla|serv-u|cerberus' -and $_.State -ne 'Stopped'
        } | Select-Object Name, State, StartMode)
        try {
            $data.Processes = @(Get-AuditCimInstance Win32_Process -Property @('Name','ProcessId') |
                Where-Object Name -match 'filezilla.*server|serv-u|cerberus|ftpd|ftpserver' | Select-Object Name, ProcessId)
            if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
                throw 'FTP 수신 포트 조회 Cmdlet 없음'
            }
            $data.Listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Where-Object LocalPort -in @(21,990) | Select-Object LocalAddress, LocalPort, OwningProcess)
        }
        catch { $data.Errors += $_.Exception.Message }
        $script:FtpRuntime = $data
    }
    if ($script:FtpRuntime.Errors.Count -or $script:FtpRuntime.Services.Count -or
        $script:FtpRuntime.Processes.Count -or $script:FtpRuntime.Listeners.Count) {
        return New-AuditResult $Id MANUAL 'IIS FTP 비실행; 다른 FTP Provider 또는 조회 실패 확인 필요' $script:FtpRuntime '발견한 서비스·프로세스·수신 포트의 실제 FTP 설정 확인'
    }
    return New-AuditResult $Id GOOD 'IIS·알려진 FTP Provider·표준 수신 포트에서 실행 미발견' $script:FtpRuntime '이름을 변경한 Provider와 비표준 포트는 수집 범위 밖'
}

function Get-FtpConfiguration {
    param([switch]$IncludeIpSecurity)
    $path = Join-Path $script:Os.WindowsDirectory 'System32\inetsrv\config\applicationHost.config'
    if (-not [IO.File]::Exists($path)) {
        throw 'IIS applicationHost.config를 확인하지 못함'
    }
    $xml = New-Object Xml.XmlDocument
    $xml.XmlResolver = $null
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create($path, $settings)
    try {
        $xml.Load($reader)
    }
    finally {
        $reader.Dispose()
    }
    # IP 제한은 IIS API로 전역·location 상속을 반영한 유효 설정을 읽는다.
    $manager = $null
    $ipError = ''
    if ($IncludeIpSecurity) {
        try {
            Add-Type -Path (Join-Path $script:Os.WindowsDirectory 'System32\inetsrv\Microsoft.Web.Administration.dll') -ErrorAction Stop
            $manager = New-Object Microsoft.Web.Administration.ServerManager
        }
        catch { $ipError = $_.Exception.Message }
    }
    # XML의 인증 문자열·계정 비밀번호는 결과 객체에 포함하지 않는다.
    $sites = @($xml.SelectNodes('/configuration/system.applicationHost/sites/site'))
    try {
        foreach ($site in $sites) {
            if (@($site.SelectNodes('bindings/binding[@protocol="ftp"]')).Count -eq 0) {
                continue
            }
            $defaults = $xml.SelectSingleNode('/configuration/system.applicationHost/sites/siteDefaults/ftpServer')
            $ssl = $site.SelectSingleNode('ftpServer/security/ssl')
            if ($null -eq $ssl -and $null -ne $defaults) {
                $ssl = $defaults.SelectSingleNode('security/ssl')
            }
            $anonymous = $site.SelectSingleNode('ftpServer/security/authentication/anonymousAuthentication')
            if ($null -eq $anonymous -and $null -ne $defaults) {
                $anonymous = $defaults.SelectSingleNode('security/authentication/anonymousAuthentication')
            }
            $vdir = $site.SelectSingleNode('application[@path="/"]/virtualDirectory[@path="/"]')
            $ftpHome = ''
            if ($null -ne $vdir) {
                $ftpHome = [Environment]::ExpandEnvironmentVariables($vdir.GetAttribute('physicalPath'))
            }
            $ip = @{ AllowUnlisted=$null; Rules=@(); Error=$ipError }
            if ($null -ne $manager) {
                try {
                    $section = $manager.GetApplicationHostConfiguration().GetSection('system.ftpServer/security/ipSecurity', $site.GetAttribute('name'))
                    $ip.AllowUnlisted = [bool]$section['allowUnlisted']
                    $ip.Rules = @($section.GetCollection() | ForEach-Object {
                        @{ Address=[string]$_['ipAddress']; Mask=[string]$_['subnetMask']; Domain=[string]$_['domainName']; Allowed=[bool]$_['allowed'] }
                    })
                }
                catch { $ip.Error = $_.Exception.Message }
            }
            [pscustomobject]@{
                Name = $site.GetAttribute('name')
                Home = $ftpHome
                ControlTls = $(if ($null -ne $ssl) {
                    $ssl.GetAttribute('controlChannelPolicy')
                }
                else {
                    ''
                })
                DataTls = $(if ($null -ne $ssl) {
                    $ssl.GetAttribute('dataChannelPolicy')
                }
                else {
                    ''
                })
                Anonymous = $(if ($null -ne $anonymous) {
                    $anonymous.GetAttribute('enabled')
                }
                else {
                    ''
                })
                IpSecurity = $ip
            }
        }
    }
    finally { if ($null -ne $manager) { $manager.Dispose() } }
}

# W-16
function Test-WindowsW16 {
    $id = 'W-16'
    $shares = @(Get-AuditCimInstance -ClassName Win32_Share -Property @('Name', 'Path', 'Type'))
    # Type 0에는 사용자가 만든 숨김 공유도 포함한다. ADMIN$/C$는 별도 Type이다.
    $ordinary = @($shares | Where-Object {
        $_.Type -eq 0
    })
    if ($ordinary.Count -eq 0) {
        return New-AuditResult $id GOOD '일반 Disk 공유 없음' ($shares | Select-Object Name, Type)
    }
    $bad = @()
    $evidence = @()
    $errors = @()
    if (-not (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue)) {
        return New-AuditResult $id MANUAL '공유 목록 확보; Share ACL API 확인 필요' $ordinary 'Get-SmbShareAccess 또는 Win32_LogicalShareSecuritySetting 확인'
    }
    foreach ($share in $ordinary) {
        try {
            $aces = @(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop)
        }
        catch {
            $errors += @{ Share=$share.Name; Error=$_.Exception.Message }
            continue
        }
        foreach ($ace in $aces) {
            try {
                $account = New-Object Security.Principal.NTAccount($ace.AccountName)
                $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
                $row = @{
                    Share = $share.Name
                    Path = $share.Path
                    Sid = $sid
                    Type = [string]$ace.AccessControlType
                    Right = [string]$ace.AccessRight
                }
                $evidence += $row
                if ($sid -eq 'S-1-1-0' -and $ace.AccessControlType -eq 'Allow') {
                    $bad += $row
                }
            }
            catch { $errors += @{ Share=$share.Name; Account=$ace.AccountName; Error=$_.Exception.Message } }
        }
    }
    $result = @{ Values=$evidence; Failed=$bad; QueryErrors=$errors }
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE '일반 공유의 Everyone Allow 권한 발견' $result
    }
    if ($errors.Count) {
        return New-AuditResult $id ERROR '일부 공유 ACL 조회 실패; 수집한 근거 보존' $result '실패한 공유·계정 변환 확인' 'SHARE_ACL_FAILED'
    }
    return New-AuditResult $id GOOD '일반 공유 ACL에서 Everyone Allow 미발견' $evidence
}

# W-17
function Test-WindowsW17 {
    $id = 'W-17'
    $shares = @(Get-AuditCimInstance -ClassName Win32_Share -Property @('Name', 'Type'))
    $default = @($shares | Where-Object {
        $_.Name -match '^[A-Z]\$$|^ADMIN\$$'
    })
    $setting = Get-RegistrySetting $script:RegistryPaths.LanmanServer 'AutoShareServer'
    if ($default.Count) {
        return New-AuditResult $id VULNERABLE '기본 관리 공유 존재' ($default | Select-Object Name) 'Backup·관리 기능 영향 및 승인 예외 확인'
    }
    if ($setting.State -eq 'OK' -and [string]$setting.Value -eq '0') {
        return New-AuditResult $id GOOD '기본 공유 없음 및 자동 생성 비활성 확인' 'AutoShareServer=0'
    }
    return New-AuditResult $id MANUAL '현재 기본 공유 없음; 재생성 정책 확인 필요' $setting 'AutoShareServer·Server 역할·재부팅 시 생성 여부 확인'
}

# W-18
function Test-WindowsW18 {
    $id = 'W-18'
    $services = @(Get-ServiceSnapshot)
    if ($script:Config.UnnecessaryServices.Count -eq 0) {
        return New-AuditResult $id MANUAL '업무상 불필요한 서비스 목록 필요' ($services | Where-Object State -eq 'Running' | Select-Object Name, State, StartMode) '가이드의 예시 서비스도 업무에 필요할 수 있음. UnnecessaryServices에 실제 Service Name 지정'
    }
    $bad = @($services | Where-Object {
        $_.Name -in $script:Config.UnnecessaryServices -and $_.State -eq 'Running'
    })
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE '불필요하다고 지정한 서비스 실행 중' $bad
    }
    $unknown = @($services | Where-Object {
        $_.Name -in $script:Config.UnnecessaryServices -and $_.State -ne 'Stopped'
    })
    if ($unknown.Count) {
        return New-AuditResult $id MANUAL '불필요 서비스의 일시 중지/전환 상태 확인 필요' $unknown 'Stopped 상태 또는 실제 제거 여부 재확인'
    }
    return New-AuditResult $id GOOD '지정한 불필요 서비스의 실행 미발견' $script:Config.UnnecessaryServices
}

# W-19
function Test-WindowsW19 {
    $id = 'W-19'
    $inactive = Get-InactiveServiceResult $id 'W3SVC'
    if ($null -ne $inactive) {
        return $inactive
    }
    if ('W3SVC' -in $script:Config.RequiredServices) {
        return New-AuditResult $id GOOD 'IIS 실행 및 사용자 지정 업무 필요성 확인' 'W3SVC=RUNNING; RequiredServices에 포함' '업무 승인 근거는 운영자가 보관'
    }
    return New-AuditResult $id MANUAL 'IIS 실행 중; 업무상 필요성 확인 필요' 'W3SVC=RUNNING' '실행 중이라는 이유만으로 불필요/취약 단정하지 않음'
}

# W-20
function Test-WindowsW20 {
    $id = 'W-20'
    $adapters = @(Get-AuditCimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -Property @('Description', 'TcpipNetbiosOptions'))
    if ($adapters.Count -eq 0) {
        return New-AuditResult $id MANUAL 'IP 활성 Adapter 범위 미확정' '' '가상·비활성 Adapter와 실제 연결 확인'
    }
    $bad = @($adapters | Where-Object TcpipNetbiosOptions -eq 1)
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE 'NetBIOS 명시적 활성 Adapter' ($bad | Select-Object Description, TcpipNetbiosOptions)
    }
    if (@($adapters | Where-Object TcpipNetbiosOptions -ne 2).Count) {
        return New-AuditResult $id MANUAL 'DHCP/기본값에 의존하는 NetBIOS 설정' ($adapters | Select-Object Description, TcpipNetbiosOptions) 'DHCP Option과 실제 NetBIOS 바인딩 확인'
    }
    return New-AuditResult $id GOOD '모든 IP 활성 Adapter에서 NetBIOS 비활성' ($adapters | Select-Object Description, TcpipNetbiosOptions)
}

# W-23
function Test-WindowsW23 {
    $id = 'W-23'
    $ftpState = Get-ServiceState 'FTPSVC'
    if ($ftpState -eq 'UNKNOWN') {
        throw 'FTP 서비스 상태 미확정'
    }
    $evidence = @{
        FtpState=$ftpState
    }
    if ($ftpState -eq 'RUNNING') {
        $sites = @(Get-FtpConfiguration)
        $evidence.FtpSites = @($sites | Select-Object Name, Anonymous)
        if (@($sites | Where-Object Anonymous -eq 'true').Count) {
            return New-AuditResult $id VULNERABLE 'IIS FTP 익명 인증 활성 설정' $evidence
        }
    }
    $serverState = Get-ServiceState 'LanmanServer'
    if ($serverState -eq 'UNKNOWN') {
        throw 'SMB 서비스 상태 미확정'
    }
    $evidence.SmbState = $serverState
    if ($serverState -eq 'RUNNING') {
        $restrict = Get-RegistrySetting $script:RegistryPaths.LanmanServer 'RestrictNullSessAccess'
        $shares = Get-RegistrySetting $script:RegistryPaths.LanmanServer 'NullSessionShares'
        $pipes = Get-RegistrySetting $script:RegistryPaths.LanmanServer 'NullSessionPipes'
        $evidence.SmbAnonymous = @{
            Restrict=$restrict
            Shares=$shares
            Pipes=$pipes
        }
        if ($restrict.State -eq 'OK' -and [int]$restrict.Value -eq 0) {
            return New-AuditResult $id VULNERABLE 'SMB 익명 Session 제한 해제' $evidence
        }
    }
    return New-AuditResult $id MANUAL 'FTP/SMB 익명 접근 설정 수집; 공유 서비스 전체 범위 확인 필요' $evidence 'Null Session 허용 대상·Share ACL·NFS/TFTP/추가 Provider·FTP 유효 상속을 확인. FTP 미사용만으로 전체 양호 처리 안 함'
}

function Invoke-FtpAuditCheck {
    param([string]$Id)
    $inactive = Get-InactiveFtpResult $id
    if ($null -ne $inactive) {
        return $inactive
    }
    $sites = @(Get-FtpConfiguration -IncludeIpSecurity:($id -eq 'W-24'))
    if ($sites.Count -eq 0) {
        return New-AuditResult $id MANUAL 'FTP 서비스 실행 중이나 IIS FTP Site를 확인하지 못함' '' '다른 Provider·Config Redirection·Site Scope 확인'
    }
    if ($id -eq 'W-21') {
        $bad = @($sites | Where-Object {
            $_.ControlTls -eq 'SslAllow' -or $_.ControlTls -eq 'SslDeny' -or $_.DataTls -eq 'SslAllow' -or $_.DataTls -eq 'SslDeny'
        })
        if ($bad.Count) {
            return New-AuditResult $id VULNERABLE '평문 허용/SSL 거부 FTP Channel 설정' ($bad | Select-Object Name, ControlTls, DataTls)
        }
        return New-AuditResult $id MANUAL 'FTP TLS 설정 확보; 유효 상속·추가 Provider 확인 필요' ($sites | Select-Object Name, ControlTls, DataTls) 'Site/Global/Location Override·추가 FTP Instance의 실제 적용 확인'
    }
    if ($id -eq 'W-22') {
        $bad = @()
        $evidence = @()
        $errors = @()
        foreach ($site in $sites) {
            try {
                if (-not $site.Home) {
                    throw "FTP Home 경로 미확정: $($site.Name)"
                }
                $aces = @(Get-AllowAceSnapshot $site.Home)
                $evidence += @{
                    Site = $site.Name
                    Path = $site.Home
                    Aces = $aces
                }
                if (@($aces | Where-Object Sid -eq 'S-1-1-0').Count) {
                    $bad += $site.Home
                }
            }
            catch { $errors += @{ Site=$site.Name; Path=$site.Home; Error=$_.Exception.Message } }
        }
        $result = @{ Values=$evidence; Failed=$bad; QueryErrors=$errors }
        if ($bad.Count) {
            return New-AuditResult $id VULNERABLE 'FTP Home의 Everyone Allow 발견' $result
        }
        if ($errors.Count) {
            return New-AuditResult $id ERROR '일부 FTP Home ACL 조회 실패; 수집한 근거 보존' $result '실패한 사이트 경로·권한 확인' 'FTP_ACL_FAILED'
        }
        return New-AuditResult $id MANUAL '확인한 FTP Home ACL에서 Everyone Allow 미발견' $evidence '가상 디렉터리·사용자 격리·Share ACL·상속 Scope 추가 확인'
    }
    $evidence = @($sites | Select-Object Name, IpSecurity)
    $bad = @($sites | Where-Object {
        -not $_.IpSecurity.Error -and $_.IpSecurity.AllowUnlisted -eq $true -and $_.IpSecurity.Rules.Count -eq 0
    } | Select-Object -ExpandProperty Name)
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE 'FTP IP 제한 없이 미등록 Source 허용' @{ Values=$evidence; Failed=$bad }
    }
    return New-AuditResult $id MANUAL 'FTP 사이트별 유효 IP 제한·허용 기본값 수집' $evidence '허용 주소의 업무 승인·하위 URL별 정책·다른 Provider 확인; 조회 실패는 Error에 기록'
}

# W-21
function Test-WindowsW21 {
    return Invoke-FtpAuditCheck -Id 'W-21'
}

# W-22
function Test-WindowsW22 {
    return Invoke-FtpAuditCheck -Id 'W-22'
}

# W-24
function Test-WindowsW24 {
    return Invoke-FtpAuditCheck -Id 'W-24'
}

function Invoke-DnsAuditCheck {
    param([string]$Id)
    $inactive = Get-InactiveServiceResult $id 'DNS'
    if ($null -ne $inactive) {
        return $inactive
    }
    if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) {
        return New-AuditResult $id MANUAL 'DNS 실행 중; DNS Server 조회 Cmdlet 미제공' 'DNS=RUNNING' 'DNS 관리 API로 Zone·Transfer·Dynamic Update 유효 정책 확인'
    }
    $zones = @(Get-DnsServerZone -ErrorAction Stop |
        Select-Object ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate, SecureSecondaries, SecondaryServers)
    if ($id -eq 'W-25') {
        $authoritative = @($zones | Where-Object { [string]$_.ZoneType -in @('Primary','Secondary','1','2') })
        $bad = @($authoritative | Where-Object { [string]$_.SecureSecondaries -in @('TransferAnyServer','NoSecurity','0') })
        if ($bad.Count) {
            return New-AuditResult $id VULNERABLE '모든 서버에 DNS 영역 전송 허용' @{ Zones=$zones; Failed=@($bad.ZoneName) }
        }
        $restricted = @($authoritative | Where-Object { [string]$_.SecureSecondaries -notin @('NoTransfer','3') })
        if ($authoritative.Count -gt 0 -and $restricted.Count -eq 0) {
            return New-AuditResult $id GOOD '조회한 권한 있는 DNS 영역에서 전송 차단' $zones
        }
        return New-AuditResult $id MANUAL 'DNS 영역별 전송 제한·대상 서버 수집' $zones '제한된 Secondary/NS 서버의 승인 여부 또는 미제공 전송 값을 확인'
    }
    if ($id -eq 'W-32') {
        $bad = @($zones | Where-Object {
            $null -ne $_.DynamicUpdate -and [string]$_.DynamicUpdate -notin @('None','0')
        })
        if ($bad.Count) {
            return New-AuditResult $id VULNERABLE 'DNS 동적 Update 활성 Zone' $bad 'AD 통합 DNS의 필요성과 가이드 기준 차이·승인 예외 검토'
        }
    }
    return New-AuditResult $id MANUAL 'DNS Zone 목록 확보; Zone별 유효 접근 정책 확인 필요' $zones 'Transfer 미사용/승인 Secondary 및 모든 Zone의 Dynamic Update 실제 적용 확인'
}

# W-25
function Test-WindowsW25 {
    return Invoke-DnsAuditCheck -Id 'W-25'
}

# W-32
function Test-WindowsW32 {
    return Invoke-DnsAuditCheck -Id 'W-32'
}

# W-26
function Test-WindowsW26 {
    $id = 'W-26'
    if ([version]$script:Os.Version -ge [version]'6.0') {
        return New-AuditResult $id GOOD '가이드의 Windows Server 2008 이상 예외에 해당' "OSVersion=$($script:Os.Version)"
    }
    return New-AuditResult $id MANUAL '구형 OS의 IIS RDS/MSADC 경로 확인 필요' $script:Os.Version '가이드 Patch·가상 디렉터리·Registry 조건 전체 확인'
}

# W-27
function Test-WindowsW27 {
    $id = 'W-27'
    return New-AuditResult $id MANUAL 'OS Build 수집; 최신 지원 Build·적용 절차 대조 필요' ($script:Os | Select-Object Caption, Version, BuildNumber) 'Vendor Release/지원 종료·배포 채널·Backport·적용 기록 확인'
}

# W-28
function Test-WindowsW28 {
    $id = 'W-28'
    $deny = Get-RegistrySetting 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($deny.State -eq 'OK' -and [string]$deny.Value -eq '1') {
        return New-AuditResult $id GOOD 'RDP 연결 비활성 설정' 'fDenyTSConnections=1'
    }
    $setting = Get-RegistrySetting $script:RegistryPaths.TerminalPolicy 'MinEncryptionLevel'
    if ($setting.State -eq 'MISSING') {
        $setting = Get-RegistrySetting 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel'
    }
    if ($deny.State -ne 'OK' -or $setting.State -ne 'OK') {
        return New-AuditResult $id MANUAL 'RDP 사용/암호화 유효값 미확정' @{
            Enabled = $deny
            Encryption = $setting
        } '정책 상속·RDP Listener와 TLS 설정 확인'
    }
    if ([int]$setting.Value -ge 2 -and [int]$setting.Value -le 4) {
        return New-AuditResult $id GOOD 'RDP 암호화 수준 중간 이상' "MinEncryptionLevel=$($setting.Value)"
    }
    return New-AuditResult $id VULNERABLE 'RDP 암호화 수준 기준 미충족' "MinEncryptionLevel=$($setting.Value)"
}

function Invoke-SnmpAuditCheck {
    param([string]$Id)
    $inactive = Get-InactiveServiceResult $id 'SNMP'
    if ($null -ne $inactive) {
        return $inactive
    }
    if ($id -eq 'W-31') {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers'
        if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
            return New-AuditResult $id VULNERABLE 'SNMP 허용 Manager 목록 없음' $path
        }
        $key = Get-Item -LiteralPath $path -ErrorAction Stop
        $values = @($key.GetValueNames() | ForEach-Object {
            $key.GetValue($_)
        } | Where-Object {
            $_
        })
        if ($values.Count -eq 0 -or '*' -in $values -or '0.0.0.0' -in $values) {
            return New-AuditResult $id VULNERABLE 'SNMP Source 제한 미흡' $values
        }
        return New-AuditResult $id MANUAL 'SNMP 허용 Manager 설정 확보' $values '실제 모든 Host 허용 옵션·적용 ACL·승인 Manager 범위 확인'
    }
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
        return New-AuditResult $id MANUAL 'SNMP Community 정책 미확정' '원문 Community는 수집 결과에 포함하지 않음' 'Provider·실제 인증·기본값 확인'
    }
    $key = Get-Item -LiteralPath $path -ErrorAction Stop
    $communities = @($key.GetValueNames())
    $defaultFound = @($communities | Where-Object {
        $_ -in @('public','private')
    }).Count -gt 0
    $index = 0
    $properties = @(
        foreach ($community in $communities) {
            $index++
            $letter = $community -cmatch '[A-Za-z]'
            $digit = $community -match '[0-9]'
            $special = $community -match '[^A-Za-z0-9]'
            $minimum = if ($special) { 8 } else { 10 }
            @{
                Index=$index
                Length=$community.Length
                HasLetter=$letter
                HasDigit=$digit
                HasSpecial=$special
                MinimumLength=$minimum
                Weak=($community -in @('public','private') -or -not $letter -or -not $digit -or $community.Length -lt $minimum)
            }
        }
    )
    $evidence = @{
        CommunityCount = $communities.Count
        DefaultCommunityFound = $defaultFound
        CommunityValues = '[xxx]'
        Properties = $properties
        Criterion = '영문+숫자 필수; 특수문자 포함 8자 이상, 미포함 10자 이상; public/private 제외'
    }
    $community = $null
    $communities = @()
    if ($id -eq 'W-30') {
        if (@($properties | Where-Object { $_.Weak }).Count) {
            return New-AuditResult $id VULNERABLE 'SNMP Community 복잡성 기준 미충족' $evidence
        }
        if ($properties.Count -gt 0) {
            return New-AuditResult $id GOOD 'SNMP Community 길이·문자 조합 기준 충족' $evidence
        }
        return New-AuditResult $id MANUAL 'SNMP 인증 설정 범위 확인 필요' $evidence '실제 Provider/다른 Config 확인'
    }
    if ('SNMP' -in $script:Config.RequiredServices -and $properties.Count -gt 0) {
        return New-AuditResult $id GOOD '입력한 SNMP 업무 필요성과 Community 설정 확인' $evidence
    }
    return New-AuditResult $id MANUAL 'SNMP 실행 중; 업무 필요성 확인 필요' $evidence '필요성·승인 근거·서비스 중지 영향 확인'
}

# W-29
function Test-WindowsW29 {
    return Invoke-SnmpAuditCheck -Id 'W-29'
}

# W-30
function Test-WindowsW30 {
    return Invoke-SnmpAuditCheck -Id 'W-30'
}

# W-31
function Test-WindowsW31 {
    return Invoke-SnmpAuditCheck -Id 'W-31'
}

# W-33
function Test-WindowsW33 {
    $id = 'W-33'
    $services = @(Get-ServiceSnapshot | Where-Object {
        $_.Name -in @('W3SVC','FTPSVC','SMTPSVC')
    } | Select-Object Name, State)
    if (@($services | Where-Object State -eq 'Running').Count -eq 0) {
        return New-AuditResult $id MANUAL '기본 HTTP/FTP/SMTP 서비스에서 실행 중인 항목 미발견' $services '추가 Web/Mail Provider·독립 Process·Proxy의 사용 여부와 Banner 확인'
    }
    return New-AuditResult $id MANUAL '실행 중 Web/FTP/SMTP의 실제 Banner 확인 필요' $services 'Server Header·FTP/SMTP Greeting·Proxy·추가 Provider를 확인. 서비스 실행만으로 취약 단정 안 함'
}

# W-34
function Test-WindowsW34 {
    $id = 'W-34'
    $inactive = Get-InactiveServiceResult $id 'TlntSvr'
    if ($null -ne $inactive) {
        return $inactive
    }
    return Test-RegistryRule $id 'HKLM:\SOFTWARE\Microsoft\TelnetServer\1.0' 'NTLM' @('2')
}

# W-35
function Test-WindowsW35 {
    $id = 'W-35'
    $data = @()
    foreach ($path in @('HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\ODBC Data Sources')) {
        if (Test-Path -LiteralPath $path -ErrorAction Stop) {
            $key = Get-Item -LiteralPath $path
            $data += @{
                Path = $path
                DsnNames = @($key.GetValueNames())
            }
        }
    }
    return New-AuditResult $id MANUAL 'System DSN 이름 수집; 실제 사용 여부 확인 필요' $data 'Connection String·비밀번호 원문은 출력하지 않음. 32/64-bit DSN·OLE DB의 업무 사용 여부 검토'
}

# W-36
function Test-WindowsW36 {
    $id = 'W-36'
    $deny = Get-RegistrySetting 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($deny.State -eq 'OK' -and [string]$deny.Value -eq '1') {
        return New-AuditResult $id GOOD 'RDP 비활성 설정 확인' 'fDenyTSConnections=1'
    }
    $setting = Get-RegistrySetting $script:RegistryPaths.TerminalPolicy 'MaxIdleTime'
    if ($setting.State -ne 'OK') {
        return New-AuditResult $id MANUAL 'RDP Timeout 유효값 확인 필요' $setting '컴퓨터/사용자 GPO·Listener별 MaxIdleTime 확인'
    }
    if ([long]$setting.Value -gt 0 -and [long]$setting.Value -le 1800000) {
        return New-AuditResult $id GOOD 'RDP 유휴 제한 30분 이하' "MaxIdleTime=$($setting.Value) ms"
    }
    return New-AuditResult $id VULNERABLE 'RDP Timeout 비활성 또는 30분 초과' "MaxIdleTime=$($setting.Value) ms"
}

# W-37
function Test-WindowsW37 {
    $id = 'W-37'
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Select-Object TaskName, TaskPath, State, @{
            Name='RunAs'
            Expression={
                $_.Principal.UserId
            }
        }, @{
            Name='Actions'
            Expression={
                @($_.Actions | ForEach-Object {
                    if ($_.PSObject.Properties['Execute']) {
                        @{
                            Execute = Protect-AuditCommand $_.Execute
                            Arguments = Protect-AuditCommand $_.Arguments
                            WorkingDirectory = $_.WorkingDirectory
                        }
                    }
                    else {
                        '[COM/비실행파일 Action: 수동 확인]'
                    }
                })
            }
        })
    }
    else {
        $tasks = @(Get-AuditCimInstance -ClassName Win32_ScheduledJob -Property @('JobId','Owner','StartTime','Command') |
            Select-Object JobId, Owner, StartTime, @{ Name='Command'; Expression={ Protect-AuditCommand $_.Command } })
    }
    return New-AuditResult $id MANUAL '예약 작업 실행파일·인수·작업 경로 수집' $tasks '정기 검토 기록·업무 필요성·서명/소유권 확인. 인식한 민감 인수만 마스킹; 구형 API는 AT 작업만 조회'
}

#endregion

#region patches

# Windows patches

# W-38
function Test-WindowsW38 {
    $id = 'W-38'
    $patches = @(Get-AuditCimInstance -ClassName Win32_QuickFixEngineering -Property @('HotFixID','InstalledOn','Description') | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, InstalledOn, Description)
    return New-AuditResult $id MANUAL '설치 Patch 식별 정보 수집; 절차·최신성 확인 필요' $patches 'Vendor 권고·EOL·적용 승인/예외/실패 기록과 대조. Patch 목록이 있다는 이유로 GOOD 처리 안 함'
}

function Invoke-AntivirusAuditCheck {
    param([string]$Id)
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $evidence = $mp | Select-Object AMServiceEnabled, AntivirusEnabled, AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, AntivirusSignatureLastUpdated
            if ($id -eq 'W-45') {
                return New-AuditResult $id GOOD 'Defender 설치 API 응답 확인' $evidence '설치와 활성/업데이트 상태는 구분하며 W-39에서 추가 검토'
            }
            return New-AuditResult $id MANUAL 'Defender 엔진·Signature 정보 확보' $evidence 'Vendor 최신 배포·망 격리 갱신 절차·실제 최신 여부 확인'
        }
        catch {
            Write-Verbose 'Defender 조회 실패: 다른 제품 증거 조회를 시도합니다.'
        }
    }
    try {
        $products = @(Get-AuditCimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -Property @('displayName','productState','timestamp') | Select-Object displayName, productState, timestamp)
        if ($products.Count -gt 0) {
            if ($id -eq 'W-45') {
                return New-AuditResult $id GOOD '등록된 Antivirus 제품 확인' $products
            }
            return New-AuditResult $id MANUAL 'Antivirus 제품 등록 정보 확보' $products '제품별 실제 엔진·Signature 갱신과 정책 확인'
        }
    }
    catch {
        Write-Verbose 'SecurityCenter2 미제공/조회 실패. 미설치로 단정하지 않습니다.'
    }
    return New-AuditResult $id MANUAL '백신 설치/업데이트를 조회 가능한 API에서 확정하지 못함' 'Windows Server는 SecurityCenter2가 없을 수 있음' '실제 제품 Console·Service·설치 기록·보안 Agent 확인'
}

# W-39
function Test-WindowsW39 {
    return Invoke-AntivirusAuditCheck -Id 'W-39'
}

#endregion

#region logging

# Windows logging

# W-40
function Test-WindowsW40 {
    $id = 'W-40'
    # 가이드의 기본 감사 범주는 언어와 무관한 secedit Key로 대조한다.
    # 고급 감사 우선 적용 시 기본 정책 수치만으로 유효 정책을 단정하지 않는다.
    $legacy = Get-SecurityPolicy
    $legacyRules = @{
        AuditAccountManage=2
        AuditAccountLogon=3
        AuditPrivilegeUse=3
        AuditDSAccess=2
        AuditLogonEvents=3
        AuditPolicyChange=3
    }
    $legacyValues = @{}
    $legacyBad = @()
    $legacyMissing = @()
    foreach ($name in $legacyRules.Keys) {
        if ($name -eq 'AuditDSAccess' -and [int]$script:Computer.DomainRole -lt 4) {
            continue
        }
        if (-not $legacy.ContainsKey($name)) {
            $legacyMissing += $name
            continue
        }
        $mask = 0
        if (-not [int]::TryParse($legacy[$name], [ref]$mask)) {
            throw "감사 정책 Mask Parsing 실패: $name"
        }
        $legacyValues[$name] = $mask
        if (($mask -band $legacyRules[$name]) -ne $legacyRules[$name]) {
            $legacyBad += $name
        }
    }
    $override = Get-RegistrySetting 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
    if ($override.State -eq 'OK' -and [int]$override.Value -eq 0 -and $script:Config.RequiredAuditSettings.Count -eq 0) {
        if ($legacyBad.Count) {
            return New-AuditResult $id VULNERABLE '기본 감사 정책의 가이드 권고 Mask 미충족' @{
                Values=$legacyValues
                Failed=$legacyBad
                Missing=$legacyMissing
            }
        }
        if ($legacyMissing.Count -eq 0) {
            return New-AuditResult $id GOOD '기본 감사 정책의 가이드 권고 Mask 충족' $legacyValues '디렉터리 서비스 액세스 범주는 DC에서 검사'
        }
    }
    $path = Join-Path $script:WorkDirectory 'audit-policy.csv'
    $native = Invoke-AuditNativeCommand 'auditpol.exe' @('/backup', "/file:$path")
    if ($native.Code -ne 0 -or -not [IO.File]::Exists($path)) {
        throw "auditpol backup 조회 실패: code=$($native.Code)"
    }
    $rows = @([IO.File]::ReadAllLines($path) | ConvertFrom-Csv)
    $settings = @{}
    foreach ($row in $rows) {
        $values = @($row.PSObject.Properties | ForEach-Object {
            [string]$_.Value
        })
        $guidValue = @($values | Where-Object {
            $_ -match '^\{?[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}?$'
        })
        $numeric = 0
        if ($guidValue.Count -eq 1 -and [int]::TryParse($values[-1], [ref]$numeric) -and $numeric -ge 0 -and $numeric -le 3) {
            $settings[([guid]$guidValue[0]).ToString()] = $numeric
        }
    }
    if ($script:Config.RequiredAuditSettings.Count -eq 0 -or $settings.Count -eq 0) {
        return New-AuditResult $id MANUAL '감사 정책 Snapshot 확보; 유효 정책과 권고 범주 대응 필요' @{
            Basic=$legacyValues
            AdvancedOverride=$override
            NumericSubcategories=$settings
            CsvRows=$rows.Count
        } '고급 감사 우선 적용 여부와 RequiredAuditSettings의 승인 GUID=Mask 확인. 언어별 표시 이름으로 비교하지 않음'
    }
    $bad = @()
    $missing = @()
    foreach ($key in $script:Config.RequiredAuditSettings.Keys) {
        $guid = ([guid]$key).ToString()
        $required = [int]$script:Config.RequiredAuditSettings[$key]
        if (-not $settings.ContainsKey($guid)) {
            $missing += $guid
            continue
        }
        if (($settings[$guid] -band $required) -ne $required) {
            $bad += @{
                Guid=$guid
                Actual=$settings[$guid]
                Required=$required
            }
        }
    }
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE '입력한 감사 정책 Mask 미충족' $bad
    }
    return New-AuditResult $id MANUAL '입력한 감사 Subcategory 수집·비교 완료' @{
        Actual=$settings
        Missing=$missing
    } '조직 정책과 가이드 권고 영역 전체가 입력됐는지 검토; 선택한 일부 규칙으로 전체 GOOD 단정 안 함'
}

# W-41
function Test-WindowsW41 {
    $id = 'W-41'
    $state = Get-ServiceState 'W32Time'
    $parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    $type = Get-RegistrySetting $parameters 'Type'
    $peers = Get-RegistrySetting $parameters 'NtpServer'
    $native = Invoke-AuditNativeCommand 'w32tm.exe' @('/query','/status')
    if ($type.State -eq 'OK' -and [string]$type.Value -eq 'NTP' -and $peers.State -eq 'OK' -and $script:Config.ApprovedTimeSources.Count -gt 0) {
        $configured = @(([string]$peers.Value -split '\s+') | Where-Object {
            $_
        } | ForEach-Object {
            ($_ -split ',')[0]
        })
        $unexpected = @($configured | Where-Object {
            $_ -notin $script:Config.ApprovedTimeSources
        })
        if ($unexpected.Count) {
            return New-AuditResult $id VULNERABLE 'NTP 설정에 승인 목록 밖의 시간 Source 포함' @{
                Configured=$configured
                Unexpected=$unexpected
            } '승인 목록이 완전한지와 실제 동기화 Source 확인'
        }
    }
    return New-AuditResult $id MANUAL '시간 서비스 설정·동기화 상태 증거 수집' @{
        State=$state
        Type=$type
        Peers=$peers
        QueryCode=$native.Code
        Runtime=$native.Stdout
        ApprovedSources=$script:Config.ApprovedTimeSources
    } '실제 승인 Source·마지막 성공·시간 오차·Domain 계층을 확인. 지역화된 상태 문구만으로 동기화 단정 안 함'
}

# W-42
function Test-WindowsW42 {
    $id = 'W-42'
    $records = @()
    $bad = @()
    $unconfirmed = @()
    $errors = @()
    foreach ($name in @('Application','Security','System')) {
        try {
            $log = Get-WinEvent -ListLog $name -ErrorAction Stop
            $record = @{
                Name=$name
                MaxBytes=$log.MaximumSizeInBytes
                Mode=[string]$log.LogMode
                Retention=$null
            }
            $records += $record
            if ($log.MaximumSizeInBytes -lt 10485760) {
                $bad += "$name capacity<10240KB"
            }
            $retention = Get-RegistrySetting "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$name" 'Retention'
            $record.Retention = $retention
            if ([string]$log.LogMode -eq 'Circular') {
                if ($retention.State -eq 'OK' -and [long]$retention.Value -ge 7776000) {
                    $unconfirmed += "$name legacy retention: 실제 현대 OS 동작 확인"
                }
                else {
                    $bad += "${name}: 90일 보존 미확보"
                }
            }
            elseif ([string]$log.LogMode -ne 'Retain') {
                $unconfirmed += "$name archive 보관 정책"
            }
        }
        catch { $errors += @{ Name=$name; Error=$_.Exception.Message } }
    }
    $result = @{ Values=$records; Failed=$bad; QueryErrors=$errors }
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE 'Event Log 용량·보존 설정 기준 미충족' $result '현대 Event Log의 보존/Archive 정책과 업무 영향 확인'
    }
    if ($errors.Count) {
        return New-AuditResult $id ERROR '일부 Event Log 조회 실패; 수집한 근거 보존' $result '실패한 Log와 조회 권한 확인' 'EVENT_LOG_FAILED'
    }
    if ($unconfirmed.Count) {
        return New-AuditResult $id MANUAL '용량 조건 확보; 실제 90일 보존 정책 확인 필요' $records ($unconfirmed -join '; ')
    }
    return New-AuditResult $id GOOD '용량 10240KB 이상·자동 덮어쓰기 금지 확인' $records 'Log Full 시 운영 대응·Archive 보존도 별도 검토'
}

# W-43
function Test-WindowsW43 {
    $id = 'W-43'
    $path = Join-Path $script:Os.WindowsDirectory 'System32\winevt\Logs'
    $aces = @(Get-AllowAceSnapshot $path)
    if (@($aces | Where-Object Sid -eq 'S-1-1-0').Count) {
        return New-AuditResult $id VULNERABLE 'Event Log 폴더 Everyone Allow 발견' @{
            Path=$path
            Aces=$aces
        }
    }
    return New-AuditResult $id MANUAL '기본 Event Log 폴더에서 Everyone Allow 미발견' @{
        Path=$path
        Aces=$aces
    } '개별 Log 파일과 변경된 Event Log 경로의 ACL 확인'
}

#endregion

#region security

# Windows security

# W-45
function Test-WindowsW45 {
    return Invoke-AntivirusAuditCheck -Id 'W-45'
}

# W-44
function Test-WindowsW44 {
    $id = 'W-44'
    $inactive = Get-InactiveServiceResult $id 'RemoteRegistry'
    if ($null -ne $inactive) {
        return $inactive
    }
    return New-AuditResult $id VULNERABLE 'Remote Registry 서비스 실행 중' 'RemoteRegistry=RUNNING' '원격 관리 필요성과 승인 예외 확인'
}

# W-46
function Test-WindowsW46 {
    $id = 'W-46'
    $path = Join-Path $script:Os.SystemDirectory 'config\SAM'
    $aces = @(Get-AllowAceSnapshot $path)
    $bad = @($aces | Where-Object {
        $_.Sid -notin @('S-1-5-18','S-1-5-32-544')
    })
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE 'SAM에 Administrators/SYSTEM 외 Allow 권한' @{
            Path=$path
            Aces=$bad
        }
    }
    return New-AuditResult $id GOOD 'SAM의 Allow 대상이 Administrators/SYSTEM으로 제한' @{
        Path=$path
        Aces=$aces
    } 'SAM 내용·Hash는 읽지 않음'
}

# W-47
function Test-WindowsW47 {
    $id = 'W-47'
    $profiles = @(Get-AuditCimInstance -ClassName Win32_UserProfile -Filter 'Special=False' -Property @('SID','LocalPath','Loaded'))
    $records = @()
    $bad = @()
    foreach ($profile in $profiles) {
        if (-not $profile.Loaded) {
            continue
        }
        $base = "Registry::HKEY_USERS\$($profile.SID)"
        $values = @{}
        foreach ($name in @('ScreenSaveActive','ScreenSaveTimeOut','ScreenSaverIsSecure')) {
            $setting = Get-RegistrySetting "$base\Software\Policies\Microsoft\Windows\Control Panel\Desktop" $name
            if ($setting.State -eq 'MISSING') {
                $setting = Get-RegistrySetting "$base\Control Panel\Desktop" $name
            }
            $values[$name] = $setting
        }
        $records += @{
            Sid=$profile.SID
            Settings=$values
        }
        if ($values.ScreenSaveActive.State -eq 'OK' -and [string]$values.ScreenSaveActive.Value -eq '0') {
            $bad += $profile.SID
        }
        if ($values.ScreenSaverIsSecure.State -eq 'OK' -and [string]$values.ScreenSaverIsSecure.Value -eq '0') {
            $bad += $profile.SID
        }
        if ($values.ScreenSaveTimeOut.State -eq 'OK') {
            $seconds = 0
            if (-not [int]::TryParse([string]$values.ScreenSaveTimeOut.Value,[ref]$seconds)) {
                throw '화면 보호기 Timeout Parsing 실패'
            }
            if ($seconds -le 0 -or $seconds -gt 600) {
                $bad += $profile.SID
            }
        }
    }
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE '로드된 사용자 Profile의 화면 잠금 기준 미충족' @{
            FailedSids=$bad
            Values=$records
        }
    }
    return New-AuditResult $id MANUAL '로드된 Profile의 화면 보호기 설정 수집' $records '미로드 Profile·Domain GPO·모든 사용자·화면 잠금 실효성 확인; Hive 강제 Load 안 함'
}

# W-48
function Test-WindowsW48 {
    $id = 'W-48'
    return Test-RegistryRule $id $script:RegistryPaths.SystemPolicy 'ShutdownWithoutLogon' @('0')
}

# W-49
function Test-WindowsW49 {
    $id = 'W-49'
    $policy = Get-SecurityPolicy
    if (-not $policy.ContainsKey('SeRemoteShutdownPrivilege')) {
        return New-AuditResult $id MANUAL '원격 종료 권한 값 미확정' '' '유효 사용자 권한 할당 확인'
    }
    $sids = @($policy.SeRemoteShutdownPrivilege -split ',' | ForEach-Object {
        $_.Trim().TrimStart('*')
    } | Where-Object {
        $_
    })
    $bad = @($sids | Where-Object {
        $_ -ne 'S-1-5-32-544'
    })
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE 'Administrators 외 원격 종료 권한' $sids
    }
    if ($sids.Count -eq 1) {
        return New-AuditResult $id GOOD '원격 종료 권한이 Administrators만 포함' $sids
    }
    return New-AuditResult $id MANUAL '명시적 원격 종료 권한 대상 없음' $sids '빈 정책의 실제 효과·Domain/GPO 적용 확인'
}

# W-50
function Test-WindowsW50 {
    $id = 'W-50'
    return Test-RegistryRule $id $script:RegistryPaths.Lsa 'CrashOnAuditFail' @('0')
}

# W-51
function Test-WindowsW51 {
    $id = 'W-51'
    return Test-RegistryRule $id $script:RegistryPaths.Lsa 'RestrictAnonymous' @('1','2')
}

# W-52
function Test-WindowsW52 {
    $id = 'W-52'
    $setting = Get-RegistrySetting 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
    if ($setting.State -eq 'MISSING' -or [string]$setting.Value -eq '0') {
        return New-AuditResult $id GOOD 'AutoAdminLogon 없음 또는 0' $setting
    }
    if ([string]$setting.Value -eq '1') {
        return New-AuditResult $id VULNERABLE '자동 로그인 활성' 'AutoAdminLogon=1; DefaultPassword 원문은 조회하지 않음'
    }
    return New-AuditResult $id MANUAL 'AutoAdminLogon 비표준 값' $setting 'Credential Provider·별도 자동 로그인 방식 확인'
}

# W-53
function Test-WindowsW53 {
    $id = 'W-53'
    return Test-RegistryRule $id 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AllocateDASD' @('0')
}

# W-54
function Test-WindowsW54 {
    $id = 'W-54'
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $rules = @{
        SynAttackProtect=@(1,2)
        EnableDeadGWDetect=@(0)
        KeepAliveTime=@(300000)
        NoNameReleaseOnDemand=@(1)
    }
    $values = @{}
    $bad = @()
    $missing = @()
    foreach ($name in $rules.Keys) {
        $setting = Get-RegistrySetting $base $name
        $values[$name] = $setting
        if ($setting.State -ne 'OK') {
            $missing += $name
            continue
        }
        if ([long]$setting.Value -notin $rules[$name]) {
            $bad += $name
        }
    }
    return New-AuditResult $id MANUAL '가이드 DoS Registry 수치 수집; 해당 OS에서의 유효성 확인 필요' @{
        Values=$values
        Mismatched=$bad
        Missing=$missing
    } '현대 OS에서 폐기·대체된 옵션을 누락만으로 취약 단정하지 않음. Vendor 지원·Kernel 기본 보호와 대조; KeepAliveTime 기준은 정확히 300000ms'
}

# W-55
function Test-WindowsW55 {
    $id = 'W-55'
    return Test-RegistryRule $id 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers' @('1')
}

# W-56
function Test-WindowsW56 {
    $id = 'W-56'
    $force = Get-RegistrySetting $script:RegistryPaths.LanmanServer 'EnableForcedLogOff'
    $idle = Get-RegistrySetting $script:RegistryPaths.LanmanServer 'AutoDisconnect'
    if ($force.State -ne 'OK' -or $idle.State -ne 'OK') {
        return New-AuditResult $id MANUAL 'SMB 강제 종료·유휴 설정 유효값 미확정' @{
            Force=$force
            Idle=$idle
        } '유효 SMB Server 정책·GPO 확인'
    }
    if ([int]$force.Value -eq 1 -and [long]$idle.Value -ge 0 -and [long]$idle.Value -le 15) {
        return New-AuditResult $id GOOD 'SMB 만료 연결 종료·유휴 15분 이하' @{
            Force=$force
            IdleMinutes=$idle.Value
        }
    }
    return New-AuditResult $id VULNERABLE 'SMB Session 종료 기준 미충족' @{
        Force=$force
        IdleMinutes=$idle.Value
    }
}

# W-57
function Test-WindowsW57 {
    $id = 'W-57'
    $title = Get-RegistrySetting $script:RegistryPaths.SystemPolicy 'LegalNoticeCaption'
    $body = Get-RegistrySetting $script:RegistryPaths.SystemPolicy 'LegalNoticeText'
    if ($title.State -ne 'OK' -or $body.State -ne 'OK') {
        return New-AuditResult $id MANUAL '경고 제목·본문 유효값 미확정' @{
            Title=$title
            Body=$body
        } 'Local/Domain 정책 확인'
    }
    if ([string]::IsNullOrWhiteSpace([string]$title.Value) -or [string]::IsNullOrWhiteSpace([string]$body.Value)) {
        return New-AuditResult $id VULNERABLE '경고 제목 또는 본문 공란' @{
            Title=$title.Value
            Body=$body.Value
        }
    }
    foreach ($marker in $script:Config.BannerMarkers) {
        if (-not ([string]$body.Value).Contains($marker)) {
            return New-AuditResult $id VULNERABLE '입력한 승인 문구 문자열 미포함' @{
                Title=$title.Value
                Body=$body.Value
                MissingMarker=$marker
            }
        }
    }
    return New-AuditResult $id GOOD '경고 제목·본문 및 입력한 필수 문구 확인' @{
        Title=$title.Value
        Body=$body.Value
    }
}

# W-58
function Test-WindowsW58 {
    $id = 'W-58'
    $profiles = @(Get-AuditCimInstance -ClassName Win32_UserProfile -Filter 'Special=False' -Property @('SID','LocalPath'))
    if ($profiles.Count -eq 0) {
        return New-AuditResult $id MANUAL '검사할 사용자 Home 목록 미확정' '' 'Domain/Roaming·별도 Home 경로 확인'
    }
    $bad = @()
    $evidence = @()
    $errors = @()
    foreach ($profile in $profiles) {
        try {
            $aces = @(Get-AllowAceSnapshot $profile.LocalPath)
            $evidence += @{
                Sid=$profile.SID
                Path=$profile.LocalPath
                Aces=$aces
            }
            if (@($aces | Where-Object Sid -eq 'S-1-1-0').Count) {
                $bad += $profile.LocalPath
            }
        }
        catch { $errors += @{ Sid=$profile.SID; Path=$profile.LocalPath; Error=$_.Exception.Message } }
    }
    $result = @{ Values=$evidence; Failed=$bad; QueryErrors=$errors }
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE '사용자 Home에 Everyone Allow 발견' $result
    }
    if ($errors.Count) {
        return New-AuditResult $id ERROR '일부 Home ACL 조회 실패; 수집한 근거 보존' $result '실패한 Profile 경로·권한 확인' 'HOME_ACL_FAILED'
    }
    return New-AuditResult $id MANUAL '로컬 Profile Home에서 Everyone Allow 미발견' $evidence '별도 HomeDirectory·Roaming 경로와 개별 파일의 Explicit ACL까지 확인'
}

# W-59
function Test-WindowsW59 {
    $id = 'W-59'
    return Test-RegistryRule $id $script:RegistryPaths.Lsa 'LmCompatibilityLevel' @('3','4','5')
}

# W-60
function Test-WindowsW60 {
    $id = 'W-60'
    if (-not $script:Computer.PartOfDomain) {
        return New-AuditResult $id NOT_APPLICABLE 'Domain 비가입으로 Domain Member 보안 채널 항목 비해당' 'PartOfDomain=False'
    }
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $values = @{}
    $bad = @()
    $missing = @()
    foreach ($key in @('RequireSignOrSeal','SealSecureChannel','SignSecureChannel')) {
        $setting = Get-RegistrySetting $path $key
        $values[$key] = $setting
        if ($setting.State -ne 'OK') {
            $missing += $key
        }
        elseif ([int]$setting.Value -ne 1) {
            $bad += $key
        }
    }
    if ($bad.Count) {
        return New-AuditResult $id VULNERABLE 'Domain 채널 암호화/서명 정책 미충족' @{
            Values=$values
            Failed=$bad
        }
    }
    if ($missing.Count) {
        return New-AuditResult $id MANUAL 'Domain 채널 정책 일부 유효값 미확정' $values '적용 GPO·Vendor 기본값 확인'
    }
    return New-AuditResult $id GOOD 'Domain 채널 3개 정책 활성 확인' $values
}

# W-61
function Test-WindowsW61 {
    $id = 'W-61'
    $volumes = @(Get-AuditCimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -Property @('DeviceID','FileSystem') | Select-Object DeviceID, FileSystem)
    if ($volumes.Count -eq 0) {
        throw '고정 Disk 파일시스템 목록 미확정'
    }
    $fat = @($volumes | Where-Object {
        $_.FileSystem -match '^FAT|^exFAT$'
    })
    if ($fat.Count) {
        return New-AuditResult $id VULNERABLE 'FAT 계열 파일시스템 발견' $fat
    }
    if (@($volumes | Where-Object FileSystem -ne 'NTFS').Count) {
        return New-AuditResult $id MANUAL 'NTFS 외 파일시스템 발견' $volumes 'ReFS 등 ACL 지원·가이드 적용 해석 확인'
    }
    return New-AuditResult $id GOOD '확인한 고정 Disk는 NTFS' $volumes
}

# W-62
function Test-WindowsW62 {
    $id = 'W-62'
    $startup = @(Get-AuditCimInstance -ClassName Win32_StartupCommand -Property @('Name','Location','User','Command') |
        Select-Object Name, Location, User, @{ Name='Command'; Expression={ Protect-AuditCommand $_.Command } })
    return New-AuditResult $id MANUAL '시작 프로그램 이름·등록 위치·실행 사용자·명령 수집' $startup '정기 검토 기록·업무 필요성·파일 서명/소유권 확인. 인식한 민감 인수만 마스킹'
}

# W-63
function Test-WindowsW63 {
    $id = 'W-63'
    if (-not $script:Computer.PartOfDomain) {
        return New-AuditResult $id NOT_APPLICABLE 'Domain 비가입으로 Domain Kerberos 시간 정책 비해당' 'PartOfDomain=False'
    }
    return Test-SecurityPolicyRule $id 'MaxClockSkew' 1 5
}

# W-64
function Test-WindowsW64 {
    $id = 'W-64'
    if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        return New-AuditResult $id MANUAL '유효 Firewall Profile 조회 Cmdlet 미제공' '' 'Firewall API로 Domain/Private/Public의 유효 상태 확인'
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    if ($profiles.Count -eq 0) {
        throw 'Firewall Profile 조회 결과 없음'
    }
    if (@($profiles | Where-Object {
        [string]$_.Enabled -notin @('True','1')
    }).Count) {
        return New-AuditResult $id VULNERABLE '비활성 Firewall Profile 발견' $profiles
    }
    return New-AuditResult $id GOOD '유효 Firewall Profile 활성 확인' $profiles
}

#endregion

$exitCode = Invoke-WindowsAudit
exit $exitCode
