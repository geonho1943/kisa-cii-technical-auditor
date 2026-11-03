#!/bin/bash
# CIIP Audit — 2026 KISA Unix U-01~U-67, Linux capability-based collector.
# 실행: bash ciip_linux_2026.sh --help / sudo bash ciip_linux_2026.sh
# Source 실행은 지원하지 않는다. 설정값은 이 Process 안에서만 사용한다.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
    printf '%s\n' '별도 Process로 실행하십시오: bash ciip_linux_2026.sh' >&2
    return 2
fi
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
    printf '%s\n' 'Bash 4.4 이상이 필요합니다.' >&2
    exit 2
fi

# ======================= 사용자 설정: 이 구역만 수정 =======================
declare -A AUDIT_CONFIG=(
    [output_dir]="./audit-results"          # 실행마다 권한이 제한된 하위 폴더 생성
    [check_ids]="ALL"                      # ALL 또는 U-01,U-18처럼 쉼표로 구분
    [command_timeout_seconds]="15"         # 네트워크·서비스 조회 명령의 timeout: 1~3600초
    [approved_log_accounts]=""            # /var/log 소유자로 승인한 추가 계정; root는 기본 허용
    [scan_roots]="AUTO"                    # AUTO=로컬 Mount; 직접 지정 시 절대 경로를 줄바꿈 구분
    [approved_accounts]=""                # 승인 계정; 계정·그룹·서비스 목록은 쉼표/줄바꿈 구분
    [approved_admin_accounts]=""          # 관리자 그룹에 허용한 계정
    [approved_groups]=""                  # 승인 그룹
    [nonlogin_accounts]=""                # 로그인이 불필요한 계정
    [required_services]=""                # 필요한 역할: nfs,rpc,r,snmp,automount 등
    [approved_time_sources]=""            # 승인 NTP 서버/Pool 이름 또는 IP
    [required_log_patterns]=""            # 필수 로깅 문자열, 줄바꿈 구분·문자 그대로 비교
    [allowed_management_cidrs]=""          # 허용 관리망 CIDR; 규칙 순서·IPv6·외부 ACL은 별도 검토
    [approved_special_files]=""           # 승인 SUID/SGID 파일; 경로 목록은 정확한 경로를 줄바꿈 구분
    [approved_world_writable_paths]=""    # 승인 World-writable 파일, 하위 경로 자동 면제 없음
    [approved_hidden_paths]=""            # 검토한 숨김 경로, OS 기본 파일도 자동 승인하지 않음
    [approved_device_files]=""            # 검토한 /dev 일반 파일
    [approved_banner_markers]=""          # 경고 문구에 포함될 문자열, 줄바꿈 구분
)
# ========================== 사용자 설정 끝 ================================

set +x
set -uo pipefail
umask 077
AUDIT_OBSERVED_PATH=${PATH-}
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C LANG=C
unset LANGUAGE

# Standalone Linux audit script; the catalog is embedded below.

read -r -d '' AUDIT_EMBEDDED_CATALOG <<'CIIP_CATALOG_2026_EOF' || :

U-01	root 계정 원격 접속 제한	상	root 직접 원격 로그인 경로를 제한	관리자 인증정보 탈취가 즉시 전체 시스템 장악으로 이어짐	12
U-02	비밀번호 관리정책 설정	상	비밀번호 길이·조합·사용기간·재사용 정책 확인	추측·재사용·장기 유출 비밀번호로 계정 탈취	15
U-03	계정 잠금 임계값 설정	상	반복 인증 실패 시 계정 잠금 적용	무차별 대입으로 비밀번호 탐색 가능	21
U-04	비밀번호 파일 보호	상	비밀번호를 보호된 저장소에 암호화 저장	공개 계정 파일에서 인증정보 수집·Offline 공격	25
U-05	root 이외의 UID가 ‘0’ 금지	상	UID 0을 root로 한정	다른 계정이 root와 같은 권한 행사	27
U-06	사용자 계정 su 기능 제한	상	su 사용자를 승인 그룹으로 제한	모든 사용자가 최고 권한 전환을 시도	29
U-07	불필요한 계정 제거	하	업무상 필요한 계정만 유지	방치 계정이 침입·권한 유지 경로가 됨	31
U-08	관리자 그룹에 최소한의 계정 포함	중	관리자 그룹 구성을 승인된 최소 인원으로 제한	불필요한 계정이 관리 권한을 행사	32
U-09	계정이 존재하지 않는 GID 금지	하	업무상 불필요한 그룹을 검토	남은 그룹 권한으로 파일·자원에 비인가 접근	33
U-10	동일한 UID 금지	중	사용자별 UID를 구분	파일 소유권·행위 추적 혼동과 권한 공유	34
U-11	사용자 shell 점검	하	로그인이 불필요한 계정의 Shell 차단	서비스 계정이 대화형 침입 경로로 사용됨	35
U-12	세션 종료 시간 설정	하	유휴 Session의 종료 시간 제한	방치된 Session을 다른 사람이 사용	36
U-13	안전한 비밀번호 암호화 알고리즘 사용	중	안전한 비밀번호 Hash 알고리즘 사용	탈취한 Hash에 대한 Offline 비밀번호 탐색이 쉬워짐	37
U-14	root 홈, 패스 디렉터리 권한 및 패스 설정	상	root PATH의 현재 디렉터리 검색 순서 확인	공격자가 심은 동명 명령을 root가 실행	39
U-15	파일 및 디렉터리 소유자 설정	상	파일·디렉터리 소유 계정의 존재 확인	재사용 UID가 과거 파일 권한을 획득	40
U-16	/etc/passwd 파일 소유자 및 권한 설정	상	passwd 파일 소유자·쓰기 권한 보호	계정·UID·Shell 정보 변조	41
U-17	시스템 시작 스크립트 권한 설정	상	시작 스크립트·Unit의 변조 방지	부팅·서비스 실행 시 악성 코드가 고권한 실행	42
U-18	/etc/shadow 파일 소유자 및 권한 설정	상	shadow 파일의 소유자·읽기 권한 보호	비밀번호 Hash 탈취·인증정보 변조	44
U-19	/etc/hosts 파일 소유자 및 권한 설정	상	hosts 파일 변조 방지	접속 목적지 위조·인증정보 유출	45
U-20	/etc/(x)inetd.conf 파일 소유자 및 권한 설정	상	inetd·xinetd 설정 변조 방지	비인가 Network 서비스 실행	46
U-21	/etc/(r)syslog.conf 파일 소유자 및 권한 설정	상	Syslog 설정의 변조 방지	감사 기록 누락·공격 흔적 은폐	48
U-22	/etc/services 파일 소유자 및 권한 설정	상	services 파일의 변조 방지	서비스·Port 식별 혼선과 비인가 설정	49
U-23	SUID, SGID, Sticky bit 설정 파일 점검	상	불필요한 SUID·SGID 실행 파일 검토	파일 실행을 통한 권한 상승	50
U-24	사용자, 시스템 환경변수 파일 소유자 및 권한 설정	상	계정 환경 파일의 소유자·쓰기 권한 보호	로그인 시 명령 주입·환경 변조	51
U-25	world writable 파일 점검	상	모든 사용자 쓰기 가능한 파일의 필요성 검토	비인가 변조·서비스 장애·권한 악용	52
U-26	/dev에 존재하지 않는 device 파일 점검	상	/dev 일반 파일의 실제 용도 확인	장치 파일로 위장한 악성·불필요 파일 은닉	53
U-27	$HOME/.rhosts, hosts.equiv 사용 금지	상	rhosts·hosts.equiv의 신뢰 관계 제한	비밀번호 없는 신뢰 인증 경로로 침입	54
U-28	접속 IP 및 포트 제한	상	접속 가능한 Host·Port를 정책에 맞게 제한	불필요한 관리·서비스 접근 경로 노출	56
U-29	hosts.lpd 파일 소유자 및 권한 설정	하	hosts.lpd 파일의 소유자·권한 보호	프린터 Host 신뢰 설정 악용	61
U-30	UMASK 설정 관리	중	생성 파일의 기본 권한 제한	새 파일이 불필요하게 쓰기 가능해짐	62
U-31	홈디렉토리 소유자 및 권한 설정	중	Home의 소유자·타 사용자 쓰기 권한 확인	환경 파일 변조·사용자 정보 접근	65
U-32	홈 디렉토리로 지정한 디렉토리의 존재 관리	중	지정한 Home 디렉터리의 존재 확인	의도하지 않은 디렉터리를 Home으로 사용	66
U-33	숨겨진 파일 및 디렉토리 검색 및 제거	하	숨김 파일의 용도·정당성 검토	공격 도구·Persistence 파일을 놓침	67
U-34	Finger 서비스 비활성화	상	불필요한 Finger 서비스 차단	계정·접속 상태 등 정보 수집	68
U-35	공유 서비스에 대한 익명 접근 제한 설정	상	공유 서비스의 익명 접근 제한	비인가 정보 열람·변조·악성 파일 유포	70
U-36	r 계열 서비스 비활성화	상	불필요한 r 계열 서비스 차단	취약한 신뢰 인증·평문 통신 악용	77
U-37	crontab 설정파일 권한 설정 미흡	상	cron·at 명령과 예약 파일 보호	비인가 예약 작업이 고권한으로 실행	80
U-38	DoS 공격에 취약한 서비스 비활성화	상	DoS에 악용되는 불필요 서비스 차단	반사·증폭 공격과 자원 소모	83
U-39	불필요한 NFS 서비스 비활성화	상	불필요한 NFS Daemon 차단	불필요한 파일 공유 공격면 노출	86
U-40	NFS 접근 통제	상	NFS Client 제한·설정 권한 확인	공유 파일 무단 접근·변조	89
U-41	불필요한 automountd 제거	상	불필요한 자동 Mount 서비스 제한	의도하지 않은 파일시스템 연결·접근	93
U-42	불필요한 RPC 서비스 비활성화	상	불필요한 RPC 서비스 차단	RPC의 취약 기능·정보 수집 경로 노출	96
U-43	NIS, NIS+ 점검	상	취약한 NIS 운용 제한	인증 DB·계정 정보 노출·신뢰 악용	99
U-44	tftp, talk 서비스 비활성화	상	TFTP·Talk·Ntalk 서비스 차단	불필요한 무인증 전송·통신 경로 노출	102
U-45	메일 서비스 버전 점검	상	메일 Server Version·Vendor 지원 확인	알려진 취약점이 미조치 상태로 운영됨	105
U-46	일반 사용자의 메일 서비스 실행 방지	상	일반 사용자의 Mail Queue 실행 제한	비인가 Queue 처리·메일 실행 권한 악용	111
U-47	스팸 메일 릴레이 제한	상	비인증 Mail Relay 제한	Spam 중계·평판 하락·메일 자원 소모	113
U-48	expn, vrfy 명령어 제한	중	EXPN·VRFY를 통한 계정 열거 제한	유효 계정·메일링 목록 정보 수집	116
U-49	DNS 보안 버전 패치	상	DNS 보안 패치 정책·적용 기록 확인	알려진 DNS 취약점이 미조치로 유지됨	118
U-50	DNS ZoneTransfer 설정	상	DNS Zone Transfer 승인 대상 제한	내부 Host·Network 구조 전체 노출	121
U-51	DNS 서비스의 취약한 동적 업데이트 설정 금지	중	DNS 동적 Update의 인증·접근 제한	비인가 DNS Record 변경·접속 유도	122
U-52	Telnet 서비스 비활성화	중	평문 원격 접속 Telnet 차단	계정 인증정보·Session 내용 도청	124
U-53	FTP 서비스 정보 노출 제한	하	FTP Banner의 제품·Version 노출 제한	공격자가 취약점에 맞는 대상을 식별	127
U-54	암호화되지 않는 FTP 서비스 비활성화	중	평문 FTP 인증·전송 차단	계정정보·전송 데이터 도청	131
U-55	FTP 계정 shell 제한	중	FTP 전용 계정의 로그인 Shell 차단	파일 전송 계정이 대화형 침입에 사용됨	134
U-56	FTP 서비스 접근 제어 설정	하	FTP 접속 Host·IP를 승인 범위로 제한	불필요한 외부 파일 전송 접근 경로 노출	135
U-57	Ftpusers 파일 설정	중	FTP를 통한 root 접속 차단	최고 권한 인증정보·파일에 대한 원격 접근	139
U-58	불필요한 SNMP 서비스 구동 점검	중	불필요한 SNMP 운용 제한	관리 정보·설정 Interface 노출	141
U-59	안전한 SNMP 버전 사용	상	안전한 SNMP Version으로 제한	취약한 Community 인증·관리 통신 악용	143
U-60	SNMP Community String 복잡성 설정	중	SNMP 인증 문자열 복잡성 확인	Community 추측으로 관리 정보·권한 획득	145
U-61	SNMP Access Control 설정	상	SNMP 조회·관리 Source 제한	비인가 Host의 관리 정보 조회·변경	148
U-62	로그인 시 경고 메시지 설정	하	서버·서비스의 승인 경고 문구 제공	접근 제한 고지가 부족하고 운영 정책 전달 누락	150
U-63	sudo 명령어 접근 관리	중	sudoers의 소유자·권한 보호	sudo 정책 변조로 최고 권한 획득	159
U-64	주기적 보안 패치 및 벤더 권고사항 적용	상	보안 패치 정책·권고 검토·적용 기록 확인	알려진 취약점이 장기간 미조치	160
U-65	NTP 및 시각 동기화 설정	중	승인 시간 Source와 실제 동기화 확인	로그 시간 신뢰 저하·시간 의존 인증 장애	164
U-66	정책에 따른 시스템 로깅 설정	중	조직 정책에 따른 실제 로그 기록 확인	침해 탐지·행위 추적·사고 원인 분석 곤란	166
U-67	로그 디렉터리 소유자 및 권한 설정	중	Log 파일 소유자·권한 보호	감사 정보 유출·변조·흔적 삭제	171

CIIP_CATALOG_2026_EOF

# shellcheck shell=bash
# All paths and commands are data. Never eval target configuration.
AUDIT_VERSION=0.2.0
AUDIT_SYSTEMCTL_AVAILABLE=0
AUDIT_NEED_ACCOUNTS=0
AUDIT_NEED_GROUPS=0
AUDIT_NEED_SHADOW=0
declare -A AUDIT_REQUIRED_ROLES=()
AUDIT_WORK_DIR=
AUDIT_OUTPUT_DIR=
AUDIT_OUTPUT_BASE=
declare -a FIND_PRUNE=()
AUDIT_INTERRUPTED=0
declare -A AUDIT_CATALOG_TITLE=() AUDIT_CATALOG_SEVERITY=()
declare -A AUDIT_CATALOG_PURPOSE=() AUDIT_CATALOG_RISK=() AUDIT_CATALOG_PAGE=()
declare -a AUDIT_SELECTED=() AUDIT_NOT_SELECTED=()
AUDIT_ITEM_TEXT_PATH=

AUDIT_OS_DESCRIPTION=unknown
AUDIT_RUNTIME_SCOPE=unknown
AUDIT_PROCESS_COMPLETE=0
AUDIT_SOCKET_COMPLETE=0
AUDIT_PROCESS_NAMES=
AUDIT_SOCKET_DATA=
AUDIT_PACKAGE_DATA=
AUDIT_PACKAGE_MANAGER=unknown
AUDIT_PACKAGE_COMPLETE=0
AUDIT_SCAN_SCOPE=unknown
declare -a AUDIT_SCAN_ROOTS=() AUDIT_MOUNTS=()
AUDIT_FIND_PRINTF=-1
AUDIT_SCAN_ROOT_ERROR=
declare -A AUDIT_SCAN_SELECTED=() AUDIT_SCAN_ITEM_COUNT=() AUDIT_SCAN_ITEM_UNAPPROVED=() AUDIT_SCAN_ITEM_ERROR=()
declare -A AUDIT_ACCOUNT_UID=() AUDIT_SERVICE_STATE=() AUDIT_SERVICE_EVIDENCE=()
PAM_ROWS=
PAM_ERROR=
declare -A PAM_VISITED=()
AUDIT_ACCOUNT_ROWS=
AUDIT_GROUP_ROWS=
AUDIT_SHADOW_ROWS=
AUDIT_SHADOW_EVIDENCE=
AUDIT_NSS_EVIDENCE=
AUDIT_ACCOUNTS_OK=0
AUDIT_GROUPS_OK=0
AUDIT_SHADOW_OK=0
AUDIT_NSS_EXTERNAL=0

# --- 공통 도구 — 실행 제한, 파일 읽기, 설정 ---

audit_log() { printf '%s\n' "$*" >&2; }
abort_run() { audit_log "$*"; exit 2; }

record_value() {
    # source, key, original value, state(OK/MISSING/ERROR/DERIVED); stdout는 사용하지 않는다.
    [[ -n $AUDIT_ITEM_TEXT_PATH ]] || return 0
    local source=$1 key=$2 value=${3-} state=${4:-OK} line
    if [[ $source != criterion ]]; then
        case ${key,,} in password|passwd|pwd|secret|token|community|rocommunity|rwcommunity|authorization) value='[비공개]' ;; esac
    fi
    case ${value,,} in
        *password*|*passwd*|*secret*|*token*|*key*|*community*|*authorization*|*'$'*|*'://'*) value=$(redact_text "$value") ;;
    esac
    source=${source//$'\n'/\\n}; key=${key//$'\n'/\\n}
    source=${source//$'\r'/\\r}; value=${value//$'\r'/\\r}
    if [[ $value == *$'\n'* ]]; then
        printf '조회: %s | %s [%s]\n' "$source" "$key" "$state" >>"$AUDIT_ITEM_TEXT_PATH"
        while IFS= read -r line; do printf '  %s\n' "$line"; done <<<"$value" >>"$AUDIT_ITEM_TEXT_PATH"
    else printf '조회: %s | %s:%s [%s]\n' "$source" "$key" "${value:-<빈 값>}" "$state" >>"$AUDIT_ITEM_TEXT_PATH"; fi
}

target_path() {
    [[ $1 == /* && $1 != *$'\n'* ]] || return 2
    printf '%s' "$1"
}





audit_cleanup() {
    [[ -z $AUDIT_WORK_DIR || ! -d $AUDIT_WORK_DIR ]] || rm -rf -- "$AUDIT_WORK_DIR"
}



capture_command() {
    # 기존 인자(seconds, command...)와 stdout/stderr/rc 계약을 유지한다.
    local budget=$1 code=0 err="$AUDIT_WORK_DIR/cmd.$BASHPID.err" command
    shift
    command=${1##*/}
    local -a run=("$@")
    case $command in
        getent|ss|netstat|systemctl|chronyc|ntpq|named-checkconf|nft|iptables-save|ip6tables-save|ufw|firewall-cmd|postconf|timedatectl)
            command -v timeout >/dev/null 2>&1 && run=(timeout "$budget" "$@") ;;
        sshd)
            [[ ${2-} != -T ]] || { command -v timeout >/dev/null 2>&1 && run=(timeout "$budget" "$@"); } ;;
    esac
    AUDIT_COMMAND_STDOUT=$("${run[@]}" 2>"$err") || code=$?
    AUDIT_COMMAND_STDERR=$(<"$err")
    AUDIT_COMMAND_RC=$code
    rm -f -- "$err"
    record_value "$command" exit_code "$code"
    ((code == 0)) || record_value "$command" stderr "$AUDIT_COMMAND_STDERR" ERROR
    return "$code"
}

read_target() {
    local file text code=0 err="$AUDIT_WORK_DIR/read.$BASHPID.err"
    file=$(target_path "$1") || return 2
    if [[ ! -f $file || ! -r $file ]]; then
        record_value "$file" read '파일 없음 또는 읽기 불가' ERROR
        return 2
    fi
    text=$(cat -- "$file" 2>"$err") || code=$?
    if ((code)); then record_value "$file" read "조회 실패: $(<"$err")" ERROR; fi
    rm -f -- "$err"
    ((code == 0)) || return "$code"
    printf '%s' "$text"
}

active_lines() {
    local text
    text=$(read_target "$1") || return $?
    printf '%s\n' "$text" | awk '{sub(/\r$/,""); if ($0 !~ /^[[:space:]]*(#|;|$)/) print}'
}

path_exists() {
    local path
    path=$(target_path "$1") || return 2
    if [[ -e $path || -L $path ]]; then
        record_value "$path" exists yes
    else
        record_value "$path" exists no MISSING
        return 1
    fi
}

config_value() {
    local path=$1 key=$2 text value code=0
    text=$(active_lines "$path") || { record_value "$path" "$key" '조회 실패' ERROR; return 1; }
    value=$(awk -v key="$key" '
        { line=$0; sub(/[[:space:]]+#.*/,"",line); gsub(/=/," ",line)
          n=split(line,a,/[[:space:]]+/); start=(a[1]==""?2:1)
          if(tolower(a[start])==tolower(key)) {value=a[start+1]; found=1} }
        END {if(found)print value;else exit 1}' <<<"$text") || code=$?
    if ((code)); then record_value "$path" "$key" '설정 없음' MISSING
    else record_value "$path" "$key" "$value"; printf '%s\n' "$value"; fi
    return "$code"
}

list_has() {
    local values=${1-} wanted=$2 value
    values=${values//,/$'\n'}
    while IFS= read -r value || [[ -n $value ]]; do
        [[ $value == "$wanted" ]] && return 0
    done <<<"$values"
    return 1
}

file_metadata() {
    # On success sets FILE_UID/FILE_GID/FILE_MODE; returns 2 on failure.
    local real
    real=$(target_path "$1") || return 2
    if ! capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" stat -Lc '%u %g %a' -- "$real"; then
        record_value "$real" metadata '조회 실패' ERROR
        return 2
    fi
    read -r FILE_UID FILE_GID FILE_MODE <<<"$AUDIT_COMMAND_STDOUT"
    [[ $FILE_UID =~ ^[0-9]+$ && $FILE_GID =~ ^[0-9]+$ && $FILE_MODE =~ ^[0-7]{1,4}$ ]] || return 2
    record_value "$real" metadata "uid:$FILE_UID gid:$FILE_GID mode:$FILE_MODE"
}

mode_within() {
    local actual=$1 allowed=$2
    [[ $actual =~ ^[0-7]{1,4}$ && $allowed =~ ^[0-7]{3,4}$ ]] || return 2
    (((8#$actual & ~8#$allowed) == 0))
}

collect_paths() {
    # /dev 직접 점검(U-26)을 포함한다. 전체 탐색의 prune은 별도로 구성한다.
    local destination=$1 root=$2
    shift 2
    find "$root" -xdev "$@" >"$destination" 2>"$destination.err"
}

list_has_line() {
    local value
    while IFS= read -r value || [[ -n $value ]]; do
        [[ $value == "$2" ]] && return 0
    done <<<"${1-}"
    return 1
}

find_printf_available() {
    if ((AUDIT_FIND_PRINTF < 0)); then
        AUDIT_FIND_PRINTF=0
        find /dev/null -maxdepth 0 -printf '' >/dev/null 2>&1 && AUDIT_FIND_PRINTF=1
    fi
    ((AUDIT_FIND_PRINTF))
}

load_catalog() {
    local id title severity purpose risk page data=${AUDIT_EMBEDDED_CATALOG-}
    while IFS=$'\t' read -r id title severity purpose risk page; do
        [[ $id =~ ^U-[0-9]{2}$ && $page =~ ^[0-9]+$ ]] || continue
        AUDIT_CATALOG_TITLE[$id]=$title
        AUDIT_CATALOG_SEVERITY[$id]=$severity
        AUDIT_CATALOG_PURPOSE[$id]=$purpose
        AUDIT_CATALOG_RISK[$id]=$risk
        AUDIT_CATALOG_PAGE[$id]=$page
    done <<<"$data"
    ((${#AUDIT_CATALOG_TITLE[@]} == 67))
}

show_config() {
    local key
    audit_log '사용자 설정 (정책 공란은 임의 추정하지 않습니다):'
    while IFS= read -r key; do
        audit_log "  $key = $(redact_text "${AUDIT_CONFIG[$key]:-(미입력)}")"
    done < <(printf '%s\n' "${!AUDIT_CONFIG[@]}" | sort)
}

select_collectors() {
    local id role roles
    for id in "${AUDIT_SELECTED[@]}"; do
        case $id in
        U-02 | U-03 | U-04 | U-05 | U-06 | U-07 | U-08 | U-09 | U-10 | U-11 | U-15 | U-21 | U-22 | U-24 | U-27 | U-31 | U-32 | U-37 | U-55 | U-67)
            AUDIT_NEED_ACCOUNTS=1 ;;
        esac
        case $id in U-08 | U-09) AUDIT_NEED_GROUPS=1 ;; esac
        case $id in U-02 | U-04 | U-13) AUDIT_NEED_SHADOW=1 ;; esac
        roles=
        case $id in
        U-01) roles='ssh telnet r' ;;
        U-62) roles='ssh telnet ftp mail dns' ;;
        U-27 | U-36) roles=r ;;
        U-34) roles=finger ;;
        U-35) roles='ftp nfs samba' ;;
        U-38) roles=dos ;;
        U-39 | U-40) roles=nfs ;;
        U-41) roles=automount ;;
        U-42) roles=rpc ;;
        U-43) roles=nis ;;
        U-44) roles=tftp ;;
        U-45 | U-46 | U-47 | U-48) roles=mail ;;
        U-49 | U-50 | U-51) roles=dns ;;
        U-52) roles=telnet ;;
        U-53 | U-54 | U-55 | U-56 | U-57) roles=ftp ;;
        U-58 | U-59 | U-60 | U-61) roles=snmp ;;
        esac
        for role in $roles; do AUDIT_REQUIRED_ROLES[$role]=1; done
    done
}

# --- 정보 수집 — 선택 항목에 필요한 상태만 조회 ---

service_definition() {
    local wanted=$1 role units processes ports packages
    # role | units | process names | ports | packages; empty fields stay empty.
    while IFS='|' read -r role units processes ports packages; do
        [[ $role == "$wanted" ]] || continue
        SERVICE_UNITS=$units
        SERVICE_PROCESSES=$processes
        SERVICE_PORTS=$ports
        SERVICE_PACKAGES=$packages
        return 0
    done <<'CIIP_SERVICES_EOF'
ssh|sshd ssh ssh.socket sshd.socket dropbear|sshd dropbear|22|openssh-server dropbear
telnet|telnet.socket telnet|telnetd in.telnetd|23|telnetd telnet-server inetutils-telnetd
ftp|vsftpd proftpd pure-ftpd ftpd|vsftpd proftpd pure-ftpd ftpd|21|vsftpd proftpd pure-ftpd
nfs|nfs-server nfs-kernel-server nfs|nfsd rpc.nfsd|2049|nfs-kernel-server nfs-utils
samba|smb smbd samba|smbd samba|139 445|samba samba-server
r|rsh.socket rlogin.socket rexec.socket rsh rlogin rexec|rshd in.rshd rlogind in.rlogind rexecd in.rexecd|512 513 514|rsh-server rsh-redone-server
finger|finger.socket fingerd|fingerd in.fingerd|79|fingerd finger-server
dos|echo.socket discard.socket daytime.socket chargen.socket|in.chargend chargen|7 9 13 19|
automount|autofs automount|automount automountd||autofs
rpc|rusersd rwalld rstatd sprayd rpc.rusersd|rpc.rusersd rpc.rwalld rpc.rstatd rpc.sprayd rusersd rwalld rstatd||rusers-server rwall-server rstat-server
nis|ypserv ypbind yppasswdd|ypserv ypbind yppasswdd||ypserv ypbind nis
tftp|tftp.socket tftpd tftpd-hpa talk.socket ntalk.socket|in.tftpd tftpd in.talkd talkd ntalkd|69 517 518|tftp-server tftpd tftpd-hpa talkd
mail|postfix sendmail exim exim4 opensmtpd|sendmail exim exim4 smtpd|25 465 587|postfix sendmail exim exim4 opensmtpd
dns|named bind9 unbound pdns knot|named unbound pdns_server knotd|53|bind9 bind unbound pdns knot
snmp|snmpd|snmpd|161|snmpd net-snmp net-snmp-agent
time|chronyd chrony ntpd ntp ntpsec systemd-timesyncd openntpd ntpd-rs|chronyd ntpd systemd-timesyn ntp-daemon|123|chrony ntp ntpsec openntpd ntpd-rs
log|rsyslog syslog-ng syslogd busybox-syslogd|rsyslogd syslog-ng syslogd||rsyslog syslog-ng sysklogd busybox-syslogd
CIIP_SERVICES_EOF
    return 2
}

socket_collect_proc() {
    local file protocol slot address state rest port base_ok=0 failed=0
    AUDIT_SOCKET_DATA=
    for protocol in tcp tcp6 udp udp6; do
        file="/proc/net/$protocol"
        if [[ ! -e $file ]]; then
            [[ $protocol == tcp || $protocol == udp ]] && failed=1
            continue
        fi
        [[ -r $file ]] || {
            failed=1
            continue
        }
        [[ $protocol == tcp || $protocol == udp ]] && ((base_ok += 1))
        while read -r slot address _ state rest; do
            [[ $slot == sl ]] && continue
            [[ $protocol == tcp* && $state != 0A ]] && continue
            port=${address##*:}
            [[ $port =~ ^[0-9A-Fa-f]{4}$ ]] || {
                failed=1
                continue
            }
            AUDIT_SOCKET_DATA+="$protocol local:$((16#$port)) peer:0"$'\n'
        done <"$file"
    done
    if ((base_ok == 2 && failed == 0)); then AUDIT_SOCKET_COMPLETE=1; fi
}

service_collect() {
    local role=$1 unit name port load active installed=0 stopped=0 active_found=0 port_found=0 info='' text
    service_definition "$role" || return 2
    for name in $SERVICE_PROCESSES; do
        if grep -Fxq -- "$name" <<<"$AUDIT_PROCESS_NAMES"; then
            active_found=1
            info+="process=$name "
        else info+="process=$name:미발견 "; fi
    done
    if ((AUDIT_SYSTEMCTL_AVAILABLE)); then
        for unit in $SERVICE_UNITS; do
            [[ $unit == *.* ]] || unit+='.service'
            if ! capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" systemctl show "$unit" --no-pager --property=LoadState,ActiveState; then
                info+="$unit query_exit:$AUDIT_COMMAND_RC "
                if ((AUDIT_COMMAND_RC == 124 || AUDIT_COMMAND_RC == 137)); then
                    AUDIT_SYSTEMCTL_AVAILABLE=0
                    break
                fi
                continue
            fi
            text=$AUDIT_COMMAND_STDOUT
            load=$(awk -F= '$1=="LoadState"{print $2}' <<<"$text")
            active=$(awk -F= '$1=="ActiveState"{print $2}' <<<"$text")
            info+="$unit LoadState:${load:-<빈 값>} ActiveState:${active:-<빈 값>} "
            if [[ $load == loaded ]]; then
                installed=1
                info+="$unit=$active "
                case $active in active | activating | reloading) active_found=1 ;; inactive | failed) stopped=1 ;; esac
            fi
        done
    fi
    for unit in $SERVICE_UNITS; do
        unit=${unit%.socket}
        unit=${unit%.service}
        if [[ -f /etc/init.d/$unit ]]; then
            installed=1
            # Status is a read operation; avoid invoking arbitrary untrusted scripts.
            info+="init-script=$unit "
        fi
        if command -v sv >/dev/null 2>&1 && [[ -d /var/service/$unit ]]; then
            installed=1
            if capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" sv status "/var/service/$unit"; then
                case $AUDIT_COMMAND_STDOUT in run:*) active_found=1 ;; down:*) stopped=1 ;; esac
                info+="runit=$unit "
            fi
        fi
    done
    for name in $SERVICE_PACKAGES; do
        if grep -Eq "(^|[[:space:]])${name}([[:space:]:-]|$)" <<<"$AUDIT_PACKAGE_DATA"; then
            installed=1
            info+="package=$name "
        else info+="package=$name:미발견 "; fi
    done
    for port in $SERVICE_PORTS; do
        if awk -v p="$port" '$0 !~ /^(Active|Proto)/ {for(i=1;i<=NF;i++)if($i ~ (":" p "$") && i<=5)found=1} END{exit !found}' <<<"$AUDIT_SOCKET_DATA"; then
            port_found=1
            info+="listener=$port (소유 서비스 미확정) "
        else info+="port=$port:미발견 "; fi
    done
    # Legacy super-server activation must not be mistaken for absence.
    if [[ -r /etc/inetd.conf ]] && grep -Ev '^[[:space:]]*(#|$)' /etc/inetd.conf | grep -Eq "(^|[[:space:]])($role|$(printf '%s' "$SERVICE_PROCESSES" | tr ' ' '|'))([[:space:]]|$)"; then
        installed=1
        info+='inetd-entry '
        if grep -Eq '^(inetd|xinetd)$' <<<"$AUDIT_PROCESS_NAMES"; then active_found=1; fi
    fi
    if ((active_found)); then
        AUDIT_SERVICE_STATE[$role]=RUNNING
    elif ((AUDIT_PROCESS_COMPLETE && AUDIT_SOCKET_COMPLETE && !port_found)); then
        if ((installed || stopped)); then
            AUDIT_SERVICE_STATE[$role]=STOPPED
        elif ((AUDIT_PACKAGE_COMPLETE)); then
            AUDIT_SERVICE_STATE[$role]=ABSENT
        else AUDIT_SERVICE_STATE[$role]=UNKNOWN; fi
    else AUDIT_SERVICE_STATE[$role]=UNKNOWN; fi
    AUDIT_SERVICE_EVIDENCE[$role]="${info:-긍정적 식별 증거 없음}; process_complete=$AUDIT_PROCESS_COMPLETE socket_complete=$AUDIT_SOCKET_COMPLETE package_manager=$AUDIT_PACKAGE_MANAGER"
}

platform_collect() {
    local file id version name role output
    id=$(config_value /etc/os-release ID 2>/dev/null) || id=unknown
    version=$(config_value /etc/os-release VERSION_ID 2>/dev/null) || version=unknown
    id=${id//\"/}
    version=${version//\"/}
    AUDIT_OS_DESCRIPTION="$id $version"
    AUDIT_RUNTIME_SCOPE='현재 Kernel/Process/Network Namespace'
    if [[ -e /.dockerenv || -e /run/.containerenv ]]; then
        AUDIT_RUNTIME_SCOPE+=' (Container: Host 전체 상태를 의미하지 않음)'
    fi
    for name in dpkg-query rpm apk pacman xbps-query opkg; do
        if command -v "$name" >/dev/null 2>&1; then AUDIT_PACKAGE_MANAGER=$name; break; fi
    done
    # Permission-only and configuration-only checks need no runtime inventory.
    ((${#AUDIT_REQUIRED_ROLES[@]})) || return 0
    if capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ps -eo comm=; then
        AUDIT_PROCESS_NAMES=$AUDIT_COMMAND_STDOUT
        AUDIT_PROCESS_COMPLETE=1
    elif [[ -d /proc/1 ]]; then
        output=
        AUDIT_PROCESS_COMPLETE=1
        for file in /proc/[0-9]*/comm; do
            [[ -e $file ]] || continue
            if IFS= read -r name <"$file" 2>/dev/null; then
                output+="$name"$'\n'
            else [[ -e $file ]] && AUDIT_PROCESS_COMPLETE=0; fi
        done
        AUDIT_PROCESS_NAMES=$output
    fi
    if command -v ss >/dev/null 2>&1 && capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ss -H -lntu; then
        AUDIT_SOCKET_DATA=$AUDIT_COMMAND_STDOUT
        AUDIT_SOCKET_COMPLETE=1
    elif command -v netstat >/dev/null 2>&1 && capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" netstat -lntu; then
        AUDIT_SOCKET_DATA=$AUDIT_COMMAND_STDOUT
        AUDIT_SOCKET_COMPLETE=1
    else
        socket_collect_proc
    fi
    for name in dpkg-query rpm apk pacman xbps-query opkg; do
        command -v "$name" >/dev/null 2>&1 || continue
        case $name in
        dpkg-query) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" dpkg-query -W '-f=${db:Status-Status} ${Package} ${Version}\n' || continue ;;
        rpm) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' || continue ;;
        apk) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" apk info -v || continue ;;
        pacman) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" pacman -Q || continue ;;
        xbps-query) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" xbps-query -l || continue ;;
        opkg) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" opkg list-installed || continue ;;
        esac
        AUDIT_PACKAGE_MANAGER=$name
        AUDIT_PACKAGE_COMPLETE=1
        AUDIT_PACKAGE_DATA=$AUDIT_COMMAND_STDOUT
        if [[ $name == dpkg-query ]]; then
            AUDIT_PACKAGE_DATA=$(awk '$1=="installed"' <<<"$AUDIT_PACKAGE_DATA")
        fi
        break
    done
    if command -v systemctl >/dev/null 2>&1 && capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" systemctl show --property=Version; then
        AUDIT_SYSTEMCTL_AVAILABLE=1
    fi
    for role in ssh telnet ftp nfs samba r finger dos automount rpc nis tftp mail dns snmp; do
        [[ -v AUDIT_REQUIRED_ROLES[$role] ]] && service_collect "$role"
    done
    return 0
}

account_collect() {
    local file line uid rows code state algorithm min max last raw_min raw_max name nss_provider sssd_checked=0
    if ((AUDIT_NEED_ACCOUNTS)); then
        file=/etc/passwd
        if [[ -r $file ]] && awk -F: '/^[+-]/ {next} NF!=7 || $1=="" || $3!~/^[0-9]+$/ || $4!~/^[0-9]+$/ {bad=1} END{exit bad}' "$file"; then
            AUDIT_ACCOUNT_ROWS=$(awk -F: 'BEGIN{OFS=":"} !/^[+-]/{print $1,$3,$4,$6,$7}' "$file")
            [[ -n $AUDIT_ACCOUNT_ROWS ]] && AUDIT_ACCOUNTS_OK=1
            while IFS=: read -r name uid _; do [[ $uid =~ ^[0-9]+$ ]] && AUDIT_ACCOUNT_UID[$name]=$uid; done <<<"$AUDIT_ACCOUNT_ROWS"
        fi
    fi
    if ((AUDIT_NEED_GROUPS)); then
        file=/etc/group
        if [[ -r $file ]] && awk -F: '/^[+-]/ {next} NF!=4 || $3!~/^[0-9]+$/ {bad=1} END{exit bad}' "$file"; then
            AUDIT_GROUP_ROWS=$(awk -F: 'BEGIN{OFS=":"} !/^[+-]/{print $1,$3,$4}' "$file")
            AUDIT_GROUPS_OK=1
        fi
    fi
    if ((AUDIT_NEED_SHADOW)); then
        file=/etc/shadow
        if [[ -r $file ]]; then
            rows=$(awk -F: '
              /^[+-]/ {next}
              NF!=9 {bad=1;next}
              {state="HASH";alg="unknown";hash=$2
               if(hash=="")state="EMPTY";else if(hash~/^[!*]/)state="LOCKED"
               else if(hash~/^\$/){split(hash,a,"$");alg=a[2]}else alg="DES_or_legacy"
               lo=$4;hi=$5
               if(lo~/^[0-9]+$/ && length(lo)<10)lo=sprintf("%.0f",lo+0)
               if(hi~/^[0-9]+$/ && length(hi)<10)hi=sprintf("%.0f",hi+0)
               print $1 ":" state ":" alg ":" lo ":" hi ":" $3 ":" $4 ":" $5}
              END{if(bad)exit 2}' "$file")
            code=$?
            while IFS=: read -r name state algorithm min max last raw_min raw_max; do
                [[ -n $name ]] || continue
                AUDIT_SHADOW_ROWS+="$name:$state:$algorithm:$min:$max:$last"$'\n'
                AUDIT_SHADOW_EVIDENCE+="$name:$state:$algorithm:$raw_min:$raw_max:$last"$'\n'
            done <<<"$rows"
            AUDIT_SHADOW_ROWS=${AUDIT_SHADOW_ROWS%$'\n'}
            AUDIT_SHADOW_EVIDENCE=${AUDIT_SHADOW_EVIDENCE%$'\n'}
            [[ $code == 0 && -n $AUDIT_SHADOW_ROWS ]] && AUDIT_SHADOW_OK=1
        fi
    fi
    if ((AUDIT_NEED_ACCOUNTS || AUDIT_NEED_GROUPS || AUDIT_NEED_SHADOW)); then
        line=$(active_lines /etc/nsswitch.conf 2>/dev/null | awk '{sub(/#.*/,"")} /^[[:space:]]*(passwd|group|shadow):/ {print}') || :
        AUDIT_NSS_EVIDENCE=$line
        for nss_provider in $line; do
            case $nss_provider in
                ldap|nis|nisplus|winbind) AUDIT_NSS_EXTERNAL=1 ;;
                sss)
                    ((sssd_checked)) && continue
                    sssd_checked=1
                    if [[ -f /etc/sssd/sssd.conf ]]; then
                        AUDIT_NSS_EXTERNAL=1
                        AUDIT_NSS_EVIDENCE+=$'\n''/etc/sssd/sssd.conf exists:yes'
                    elif command -v systemctl >/dev/null 2>&1; then
                        capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" systemctl is-active sssd || :
                        AUDIT_NSS_EVIDENCE+=$'\n'"sssd config_exists:no ActiveState:$AUDIT_COMMAND_STDOUT query_rc:$AUDIT_COMMAND_RC"
                        [[ $AUDIT_COMMAND_RC != 0 || $AUDIT_COMMAND_STDOUT != active ]] || AUDIT_NSS_EXTERNAL=1
                    else AUDIT_NSS_EVIDENCE+=$'\n''sssd config_exists:no service_query:도구 없음'; fi ;;
                compat) if grep -q '^+' /etc/passwd; then AUDIT_NSS_EXTERNAL=1; fi ;;
            esac
        done
    fi
    return 0
}

record_accounts() {
    local name uid gid home shell members state algorithm min max last
    case $AUDIT_CURRENT_ID in
    U-02|U-03|U-04|U-05|U-06|U-07|U-08|U-09|U-10|U-11|U-15|U-21|U-22|U-24|U-27|U-31|U-32|U-37|U-55|U-67)
        record_value /etc/passwd collection_ok "$AUDIT_ACCOUNTS_OK"
        while IFS=: read -r name uid gid home shell; do
            [[ -n $name ]] && record_value "/etc/passwd:$name" account "uid:$uid gid:$gid home:$home shell:$shell"
        done <<<"$AUDIT_ACCOUNT_ROWS"
        record_value /etc/nsswitch.conf account_sources "$AUDIT_NSS_EVIDENCE"
        record_value /etc/nsswitch.conf external_source_detected "$AUDIT_NSS_EXTERNAL"
        ;;
    esac
    case $AUDIT_CURRENT_ID in
    U-08|U-09)
        record_value /etc/group collection_ok "$AUDIT_GROUPS_OK"
        while IFS=: read -r name gid members; do
            [[ -n $name ]] && record_value "/etc/group:$name" group "gid:$gid members:$members"
        done <<<"$AUDIT_GROUP_ROWS"
        ;;
    U-02|U-04|U-13)
        record_value /etc/shadow collection_ok "$AUDIT_SHADOW_OK"
        while IFS=: read -r name state algorithm min max last; do
            [[ -n $name ]] && record_value "/etc/shadow:$name" account "state:$state algorithm:$algorithm min_days:${min:-<빈 값>} max_days:${max:-<빈 값>} last_change:${last:-<빈 값>}"
        done <<<"$AUDIT_SHADOW_EVIDENCE"
        ;;
    esac
}

scan_find_pattern() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\*/\\*}
    value=${value//\?/\\?}
    value=${value//\[/\\[}
    printf '%s' "$value"
}

scan_scope_error() {
    AUDIT_SCAN_ROOT_ERROR+="$1; "
}

scan_record() {
    local AUDIT_CURRENT_ID=${AUDIT_SCAN_SELECTED[$1]}
    local AUDIT_ITEM_TEXT_PATH="$AUDIT_WORK_DIR/$AUDIT_CURRENT_ID.txt"
    shift
    record_value "$@"
}





scan_collect_roots() {
    local path root fs dev backing rest value index old_root old_dev old_backing source shadow covered
    local -a candidate_paths=() candidate_devs=() candidate_roots=() kept_devs=() kept_roots=()
    local -A seen_mounts=()
    if [[ ${AUDIT_CONFIG[scan_roots]} == AUTO ]]; then
        AUDIT_SCAN_SCOPE='AUTO: 현재 Mount Namespace의 로컬 파일시스템; bind 별칭 중복 제외'
    else
        AUDIT_SCAN_SCOPE='사용자 지정 부분 범위: 전체 시스템 판정 불가'
    fi
    # Prune every submount; only known local filesystems enter AUTO scope.
    if [[ -r /proc/self/mountinfo ]]; then
        while read -r _ _ dev backing path _ rest; do
            printf -v path '%b' "$path"
            printf -v backing '%b' "$backing"
            AUDIT_MOUNTS+=("$path")
            case $rest in '- '*) value=${rest#'- '} ;; *' - '*) value=${rest#*' - '} ;; *) scan_scope_error 'Mount 정보 해석 실패'; continue ;; esac
            fs=${value%% *}
            [[ ${AUDIT_CONFIG[scan_roots]} == AUTO ]] || continue
            case $path in /dev | /dev/* | /proc | /proc/* | /sys | /sys/*) continue ;; esac
            case $fs in
                ext2 | ext3 | ext4 | xfs | btrfs | zfs | f2fs | jfs | reiserfs | reiser4 | nilfs2 | vfat | msdos | exfat | ntfs | ntfs3 | fuseblk | overlay | aufs | tmpfs | ramfs | squashfs | erofs | iso9660 | udf) ;;
                proc | sysfs | devtmpfs | devpts | cgroup | cgroup2 | securityfs | debugfs | tracefs | pstore | mqueue | hugetlbfs | nfs | nfs4 | cifs | smb3 | fuse | fuse.* | autofs | rpc_pipefs | binfmt_misc | configfs | 9p | ceph | glusterfs | lustre | afs | nsfs | bpf | efivarfs | selinuxfs | smackfs | fusectl) continue ;;
                *) scan_scope_error "미확인 파일시스템 제외:$fs"; continue ;;
            esac
            candidate_paths+=("$path")
            candidate_devs+=("$dev")
            candidate_roots+=("$backing")
        done </proc/self/mountinfo
    else
        scan_scope_error 'Mount 목록을 읽지 못해 하위 Mount 제외를 보장하지 못함'
        [[ ${AUDIT_CONFIG[scan_roots]} == AUTO ]] && candidate_paths=(/)
    fi
    if [[ ${AUDIT_CONFIG[scan_roots]} != AUTO ]]; then
        candidate_paths=()
        while IFS= read -r root || [[ -n $root ]]; do
            [[ -n $root ]] || continue
            if [[ $root != /* || $root == *$'\n'* || $root == *'/../'* || $root == */.. ]]; then
                scan_scope_error '탐색 경로는 정규화 가능한 절대 경로여야 함'
                continue
            fi
            candidate_paths+=("$root")
        done <<<"${AUDIT_CONFIG[scan_roots]}"
    fi
    # A previous mount with the same device and a parent backing root covers a
    # bind alias only when its original path remains reachable (no overmount).
    for ((index=0; index<${#candidate_paths[@]}; index++)); do
        root=${candidate_paths[$index]}
        dev=${candidate_devs[$index]-custom}
        backing=${candidate_roots[$index]-$root}
        [[ ${seen_mounts["$root"]-} == 1 ]] && continue
        seen_mounts["$root"]=1
        covered=0
        for ((old_root=0; old_root<${#AUDIT_SCAN_ROOTS[@]}; old_root++)); do
            old_dev=${kept_devs[$old_root]}
            old_backing=${kept_roots[$old_root]}
            [[ $dev == "$old_dev" ]] || continue
            [[ $backing == "$old_backing" || $old_backing == / || $backing == "${old_backing%/}/"* ]] || continue
            value=${backing#"${old_backing%/}"}
            source="${AUDIT_SCAN_ROOTS[$old_root]%/}$value"
            shadow=0
            for path in "${AUDIT_MOUNTS[@]}"; do
                [[ $path == "${AUDIT_SCAN_ROOTS[$old_root]}" ]] && continue
                [[ ${AUDIT_SCAN_ROOTS[$old_root]} == / || $path == "${AUDIT_SCAN_ROOTS[$old_root]%/}/"* ]] || continue
                if [[ $source == "$path" || $source == "${path%/}/"* || $path == "${source%/}/"* ]]; then shadow=1; break; fi
            done
            ((shadow)) || { covered=1; break; }
        done
        ((covered)) && continue
        AUDIT_SCAN_ROOTS+=("$root")
        kept_devs+=("$dev")
        kept_roots+=("$backing")
    done
    ((${#AUDIT_SCAN_ROOTS[@]})) || { scan_scope_error '유효한 로컬 Mount 없음'; return; }
}

find_prune_args() {
    local root=$1 path
    FIND_PRUNE=('(' -path "$(scan_find_pattern "$AUDIT_OUTPUT_BASE")")
    for path in /proc /sys /dev "${AUDIT_MOUNTS[@]}"; do
        if [[ $path != "$root" && ($root == / || $path == "${root%/}/"*) ]]; then
            FIND_PRUNE+=(-o -path "$(scan_find_pattern "$path")")
        fi
    done
    FIND_PRUNE+=(')' -prune -o)
}

scan_collect() {
    local spec id kind policy root records rc record reason uid gid mode path previous approved
    local -a filters=()
    local -A approved_paths=()
    for spec in U-15:AUDIT_ORPHANS: U-23:AUDIT_SPECIAL_FILES:approved_special_files \
        U-25:AUDIT_WORLD_FILES:approved_world_writable_paths U-33:AUDIT_HIDDEN_FILES:approved_hidden_paths; do
        IFS=: read -r id kind policy <<<"$spec"
        [[ ${AUDIT_CONFIG[check_ids]} == ALL ]] || list_has "${AUDIT_CONFIG[check_ids]}" "$id" || continue
        AUDIT_SCAN_SELECTED[$kind]=$id
        AUDIT_SCAN_ITEM_COUNT[$kind]=0
        AUDIT_SCAN_ITEM_UNAPPROVED[$kind]=0
        AUDIT_SCAN_ITEM_ERROR[$kind]=
    done
    if ((${#AUDIT_SCAN_SELECTED[@]} == 0)); then AUDIT_SCAN_SCOPE='파일 탐색 항목 미선택'; return; fi
    scan_collect_roots
    for kind in "${!AUDIT_SCAN_SELECTED[@]}"; do
        AUDIT_SCAN_ITEM_ERROR[$kind]=$AUDIT_SCAN_ROOT_ERROR
        if ! find_printf_available; then
            AUDIT_SCAN_ITEM_ERROR[$kind]+='UNSUPPORTED_FIND: GNU find -printf 필요'
            continue
        fi
        policy=
        case $kind in
            AUDIT_ORPHANS)
                # 한 파일에 소유 계정·그룹이 모두 없으면 두 이유를 각각 기록한다.
                filters=('(' -nouser -printf 'nouser %U %G %m %p\0' ')' ',' '(' -nogroup -printf 'nogroup %U %G %m %p\0' ')') ;;
            AUDIT_SPECIAL_FILES)
                policy=approved_special_files
                filters=(-type f '(' -perm -4000 -o -perm -2000 ')' -printf 'special %U %G %m %p\0') ;;
            AUDIT_WORLD_FILES)
                policy=approved_world_writable_paths
                filters=(-type f -perm -0002 -printf 'world_writable %U %G %m %p\0') ;;
            AUDIT_HIDDEN_FILES)
                policy=approved_hidden_paths
                filters=(-name '.*' -printf 'hidden %U %G %m %p\0') ;;
        esac
        approved_paths=()
        if [[ -n $policy ]]; then
            scan_record "$kind" policy "$policy" "${AUDIT_CONFIG[$policy]}"
            while IFS= read -r path || [[ -n $path ]]; do
                [[ -z $path ]] || approved_paths["$path"]=1
            done <<<"${AUDIT_CONFIG[$policy]}"
        fi
        records="$AUDIT_WORK_DIR/find.${AUDIT_SCAN_SELECTED[$kind]}"
        for root in "${AUDIT_SCAN_ROOTS[@]}"; do
            ((AUDIT_INTERRUPTED == 0)) || break
            if ! capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" readlink -f -- "$root"; then
                AUDIT_SCAN_ITEM_ERROR[$kind]+="경로 해석 실패:$root; "; continue
            fi
            root=$AUDIT_COMMAND_STDOUT
            [[ -d $root ]] || { AUDIT_SCAN_ITEM_ERROR[$kind]+="디렉터리 없음:$root; "; continue; }
            find_prune_args "$root"
            rc=0
            find "$root" -xdev "${FIND_PRUNE[@]}" '(' "${filters[@]}" ')' >"$records" 2>"$records.err" || rc=$?
            scan_record "$kind" "$root" find_exit_code "$rc"
            if ((rc)); then
                AUDIT_SCAN_ITEM_ERROR[$kind]+="find 조회 실패:$root(rc=$rc); "
                scan_record "$kind" "$root" find_stderr "$(<"$records.err")" ERROR
            fi
            previous=
            while IFS= read -r -d '' record; do
                reason=${record%% *}; record=${record#* }
                uid=${record%% *}; record=${record#* }
                gid=${record%% *}; record=${record#* }
                mode=${record%% *}; path=${record#* }
                if [[ ! $uid =~ ^[0-9]+$ || ! $gid =~ ^[0-9]+$ || ! $mode =~ ^[0-7]{1,4}$ || $path != /* ]]; then
                    AUDIT_SCAN_ITEM_ERROR[$kind]+='Metadata 형식 오류; '; continue
                fi
                approved=${approved_paths[$path]:-0}
                scan_record "$kind" "$path" "$reason" "uid:$uid gid:$gid mode:$mode approved:$approved"
                if [[ $path != "$previous" ]]; then
                    ((AUDIT_SCAN_ITEM_COUNT[$kind] += 1))
                    ((approved)) || ((AUDIT_SCAN_ITEM_UNAPPROVED[$kind] += 1))
                fi
                previous=$path
            done <"$records"
            rm -f -- "$records" "$records.err"
        done
    done
}

# --- 판정 보조 — 입력과 확인된 근거를 해석 ---

require_accounts() {
    if ((AUDIT_ACCOUNTS_OK == 0)); then
        emit_result ERROR '계정 DB를 읽거나 해석하지 못함' '/etc/passwd' '형식·읽기 권한 확인' ACCOUNT_DB_FAILED
        return 1
    fi
}

account_emit() {
    local status=$1
    shift
    if [[ $status == GOOD && $AUDIT_NSS_EXTERNAL == 1 ]]; then
        emit_result MANUAL '로컬 계정 검사 완료; 외부 NSS 계정 범위 추가 확인 필요' "${2-}" 'LDAP/SSSD/NIS/Winbind의 계정·정책 확인'
    else emit_result "$status" "$@"; fi
}

pam_walk() {
    local path=$1 wanted=$2 depth=$3 file line type control module options include
    if ((depth > 20)) || [[ -v PAM_VISITED[$path] ]]; then PAM_ERROR+="PAM depth/cycle:$path; "; return; fi
    PAM_VISITED[$path]=1
    if ! file=$(target_path "$path") || [[ ! -r $file || ! -f $file ]]; then
        PAM_ERROR+="PAM read:$path; "; record_value "$path" "PAM.$wanted" '' ERROR
        unset 'PAM_VISITED[$path]'; return
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        include=
        if [[ $line =~ ^[[:space:]]*@include[[:space:]]+([^[:space:]]+) ]]; then
            include=${BASH_REMATCH[1]}
        elif [[ $line =~ ^[[:space:]]*-?([a-z]+)[[:space:]]+(\[[^]]+\]|[^[:space:]]+)[[:space:]]+([^[:space:]]+)(.*)$ ]]; then
            type=${BASH_REMATCH[1]} control=${BASH_REMATCH[2]} module=${BASH_REMATCH[3]} options=${BASH_REMATCH[4]}
            [[ $type == "$wanted" ]] || continue
            if [[ $control == include || $control == substack ]]; then
                include=$module
            else
                module=${module##*/}
                PAM_ROWS+="$path|$type|$control|$module|$options"$'\n'
                record_value "$path" "PAM.$type.$module.control" "$control"
            fi
        else PAM_ERROR+="PAM syntax:$path; "; fi
        if [[ -n $include ]]; then
            [[ $include == /* ]] || include="/etc/pam.d/$include"
            pam_walk "$include" "$wanted" "$((depth + 1))"
        fi
    done <"$file"
    unset 'PAM_VISITED[$path]'
}

pam_load() {
    PAM_ROWS= PAM_ERROR=
    PAM_VISITED=()
    pam_walk "$1" "$2" 0
    [[ -z $PAM_ERROR && -n $PAM_ROWS ]]
}

pam_simple_password_policy() {
    # One numeric parser serves resolved stacks and unverified static candidates.
    local rows=$PAM_ROWS path type control module options index=0 q=0 h=0 early=0
    local quality='' history='' legacy_history='' value key text minlen minclass dcredit lcredit ucredit ocredit remember
    local interpreted=${1:-1} config_dir real root_quality=0 root_history=0
    while IFS='|' read -r path type control module options; do
        [[ -n $module ]] || continue
        ((index += 1))
        case $module in
        pam_pwquality.so | pam_cracklib.so)
            [[ $control == required || $control == requisite ]] || early=1
            q=$index; quality+=$'\n'"$options" ;;
        pam_pwhistory.so)
            [[ $control == required || $control == requisite ]] || early=1
            h=$index; history+=$'\n'"$options" ;;
        pam_unix.so)
            legacy_history+=$'\n'"$options"
            [[ $control != sufficient || ($q != 0 && $h != 0) ]] || early=1 ;;
        *) if [[ $q == 0 || $h == 0 ]]; then [[ $control == sufficient || $control == \[* ]] && early=1; fi ;;
        esac
    done <<<"$rows"
    PAM_POLICY_QUALITY=$q
    ((q && h && !early)) || interpreted=0
    quality="$(active_lines /etc/security/pwquality.conf 2>/dev/null)"$'\n'"$quality"
    history="$(active_lines /etc/security/pwhistory.conf 2>/dev/null)"$'\n'"$history"
    ((h)) || history+=$'\n'"$legacy_history"
    for config_dir in /etc/security/pwquality.conf.d /etc/security/pwhistory.conf.d; do
        real=$(target_path "$config_dir") || continue
        if [[ -d $real ]] && compgen -G "$real/*.conf" >/dev/null; then interpreted=0; fi
    done
    for key in minlen minclass dcredit lcredit ucredit ocredit remember; do
        text=$quality; [[ $key == remember ]] && text=$history
        if ! value=$(option_number "$text" "$key" 'policy|PAM password'); then
            value=0; record_value 'policy|PAM password' "$key" "$value" DERIVED
            [[ $key != minlen && $key != remember ]] || interpreted=0
        fi
        printf -v "$key" '%s' "$value"
    done
    grep -Eq '(^|[[:space:]])enforce_for_root([[:space:]]|$)' <<<"$quality" && root_quality=1
    grep -Eq '(^|[[:space:]])enforce_for_root([[:space:]]|$)' <<<"$history" && root_history=1
    PAM_POLICY_LENGTH=$((minlen >= 8 && remember >= 4))
    PAM_POLICY_COMPLEXITY=$((minclass >= 4 || (dcredit < 0 && ocredit < 0 && (lcredit < 0 || ucredit < 0))))
    PAM_POLICY_EVIDENCE="minlen=$minlen minclass=$minclass credits=$dcredit/$lcredit/$ucredit/$ocredit remember=$remember root_quality=$root_quality root_history=$root_history"
    record_value 'policy|PAM password' evaluated "$PAM_POLICY_EVIDENCE interpreted=$interpreted" DERIVED
    ((interpreted)) || return 2
    ((PAM_POLICY_LENGTH && PAM_POLICY_COMPLEXITY)) || return 1
    ((root_quality && root_history)) || return 2
    return 0
}

option_number() {
    local raw number sign='' key=$2
    raw=$(awk -v k="$key" '{gsub(/=/," ");for(i=1;i<NF;i++)if($i==k && $(i+1)~/^-?[0-9]+$/)v=$(i+1)} END{if(v=="")exit 1;print v}' <<<"$1") || {
        [[ $# -lt 3 ]] || record_value "$3" "$key" '' MISSING; return 1
    }
    [[ $# -lt 3 ]] || record_value "$3" "$key" "$raw"
    number=${raw#-}; [[ $raw != -* ]] || sign=-
    number=${number#"${number%%[!0]*}"}; number=${number:-0}
    [[ $number != 0 ]] || sign=
    printf '%s\n' "$sign$number"
}

allowed_system_owners() {
    local name uid gid home shell out=0
    while IFS=: read -r name uid gid home shell; do
        [[ $name == bin || $name == sys ]] && out+=",$uid"
    done <<<"$AUDIT_ACCOUNT_ROWS"
    printf '%s' "$out"
}

service_gate() {
    local role=$1 state=${AUDIT_SERVICE_STATE[$1]:-UNKNOWN}
    record_value "service:$role" state "$state" "$([[ $state == UNKNOWN ]] && printf ERROR || printf OK)"
    record_value "service:$role" evidence "${AUDIT_SERVICE_EVIDENCE[$role]:-수집 없음}"
    record_value criterion service_state 'STOPPED/ABSENT=비실행, RUNNING=설정 검사, UNKNOWN=ERROR' DERIVED
    case $state in
    STOPPED | ABSENT)
        emit_result GOOD '서비스 비실행을 대체 조회로 확인' "${AUDIT_SERVICE_EVIDENCE[$role]}"
        ;;
    RUNNING) return 0 ;;
    *)
        emit_result ERROR '서비스 실행 여부를 확정하지 못함' "${AUDIT_SERVICE_EVIDENCE[$role]:-수집 없음}" '명령·권한·Runtime 및 비표준 데몬 확인' SERVICE_UNRESOLVED
        ;;
    esac
    return 1
}

check_file_rule() {
    local path=$1 allowed=$2 owners=${3:-0} optional=${4:-0}
    if ! path_exists "$path"; then
        if ((optional)); then
            emit_result GOOD '가이드상 파일 미존재 허용' "$path: 없음"
        else emit_result ERROR '필수 파일을 확인할 수 없음' "$path" '경로·권한·OS 제공 방식을 확인' MISSING_FILE; fi
        return
    fi
    local -A rules=([checked]=0 [errors]=0 [bad]='')
    file_rule_add "$path" "$allowed" "$owners" rules || :
    file_rule_result "$path" rules GOOD ERROR '배포판 기본 설정·서비스 영향 및 승인 예외 확인'
}

# State is the caller's associative array: checked/errors/bad. Metadata failures
# return 1; findings accumulate without changing the caller's result precedence.
file_rule_add() {
    if ! file_metadata "$1"; then
        local -n state=$4
        state[errors]=1
        return 1
    fi
    file_rule_compare "$@"
}

file_rule_compare() {
    # Metadata는 호출자가 한 번 수집한다. 이 함수는 외부 명령을 호출하지 않는다.
    local path=$1 allowed=$2 owners=$3 name
    local -n state=$4
    ((state[checked] += 1))
    if [[ $AUDIT_CURRENT_ID == U-37 && $path == /var/spool/cron/* && $path != /var/spool/cron/atjobs/* ]]; then
        name=${path##*/}
        if [[ -v AUDIT_ACCOUNT_UID[$name] ]]; then owners="0,${AUDIT_ACCOUNT_UID[$name]}"
        elif [[ $FILE_UID != 0 ]]; then
            record_value "$path" account_mapping "name:$name local_uid:미발견" MISSING
            if ((AUDIT_NSS_EXTERNAL)); then
                state[manual]=1
                owners="0,$FILE_UID"
            fi
        fi
    fi
    record_value "$path" metadata "uid:$FILE_UID gid:$FILE_GID mode:$FILE_MODE allowed_mode:$allowed allowed_uids:$owners"
    if ! list_has "$owners" "$FILE_UID" || ! mode_within "$FILE_MODE" "$allowed"; then
        ((${#state[bad]} >= 24000)) || state[bad]+="$path uid=$FILE_UID mode=$FILE_MODE"$'\n'
    fi
    return 0
}

file_rule_read() {
    local records=$1 allowed=$2 owners=$3 record type path
    local -n state=$4
    while IFS= read -r -d '' record; do
        type=${record%% *}; record=${record#* }
        FILE_UID=${record%% *}; record=${record#* }
        FILE_GID=${record%% *}; record=${record#* }
        FILE_MODE=${record%% *}; path=${record#* }
        if [[ $AUDIT_CURRENT_ID == U-24 ]]; then
            case ${path##*/} in
                .profile|.bash_profile|.bash_login|.bashrc|.bash_logout|.cshrc|.tcshrc|.zshrc|.zprofile|.kshrc|.login) ;;
                *) continue ;;
            esac
        fi
        if [[ $type != f || ! $FILE_UID =~ ^[0-9]+$ || ! $FILE_GID =~ ^[0-9]+$ || ! $FILE_MODE =~ ^[0-7]{1,4}$ ]]; then
            record_value "$path" metadata '파일 대상 또는 Metadata 조회 실패' ERROR
            state[errors]=1
            continue
        fi
        file_rule_compare "$path" "$allowed" "$owners" "$4"
    done <"$records"
}

file_rule_scan() {
    local dir=$1 allowed=$2 owners=$3 rc=0 records="$AUDIT_WORK_DIR/permissions.$BASHPID"
    local -n state=$4
    local -a options=() follow=(-P) types=(-type f)
    [[ -d $dir ]] || { record_value "$dir" directory no MISSING; return 0; }
    if ! find_printf_available; then
        state[manual]=1; record_value "$dir" collector 'GNU find -printf 필요' MISSING; return 0
    fi
    [[ -z ${5:-} ]] || options=(-maxdepth "$5")
    if [[ $AUDIT_CURRENT_ID == U-24 ]]; then
        follow=(-L); options=(-maxdepth 1); types=(-name '.*' '(' -type f -o -type l ')')
    fi
    record_value "$dir" scope "maxdepth:${5:-전체} allowed_mode:$allowed allowed_uids:$owners"
    find_prune_args "$dir"
    find "${follow[@]}" "$dir" -xdev "${options[@]}" "${FIND_PRUNE[@]}" "${types[@]}" \
        -printf '%y %U %G %m %p\0' >"$records" 2>"$records.err" || rc=$?
    if ((rc)); then state[errors]=1; record_value "$dir" find_stderr "$(<"$records.err")" ERROR; fi
    file_rule_read "$records" "$allowed" "$owners" "$4"
    rm -f -- "$records" "$records.err"
}

file_rule_paths() {
    local allowed=$1 owners=$2 state_name=$3 path rc=0 records="$AUDIT_WORK_DIR/permissions.$BASHPID"
    local -n state=$3
    shift 3
    local -a paths=()
    for path in "$@"; do path_exists "$path" && paths+=("$path"); done
    ((${#paths[@]})) || return 0
    if ! find_printf_available; then state[manual]=1; record_value find capability '-printf 미지원' MISSING; return 0; fi
    find -H "${paths[@]}" -xdev -maxdepth 0 -printf '%y %U %G %m %p\0' >"$records" 2>"$records.err" || rc=$?
    if ((rc)); then state[errors]=1; record_value find stderr "$(<"$records.err")" ERROR; fi
    file_rule_read "$records" "$allowed" "$owners" "$state_name"
    rm -f -- "$records" "$records.err"
}

file_rule_result() {
    # label, state, success/empty statuses, manual action, emitter, error code.
    local label=$1 good=${3:-GOOD} empty=${4:-MANUAL} manual=${5:-} emitter=${6:-emit_result} code=${7:-STAT_FAILED}
    local -n state=$2
    record_value "$label" checked "${state[checked]}"
    record_value "$label" collection_errors "${state[errors]}"
    if [[ -n ${state[bad]} ]]; then
        "$emitter" VULNERABLE "$label 소유자·권한 기준 초과" "${state[bad]}" "$manual"
    elif ((state[errors])) || [[ ${state[checked]} == 0 && $empty == ERROR ]]; then
        "$emitter" ERROR "$label Metadata 수집 미완료" "checked=${state[checked]}" "$manual" "$code"
    elif (( ${state[manual]:-0} )); then
        "$emitter" MANUAL "$label 수집 기능 또는 소유 계정 확인 필요" "checked=${state[checked]}" "$manual"
    elif ((state[checked] == 0)); then
        "$emitter" "$empty" "$label 점검 대상 파일 없음" 'checked=0' "$manual"
    else "$emitter" "$good" "$label 소유자·권한 기준 충족" "checked=${state[checked]}" "$manual"; fi
}

check_disabled_service() {
    local role=$1
    service_gate "$role" || return
    record_value policy required_services "${AUDIT_CONFIG[required_services]}" DERIVED
    record_value criterion disabled_service '실행 중이고 필요 목록에 없으면 VULNERABLE, 필요 목록 포함은 MANUAL' DERIVED
    if list_has "${AUDIT_CONFIG[required_services]}" "$role"; then
        emit_result MANUAL '업무상 필요하다고 지정한 서비스가 실행 중' "${AUDIT_SERVICE_EVIDENCE[$role]}" '필요성·승인 근거·보완 통제를 검토; 자동 GOOD 면제 없음'
    else emit_result VULNERABLE '비활성화 대상 서비스가 실행 중' "${AUDIT_SERVICE_EVIDENCE[$role]}" '업무상 필요성과 서비스 중지 영향을 확인'; fi
}

runtime_provider() {
    # Product identity comes from runtime evidence, never leftover files/packages.
    local role=$1 specs provider processes units name unit matched evidence count=0
    RUNTIME_PROVIDER=unknown
    evidence=" ${AUDIT_SERVICE_EVIDENCE[$role]:-} "
    case $role in
    ftp) specs=$'vsftpd|vsftpd|vsftpd.service\nproftpd|proftpd|proftpd.service\npure-ftpd|pure-ftpd|pure-ftpd.service\nftpd|ftpd|ftpd.service' ;;
    mail) specs=$'postfix|postfix|postfix.service\nsendmail|sendmail|sendmail.service\nexim|exim exim4|exim.service exim4.service\nopensmtpd||opensmtpd.service smtpd.service' ;;
    *) return 2 ;;
    esac
    while IFS='|' read -r provider processes units; do
        matched=0
        for name in $processes; do grep -Fxq -- "$name" <<<"$AUDIT_PROCESS_NAMES" && matched=1; done
        for unit in $units; do
            case $evidence in
            *" $unit=active "* | *" $unit=activating "* | *" $unit=reloading "*) matched=1 ;;
            esac
        done
        ((matched)) && { ((count += 1)); RUNTIME_PROVIDER=$provider; }
    done <<<"$specs"
    record_value "service:$role" provider_candidates "$count" DERIVED
    if ((count != 1)); then RUNTIME_PROVIDER=unknown; record_value "service:$role" provider unknown MISSING; return 2; fi
    record_value "service:$role" provider "$RUNTIME_PROVIDER"
    return 0
}

ftp_config() {
    local line candidate='' path arg option
    local -a args=()
    FTP_CONFIG_PATH=
    record_value criterion ftp_config '실행 제품이 vsftpd이고 Listener의 단일 설정 경로·읽기 가능 여부를 확정해야 사용' DERIVED
    runtime_provider ftp || return 2
    [[ $RUNTIME_PROVIDER == vsftpd ]] || return 2
    # Query only this product; do not collect all process arguments.
    capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ps -C vsftpd -o args= || { record_value ps vsftpd_arguments '조회 실패' ERROR; return 2; }
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        read -r -a args <<<"$line"
        ((${#args[@]})) || continue
        record_value ps vsftpd_arg_count "${#args[@]}" DERIVED
        # Session children may replace their process title; the listener is needed.
        case ${args[0]##*/} in vsftpd:) continue ;; vsftpd) ;; *) record_value ps vsftpd_parse unrecognized_process_title DERIVED; return 2 ;; esac
        case ${#args[@]} in
        1) path=/etc/vsftpd.conf ;;
        2)
            path=${args[1]}; [[ $path != -o* ]] || record_value ps vsftpd_option -o DERIVED
            [[ $path == /* ]] || { record_value ps vsftpd_parse config_path_not_absolute DERIVED; return 2; } ;;
        *)
            option=none
            for arg in "${args[@]:1}"; do [[ $arg != -o* ]] || option=-o; done
            record_value ps vsftpd_option "$option" DERIVED
            record_value ps vsftpd_parse unsupported_argument_layout DERIVED
            return 2 ;;
        esac
        [[ $path != *$'\n'* && $path != *'"'* && $path != *"'"* && $path != *'\'* ]] || { record_value ps vsftpd_parse ambiguous_path_quoting DERIVED; return 2; }
        [[ -z $candidate || $candidate == "$path" ]] || { record_value ps vsftpd_parse conflicting_config_paths DERIVED; return 2; }
        candidate=$path
    done <<<"$AUDIT_COMMAND_STDOUT"
    [[ -n $candidate ]] || { record_value ps vsftpd_config '확정하지 못함' MISSING; return 2; }
    record_value ps vsftpd_config "$candidate"
    active_lines "$candidate" >/dev/null || { record_value "$candidate" readable false ERROR; return 2; }
    FTP_CONFIG_PATH=$candidate
    return 0
}

postfix_runtime_scope() {
    # Bind postconf to the configuration of exactly one identified Postfix master.
    local pid executable directory='' candidate='' masters=0
    MAIL_CONFIG_DIR=
    command -v postconf >/dev/null 2>&1 || { record_value command postconf unavailable MISSING; return 2; }
    capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ps -C master -o pid= || { record_value ps postfix_master '조회 실패' ERROR; return 2; }
    local pids=$AUDIT_COMMAND_STDOUT
    while read -r pid; do
        [[ -n $pid ]] || continue
        [[ $pid =~ ^[1-9][0-9]*$ ]] || return 2
        executable=$(readlink -f -- "/proc/$pid/exe" 2>/dev/null) || { record_value "/proc/$pid/exe" target '조회 실패' ERROR; return 2; }
        record_value "/proc/$pid/exe" target "$executable"
        case $executable in */postfix/master | */postfix/*/master) ;; *) continue ;; esac
        ((masters += 1))
        # Whitelist one environment field. Other environment values are not saved.
        capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" awk 'BEGIN{RS="\0"} /^MAIL_CONFIG=/{sub(/^MAIL_CONFIG=/,"");print;exit}' "/proc/$pid/environ" || { record_value "/proc/$pid/environ" MAIL_CONFIG '조회 실패' ERROR; return 2; }
        directory=$AUDIT_COMMAND_STDOUT
        record_value "/proc/$pid/environ" MAIL_CONFIG "$directory" "$([[ -n $directory ]] && printf OK || printf MISSING)"
        [[ $directory == /* && $directory != *$'\n'* ]] || return 2
        [[ -z $candidate || $candidate == "$directory" ]] || return 2
        candidate=$directory
    done <<<"$pids"
    # Additional instances need their own review, not the primary main.cf values.
    record_value postfix instance_count "$masters" DERIVED
    ((masters == 1)) && [[ -n $candidate ]] || return 2
    active_lines "$candidate/main.cf" >/dev/null || { record_value "$candidate/main.cf" readable false ERROR; return 2; }
    MAIL_CONFIG_DIR=$candidate
    return 0
}

mail_provider() {
    local line executable path=/etc/mail/sendmail.cf count=0 daemon=0 i option
    local -a args=()
    MAIL_PROVIDER=unknown
    MAIL_CONFIG_DIR=
    SENDMAIL_PRIVACY_OPTIONS=
    runtime_provider mail || return 0
    case $RUNTIME_PROVIDER in
    postfix)
        if postfix_runtime_scope; then MAIL_PROVIDER=postfix; fi
        ;;
    sendmail)
        capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ps -C sendmail -o args= || { record_value ps sendmail_arguments '조회 실패' ERROR; return 0; }
        while IFS= read -r line; do
            [[ -n $line ]] || continue
            read -r -a args <<<"$line"
            ((${#args[@]})) || continue
            record_value ps sendmail_arg_count "${#args[@]}" DERIVED
            executable=${args[0]##*/}
            # A rewritten title does not prove which -C/-O options started it.
            [[ $executable == sendmail ]] || { record_value ps sendmail_parse unrecognized_or_rewritten_title DERIVED; return 0; }
            path=/etc/mail/sendmail.cf
            daemon=0
            for ((i = 1; i < ${#args[@]}; i++)); do
                case ${args[i]} in
                -bd | -bD) daemon=1; record_value ps sendmail_option "${args[i]}" DERIVED ;;
                -C)
                    record_value ps sendmail_option -C DERIVED
                    ((i += 1)); ((i < ${#args[@]})) || { record_value ps sendmail_parse missing_config_argument DERIVED; return 0; }
                    path=${args[i]} ;;
                -C*) path=${args[i]#-C}; record_value ps sendmail_option -C DERIVED ;;
                -Ac | -O* | -o*)
                    option=${args[i]:0:2}; [[ ${args[i]} != -Ac ]] || option=-Ac
                    record_value ps sendmail_option "$option" DERIVED
                    record_value ps sendmail_parse unsupported_policy_override DERIVED
                    return 0 ;;
                esac
            done
            record_value ps sendmail_scope "config=$path daemon_mode=$daemon" DERIVED
            ((daemon)) || { record_value ps sendmail_parse daemon_mode_not_confirmed DERIVED; return 0; }
            # Existing Sendmail checks consume this canonical file only.
            [[ $path == /etc/mail/sendmail.cf ]] || { record_value ps sendmail_parse noncanonical_config_path DERIVED; return 0; }
            ((count += 1))
        done <<<"$AUDIT_COMMAND_STDOUT"
        record_value ps sendmail_instances "$count" DERIVED
        ((count == 1)) || { record_value ps sendmail_parse single_daemon_not_confirmed DERIVED; return 0; }
        SENDMAIL_PRIVACY_OPTIONS=$(active_lines /etc/mail/sendmail.cf) || { record_value /etc/mail/sendmail.cf readable false ERROR; return 0; }
        SENDMAIL_PRIVACY_OPTIONS=$(grep PrivacyOptions <<<"$SENDMAIL_PRIVACY_OPTIONS") || SENDMAIL_PRIVACY_OPTIONS=
        record_value /etc/mail/sendmail.cf PrivacyOptions "$SENDMAIL_PRIVACY_OPTIONS" "$([[ -n $SENDMAIL_PRIVACY_OPTIONS ]] && printf OK || printf MISSING)"
        MAIL_PROVIDER=sendmail
        ;;
    exim | opensmtpd) MAIL_PROVIDER=$RUNTIME_PROVIDER ;;
    esac
    return 0
}

postfix_value() {
    local key=$1
    [[ ${MAIL_PROVIDER:-unknown} == postfix && ${MAIL_CONFIG_DIR:-} == /* ]] || return 2
    capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" postconf -c "$MAIL_CONFIG_DIR" -h "$key" || { record_value "postconf:$MAIL_CONFIG_DIR" "$key" '조회 실패' ERROR; return 2; }
    record_value "postconf:$MAIL_CONFIG_DIR" "$key" "$AUDIT_COMMAND_STDOUT"
    printf '%s' "$AUDIT_COMMAND_STDOUT"
}

ftp_gate() {
    service_gate ftp || return 1
    ftp_config && return 0
    record_value service:ftp config_scope "provider=${RUNTIME_PROVIDER:-unknown}; 유효 설정 미확정" MISSING
    emit_result MANUAL 'FTP Provider의 유효 설정 확인 필요' '' 'Custom 경로·ProFTPD/Pure-FTPd의 Banner·TLS·root 인증 정책을 확인'
    return 1
}

package_version_check() {
    local role=$1 pattern=$2 summary=$3 manual=$4 versions state=OK
    service_gate "$role" || return
    versions=$(grep -Ei "$pattern" <<<"$AUDIT_PACKAGE_DATA")
    [[ -n $versions ]] || state=MISSING
    ((AUDIT_PACKAGE_COMPLETE)) || state=ERROR
    record_value "packages:$AUDIT_PACKAGE_MANAGER" "$role" "$versions" "$state"
    record_value criterion "${role}_version" "$manual" DERIVED
    emit_result MANUAL "$summary" "$versions" "$manual"
}

sendmail_options_check() {
    # Reuse mail_provider's PrivacyOptions snapshot; emit one result.
    local required=$1 good=$2 manual=$3 action=$4 token
    for token in $required; do
        if ! grep -qi -- "$token" <<<"$SENDMAIL_PRIVACY_OPTIONS"; then
            emit_result MANUAL "$manual" "$SENDMAIL_PRIVACY_OPTIONS" "$action"
            return
        fi
    done
    emit_result GOOD "$good" "$SENDMAIL_PRIVACY_OPTIONS"
}

dns_canonical_config() {
    local path
    DNS_CANONICAL=
    command -v named-checkconf >/dev/null 2>&1 || { record_value command named-checkconf unavailable MISSING; return 2; }
    for path in /etc/named.conf /etc/bind/named.conf; do
        path_exists "$path" || { record_value "$path" present false MISSING; continue; }
        # -x prevents printing TSIG secrets; never fall back to unmasked -p.
        capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" named-checkconf -px "$path" || { record_value "$path" canonical '조회 실패' ERROR; return 2; }
        DNS_CANONICAL=$AUDIT_COMMAND_STDOUT
        [[ -n $DNS_CANONICAL ]] && return 0
    done
    return 2
}

dns_acl_check() {
    local directive=$1 flat blocks
    service_gate dns || return
    record_value criterion "$directive" '정규화한 ACL의 any=VULNERABLE; none/개별 ACL도 상속·View·Zone 검토 MANUAL' DERIVED
    if ! dns_canonical_config; then
        emit_result MANUAL 'DNS 유효 설정의 안전한 정규화가 필요' "$directive: Provider 또는 Canonical Parser 미지원" 'BIND named-checkconf -px 또는 Provider별 동일 기능으로 전체 Include/Zone/View ACL 확인'
        return
    fi
    flat=$(tr '\n' ' ' <<<"$DNS_CANONICAL")
    blocks=$(grep -oE "${directive}[[:space:]]*\{[^}]*\}" <<<"$flat") || blocks=
    record_value named-checkconf "$directive" "$blocks" "$([[ -n $blocks ]] && printf OK || printf MISSING)"
    if grep -Eq "${directive}[[:space:]]*\{[[:space:]]*any[[:space:]]*;" <<<"$flat"; then
        emit_result VULNERABLE 'DNS ACL에 전체 허용 설정 발견' "$directive { any; }" '해당 Zone/View의 적용 범위와 승인 대상 확인'
    else
        if [[ -n $blocks ]] && ! grep -Ev "${directive}[[:space:]]*\{[[:space:]]*none[[:space:]]*;[[:space:]]*\}" <<<"$blocks" | grep -q .; then
            emit_result MANUAL '명시적 DNS ACL은 none; 상속·다른 ACL 구문 검토 필요' "$blocks" 'Canonical 설정에서 모든 Zone/View가 해당 제한을 상속하는지 확인'
        else emit_result MANUAL 'DNS ACL의 승인 대상·TSIG·상속 관계 검토 필요' "${blocks:-명시적 ACL 없음}" '기본값을 추정하지 않고 Provider Version·모든 Zone/View 확인'; fi
    fi
}

snmp_config() {
    local p text count=0
    SNMP_TEXT=
    SNMP_UNCERTAIN=0
    for p in /etc/snmp/snmpd.conf /etc/snmpd.conf; do
        path_exists "$p" || { record_value "$p" present false MISSING; continue; }
        ((count += 1))
        text=$(active_lines "$p") || { record_value "$p" readable false ERROR; return 2; }
        record_value "$p" readable true
        SNMP_TEXT+=$'\n'"$text"
        grep -qiE '^[[:space:]]*(include|includeFile|includeDir|includeSearch)' <<<"$text" && SNMP_UNCERTAIN=1
    done
    ((count == 1)) || SNMP_UNCERTAIN=1
    record_value snmp config_scope "files=$count include_uncertain=$SNMP_UNCERTAIN" DERIVED
    ((count > 0))
}

community_strong() {
    local value=$1 length=${#1} alpha=0 digit=0 special=0 default_name=0
    [[ $value =~ [A-Za-z] ]] && alpha=1
    [[ $value =~ [0-9] ]] && digit=1
    [[ $value =~ [^A-Za-z0-9] ]] && special=1
    [[ ${value,,} == public || ${value,,} == private ]] && default_name=1
    COMMUNITY_PROPERTIES="length=$length alpha=$alpha digit=$digit special=$special default_name=$default_name"
    ((!default_name && alpha && digit && ((special && length >= 8) || (!special && length >= 10))))
}

snmp_audit_check() {
    local id=$1 directive secret source rest rules=0 communities=0 bad=0 broad=0 legacy=0
    service_gate snmp || return
    snmp_config || { emit_result ERROR 'SNMP 설정 읽기 실패' '' '' READ_FAILED; return; }
    grep -qiE '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]' <<<"$SNMP_TEXT" && legacy=1
    while read -r directive secret source rest; do
        case ${directive,,} in
        rocommunity | rwcommunity | rocommunity6 | rwcommunity6)
            ((communities += 1)); community_strong "$secret" || bad=1 ;;
        com2sec | com2sec6)
            read -r secret _ <<<"$rest"
            if community_strong "$secret"; then ((communities += 1)); else bad=1; fi ;;
        *) continue ;;
        esac
        ((rules += 1))
        case ${source:-default} in default | 0.0.0.0/0 | ::/0) broad=1 ;; esac
        record_value snmp "$directive.rule_$rules" "source:${source:-<미지정>} effective_source:${source:-default} $COMMUNITY_PROPERTIES"
        secret=; rest=
    done <<<"$SNMP_TEXT"
    local evidence="rules=$rules communities=$communities legacy_auth=$legacy complexity_failed=$bad broad_source=$broad include_uncertain=$SNMP_UNCERTAIN"
    case $id in
    59)
        record_value criterion snmp_version 'v1/v2c Community 인증 설정 발견=VULNERABLE; 미발견도 v3 전용 확인은 MANUAL' DERIVED
        if ((legacy)); then emit_result VULNERABLE 'SNMP v1/v2c Community 인증 설정 발견' "$evidence" 'v3 설정이 함께 있어도 v1/v2c 허용을 제거했는지 확인'
        else emit_result MANUAL '명시적 Community 설정 미발견; v3 전용 운용 확인 필요' "$evidence" 'VACM Security Model·Custom Config·Daemon Option 및 실제 v1/v2 응답 제한 확인'; fi ;;
    60)
        record_value criterion community 'public/private 제외, 영문+숫자 필수; 특수문자 포함 8자 이상 또는 미포함 10자 이상' DERIVED
        if ((bad)); then emit_result VULNERABLE 'Community 복잡성 기준 미충족' "$evidence"
        elif ((communities && !SNMP_UNCERTAIN)); then emit_result GOOD '명시적 Community가 2026 복잡성 수치 충족' "$evidence" 'SNMPv3 인증 비밀번호는 별도 정책 검토'
        else emit_result MANUAL 'SNMP Community/v3 비밀번호 전체 정책 확인 필요' "$evidence" 'Include·com2sec·v3 USM 인증 방식·비밀번호 정책 확인'; fi ;;
    61)
        record_value criterion snmp_acl 'Source 생략/default/0.0.0.0/0/::/0=VULNERABLE; 나머지는 전체 ACL 적용 MANUAL' DERIVED
        if ((broad)); then emit_result VULNERABLE 'SNMP 전체 Source 허용 설정' "$evidence"
        else emit_result MANUAL 'SNMP ACL 설정의 전체 적용 확인 필요' "$evidence" 'view 존재만으로 양호 처리하지 않음. VACM·IPv6·Include·실제 Source 제한 확인'; fi ;;
    esac
}

scan_result() {
    local kind=$1 description=$2 policy_key=$3 count missing error evidence
    count=${AUDIT_SCAN_ITEM_COUNT[$kind]:-0}
    missing=${AUDIT_SCAN_ITEM_UNAPPROVED[$kind]:-0}
    error=${AUDIT_SCAN_ITEM_ERROR[$kind]-}
    evidence="scope=$AUDIT_SCAN_SCOPE findings=$count unreviewed=$missing"
    [[ -z $error ]] || evidence+="; 조회 실패:$error"
    record_value filesystem "$kind" "$evidence"
    record_value filesystem roots "${AUDIT_SCAN_ROOTS[*]}"
    if [[ $kind == AUDIT_ORPHANS && $count -gt 0 && $AUDIT_NSS_EXTERNAL == 0 && $AUDIT_ACCOUNTS_OK == 1 ]]; then
        emit_result VULNERABLE '소유 계정 또는 그룹이 없는 파일·디렉터리 발견' "$evidence" 'nouser/nogroup별 경로·UID·GID 확인; 조회 실패 경로는 별도 확인'
    elif [[ $error == *UNSUPPORTED_FIND* ]]; then
        emit_result MANUAL '지원하는 find 기능 없음' "$evidence" 'GNU find -printf로 해당 항목을 점검'
    elif [[ -n $error ]]; then
        emit_result ERROR '파일 탐색 조회 실패; 발견값은 조회 기록에 보존' "$evidence" '경로·권한·NSS 조회 오류 확인' FIND_FAILED
    elif [[ $kind == AUDIT_ORPHANS && $AUDIT_ACCOUNTS_OK == 0 ]]; then
        emit_result ERROR '로컬 계정 DB 조회 실패' "$evidence" 'passwd 형식·읽기 권한 확인' ACCOUNT_DB_FAILED
    elif [[ $kind == AUDIT_ORPHANS && $count -gt 0 ]]; then
        emit_result MANUAL 'find에서 소유 계정·그룹 미확인; 외부 NSS 응답 상태 확인 필요' "$evidence" 'NSS Provider 설정의 존재와 조회 성공을 동일하게 취급하지 않음; 실제 계정 삭제 여부 확인'
    elif [[ ${AUDIT_CONFIG[scan_roots]} != AUTO ]]; then
        emit_result MANUAL '사용자 지정 범위 결과; 전체 시스템 범위 확인 필요' "$evidence"
    elif ((count == 0)); then
        emit_result GOOD "$description: 점검 범위에서 미발견" "$evidence"
    elif ((missing == 0)) && [[ -n $policy_key ]]; then
        emit_result GOOD "$description: 명시한 승인 목록 충족" "$evidence"
    else emit_result MANUAL "$description: 미승인 경로 검토 필요" "$evidence" '조회 기록의 전체 발견값·승인 여부와 운영상 필요성 확인'; fi
}

# --- 항목별 점검 — U-01 ~ U-67 ---

ssh_read_config() {
    # SSH만 first-match로 읽는다. Include의 Match도 공유 상태에 반영한다.
    local path=$1 text line key value rest pattern file
    local -a patterns=()
    if [[ -v SSH_VISITED[$path] ]]; then SSH_CONFIG_ERROR+="중복/순환 Include:$path; "; return; fi
    SSH_VISITED[$path]=1
    text=$(read_target "$path") || { SSH_CONFIG_ERROR+="읽기 실패:$path; "; return; }
    while IFS= read -r line; do
        line=${line%%#*}
        read -r key value rest <<<"$line"
        case ${key,,} in
            match) SSH_HAS_MATCH=1; record_value "$path" Match "$value $rest" ;;
            include)
                read -r -a patterns <<<"$value $rest"
                for pattern in "${patterns[@]}"; do
                    if [[ $pattern == *\"* || $pattern == *\'* || $pattern == *\\* ]]; then SSH_CONFIG_ERROR+='Include 경로 구문 미해석; '; continue; fi
                    [[ $pattern == /* ]] || pattern="/etc/ssh/$pattern"
                    while IFS= read -r file; do ssh_read_config "$file"; done < <(compgen -G "$pattern" | sort)
                done ;;
            permitrootlogin)
                record_value "$path" PermitRootLogin "$value"
                if [[ -z $SSH_STATIC_VALUE && $SSH_HAS_MATCH == 0 ]]; then SSH_STATIC_VALUE=$value; fi ;;
        esac
    done <<<"$text"
}

check_u_01() {
    local state=${AUDIT_SERVICE_STATE[ssh]:-UNKNOWN} role value='' effective=0 evidence='' telnet=${AUDIT_SERVICE_STATE[telnet]:-UNKNOWN}
    local SSH_STATIC_VALUE='' SSH_HAS_MATCH=0 SSH_CONFIG_ERROR=''
    local -A SSH_VISITED=()
    for role in ssh telnet r; do record_value "service:$role" runtime "state:${AUDIT_SERVICE_STATE[$role]:-UNKNOWN} ${AUDIT_SERVICE_EVIDENCE[$role]:-수집 없음}"; done
    case $state in
        RUNNING)
            if command -v sshd >/dev/null 2>&1 && capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" sshd -T; then
                value=$(awk '$1=="permitrootlogin"{print $2;exit}' <<<"$AUDIT_COMMAND_STDOUT")
                [[ -z $value ]] || effective=1
                record_value 'sshd -T' PermitRootLogin "$value"
            fi
            ssh_read_config /etc/ssh/sshd_config
            if ((effective == 0)); then value=$SSH_STATIC_VALUE; fi
            evidence="PermitRootLogin:${value:-미설정} effective:$effective Match:$SSH_HAS_MATCH; $SSH_CONFIG_ERROR"
            if ((SSH_HAS_MATCH)) || [[ -n $SSH_CONFIG_ERROR ]]; then
                emit_result MANUAL 'SSH 조건별 설정 또는 정적 조회 범위 확인 필요' "$evidence" 'Include 내부 Match를 포함해 접속 조건별 sshd -T -C로 확인'; return
            fi
            case ${value,,} in
                yes|prohibit-password|without-password|forced-commands-only)
                    emit_result VULNERABLE 'root 직접 SSH 접속을 허용하는 설정' "$evidence" '확인된 전역 허용값과 조건별 예외를 검토'; return ;;
                no) ;;
                *) emit_result MANUAL 'root SSH 차단 설정을 확정하지 못함' "$evidence" '실제 Provider·설정 경로·sshd 조회 실패 확인'; return ;;
            esac
            ;;
        STOPPED|ABSENT) evidence="SSH $state" ;;
        *) emit_result ERROR 'SSH 실행 여부 조회 실패' "${AUDIT_SERVICE_EVIDENCE[ssh]:-수집 없음}" '' SERVICE_UNRESOLVED; return ;;
    esac
    if [[ $telnet == RUNNING || ${AUDIT_SERVICE_STATE[r]:-UNKNOWN} == RUNNING ]]; then
        emit_result MANUAL '레거시 원격 터미널 root 제한 확인 필요' "$evidence" 'Telnet/rlogin 인증 경로 확인'
    elif [[ $telnet == UNKNOWN || ${AUDIT_SERVICE_STATE[r]:-UNKNOWN} == UNKNOWN ]]; then
        emit_result MANUAL '다른 원격 터미널 범위 미확정' "$evidence"
    else emit_result GOOD '원격 root 직접 접속 경로가 비실행 또는 차단됨' "$evidence"; fi
}

check_u_02() {
    require_accounts || return
    record_value criterion password_policy 'minlen>=8, remember>=4, min_days>=1, max_days=1~90; minclass>=4 또는 dcredit<0·ocredit<0·(lcredit<0 또는 ucredit<0); root 품질·이력 강제 적용'
    local strict=0 rc=0 path pooled='' min='' max='' name state alg lo hi bad_age='' bad_defaults='' age_unknown='' parse_error=0 defaults_good=0
    if path_exists /etc/pam.d/passwd && pam_load /etc/pam.d/passwd password; then strict=1
    else
        for path in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/passwd /etc/pam.d/login; do
            path_exists "$path" || continue
            pam_load "$path" password || :
            pooled+="$PAM_ROWS"$'\n'
        done
        PAM_ROWS=$pooled
    fi
    pam_simple_password_policy "$strict" || rc=$?
    if min=$(config_value /etc/login.defs PASS_MIN_DAYS 2>/dev/null); then
        if [[ $min =~ ^[0-9]{1,9}$ ]]; then ((10#$min >= 1)) || bad_defaults+="PASS_MIN_DAYS:$min; "
        else parse_error=1; fi
    fi
    if max=$(config_value /etc/login.defs PASS_MAX_DAYS 2>/dev/null); then
        if [[ $max =~ ^[0-9]{1,9}$ ]]; then ((10#$max >= 1 && 10#$max <= 90)) || bad_defaults+="PASS_MAX_DAYS:$max; "
        else parse_error=1; fi
    fi
    [[ -z $min || -z $max || -n $bad_defaults || $parse_error == 1 ]] || defaults_good=1
    if ((AUDIT_SHADOW_OK)); then
        while IFS=: read -r name state alg lo hi _; do
            [[ $state == HASH || $state == EMPTY ]] || continue
            if [[ ! $lo =~ ^[0-9]{1,9}$ || ! $hi =~ ^[0-9]{1,9}$ ]]; then age_unknown+="$name min_days:$lo max_days:$hi; "
            elif ((10#$lo < 1 || 10#$hi < 1 || 10#$hi > 90)); then bad_age+="$name min_days:$lo max_days:$hi; "; fi
        done <<<"$AUDIT_SHADOW_ROWS"
    fi
    local evidence="$PAM_POLICY_EVIDENCE PASS_MIN_DAYS:${min:-미설정} PASS_MAX_DAYS:${max:-미설정}; $bad_defaults$bad_age$age_unknown"
    if [[ -n $bad_defaults || -n $bad_age ]]; then
        emit_result VULNERABLE '조회한 비밀번호 사용기간이 기준 미충족' "$evidence" '고객사 승인 예외는 별도 검토; 다른 PAM 해석 불확실성으로 확인된 취약값을 덮어쓰지 않음'
    elif ((rc == 1)); then
        emit_result VULNERABLE '적용 경로가 확인된 필수 PAM 비밀번호 정책의 수치 미충족' "$evidence"
    elif ((parse_error || !AUDIT_SHADOW_OK)); then
        emit_result ERROR '비밀번호 기간값 해석 또는 shadow 조회 실패' "$evidence" '원래 값과 파일 읽기 권한 확인' PASSWORD_POLICY_READ_FAILED
    elif ((rc == 0 && defaults_good)) && [[ -z $age_unknown ]]; then
        account_emit GOOD '비밀번호 품질·이력·root 적용과 사용기간 기준 충족' "$evidence"
    else
        emit_result MANUAL '확인한 값은 기록했으나 미설정·유효 PAM 적용 범위 확인 필요' "$evidence" 'PAM Control/Include·품질·이력·기존 계정의 미설정 기간 확인'
    fi
}

check_u_03() {
    local default_deny default_root_enforced=0 entry path type control module options value deny module_root
    local preauth authfail unix_index reset index checked=0 complete=1 evidence='' root_enforced
    default_deny=$(config_value /etc/security/faillock.conf deny 2>/dev/null) || default_deny=''
    default_deny=$(option_number "deny=$default_deny" deny) || default_deny=''
    if active_lines /etc/security/faillock.conf 2>/dev/null | grep -Eq '^[[:space:]]*even_deny_root([[:space:]]|$)'; then default_root_enforced=1; fi
    for entry in /etc/pam.d/login /etc/pam.d/sshd /etc/pam.d/su; do
        path_exists "$entry" || continue
        ((checked += 1))
        if ! pam_load "$entry" auth; then
            complete=0
            evidence+="$entry: $PAM_ERROR "
            continue
        fi
        preauth=0 authfail=0 unix_index=0 reset=0 index=0 root_enforced=1 deny=$default_deny
        while IFS='|' read -r path type control module options; do
            [[ -n $module ]] || continue
            ((index += 1))
            if [[ $module == pam_faillock.so ]]; then
                value=$(option_number "$options" deny "$path|$module") && deny=$value
                module_root=$default_root_enforced
                [[ $options =~ (^|[[:space:]])even_deny_root($|[[:space:]]) ]] && module_root=1
                ((module_root)) || root_enforced=0
                [[ $options == *preauth* && ($control == required || $control == requisite) ]] && preauth=$index
                [[ $options == *authfail* && ($control == required || $control == requisite || $control == '[default=die]') ]] && authfail=$index
                [[ $options == *authsucc* ]] && reset=1
            elif [[ $module == pam_unix.so ]]; then
                unix_index=$index
            elif ((preauth == 0)) && [[ $control == sufficient || $control == \[* ]]; then complete=0; fi
        done <<<"$PAM_ROWS"
        record_value "$entry" faillock_evaluated "deny=${deny:-미확정} preauth=$preauth authfail=$authfail authsucc=$reset root_enforced=$root_enforced" DERIVED
        evidence+="$entry deny=${deny:-미확정} preauth=$preauth authfail=$authfail authsucc=$reset root_enforced=$root_enforced; "
        if [[ $deny =~ ^[0-9]+$ ]] && ((deny == 0 || deny > 10)); then
            emit_result VULNERABLE '사용 중인 PAM 경로의 잠금 비활성·10회 초과' "$evidence"
            return
        fi
        [[ $deny =~ ^[0-9]+$ ]] || complete=0
        ((preauth && unix_index > preauth && authfail > unix_index && reset && root_enforced)) || complete=0
    done
    if ((checked && complete)); then
        account_emit GOOD '해석한 로그인 경로의 faillock 순서·임계값·root 적용 확인' "$evidence"
    else emit_result MANUAL '계정 잠금 수치 또는 실제 PAM 적용 경로 확인 필요' "$evidence" '다른 인증 Provider·PAM Control/Include·root 적용·실패 후 잠금/성공 후 초기화 확인'; fi
}

check_u_04() {
    require_accounts || return
    local file out
    file=$(target_path /etc/passwd) || { emit_result ERROR 'passwd 경로 오류' '' '' PATH_FAILED; return; }
    out=$(awk -F: '$2!="x" && $2!="*" && $2!="!" && $2!="!!" && $2!~/^\$/ {print $1 ": password storage marker invalid"}' "$file")
    if [[ -n $out ]]; then
        account_emit VULNERABLE '비밀번호 분리 저장/암호화 미충족 계정' "$out"
    elif ((AUDIT_SHADOW_OK == 0)); then
        emit_result ERROR 'Shadow 저장 상태를 읽지 못함' '/etc/shadow' '' SHADOW_UNREADABLE
    else account_emit GOOD 'Shadow 또는 암호화 저장 표식 확인' '비밀번호/Hash 원문 수집·출력 없음'; fi
}

check_u_05() {
    require_accounts || return
    local out
    out=$(awk -F: '$2==0 && $1!="root" {print $1 " uid=" $2}' <<<"$AUDIT_ACCOUNT_ROWS")
    if [[ -n $out ]]; then
        account_emit VULNERABLE 'root 외 UID 0 계정 발견' "$out"
    else account_emit GOOD 'root 외 UID 0 계정 없음' '로컬 passwd UID 비교'; fi
}

check_u_06() {
    require_accounts || return
    local count pam control query_state=OK
    count=$(awk -F: '$2!=0 && $5!~/(nologin|false)$/ {n++}END{print n+0}' <<<"$AUDIT_ACCOUNT_ROWS")
    if ((count == 0 && AUDIT_NSS_EXTERNAL == 0)); then
        emit_result GOOD '일반 로그인 계정이 없는 root 전용 환경' '가이드 예외: 일반 계정 없음'
        return
    fi
    pam=$(active_lines /etc/pam.d/su 2>/dev/null) || { pam=; query_state=ERROR; }
    control=$(awk '$1=="auth" && $3~/(^|\/)pam_wheel\.so$/ {print $2}' <<<"$pam")
    [[ -n $control || $query_state == ERROR ]] || query_state=MISSING
    record_value /etc/pam.d/su pam_wheel.control "$control" "$query_state"
    if grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' <<<"$pam"; then
        emit_result MANUAL 'su 그룹 제한 설정 확보' 'pam_wheel required 활성' 'include/substack·trust 옵션·그룹 실제 구성과 su 대체 경로 확인'
    else emit_result MANUAL 'su 사용자 제한 유효 설정 미확정' '명시적인 pam_wheel required를 확인하지 못함' 'PAM 이외 권한 제어 및 su 실행 권한 확인'; fi
}

check_u_07() {
    require_accounts || return
    record_value policy approved_accounts "${AUDIT_CONFIG[approved_accounts]}"
    local name uid gid home shell out=''
    if [[ -z ${AUDIT_CONFIG[approved_accounts]} ]]; then
        emit_result MANUAL '불필요 계정 여부는 승인 계정 목록 필요' "$(cut -d: -f1,2,5 <<<"$AUDIT_ACCOUNT_ROWS")" 'approved_accounts를 조직의 전체 계정 목록과 대조'
        return
    fi
    while IFS=: read -r name uid gid home shell; do list_has "${AUDIT_CONFIG[approved_accounts]}" "$name" || out+="$name uid=$uid shell=$shell"$'\n'; done <<<"$AUDIT_ACCOUNT_ROWS"
    if [[ -n $out ]]; then
        emit_result VULNERABLE '승인 목록에 없는 로컬 계정' "$out" '목록의 완전성 및 업무상 필요성 재확인'
    else account_emit GOOD '모든 로컬 계정이 입력한 승인 목록에 포함' '기술 검증 + 사용자 제공 정책에 근거'; fi
}

check_u_08() {
    require_accounts || return
    record_value policy approved_admin_accounts "${AUDIT_CONFIG[approved_admin_accounts]}"
    ((AUDIT_GROUPS_OK)) || { emit_result ERROR '그룹 DB 수집 실패' '/etc/group' '' GROUP_DB_FAILED; return; }
    local group gid members name uid primary home shell out='' bad=''
    while IFS=: read -r group gid members; do
        [[ $group == root || $group == wheel || $group == sudo || $group == admin || $gid == 0 ]] || continue
        for name in ${members//,/ }; do out+="$group:$name"$'\n'; done
        while IFS=: read -r name uid primary home shell; do [[ $primary == "$gid" ]] && out+="$group:$name"$'\n'; done <<<"$AUDIT_ACCOUNT_ROWS"
    done <<<"$AUDIT_GROUP_ROWS"
    if [[ -z ${AUDIT_CONFIG[approved_admin_accounts]} ]]; then
        emit_result MANUAL '관리자 그룹 최소 구성 승인 목록 필요' "$out" 'approved_admin_accounts 확인'
        return
    fi
    while IFS=: read -r group name; do
        [[ -z $name ]] && continue
        list_has "${AUDIT_CONFIG[approved_admin_accounts]}" "$name" || bad+="$group:$name"$'\n'
    done <<<"$out"
    if [[ -n $bad ]]; then
        account_emit VULNERABLE '관리자 그룹의 미승인 계정' "$bad"
    else account_emit GOOD '입력한 관리자 승인 목록과 일치' "$out"; fi
}

check_u_09() {
    require_accounts || return
    record_value policy approved_groups "${AUDIT_CONFIG[approved_groups]}"
    ((AUDIT_GROUPS_OK)) || { emit_result ERROR '그룹 DB 수집 실패' '' '' GROUP_DB_FAILED; return; }
    local group gid members out='' unused=''
    while IFS=: read -r group gid members; do
        if [[ -z $members ]] && ! awk -F: -v g="$gid" '$3==g{found=1}END{exit !found}' <<<"$AUDIT_ACCOUNT_ROWS"; then unused+="$group gid=$gid (primary/secondary 구성원 없음)"$'\n'; fi
        [[ -z ${AUDIT_CONFIG[approved_groups]} ]] || list_has "${AUDIT_CONFIG[approved_groups]}" "$group" || out+="$group gid=$gid"$'\n'
    done <<<"$AUDIT_GROUP_ROWS"
    if [[ -z ${AUDIT_CONFIG[approved_groups]} ]]; then
        emit_result MANUAL '불필요 그룹 여부는 업무 정책 확인 필요' "$unused" '빈 그룹도 서비스 권한용일 수 있음. approved_groups와 파일 소유 GID 대조'
    elif [[ -n $out ]]; then
        account_emit VULNERABLE '승인 목록 밖의 그룹' "$out"
    else account_emit GOOD '그룹 승인 목록과 일치' "$unused"; fi
}

check_u_10() {
    require_accounts || return
    local out
    out=$(awk -F: '{n[$2]++;names[$2]=names[$2] " " $1}END{for(u in n)if(n[u]>1)print "uid=" u names[u]}' <<<"$AUDIT_ACCOUNT_ROWS")
    if [[ -n $out ]]; then
        account_emit VULNERABLE '중복 UID 발견' "$out"
    else account_emit GOOD '로컬 계정 UID 중복 없음' 'passwd UID 중복 집계'; fi
}

check_u_11() {
    require_accounts || return
    record_value policy nonlogin_accounts "${AUDIT_CONFIG[nonlogin_accounts]}"
    local name uid gid home shell out='' matched='' missing='' count=0
    if [[ -z ${AUDIT_CONFIG[nonlogin_accounts]} ]]; then
        emit_result MANUAL '로그인 불필요 계정의 정책 목록 필요' "$(cut -d: -f1,2,5 <<<"$AUDIT_ACCOUNT_ROWS")" '서비스 계정이라는 이유만으로 로그인 불필요를 추정하지 않음'
        return
    fi
    while IFS=: read -r name uid gid home shell; do
        list_has "${AUDIT_CONFIG[nonlogin_accounts]}" "$name" || continue
        ((count += 1))
        matched+="$name"$'\n'
        [[ $shell == */nologin || $shell == */false ]] || out+="$name shell=$shell"$'\n'
    done <<<"$AUDIT_ACCOUNT_ROWS"
    while IFS= read -r name; do
        [[ -z $name ]] || list_has "$matched" "$name" || missing+="$name "
    done <<<"${AUDIT_CONFIG[nonlogin_accounts]//,/$'\n'}"
    if [[ -n $out ]]; then
        account_emit VULNERABLE '로그인 불필요 계정에 로그인 Shell 부여' "$out checked=$count missing=$missing"
    elif [[ -n $missing ]] || ((count == 0)); then
        emit_result MANUAL '지정한 로그인 불필요 계정을 모두 확인하지 못함' "checked=$count missing=$missing" '계정명 오타·미존재 계정·외부 NSS 계정 여부와 정책 목록 확인'
    else account_emit GOOD '지정한 로그인 불필요 계정의 Shell 제한' "checked=$count"; fi
}

check_u_12() {
    local path file lines value found=0 bad='' evidence=''
    local -a paths=(/etc/profile /etc/bashrc /etc/bash.bashrc)
    file=$(target_path /etc/profile.d) || file=
    if [[ -d $file ]]; then for file in "$file"/*.sh; do [[ -f $file ]] && paths+=("$file"); done; fi
    for path in "${paths[@]}"; do
        path_exists "$path" || { record_value "$path" TMOUT '' MISSING; continue; }
        lines=$(active_lines "$path" 2>/dev/null) || { record_value "$path" TMOUT '' ERROR; continue; }
        lines=$(grep -E '(^|[[:space:];])(export[[:space:]]+|readonly[[:space:]]+)?TMOUT=' <<<"$lines") || { record_value "$path" TMOUT '' MISSING; continue; }
        while IFS= read -r value; do
            value=${value#*TMOUT=}
            value=${value%%[;[:space:]]*}
            value=${value//\"/}
            value=${value//\'/}
            record_value "$path" TMOUT "$value"
            evidence+="$path TMOUT=$value"$'\n'
            found=1
            if [[ ! $value =~ ^[0-9]+$ ]]; then
                emit_result MANUAL '동적 TMOUT 표현식의 실제 값 확인 필요' "$evidence" '대상 설정을 실행하지 않고 수집. 로그인 Shell에서 유효값 확인'
                return
            elif ((10#$value == 0 || 10#$value > 600)); then bad+="$path TMOUT=$value "; fi
        done <<<"$lines"
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE 'Timeout 비활성 또는 600초 초과' "$evidence"
    elif ((found)); then
        emit_result MANUAL '600초 이하 TMOUT 설정 확보' "$evidence" 'Shell 종류·로그인 경로·사용자 덮어쓰기·csh/zsh 등의 세션 정책 확인'
    else emit_result MANUAL '세션 종료 정책의 실제 적용 미확정' '' '모든 로그인 Shell과 터미널의 Timeout 정책 확인'; fi
}

check_u_13() {
    local name state alg min max out='' unknown='' method
    ((AUDIT_SHADOW_OK)) || { emit_result ERROR 'Hash 알고리즘 식별 정보 수집 실패' '/etc/shadow (Hash 원문은 반환하지 않음)' '' SHADOW_UNREADABLE; return; }
    while IFS=: read -r name state alg min max _; do
        [[ $state == HASH ]] || continue
        case $alg in 5 | 6 | y | gy) ;; 1 | DES_or_legacy) out+="$name algorithm=$alg"$'\n' ;; *) unknown+="$name algorithm=$alg"$'\n' ;; esac
    done <<<"$AUDIT_SHADOW_ROWS"
    method=$(config_value /etc/login.defs ENCRYPT_METHOD 2>/dev/null) || method=
    case ${method^^} in DES | MD5) out+="신규 계정 기본 알고리즘=$method" ;; esac
    if [[ -n $out ]]; then
        emit_result VULNERABLE 'SHA-2 이상 기준을 충족하지 않는 알고리즘' "$out" '알고리즘 지원 정책과 기존 비밀번호 재설정 영향 확인'
    elif [[ -n $unknown || -z $method ]]; then
        emit_result MANUAL '기존 Hash 일부 또는 신규 비밀번호 알고리즘 미확정' "$unknown method=${method:-미설정}" 'PAM Module·libcrypt·Provider 기본값 확인'
    else emit_result GOOD '기존 Hash와 명시된 기본 알고리즘에서 취약 형식 미발견' "default_method=$method; Hash 원문 미수집"; fi
}

check_u_14() {
    local part rest=${AUDIT_OBSERVED_PATH-} index=0 out=''
    record_value 'caller environment' PATH "$rest"
    if ((EUID != 0)); then
        emit_result MANUAL 'root 로그인 PATH 유효값 확인 필요' '현재 실행 환경은 대상 root 로그인 Session과 다름' 'root 초기화 파일과 실제 로그인 PATH 확인'
        return
    fi
    while [[ $rest == *:* ]]; do
        part=${rest%%:*}
        rest=${rest#*:}
        ((index += 1))
        [[ $part == . || -z $part ]] && out+="position=$index current-directory "
    done
    if [[ -n $out ]]; then
        emit_result VULNERABLE 'root PATH 앞/중간에 현재 디렉터리 포함' "$out" '원래 호출 Session PATH를 검사했으며 실행 도구 PATH는 고정 경로 사용'
    else emit_result MANUAL '현재 root 호출 Session에서 위험한 PATH 구간 미발견' '현재 디렉터리 앞/중간 미포함' '시스템·root 초기화 파일의 로그인별 PATH도 확인'; fi
}

check_u_15() { scan_result AUDIT_ORPHANS '소유 계정·그룹 없는 파일·디렉터리' ''; }

check_u_16() { check_file_rule /etc/passwd 0644; }

check_u_17() {
    local dir
    local -A rules=([checked]=0 [errors]=0 [bad]='')
    for dir in /etc/init.d /etc/rc.d/init.d /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/local.d; do
        file_rule_scan "$dir" 0755 0 rules 2
    done
    file_rule_result '시작 스크립트/Unit' rules MANUAL ERROR 'Unit ExecStart·EnvironmentFile·Drop-in 및 다른 Init의 실제 실행 파일까지 확인' emit_result FIND_FAILED
}

check_u_18() { check_file_rule /etc/shadow 0400; }

check_u_19() { check_file_rule /etc/hosts 0644; }

check_u_20() {
    local p
    local -A rules=([checked]=0 [errors]=0 [bad]='')
    for p in /etc/inetd.conf /etc/xinetd.conf; do
        if path_exists "$p"; then file_rule_add "$p" 0600 0 rules || :; fi
    done
    file_rule_result 'inetd/xinetd 설정' rules GOOD MANUAL '서비스 미사용과 대체 설정·Include 경로를 확인'
}

check_u_21() {
    local p file owners
    local -A rules=([checked]=0 [errors]=0 [bad]='')
    owners=$(allowed_system_owners)
    local -a paths=(/etc/rsyslog.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf)
    for p in /etc/rsyslog.d /etc/syslog-ng/conf.d; do
        for file in "$p"/*.conf; do [[ -f $file ]] && paths+=("$file"); done
    done
    for p in "${paths[@]}"; do
        if path_exists "$p"; then file_rule_add "$p" 0640 "$owners" rules || :; fi
    done
    file_rule_result 'Syslog 설정' rules GOOD MANUAL '허용 소유자 root/bin/sys; journald·Custom Include·다른 Logger 설정은 별도 확인'
}

check_u_22() { check_file_rule /etc/services 0644 "$(allowed_system_owners)"; }

check_u_23() { scan_result AUDIT_SPECIAL_FILES 'SUID/SGID 파일' approved_special_files; }

check_u_24() {
    require_accounts || return
    local uid home
    local -A rules=([checked]=0 [errors]=0 [bad]='') seen=()
    while IFS=: read -r _ uid _ home _; do
        [[ $home == /* && $home != / ]] || continue
        [[ ! -v seen["$home|$uid"] ]] || continue
        seen["$home|$uid"]=1
        file_rule_scan "$home" 0755 "0,$uid" rules 1
    done <<<"$AUDIT_ACCOUNT_ROWS"
    file_rule_result '계정 환경 파일' rules GOOD GOOD '11개 환경 파일과 연결된 대상의 소유자·권한 확인; 동적 Include 별도 확인' account_emit
}

check_u_25() { scan_result AUDIT_WORLD_FILES 'World-writable 일반 파일' approved_world_writable_paths; }

check_u_26() {
    local path out='' count=0 approved
    [[ -d /dev ]] || { record_value /dev directory no MISSING; emit_result ERROR '/dev 디렉터리 없음' '' '' PATH_FAILED; return; }
    local records="$AUDIT_WORK_DIR/dev.$BASHPID"
    if ! collect_paths "$records" /dev -type f -print0; then
        emit_result ERROR '/dev 탐색 실패' '' '' FIND_FAILED
        return
    fi
    while IFS= read -r -d '' path; do
        ((count += 1))
        approved=0; list_has_line "${AUDIT_CONFIG[approved_device_files]}" "$path" && approved=1
        record_value "$path" approved "$approved"
        if ((approved == 0 && ${#out} < 24000)); then out+="$path"$'\n'; fi
    done <"$records"
    if [[ -n $out ]]; then
        emit_result MANUAL '/dev 일반 파일의 정당성 확인 필요' "$out" 'udev 생성 파일 등 정상 용도를 검토; 존재 자체만으로 취약 단정 금지'
    else emit_result GOOD '/dev에서 미검토 일반 파일 미발견' "regular_files=$count"; fi
}

check_u_27() {
    service_gate r || return
    local home path out='' seen=0 plus
    local -a paths=(/etc/hosts.equiv)
    while IFS=: read -r _ _ _ home _; do [[ $home == /* ]] && paths+=("$home/.rhosts"); done <<<"$AUDIT_ACCOUNT_ROWS"
    for path in "${paths[@]}"; do
        path_exists "$path" || continue
        ((seen += 1))
        if ! file_metadata "$path"; then
            emit_result ERROR 'rhosts Metadata 실패' "$path" '' STAT_FAILED
            return
        fi
        plus=0; grep -Eq '(^|[[:space:]])\+([[:space:]]|$)' "$path" && plus=1
        record_value "$path" allowed_mode 0600
        record_value "$path" unrestricted_trust "$plus"
        if ! mode_within "$FILE_MODE" 0600 || ((plus)); then out+="$path uid=$FILE_UID mode=$FILE_MODE +여부 확인"$'\n'; fi
    done
    if [[ -n $out ]]; then
        emit_result VULNERABLE 'r 계열 인증 파일 제한 미흡' "$out"
    else emit_result MANUAL 'r 계열 서비스 사용: 파일 소유 계정 및 신뢰 관계 검토 필요' "files=$seen" '소유자는 root/해당 계정인지, 허용 Host/User의 적절성 확인'; fi
}

ipv4_network() {
    local address=${1%/*} prefix=32 a b c d extra octet
    [[ $1 != */* ]] || prefix=${1##*/}
    [[ $prefix =~ ^[0-9]{1,2}$ ]] && ((10#$prefix <= 32)) || return 1
    IFS=. read -r a b c d extra <<<"$address"
    [[ -z $extra ]] || return 1
    for octet in "$a" "$b" "$c" "$d"; do [[ $octet =~ ^[0-9]{1,3}$ ]] && ((10#$octet <= 255)) || return 1; done
    IPV4_PREFIX=$((10#$prefix))
    IPV4_MASK=$((IPV4_PREFIX == 0 ? 0 : (0xffffffff << (32 - IPV4_PREFIX)) & 0xffffffff))
    IPV4_NETWORK=$((((10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d) & IPV4_MASK))
}

management_source_allowed() {
    # 0=승인 범위, 1=IPv4 승인 범위 밖, 2=추가 해석 필요.
    local source=$1 family=$2 approved network prefix valid=0
    if [[ $family == 6 ]]; then
        list_has "${AUDIT_CONFIG[allowed_management_cidrs]}" "$source" && return 0
        return 2
    fi
    ipv4_network "$source" || return 2
    network=$IPV4_NETWORK; prefix=$IPV4_PREFIX
    while IFS= read -r approved; do
        [[ -n $approved && $approved != *:* ]] || continue
        ipv4_network "$approved" || return 2
        valid=1
        if ((prefix >= IPV4_PREFIX && (network & IPV4_MASK) == IPV4_NETWORK)); then return 0; fi
    done <<<"${AUDIT_CONFIG[allowed_management_cidrs]//,/$'\n'}"
    ((valid)) && return 1
    return 2
}

iptables_management_policy() {
    # 단순한 filter/INPUT만 확정한다. 해석하지 못한 매치·점프는 GOOD 근거로 쓰지 않는다.
    local text=$1 family=$2 table='' policy='' line token source protocol target ports states iface port rc
    local -a args=() selected_ports=()
    local -A closed=([21]=0 [22]=0 [23]=0)
    FW_REASON=
    while IFS= read -r line; do
        case $line in
            \#*|'') continue ;;
            \**) table=${line#\*}; continue ;;
            ':INPUT '*) if [[ $table == filter ]]; then read -r _ policy _ <<<"$line"; fi; continue ;;
            '-A '*) ;;
            *) continue ;;
        esac
        [[ $table == filter ]] || { FW_REASON='filter 외 테이블 규칙 해석 필요'; return 2; }
        [[ $line == '-A INPUT '* ]] || continue
        read -r -a args <<<"${line#-A INPUT }"
        source=0.0.0.0/0; [[ $family != 6 ]] || source=::/0
        protocol=all; target=; ports=; states=; iface=
        while ((${#args[@]})); do
            token=${args[0]}; args=("${args[@]:1}")
            case $token in
                -s|--source) source=${args[0]-}; args=("${args[@]:1}") ;;
                -p|--protocol) protocol=${args[0]-}; args=("${args[@]:1}") ;;
                -j|--jump) target=${args[0]-}; args=("${args[@]:1}") ;;
                --dport|--destination-port|--dports) ports=${args[0]-}; args=("${args[@]:1}") ;;
                --ctstate|--state) states=${args[0]-}; args=("${args[@]:1}") ;;
                -i|--in-interface) iface=${args[0]-}; args=("${args[@]:1}") ;;
                -m|--match)
                    case ${args[0]-} in tcp|multiport|conntrack|state) args=("${args[@]:1}") ;;
                        *) FW_REASON="미해석 모듈:$line"; return 2 ;; esac ;;
                *) FW_REASON="미해석 조건:$line"; return 2 ;;
            esac
        done
        [[ $iface != lo ]] || continue
        [[ $protocol == tcp || $protocol == all ]] || continue
        [[ -z $iface ]] || { FW_REASON="인터페이스 조건:$line"; return 2; }
        if [[ -n $states ]] && ! list_has "$states" NEW; then
            case $states in ESTABLISHED|RELATED|ESTABLISHED,RELATED|RELATED,ESTABLISHED|INVALID) continue ;;
                *) FW_REASON="연결 상태 조건:$line"; return 2 ;; esac
        fi
        [[ $ports != *:* && $ports != *-* ]] || { FW_REASON="포트 범위:$line"; return 2; }
        selected_ports=()
        for port in 21 22 23; do
            [[ -z $ports ]] || list_has "$ports" "$port" || continue
            [[ ${closed[$port]} == 0 ]] && selected_ports+=("$port")
        done
        ((${#selected_ports[@]})) || continue
        record_value "iptables:IPv$family" management_rule "$line"
        case $target in
            DROP|REJECT)
                [[ $source == 0.0.0.0/0 || $source == ::/0 ]] || { FW_REASON="선행 Source별 차단:$line"; return 2; }
                for port in "${selected_ports[@]}"; do closed[$port]=1; done ;;
            ACCEPT)
                if [[ $source == 0.0.0.0/0 || $source == ::/0 ]]; then FW_REASON="관리 포트 전체 Source 허용:$line"; return 1; fi
                rc=0; management_source_allowed "$source" "$family" || rc=$?
                if ((rc == 1)); then FW_REASON="승인 CIDR 밖의 관리 포트 허용:$line"; return 1
                elif ((rc)); then FW_REASON="Source/CIDR 관계 미해석:$line"; return 2; fi ;;
            *) FW_REASON="다른 체인/Target:$line"; return 2 ;;
        esac
    done <<<"$text"
    [[ $policy == DROP ]] || { FW_REASON="INPUT 기본 정책:${policy:-미확인}"; return 2; }
    FW_REASON='관리 포트의 신규 TCP 허용 Source가 승인 범위이며 INPUT 기본 정책 DROP'
    return 0
}

check_u_28() {
    local evidence='' query_ok=0 tool family rc good=0 bad='' unknown='' nft_rules=''
    local -A rules=()
    record_value policy allowed_management_cidrs "${AUDIT_CONFIG[allowed_management_cidrs]}"
    for tool in nft iptables-save ip6tables-save ufw firewall-cmd; do
        command -v "$tool" >/dev/null 2>&1 || { record_value "$tool" available no MISSING; continue; }
        case $tool in
            nft) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" nft list ruleset || continue ;;
            iptables-save|ip6tables-save) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" "$tool" || continue ;;
            ufw) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ufw status verbose || continue ;;
            firewall-cmd) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" firewall-cmd --list-all-zones || continue ;;
        esac
        query_ok=1; rules[$tool]=$AUDIT_COMMAND_STDOUT
        record_value "$tool" rules "$AUDIT_COMMAND_STDOUT"
        evidence+="$tool:"$'\n'"${AUDIT_COMMAND_STDOUT:0:12000}"$'\n'
    done
    if ((query_ok == 0)); then emit_result ERROR 'Firewall 조회 실패 또는 도구 없음' '' '권한·사용 Provider 확인' FIREWALL_QUERY_FAILED; return; fi
    if [[ -z ${AUDIT_CONFIG[allowed_management_cidrs]} ]]; then
        emit_result MANUAL 'Firewall 규칙 수집; 승인 관리망 입력 필요' "$evidence" 'allowed_management_cidrs와 실제 유입 경로 대조'; return
    fi
    for family in 4 6; do
        tool=iptables-save; [[ $family != 6 ]] || tool=ip6tables-save
        if [[ ! -v rules[$tool] ]]; then unknown+="IPv$family INPUT 미조회; "; continue; fi
        rc=0; iptables_management_policy "${rules[$tool]}" "$family" || rc=$?
        record_value "$tool" management_policy "$FW_REASON" DERIVED
        case $rc in 0) ((good += 1)) ;; 1) bad+="IPv$family:$FW_REASON; " ;; *) unknown+="IPv$family:$FW_REASON; " ;; esac
    done
    # 별도 nft hook의 DROP이 ACCEPT를 다시 제한할 수 있어 취약 확정에 함께 고려한다.
    nft_rules=${rules[nft]-}
    if [[ -n $bad && -v rules[nft] && -z $nft_rules ]]; then
        emit_result VULNERABLE '관리 포트에 전체 Source 또는 승인 CIDR 밖의 허용 규칙' "$bad$unknown" '확인된 INPUT 규칙과 상위 ACL을 대조'
    elif ((good == 2)); then
        emit_result GOOD 'IPv4/IPv6 관리 포트의 단순 INPUT 규칙이 승인 CIDR·기본 DROP 기준 충족' "$evidence" '검사 범위: 신규 TCP 21/22/23, 현재 Network Namespace'
    else emit_result MANUAL 'Firewall 유효 규칙의 추가 해석 필요' "$bad$unknown" 'nft/체인 점프·조건·IPv6 CIDR 표현·규칙 순서와 실제 유입 경로 확인; 원래 규칙은 조회 기록 참조'; fi
}

check_u_29() { check_file_rule /etc/hosts.lpd 0600 0 1; }

check_u_30() {
    local path text rows line value direct complex found=0 definite='' ambiguous='' good bad count
    record_value criterion UMASK 'umask&0022=0022; 단일/동일한 무조건 취약값은 VULNERABLE, 조건·혼합값은 MANUAL'
    for path in /etc/login.defs /etc/profile /etc/bashrc /etc/bash.bashrc; do
        path_exists "$path" || continue
        text=$(read_target "$path") || { ambiguous+="$path 읽기 실패; "; continue; }
        complex=0
        if [[ $path != /etc/login.defs ]] && grep -Eq '(^|[;[:space:]])(if|elif|else|case|for|while|until|function|source)([[:space:]]|$)|[{}]|&&|\|\|' <<<"$text"; then complex=1; fi
        rows=$(awk '
            /^[[:space:]]*#/ {next}
            {line=$0;sub(/[[:space:]]*#.*/,"",line)
             while(match(line,/(^|[;[:space:]])[uU][mM][aA][sS][kK][[:space:]]+[^;[:space:]]+/)) {
                 token=substr(line,RSTART,RLENGTH);sub(/^[;[:space:]]*/,"",token)
                 sub(/^[^[:space:]]+[[:space:]]+/,"",token)
                 direct=(substr(line,1,RSTART-1) ~ /^[[:space:]]*$/)
                 gsub(/"/,"",token);gsub(sprintf("%c",39),"",token)
                 printf "%d:%s:%d\n",NR,token,direct
                 line=substr(line,RSTART+RLENGTH)
             }}' <<<"$text")
        [[ -n $rows ]] || { record_value "$path" UMASK '' MISSING; continue; }
        good=0; bad=0; count=0
        while IFS=: read -r line value direct; do
            ((found += 1, count += 1))
            record_value "$path:$line" UMASK "$value"
            ((direct)) || complex=1
            if [[ $value =~ ^[0-7]{3,4}$ ]]; then
                if (((8#$value & 0022) == 0022)); then ((good += 1)); else ((bad += 1)); fi
            else complex=1; fi
        done <<<"$rows"
        if ((bad && !good && !complex)); then definite+="$path:조건 없는 취약값 $bad개; "
        elif ((bad || complex)); then ambiguous+="$path:조건문 내 다른 값 존재 가능(수집:$count, 충족:$good, 미충족:$bad); "; fi
    done
    if [[ -n $definite ]]; then
        emit_result VULNERABLE '조건 없이 명시된 UMASK가 Group/Other 쓰기를 차단하지 않음' "$definite$ambiguous"
    elif [[ -n $ambiguous ]]; then
        emit_result MANUAL 'UMASK 조건·혼합값의 유효 적용 확인 필요' "$ambiguous"
    elif ((found)); then
        emit_result MANUAL '수집한 UMASK 수치는 충족; 로그인 경로별 적용 확인 필요' "values:$found" 'profile.d·사용자 Shell·PAM·서비스별 덮어쓰기 확인'
    else emit_result MANUAL 'UMASK 설정값 미발견' '' '로그인 경로별 유효값 확인'; fi
}

check_u_31() {
    require_accounts || return
    local name uid home shell
    local -A rules=([checked]=0 [errors]=0 [bad]='')
    while IFS=: read -r name uid _ home shell; do
        [[ $shell == */nologin || $shell == */false ]] && continue
        record_value "/etc/passwd:$name" home "$home"
        [[ $home == /* ]] || {
            rules[bad]+="$name home=$home (절대 경로 아님)"$'\n'
            continue
        }
        path_exists "$home" || continue
        if ! file_rule_add "$home" 7775 "$uid" rules; then
            emit_result ERROR 'Home Metadata 조회 실패' "$name $home" '' STAT_FAILED
            return
        fi
    done <<<"$AUDIT_ACCOUNT_ROWS"
    file_rule_result '로그인 계정 Home' rules GOOD GOOD '다른 사용자 쓰기 Bit 금지(allowed=7775)' account_emit
}

check_u_32() {
    require_accounts || return
    local name home shell out=''
    while IFS=: read -r name _ _ home shell; do
        [[ $shell == */nologin || $shell == */false ]] && continue
        record_value "/etc/passwd:$name" home "$home"
        if [[ $home != /* ]] || ! path_exists "$home"; then out+="$name home=$home"$'\n'; fi
    done <<<"$AUDIT_ACCOUNT_ROWS"
    if [[ -n $out ]]; then
        account_emit VULNERABLE '실재하지 않거나 유효하지 않은 로그인 Home' "$out"
    else account_emit GOOD '로컬 로그인 계정의 Home 존재 확인' 'UID 숫자 기준으로 계정을 누락하지 않음'; fi
}

check_u_33() { scan_result AUDIT_HIDDEN_FILES '숨김 파일·디렉터리' approved_hidden_paths; }

check_u_34() { check_disabled_service finger; }

check_u_35() {
    local role state unknown=0 bad='' evidence='' value
    record_value criterion anonymous_access '서비스 비실행 또는 vsftpd anonymous_enable=NO; YES=VULNERABLE; NFS/Samba 실행은 MANUAL' DERIVED
    for role in ftp nfs samba; do
        state=${AUDIT_SERVICE_STATE[$role]:-UNKNOWN}
        record_value "service:$role" state "$state" "$([[ $state == UNKNOWN ]] && printf ERROR || printf OK)"
        record_value "service:$role" evidence "${AUDIT_SERVICE_EVIDENCE[$role]:-수집 없음}"
        case $role:$state in
        *:STOPPED | *:ABSENT) evidence+="$role: 비실행 " ;;
        ftp:RUNNING)
            if ftp_config; then
                value=$(config_value "$FTP_CONFIG_PATH" anonymous_enable 2>/dev/null) || value=
                evidence+="vsftpd anonymous_enable=${value:-기본값 미확정} "
                case ${value^^} in YES) bad+='FTP 익명 허용; ' ;; NO) ;; *) unknown=1 ;; esac
            else unknown=1; fi ;;
        *:RUNNING) unknown=1; evidence+="$role: 익명 UID·Guest·Share ACL 확인 필요 " ;;
        *) unknown=1; evidence+="$role: 실행 여부 미확정 " ;;
        esac
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE '공유 서비스 익명 접근 허용 설정' "$bad $evidence"
    elif ((unknown)); then
        emit_result MANUAL '공유 서비스 전체 익명 접근 제한 확인 필요' "$evidence" 'FTP Custom Config·Samba Guest mapping·NFS anonymous/export 접근 정책 확인'
    else emit_result GOOD '확인한 공유 서비스의 비실행 또는 익명 접근 차단' "$evidence"; fi
}

check_u_36() { check_disabled_service r; }

check_u_37() {
    require_accounts || return
    local dir
    local -A rules=([checked]=0 [errors]=0 [bad]='')
    record_value criterion cron_permissions '명령:root, mode&0022=0(SUID/SGID 허용); 설정·spool:mode&0027=0; cron spool 소유자는 root 또는 파일명 계정'
    file_rule_paths 7755 0 rules /usr/bin/crontab /usr/bin/at /bin/crontab /bin/at
    file_rule_paths 7750 0 rules /etc/crontab /etc/anacrontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny
    for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/at; do
        file_rule_scan "$dir" 7750 0 rules
    done
    file_rule_result 'cron/at 명령·설정' rules GOOD MANUAL 'cron spool 계정 매핑·비표준 Scheduler 범위 확인; at spool은 root 소유 기준'
}

check_u_38() { check_disabled_service dos; }

check_u_39() { check_disabled_service nfs; }

check_u_40() {
    service_gate nfs || return
    local path file text bad='' evidence='' count=0
    local -a paths=(/etc/exports)
    record_value criterion nfs_exports '설정 파일 허용 권한 Bit 0644, wildcard client *(...) 발견=VULNERABLE; 그 외 ACL은 MANUAL' DERIVED
    file=$(target_path /etc/exports.d) || file=
    if [[ -d $file ]]; then for file in "$file"/*.exports; do [[ -f $file ]] && paths+=("$file"); done; fi
    for path in "${paths[@]}"; do
        path_exists "$path" || { record_value "$path" present false MISSING; continue; }
        ((count += 1))
        if ! file_metadata "$path"; then
            emit_result ERROR 'NFS 설정 Metadata 실패' "$path" '' STAT_FAILED
            return
        fi
        mode_within "$FILE_MODE" 0644 || bad+="$path mode=$FILE_MODE; "
        text=$(active_lines "$path") || {
            emit_result ERROR 'NFS 설정 읽기 실패' "$path" '' READ_FAILED
            return
        }
        evidence+="$path: $text"$'\n'
        record_value "$path" exports "$text"
        if grep -Eq '(^|[[:space:]])\*\(' <<<"$text"; then bad+="$path: wildcard client; "; fi
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE 'NFS 권한 또는 Client 제한 미흡' "$bad $evidence" 'Netgroup·Subnet·IPv6·Root Squash 등 실제 Export ACL 검토'
    else emit_result MANUAL 'NFS 설정 증거 확보; 허용 Client의 적절성 검토 필요' "files=$count $evidence" 'exportfs -v의 적용 상태와 허용 Host·설정 파일 권한 대조'; fi
}

check_u_41() { check_disabled_service automount; }

check_u_42() { check_disabled_service rpc; }

check_u_43() { check_disabled_service nis; }

check_u_44() { check_disabled_service tftp; }

check_u_45() { package_version_check mail '(postfix|sendmail|exim|opensmtpd)' '메일 Version 증거 확보; Vendor 보안 지원·Backport 확인 필요' '해당 배포판 Security Advisory·지원 종료·적용 기록과 대조; 숫자 Version만으로 최신/취약 단정 금지'; }

check_u_46() {
    service_gate mail || return
    mail_provider
    record_value service:mail policy_provider "$MAIL_PROVIDER" DERIVED
    record_value criterion sendmail_queue '확정한 Sendmail PrivacyOptions에 restrictqrun 포함=GOOD, 그 외 MANUAL' DERIVED
    if [[ $MAIL_PROVIDER == sendmail ]]; then
        sendmail_options_check restrictqrun 'Sendmail 일반 사용자 Queue 실행 제한 설정' 'Sendmail Queue 실행 제한 유효값 확인 필요' 'Sendmail Version·기본값·binary/Queue 권한 확인'
    else emit_result MANUAL '메일 Provider의 일반 사용자 실행 제한 확인 필요' "provider=$MAIL_PROVIDER" 'Postfix/Exim 등의 Queue 실행·명령 권한·Daemon 권한을 Vendor 방식으로 확인'; fi
}

check_u_47() {
    service_gate mail || return
    local restrictions networks tokens token found=0 broad=0
    mail_provider
    record_value service:mail policy_provider "$MAIL_PROVIDER" DERIVED
    record_value criterion postfix_relay 'mynetworks 전체 주소 허용=VULNERABLE; Relay 차단·선행 Permit·Map은 MANUAL' DERIVED
    if [[ $MAIL_PROVIDER == postfix ]]; then
        restrictions=$(postfix_value smtpd_relay_restrictions) || {
            emit_result ERROR 'Postfix 유효 Relay 정책 조회 실패' '' '' POSTCONF_FAILED
            return
        }
        [[ -n $restrictions ]] || restrictions=$(postfix_value smtpd_recipient_restrictions) || :
        networks=$(postfix_value mynetworks) || {
            emit_result ERROR 'Postfix 신뢰망 조회 실패' '' '' POSTCONF_FAILED
            return
        }
        if grep -Eq '(^|[[:space:],])(0\.0\.0\.0/0|\[?::\]?/0)([[:space:],]|$)' <<<"$networks"; then broad=1; fi
        tokens=${restrictions//,/$'\n'}
        while read -r token; do
            token=${token//[[:space:]]/}
            case $token in reject_unauth_destination | defer_unauth_destination)
                found=1
                break
                ;;
            permit) break ;; esac
        done <<<"$tokens"
        if ((broad)); then
            emit_result VULNERABLE 'Postfix 신뢰망이 전체 주소 범위' 'mynetworks에 IPv4/IPv6 전체 허용'
        elif ((found)); then
            emit_result MANUAL '비인증 Relay 차단 조건 확인; 선행 Permit 범위 검토 필요' "restrictions=$restrictions mynetworks=$networks" 'master.cf Override·Access Map·선행 Permit 정책 및 허용망 확인'
        else emit_result MANUAL '유효 Relay 차단 조건을 확정하지 못함' "restrictions=$restrictions" 'Access Map·인증·상위 Relay ACL을 포함해 검토'; fi
    else emit_result MANUAL '메일 Relay 제한 정책 검토 필요' "provider=$MAIL_PROVIDER" 'Sendmail access/relay-domains, Exim ACL과 실제 적용 순서를 확인'; fi
}

check_u_48() {
    service_gate mail || return
    local value
    mail_provider
    record_value service:mail policy_provider "$MAIL_PROVIDER" DERIVED
    record_value criterion mail_commands 'Postfix disable_vrfy_command=yes 또는 Sendmail noexpn+novrfy=GOOD; Postfix no=VULNERABLE' DERIVED
    case $MAIL_PROVIDER in
    postfix)
        value=$(postfix_value disable_vrfy_command) || {
            emit_result ERROR 'Postfix VRFY 유효값 조회 실패' '' '' POSTCONF_FAILED
            return
        }
        case ${value,,} in yes) emit_result GOOD 'Postfix VRFY 비활성 설정 확인' 'disable_vrfy_command=yes; Postfix는 EXPN 미제공' ;; no) emit_result VULNERABLE 'VRFY 비활성화되지 않음' 'disable_vrfy_command=no' ;; *) emit_result ERROR 'VRFY 설정 형식 미확정' '' '' PARSE_FAILED ;; esac
        ;;
    sendmail)
        sendmail_options_check 'noexpn novrfy' 'Sendmail EXPN/VRFY 제한 설정' 'Sendmail EXPN/VRFY 유효 제한 미확정' '실제 PrivacyOptions 기본값·Include·Daemon 적용 확인'
        ;;
    *) emit_result MANUAL '메일 Provider별 EXPN/VRFY ACL 확인 필요' "provider=$MAIL_PROVIDER" '명령 지원 여부·거부 ACL·Version 확인' ;;
    esac
}

check_u_49() { package_version_check dns '(bind|unbound|pdns|knot)' 'DNS 패치 정책·Vendor 지원 상태 확인 필요' 'Vendor Advisory·지원 종료·실제 적용 기록을 확인; Resolver Client Version과 서버 Version을 구분'; }

check_u_50() { dns_acl_check allow-transfer; }

check_u_51() { dns_acl_check allow-update; }

check_u_52() { check_disabled_service telnet; }

check_u_53() {
    local banner
    record_value criterion ftp_banner 'Banner 실제 노출·banner_file Override·제품/Version 포함 여부는 MANUAL' DERIVED
    ftp_gate || return
    banner=$(config_value "$FTP_CONFIG_PATH" ftpd_banner 2>/dev/null) || banner=
    if [[ -z $banner ]]; then
        emit_result MANUAL 'FTP Banner의 실제 노출 내용 확인 필요' '명시적 ftpd_banner 없음' 'banner_file·Provider 기본값·접속 Banner를 확인'
    else emit_result MANUAL '사용자 지정 FTP Banner 설정 확보' "ftpd_banner=$banner" 'OS·제품·Version 정보 노출 여부와 banner_file Override 확인'; fi
}

check_u_54() {
    local enabled force_login force_data
    record_value criterion ftp_tls '실행 vsftpd ssl_enable=NO는 VULNERABLE; YES와 로그인/데이터 TLS 강제는 추가 Listener·익명 정책 MANUAL' DERIVED
    ftp_gate || return
    enabled=$(config_value "$FTP_CONFIG_PATH" ssl_enable 2>/dev/null) || enabled=
    force_login=$(config_value "$FTP_CONFIG_PATH" force_local_logins_ssl 2>/dev/null) || force_login=
    force_data=$(config_value "$FTP_CONFIG_PATH" force_local_data_ssl 2>/dev/null) || force_data=
    if [[ ${enabled^^} == NO ]]; then
        emit_result VULNERABLE '실행 중 vsftpd의 TLS 비활성 설정' 'ssl_enable=NO'
    elif [[ ${enabled^^} == YES && ${force_login^^} == YES && ${force_data^^} == YES ]]; then
        emit_result MANUAL 'TLS 강제 설정 확보; 익명·추가 Listener 확인 필요' 'ssl_enable/force_local_logins_ssl/force_local_data_ssl=YES' 'Anonymous TLS·실제 적용 Config·별도 FTP Instance 확인'
    else emit_result MANUAL '평문 FTP 허용 여부 미확정' "ssl_enable=${enabled:-default} login_tls=${force_login:-default} data_tls=${force_data:-default}" 'Provider의 실제 TLS 강제값 확인'; fi
}

check_u_55() {
    service_gate ftp || return
    require_accounts || return
    local name uid gid home shell bad='' found=0
    record_value criterion ftp_shell 'ftp/anonymous 계정 Shell은 */false 또는 */nologin; 가상 계정·실제 인증 계정은 MANUAL' DERIVED
    while IFS=: read -r name uid gid home shell; do
        [[ $name == ftp || $name == anonymous ]] || continue
        found=1
        [[ $shell == */false || $shell == */nologin ]] || bad+="$name shell=$shell"$'\n'
    done <<<"$AUDIT_ACCOUNT_ROWS"
    ((found)) || record_value passwd ftp_accounts 'ftp/anonymous 계정 없음' MISSING
    if [[ -n $bad ]]; then
        emit_result VULNERABLE '확인한 FTP 계정에 로그인 Shell 부여' "$bad"
    else emit_result MANUAL '기본 FTP 계정 Shell 검사 완료; 실제 인증 계정 범위 확인 필요' "default_account_found=$found" 'FTP 가상 계정·PAM·매핑 UID 및 실제 서비스 계정 확인'; fi
}

check_u_56() {
    service_gate ftp || return
    record_value criterion ftp_acl '실제 Host/IP ACL·IPv6·추가 Listener를 검토; 사용자 차단 목록만으로 IP 제한을 확정하지 않음' DERIVED
    emit_result MANUAL 'FTP에 실제 적용되는 Host/IP ACL 검토 필요' "${AUDIT_SERVICE_EVIDENCE[ftp]}" '방화벽·TCP Wrapper의 실제 연계·Provider ACL·IPv6·Custom Listener 확인. 사용자 차단 목록은 IP ACL 증거가 아님'
}

check_u_57() {
    local enable deny file text
    record_value criterion ftp_root 'userlist_enable=YES, userlist_deny=YES, 절대 경로 Userlist의 root 포함=GOOD, 미포함=VULNERABLE' DERIVED
    ftp_gate || return
    enable=$(config_value "$FTP_CONFIG_PATH" userlist_enable 2>/dev/null) || enable=
    deny=$(config_value "$FTP_CONFIG_PATH" userlist_deny 2>/dev/null) || deny=
    file=$(config_value "$FTP_CONFIG_PATH" userlist_file 2>/dev/null) || file=
    if [[ ${enable^^} == YES && ${deny^^} == YES && $file == /* ]]; then
        text=$(active_lines "$file") || { record_value "$file" userlist '조회 실패' ERROR; emit_result ERROR 'FTP Userlist 읽기 실패' "$file" '' READ_FAILED; return; }
        record_value "$file" userlist "$text"
        if grep -Eq '^[[:space:]]*root[[:space:]]*$' <<<"$text"; then
            emit_result GOOD '명시적으로 활성화된 FTP Deny Userlist에 root 포함' "$file: userlist_enable=YES userlist_deny=YES"
        else emit_result VULNERABLE '활성 Deny Userlist에 root 미포함' "$file"; fi
    else emit_result MANUAL 'FTP root 차단의 실제 인증 경로 확인 필요' "userlist_enable=${enable:-default} userlist_deny=${deny:-default} file=${file:-default}" 'PAM pam_listfile·ftpusers·userlist 기본값 및 실제 적용을 확인'; fi
}

check_u_58() { check_disabled_service snmp; }

check_u_59() { snmp_audit_check 59; }
check_u_60() { snmp_audit_check 60; }
check_u_61() { snmp_audit_check 61; }

banner_matches() {
    local path=$1 content marker matched=1
    [[ -e $path || -L $path ]] || { record_value "$path" exists no MISSING; return 1; }
    content=$(read_target "$path") || return 2
    record_value "$path" banner "$content"
    while IFS= read -r marker; do
        [[ -n $marker ]] || continue
        if [[ $content == *"$marker"* ]]; then record_value "$path" marker_match "$marker:yes"
        else matched=0; record_value "$path" marker_match "$marker:no"; fi
    done <<<"${AUDIT_CONFIG[approved_banner_markers]}"
    ((matched))
}

check_u_62() {
    local path rc local_match=0 net_match=0 read_error=0 role banner='' unresolved=''
    record_value policy approved_banner_markers "${AUDIT_CONFIG[approved_banner_markers]}"
    if [[ -z ${AUDIT_CONFIG[approved_banner_markers]//[$'\r\n\t ']/} ]]; then
        for path in /etc/issue /etc/issue.net /etc/motd; do
            path_exists "$path" && record_value "$path" banner "$(read_target "$path")"
        done
        emit_result MANUAL '승인 경고 문구와 실제 로그인·서비스 적용 확인 필요' '' 'approved_banner_markers에 필수 문구 입력'; return
    fi
    for path in /etc/issue /etc/issue.net; do
        rc=0; banner_matches "$path" || rc=$?
        if ((rc == 0)); then
            if [[ $path == /etc/issue ]]; then local_match=1; else net_match=1; fi
        elif ((rc == 2)); then read_error=1; fi
    done
    if ((local_match == 0 && net_match == 0)); then
        if ((read_error)); then emit_result ERROR '경고 문구 파일 조회 실패' '' '' READ_FAILED
        else emit_result VULNERABLE 'issue/issue.net 어느 파일에도 승인 마커 전체가 없음' '' '필수 경고 문구와 실제 서비스 연결 설정 확인'; fi
        return
    fi
    ((local_match)) || unresolved+='로컬 /etc/issue의 승인 문구 미확인; '
    for role in ssh telnet ftp mail dns; do
        record_value "service:$role" state "${AUDIT_SERVICE_STATE[$role]:-UNKNOWN}"
        if [[ $role != ssh ]]; then
            case ${AUDIT_SERVICE_STATE[$role]:-UNKNOWN} in RUNNING|UNKNOWN) unresolved+="$role 실제 Banner 적용 확인 필요; " ;; esac
            continue
        fi
        case ${AUDIT_SERVICE_STATE[ssh]:-UNKNOWN} in
            RUNNING)
                if ! command -v sshd >/dev/null 2>&1 || ! capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" sshd -T; then unresolved+='sshd Banner 조회 실패; '; continue; fi
                banner=$(awk '$1=="banner"{print $2;exit}' <<<"$AUDIT_COMMAND_STDOUT")
                record_value 'sshd -T' Banner "$banner"
                local SSH_STATIC_VALUE='' SSH_HAS_MATCH=0 SSH_CONFIG_ERROR=''
                local -A SSH_VISITED=()
                ssh_read_config /etc/ssh/sshd_config
                if ((SSH_HAS_MATCH)) || [[ -n $SSH_CONFIG_ERROR ]]; then unresolved+='SSH Match/Include 조건별 Banner 확인 필요; '; continue; fi
                if [[ -z $banner || $banner == none ]]; then
                    emit_result VULNERABLE '실행 중 SSH에 로그인 전 경고 Banner가 설정되지 않음' "Banner:${banner:-미설정}"; return
                fi
                rc=0; banner_matches "$banner" || rc=$?
                if ((rc == 1)); then emit_result VULNERABLE 'SSH가 사용하는 Banner에 승인 문구 미충족' "Banner:$banner"; return
                elif ((rc)); then unresolved+="SSH Banner 읽기 실패:$banner; "; fi
                ;;
            UNKNOWN) unresolved+='SSH 실행 상태 미확인; ' ;;
        esac
    done
    if [[ -n $unresolved ]]; then emit_result MANUAL '파일 문구는 확인했으나 서비스 적용 범위 확인 필요' "$unresolved"
    else emit_result GOOD '승인 경고 문구와 확인한 로그인 경로의 Banner 설정 충족' "issue:$local_match issue.net:$net_match SSH_Banner:${banner:-비실행}"; fi
}

check_u_63() {
    local path
    local -A rules=([checked]=0 [errors]=0 [bad]='')
    if ! path_exists /etc/sudoers; then
        emit_result MANUAL 'sudoers 없음: sudo 미사용·대체 정책 확인 필요' '' 'sudo Plugin·sudoers.d·LDAP 정책 경로 확인'
        return
    fi
    local -a paths=(/etc/sudoers)
    for path in /etc/sudoers.d/*; do [[ -f $path ]] && paths+=("$path"); done
    for path in "${paths[@]}"; do
        if ! file_rule_add "$path" 0640 0 rules; then
            emit_result ERROR 'sudoers Metadata 확인 실패' "$path" '' STAT_FAILED
            return
        fi
    done
    file_rule_result sudoers rules GOOD MANUAL '0440/0400 등 더 제한적인 Bit 허용; 정당한 관리자 ALL/NOPASSWD 자체는 추가 취약 기준이 아님'
}

check_u_64() {
    local evidence file
    evidence="package_manager=$AUDIT_PACKAGE_MANAGER kernel=$(uname -r)"
    record_value system patch_context "$evidence"
    for file in /var/log/dpkg.log /var/log/apt/history.log /var/log/dnf.log /var/log/yum.log /var/log/pacman.log /var/log/apk.log; do
        if path_exists "$file" && file_metadata "$file"; then evidence+=$'\n'"$file uid=$FILE_UID mode=$FILE_MODE (내용·날짜·승인 기록 별도 확인)"; fi
    done
    emit_result MANUAL '패치 적용 정책·Vendor 권고·적용 기록 검토 필요' "$evidence" '온라인 갱신·패치 설치를 수행하지 않음. Vendor Backport·EOL·영향도 검토·적용 승인 기록과 대조; 업데이트 목록 0개만으로 GOOD 판정하지 않음'
}

check_u_65() {
    local provider=unknown runtime=unknown original=0 configured=0 policy_bad=0 source evidence=''
    record_value policy approved_time_sources "${AUDIT_CONFIG[approved_time_sources]}"
    if command -v chronyc >/dev/null 2>&1; then
        # -N exposes the names actually loaded by chronyd, including runtime changes.
        if capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" chronyc -N sources -a; then
            provider=chronyd; original=1
        elif capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" chronyc -n sources; then provider=chronyd; fi
        if [[ $provider == chronyd ]]; then
            evidence=$AUDIT_COMMAND_STDOUT
            if grep -Eq '^[[:space:]]*[\^=#]\*' <<<"$evidence"; then runtime=synchronized
            elif grep -Eq '^[[:space:]]*[\^=#][-+?x~]' <<<"$evidence"; then runtime=not_synchronized; fi
        fi
    fi
    if [[ $provider == unknown ]] && command -v ntpq >/dev/null 2>&1 && capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ntpq -pn; then
        provider=ntpd; evidence=$AUDIT_COMMAND_STDOUT
        if grep -Eq '^[*o]' <<<"$evidence"; then runtime=synchronized
        elif grep -Eq 'remote[[:space:]]+refid' <<<"$evidence"; then runtime=not_synchronized; fi
    fi
    if [[ $provider == unknown ]] && command -v timedatectl >/dev/null 2>&1 && capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" timedatectl show --property=NTPSynchronized --value; then
        evidence="NTPSynchronized=$AUDIT_COMMAND_STDOUT"
        case $AUDIT_COMMAND_STDOUT in yes) runtime=synchronized ;; no) runtime=not_synchronized ;; esac
    fi
    if ((original)); then
        while IFS= read -r source; do
            [[ -n $source ]] || continue
            case $source in '?' | *'>'* | *'..'*) original=0; continue ;; esac
            ((configured += 1))
            if [[ -n ${AUDIT_CONFIG[approved_time_sources]} ]] && ! list_has "${AUDIT_CONFIG[approved_time_sources]}" "$source"; then policy_bad=1; fi
        done < <(awk '$1 ~ /^[\^=][-+*?x~]$/ {print $2}' <<<"$evidence")
    fi
    evidence="provider=$provider runtime=$runtime configured_sources=$configured original_source_names=$original"$'\n'"$evidence"
    record_value "$provider" time_sync "$evidence"
    if [[ $runtime == not_synchronized ]]; then
        emit_result VULNERABLE '실제 시간 Source와 동기화되지 않음' "$evidence"
    elif ((original && policy_bad)); then
        emit_result VULNERABLE '활성 시간 Source와 입력한 승인 목록 불일치' "$evidence" '실제 설정 이름·Pool Member IP와 승인 이름의 관계 확인'
    elif [[ $original == 1 && $runtime == synchronized && -n ${AUDIT_CONFIG[approved_time_sources]} && $configured -ge 1 ]]; then
        emit_result MANUAL 'Runtime 동기화·승인 Source 설정 확보' "$evidence" '실제 선택 Source·Polling 주기·동기화 오차 기준 확인'
    else emit_result MANUAL '시간 동기화 정책 또는 Runtime 증거 미확정' "$evidence" '승인 Source·실제 Provider·원래 설정 이름과 IP 대응·시간 오차·Polling 기준 확인'; fi
}

check_u_66() {
    local path real file policy line policy_index=0 evidence='' missing=0 files=0
    local -A matched_policy=()
    local -a paths=(/etc/rsyslog.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf /etc/systemd/journald.conf
        /etc/rsyslog.d/*.conf /etc/syslog-ng/conf.d/*.conf /etc/systemd/journald.conf.d/*.conf)
    record_value policy required_log_patterns "${AUDIT_CONFIG[required_log_patterns]}"
    for path in "${paths[@]}"; do
        path_exists "$path" || continue
        real=$(target_path "$path") || {
            emit_result ERROR 'Logger 설정 수집 실패' "$path" '' READ_FAILED
            return
        }
        # 설정 전체나 로그 본문 대신 비교에 사용한 필드와 행 번호만 수집한다.
        if ! capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" awk '
            BEGIN {
                required_count=split(ARGV[1],required,"\n");ARGV[1]=""
                active=0;local_dest=0;remote_dest=0;storage="not_explicit"
            }
            {
                sub(/\r$/,"")
                if($0 ~ /^[[:space:]]*(#|;|$)/)next
                active++
                if($0 ~ /^[[:space:]]*[^[:space:]]+[[:space:]]+-?\//) {local_dest++;printf "line=%d selector=%s destination=%s\n",NR,$1,$2}
                else if($0 ~ /file[[:space:]]*\([[:space:]]*"\//) {
                    local_dest++;value="local_file (경로 해석 불가)"
                    if(match($0,/file[[:space:]]*\([[:space:]]*"\/[^"]*"/))value=substr($0,RSTART,RLENGTH)
                    printf "line=%d destination=%s\n",NR,value
                }
                if($0 ~ /^[[:space:]]*[^[:space:]]+[[:space:]]+@@?/) {remote_dest++;printf "line=%d selector=%s destination=%s\n",NR,$1,$2}
                else if(tolower($0) ~ /type[[:space:]]*=[[:space:]]*"omfwd"/ || $0 ~ /(tcp|udp|network)[[:space:]]*\(/) {remote_dest++;printf "line=%d destination=remote\n",NR}
                if($0 ~ /^[[:space:]]*Storage[[:space:]]*=/) {
                    value=$0;sub(/^[^=]*=[[:space:]]*/,"",value);sub(/[[:space:]]*#.*/,"",value);sub(/[[:space:]]*$/,"",value)
                    storage=(value ~ /^(auto|volatile|persistent|none)$/ ? value : "other")
                    printf "line=%d Storage=%s\n",NR,value
                }
                for(i=1;i<=required_count;i++)if(required[i]!="" && index($0,required[i]) && !matched[i])matched[i]=NR
            }
            END {
                printf "active_lines=%d local_destination_candidates=%d remote_destination_candidates=%d storage=%s\n",active,local_dest,remote_dest,storage
                for(i=1;i<=required_count;i++)if(matched[i])printf "policy_index=%d line=%d\n",i,matched[i]
            }' "${AUDIT_CONFIG[required_log_patterns]}" "$real"; then
            emit_result ERROR 'Logger 설정 수집 실패' "$path" '' READ_FAILED
            return
        fi
        evidence+="$path:"$'\n'"$AUDIT_COMMAND_STDOUT"$'\n'
        record_value "$path" logging "$AUDIT_COMMAND_STDOUT"
        while IFS= read -r line; do
            if [[ $line =~ ^policy_index=([0-9]+)[[:space:]] ]]; then matched_policy[${BASH_REMATCH[1]}]=1; fi
        done <<<"$AUDIT_COMMAND_STDOUT"
    done
    real=$(target_path /var/log) || real=
    if [[ -d $real ]]; then
        local records="$AUDIT_WORK_DIR/logger.$BASHPID"
        if ! collect_paths "$records" "$real" -maxdepth 2 -type f -size +0c -print0; then
            emit_result ERROR 'Log 파일 탐색 실패' "$evidence" '' FIND_FAILED
            return
        fi
        while IFS= read -r -d '' file; do
            ((files += 1))
            if capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" stat -Lc '%s' -- "$file"; then
                record_value "$file" size_bytes "$AUDIT_COMMAND_STDOUT"
            else record_value "$file" size_bytes '조회 실패' ERROR; fi
        done <"$records"
        rm -f -- "$records" "$records.err"
    fi
    if [[ -n ${AUDIT_CONFIG[required_log_patterns]} ]]; then
        while IFS= read -r policy; do
            ((policy_index += 1))
            [[ -z $policy ]] && continue
            record_value policy required_pattern_match "pattern:$policy found:${matched_policy[$policy_index]:-0}"
            [[ -v matched_policy[$policy_index] ]] || missing=1
        done <<<"${AUDIT_CONFIG[required_log_patterns]}"
    fi
    emit_result MANUAL '로깅 설정·기록 파일 증거 확보; 정책과 실제 기록 검토 필요' "nonempty_log_files=$files required_pattern_missing=$missing $evidence" '설정 파일/Process 존재만으로 GOOD 판정하지 않음. 조직 정책·Facility/Level·실제 최근 기록·중앙 전송·journald 저장 방식 확인'
}

check_u_67() {
    require_accounts || return
    [[ -d /var/log ]] || { record_value /var/log directory no MISSING; emit_result ERROR '/var/log 없음' '' '' PATH_FAILED; return; }
    local owners=0 name
    local -A rules=([checked]=0 [errors]=0 [bad]='')
    record_value policy approved_log_accounts "${AUDIT_CONFIG[approved_log_accounts]}"
    while IFS= read -r name; do
        [[ -n $name ]] || continue
        if [[ -v AUDIT_ACCOUNT_UID[$name] ]]; then owners+=",${AUDIT_ACCOUNT_UID[$name]}"
        else rules[manual]=1; record_value policy "$name" '승인 계정 UID 확인 실패' MISSING; fi
    done <<<"${AUDIT_CONFIG[approved_log_accounts]//,/$'\n'}"
    record_value criterion log_permissions 'mode&0002=0; UID 0 또는 명시 승인한 계정. UID 1~999라는 이유만으로 자동 승인하지 않음'
    file_rule_scan /var/log 7775 "$owners" rules
    file_rule_result 'Log 파일' rules GOOD MANUAL '0660 등 그룹 쓰기는 허용; 추가 소유자는 approved_log_accounts에 명시' emit_result FIND_FAILED
}

# --- 결과 출력 — 민감값 제거 후 기록 ---

json_quote() {
    # Validate UTF-8 before writing JSON. Invalid filename bytes become \u00xx.
    local input=${1-} output='"' char code i j next size need valid hex
    local LC_ALL=C
    size=${#input}
    for ((i = 0; i < size; i++)); do
        char=${input:i:1}
        printf -v code '%d' "'$char"
        case $char in
        '"') output+='\"' ;;
        '\') output+='\\' ;;
        $'\n') output+='\n' ;;
        $'\r') output+='\r' ;;
        $'\t') output+='\t' ;;
        *)
            if ((code < 32 || code == 127)); then
                printf -v hex '\\u%04x' "$code"
                output+=$hex
            elif ((code < 128)); then
                output+=$char
            else
                need=0
                ((code >= 194 && code <= 223)) && need=1
                ((code >= 224 && code <= 239)) && need=2
                ((code >= 240 && code <= 244)) && need=3
                valid=1
                ((need == 0 || i + need >= size)) && valid=0
                for ((j = 1; valid && j <= need; j++)); do
                    printf -v next '%d' "'${input:i+j:1}"
                    ((next >= 128 && next <= 191)) || valid=0
                    if ((j == 1)); then
                        ((code == 224 && next < 160)) && valid=0
                        ((code == 237 && next > 159)) && valid=0
                        ((code == 240 && next < 144)) && valid=0
                        ((code == 244 && next > 143)) && valid=0
                    fi
                done
                if ((valid)); then
                    output+=${input:i:need+1}
                    ((i += need))
                else
                    printf -v hex '\\u%04x' "$code"
                    output+=$hex
                fi
            fi
            ;;
        esac
    done
    printf '%s"' "$output"
}

redact_text() {
    # Retain surrounding evidence; never return credential values or PEM bodies.
    printf '%s' "${1-}" | awk '
    function masked_fields(text,    output,rest,low,head,value,n,i,q,ch,token) {
        output=""; rest=text
        while (match(tolower(rest),key_re)) {
            head=substr(rest,1,RSTART+RLENGTH-1)
            value=substr(rest,RSTART+RLENGTH)
            q=substr(value,1,1); n=0
            if (q=="\"" || q==sq) {
                n=length(value)
                for(i=2;i<=length(value);i++) {
                    ch=substr(value,i,1)
                    if(ch=="\\") {i++;continue}
                    if(ch==q) {n=i;break}
                }
                output=output head q "[xxx]" q
            } else {
                if(match(value,/^[^[:space:],;)}]+/)) n=RLENGTH
                token=tolower(substr(value,1,n))
                if(tolower(head) ~ /authorization[[:space:]]*[:=][[:space:]]*$/ && (token=="bearer" || token=="basic")) {
                    if(match(substr(value,n+1),/^[[:space:]]+[^[:space:],;)}]+/)) n+=RLENGTH
                }
                output=output head "[xxx]"
            }
            rest=substr(value,n+1)
        }
        return output rest
    }
    BEGIN {
        sq=sprintf("%c",39)
        key_re="(^|[^[:alnum:]_])([[:alnum:]_.-]*(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key)|pass|authorization|rocommunity6?|rwcommunity6?|community)[\"" sq "]?[[:space:]]*[:=][[:space:]]*"
        pem=0
    }
    {
        line=$0; low=tolower(line)
        if(low ~ /-----begin .*private key-----/) {pem=1;print "[private key:xxx]";next}
        if(pem) {if(low ~ /-----end .*private key-----/) pem=0;next}
        while(match(line,/\$[[:alnum:]-]+\$[^[:space:]:]+/)) {
            token=substr(line,RSTART,RLENGTH);split(token,p,"$")
            line=substr(line,1,RSTART-1) "[hash:" p[2] ":xxx]" substr(line,RSTART+RLENGTH)
        }
        while(match(line,/:\/\/[^[:space:]\/:@]+:[^[:space:]\/@]+@/)) {
            line=substr(line,1,RSTART-1) "://[xxx]@" substr(line,RSTART+RLENGTH)
        }
        print masked_fields(line)
    }'
}

emit_result() {
    local status=$1 summary=${2-} evidence=${3-} manual=${4-} error_code=${5-}
    case $status in GOOD | VULNERABLE | MANUAL | NOT_APPLICABLE | ERROR) ;; *)
        status=ERROR
        error_code=INVALID_STATUS
        ;;
    esac
    summary=$(redact_text "${summary:0:12000}")
    evidence=$(redact_text "${evidence:0:24000}")
    manual=$(redact_text "${manual:0:12000}")
    if [[ -n $AUDIT_ITEM_TEXT_PATH ]]; then
        printf '판정: %s\n이유: %s\n근거: %s\n추가 확인: %s\n오류: %s\n\n' \
            "$status" "$summary" "$evidence" "$manual" "$error_code" >>"$AUDIT_ITEM_TEXT_PATH"
    fi
    printf '{"id":%s,"title":%s,"severity":%s,"status":%s,"summary":%s,"evidence":%s,"manual_action":%s,"error_code":%s,"purpose":%s,"risk":%s,"guide_pdf_page":%s}\n' \
        "$(json_quote "$AUDIT_CURRENT_ID")" "$(json_quote "${AUDIT_CATALOG_TITLE[$AUDIT_CURRENT_ID]}")" \
        "$(json_quote "${AUDIT_CATALOG_SEVERITY[$AUDIT_CURRENT_ID]}")" "$(json_quote "$status")" \
        "$(json_quote "$summary")" "$(json_quote "$evidence")" "$(json_quote "$manual")" \
        "$(json_quote "$error_code")" "$(json_quote "${AUDIT_CATALOG_PURPOSE[$AUDIT_CURRENT_ID]}")" \
        "$(json_quote "${AUDIT_CATALOG_RISK[$AUDIT_CURRENT_ID]}")" "${AUDIT_CATALOG_PAGE[$AUDIT_CURRENT_ID]}"
}

report_text() {
    local -n statuses=$1
    local started_at=$2 target=$3 policy_hash=$4 script_hash=$5 id status count
    printf 'CIIP Audit %s / Guide 2026\n시작: %s\n대상: %s / %s\n실행 범위: %s\n파일 탐색: %s\n정책 SHA256: %s\n스크립트 SHA256: %s\n' \
        "$AUDIT_VERSION" "$started_at" "$target" "$AUDIT_OS_DESCRIPTION" "$AUDIT_RUNTIME_SCOPE" "$AUDIT_SCAN_SCOPE" "$policy_hash" "$script_hash"
    printf '\n결과 요약:'
    for status in VULNERABLE ERROR MANUAL GOOD NOT_APPLICABLE; do
        count=0
        for id in "${AUDIT_SELECTED[@]}"; do [[ ${statuses[$id]-} == "$status" ]] && ((count += 1)); done
        printf ' %s=%d' "$status" "$count"
    done
    printf '\n우선 확인 항목:\n'
    for id in "${AUDIT_SELECTED[@]}"; do
        status=${statuses[$id]-}
        if [[ $status == VULNERABLE || $status == ERROR ]]; then
            printf '  %s %s — %s\n' "$id" "$status" "${AUDIT_CATALOG_TITLE[$id]}"
        fi
    done
    printf '\n'
    for id in "${AUDIT_SELECTED[@]}"; do
        [[ -r $AUDIT_WORK_DIR/$id.txt ]] || continue
        printf '[%s] %s (%s) — %s\n' "$id" "${AUDIT_CATALOG_TITLE[$id]}" "${AUDIT_CATALOG_SEVERITY[$id]}" "${statuses[$id]-미완료}"
        cat -- "$AUDIT_WORK_DIR/$id.txt"
    done
    printf '\n미선택 항목: %s\n' "${AUDIT_NOT_SELECTED[*]}"
}

# --- 실행 ---

audit_main() {
    local arg key value i id flag result count=0 full_json first=1 status
    local preview_only=0 started_at target policy_hash=unavailable script_hash=unavailable
    local -A result_status=()
    trap audit_cleanup EXIT
    trap 'AUDIT_INTERRUPTED=1' INT TERM
    while (($#)); do
        arg=$1
        shift
        case $arg in
        --help | -h)
            audit_log '사용법: bash ciip_linux_2026.sh [--set key=value] [--show-config] [--validate-config]'
            audit_log '외부 실행 제한 예: sudo nice -n 19 ionice -c3 timeout 3600 bash ciip_linux_2026.sh'
            audit_log '일괄 파일 점검은 GNU find의 -printf가 필요하며, 미지원 시 해당 항목에 기록합니다.'
            show_config
            return 0
            ;;
        --show-config | --validate-config) preview_only=1 ;;
        --set)
            (($#)) || abort_run '--set key=value 필요'
            [[ $1 == *=* ]] || abort_run '--set key=value 형식 필요'
            key=${1%%=*}
            value=${1#*=}
            shift
            [[ $key =~ ^[a-z_]+$ ]] || abort_run '설정 Key 형식 오류'
            [[ -v AUDIT_CONFIG[$key] ]] || abort_run "알 수 없는 설정: $key"
            AUDIT_CONFIG[$key]=$value
            ;;
        *) abort_run "알 수 없는 인자: $arg" ;;
        esac
    done
    value=${AUDIT_CONFIG[command_timeout_seconds]}
    [[ $value =~ ^[1-9][0-9]{0,3}$ ]] && ((value <= 3600)) || abort_run 'command_timeout_seconds: 1~3600 사이 정수 필요'
    [[ -n ${AUDIT_CONFIG[output_dir]} && ${AUDIT_CONFIG[output_dir]} != *$'\n'* ]] || abort_run '출력 경로 오류'
    load_catalog || abort_run '가이드 Catalog 오류'
    for ((i = 1; i <= 67; i++)); do
        printf -v id 'U-%02d' "$i"
        if [[ ${AUDIT_CONFIG[check_ids]} == ALL ]] || list_has "${AUDIT_CONFIG[check_ids]}" "$id"; then
            AUDIT_SELECTED+=("$id")
        else AUDIT_NOT_SELECTED+=("$id"); fi
    done
    if [[ ${AUDIT_CONFIG[check_ids]} != ALL ]]; then
        while IFS= read -r id; do
            [[ $id =~ ^U-[0-9]{2}$ ]] || abort_run '항목 ID 형식 오류'
            [[ -v AUDIT_CATALOG_TITLE[$id] ]] || abort_run "알 수 없는 항목: $id"
        done <<<"${AUDIT_CONFIG[check_ids]//,/$'\n'}"
    fi
    show_config
    ((preview_only)) && return 0
    readonly -A AUDIT_CONFIG
    for key in awk sed stat find sort head date mktemp readlink grep cat rm mv wc chmod mkdir uname tr cut; do
        command -v "$key" >/dev/null 2>&1 || abort_run "필수 도구 없음: $key"
    done
    if ((EUID != 0)); then audit_log '주의: root가 아니며 일부 항목은 ERROR가 될 수 있습니다.'; fi
    [[ $(uname -s) == Linux ]] || abort_run 'Linux Kernel이 필요합니다.'
    mkdir -p -- "${AUDIT_CONFIG[output_dir]}" || return 2
    AUDIT_OUTPUT_BASE=$(cd -- "${AUDIT_CONFIG[output_dir]}" && pwd -P) || return 2
    AUDIT_OUTPUT_DIR=$(mktemp -d "$AUDIT_OUTPUT_BASE/audit.XXXXXXXX") || return 2
    AUDIT_OUTPUT_DIR=$(cd -- "$AUDIT_OUTPUT_DIR" && pwd -P) || return 2
    chmod 700 -- "$AUDIT_OUTPUT_DIR" || return 2
    AUDIT_WORK_DIR=$(mktemp -d "$AUDIT_OUTPUT_DIR/.work.XXXXXXXX") || return 2
    started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    target=$(uname -n)
    if command -v sha256sum >/dev/null 2>&1; then
        script_hash=$(sha256sum -- "${BASH_SOURCE[0]}" 2>/dev/null) || script_hash=unavailable
        policy_hash=$(for key in "${!AUDIT_CONFIG[@]}"; do printf '%s\n' "$key"; done | sort |
            while IFS= read -r key; do printf '%s\0%s\0' "$key" "${AUDIT_CONFIG[$key]}"; done | sha256sum) || policy_hash=unavailable
        script_hash=${script_hash%% *}; policy_hash=${policy_hash%% *}
    fi
    select_collectors
    platform_collect
    if ((AUDIT_NEED_ACCOUNTS || AUDIT_NEED_GROUPS || AUDIT_NEED_SHADOW)); then account_collect; fi
    scan_collect
    : >"$AUDIT_OUTPUT_DIR/items.jsonl"
    for id in "${AUDIT_SELECTED[@]}"; do
        ((AUDIT_INTERRUPTED)) && break
        AUDIT_CURRENT_ID=$id
        AUDIT_ITEM_TEXT_PATH="$AUDIT_WORK_DIR/$id.txt"
        record_accounts
        flag=${id/U-/check_u_}
        result="$AUDIT_WORK_DIR/$id.json"
        if ! declare -F "$flag" >/dev/null; then
            emit_result ERROR '점검 함수 없음' "$flag" '' MISSING_IMPLEMENTATION >"$result"
        else
            # Isolated Scope: an unexpected exception/exit affects one item.
            ("$flag") >"$result" 2>"$AUDIT_WORK_DIR/$id.err" || :
            count=$(wc -l <"$result")
            if [[ $count != 1 || $(head -c 6 "$result") != '{"id":' ]]; then
                emit_result ERROR '항목 실행 중 결과 계약 위반 또는 예외' "$(redact_text "$(head -c 8192 "$AUDIT_WORK_DIR/$id.err")")" 'Runtime/Script 오류 확인' CHECK_FAILED >"$result"
            fi
        fi
        status=$(sed -n 's/.*"status":"\([A-Z_]*\)".*/\1/p' "$result")
        # Read by report_text through its statuses nameref.
        # shellcheck disable=SC2034
        result_status[$id]=$status
        cat -- "$result" >>"$AUDIT_OUTPUT_DIR/items.jsonl" || return 2
        audit_log "$id 완료"
    done
    full_json="$AUDIT_WORK_DIR/result.json"
    {
        printf '{"schema_version":"1.1","tool_version":%s,"started_at":%s,"target":%s,"policy_sha256":%s,"script_sha256":%s,"guide_version":"2026","platform":"linux","os":%s,"kernel":%s,"runtime_scope":%s,"scan_scope":%s,"interrupted":%s,"selected_count":%d,"not_selected":[' \
            "$(json_quote "$AUDIT_VERSION")" "$(json_quote "$started_at")" "$(json_quote "$target")" \
            "$(json_quote "$policy_hash")" "$(json_quote "$script_hash")" "$(json_quote "$AUDIT_OS_DESCRIPTION")" "$(json_quote "$(uname -r)")" \
            "$(json_quote "$AUDIT_RUNTIME_SCOPE")" \
            "$(json_quote "$AUDIT_SCAN_SCOPE")" "$([[ $AUDIT_INTERRUPTED == 1 ]] && printf true || printf false)" "${#AUDIT_SELECTED[@]}"
        first=1
        for id in "${AUDIT_NOT_SELECTED[@]}"; do
            ((first)) || printf ','
            json_quote "$id"
            first=0
        done
        printf '],"items":['
        first=1
        while IFS= read -r result; do
            ((first)) || printf ','
            printf '%s' "$result"
            first=0
        done <"$AUDIT_OUTPUT_DIR/items.jsonl"
        printf ']}\n'
    } >"$full_json" || return 2
    mv -- "$full_json" "$AUDIT_OUTPUT_DIR/result.json" || return 2
    report_text result_status "$started_at" "$target" "$policy_hash" "$script_hash" >"$AUDIT_OUTPUT_DIR/report.txt" || return 2
    audit_log "완료: $AUDIT_OUTPUT_DIR/result.json / report.txt"
    ((AUDIT_INTERRUPTED)) && return 130
    if grep -q '"status":"ERROR"' "$AUDIT_OUTPUT_DIR/items.jsonl"; then return 3; fi
    return 0
}

audit_main "$@"
