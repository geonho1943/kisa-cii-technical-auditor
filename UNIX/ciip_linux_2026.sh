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
    [output_dir]="./audit-results"
    [check_ids]="ALL"
    [command_timeout_seconds]="15"
    [scan_timeout_seconds]="180"
    [scan_roots]="AUTO"
    [approved_accounts]=""
    [approved_admin_accounts]=""
    [approved_groups]=""
    [nonlogin_accounts]=""
    [required_services]=""
    [approved_time_sources]=""
    [required_log_patterns]=""
    [allowed_management_cidrs]=""
    [approved_special_files]=""
    [approved_world_writable_paths]=""
    [approved_hidden_paths]=""
    [approved_device_files]=""
    [approved_banner_markers]=""
)
# 설명도 상단에서 함께 관리한다. 도움말·설정 미리보기는 이 정의를 읽는다.
declare -A AUDIT_CONFIG_INFO=(
    [output_dir]="string|결과 저장 경로. 접근 권한을 제한한 실행별 하위 폴더 생성|./audit-results"
    [check_ids]="ids|검사할 공식 ID. ALL 또는 쉼표 구분. 미선택 항목은 별도 기록|U-01,U-18"
    [command_timeout_seconds]="seconds|명령별 제한 시간(초). 1~3600|15"
    [scan_timeout_seconds]="seconds|파일 탐색·처리 제한 시간(초). 1~86400|180"
    [scan_roots]="paths|AUTO=현재 Namespace의 로컬 Mount. 지정 시 줄바꿈 구분 절대 경로; 부분 범위로 표시|AUTO"
    [approved_accounts]="list|업무상 승인한 전체 계정. 줄바꿈 또는 쉼표 구분; 미입력 U-07 수동 확인|root,appuser"
    [approved_admin_accounts]="list|관리자 그룹에 허용할 계정; 미입력 U-08 수동 확인|root,adminuser"
    [approved_groups]="list|업무상 승인한 그룹; 미입력 U-09 수동 확인|root,appgroup"
    [nonlogin_accounts]="list|로그인이 불필요한 서비스 계정; 미입력 U-11 수동 확인|daemon,appsvc"
    [required_services]="list|업무상 필요한 서비스 역할. nfs,rpc,r,snmp,automount 등. 필요성은 자동 추정하지 않음|nfs"
    [approved_time_sources]="list|승인 NTP 서버/Pool 이름 또는 IP; 미입력 U-65 정책 확인 필요|time.example.org"
    [required_log_patterns]="lines|조직에서 요구하는 활성 로깅 설정 문자열. 줄바꿈 구분, Literal 일치|authpriv.*"
    [allowed_management_cidrs]="list|허용 관리망 CIDR. 방화벽의 실제 순서·IPv6·외부 ACL은 별도 검토|192.0.2.0/24"
    [approved_special_files]="paths|SUID/SGID가 승인된 파일의 정확한 경로. 줄바꿈 구분|/usr/bin/passwd"
    [approved_world_writable_paths]="paths|쓰기 허용 사유를 검토한 정확한 파일 경로. 하위 경로 자동 면제 없음|/srv/share/file"
    [approved_hidden_paths]="paths|검토 완료한 정확한 숨김 경로. 기본 OS 파일도 자동 승인하지 않음|/root/.profile"
    [approved_device_files]="paths|검토 완료한 /dev 일반 파일의 정확한 경로|/dev/example"
    [approved_banner_markers]="lines|승인 경고 문구에 반드시 포함될 문자열. 언어 무관, 줄바꿈 구분|승인된 사용자"
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
AUDIT_VERSION=0.1.0
AUDIT_ITEM_DEADLINE=0
AUDIT_SYSTEMCTL_AVAILABLE=0
AUDIT_NEED_ACCOUNTS=0
AUDIT_NEED_GROUPS=0
AUDIT_NEED_SHADOW=0
declare -A AUDIT_REQUIRED_ROLES=()
AUDIT_WORK_DIR=
AUDIT_OUTPUT_DIR=
AUDIT_INTERRUPTED=0
declare -A AUDIT_CATALOG_TITLE=() AUDIT_CATALOG_SEVERITY=()
declare -A AUDIT_CATALOG_PURPOSE=() AUDIT_CATALOG_RISK=() AUDIT_CATALOG_PAGE=()
declare -a AUDIT_SELECTED=() AUDIT_NOT_SELECTED=()
AUDIT_COMMAND_COUNTER=0
AUDIT_ITEM_TEXT_PATH=

audit_log() { printf '%s\n' "$*" >&2; }

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
        printf '[%s] %s (%s) — %s\n결과: %s\n근거: %s\n확인 방법: %s\n점검 목적: %s\n미조치 위험: %s\n오류: %s\n\n' \
            "$AUDIT_CURRENT_ID" "${AUDIT_CATALOG_TITLE[$AUDIT_CURRENT_ID]}" "${AUDIT_CATALOG_SEVERITY[$AUDIT_CURRENT_ID]}" \
            "$status" "$summary" "$evidence" "$manual" "${AUDIT_CATALOG_PURPOSE[$AUDIT_CURRENT_ID]}" \
            "${AUDIT_CATALOG_RISK[$AUDIT_CURRENT_ID]}" "$error_code" >"$AUDIT_ITEM_TEXT_PATH"
    fi
    printf '{"id":%s,"title":%s,"severity":%s,"status":%s,"summary":%s,"evidence":%s,"manual_action":%s,"error_code":%s,"purpose":%s,"risk":%s,"guide_pdf_page":%s}\n' \
        "$(json_quote "$AUDIT_CURRENT_ID")" "$(json_quote "${AUDIT_CATALOG_TITLE[$AUDIT_CURRENT_ID]}")" \
        "$(json_quote "${AUDIT_CATALOG_SEVERITY[$AUDIT_CURRENT_ID]}")" "$(json_quote "$status")" \
        "$(json_quote "$summary")" "$(json_quote "$evidence")" "$(json_quote "$manual")" \
        "$(json_quote "$error_code")" "$(json_quote "${AUDIT_CATALOG_PURPOSE[$AUDIT_CURRENT_ID]}")" \
        "$(json_quote "${AUDIT_CATALOG_RISK[$AUDIT_CURRENT_ID]}")" "${AUDIT_CATALOG_PAGE[$AUDIT_CURRENT_ID]}"
}

path_exists() {
    local path
    path=$(target_path "$1") || return 2
    [[ -e $path || -L $path ]]
}



read_target() {
    local file text code=0 err="$AUDIT_WORK_DIR/read.$BASHPID.$RANDOM.err"
    file=$(target_path "$1") || return 2
    [[ -f $file && -r $file ]] || return 2
    # Read through a pipe, never a plaintext temporary copy of the config.
    text=$(capture_file /dev/stdout "$err" "${AUDIT_CONFIG[command_timeout_seconds]}" head -c 262145 -- "$file") || code=$?
    rm -f -- "$err"
    ((code == 0)) || return "$code"
    ((${#text} <= 262144)) || return 125
    printf '%s' "$text"
}

active_lines() {
    local text
    text=$(read_target "$1") || return $?
    printf '%s\n' "$text" | awk '{sub(/\r$/,""); if ($0 !~ /^[[:space:]]*(#|;|$)/) print}'
}

config_value() {
    local path=$1 key=$2
    active_lines "$path" | awk -v key="$key" '
        { line=$0; sub(/[[:space:]]+#.*/,"",line); gsub(/=/," ",line)
          n=split(line,a,/[[:space:]]+/); start=(a[1]==""?2:1)
          if(tolower(a[start])==tolower(key)) {value=a[start+1]; found=1} }
        END {if(found)print value;else exit 1}'
}

list_has() {
    local values=${1-} wanted=$2 value
    values=${values//,/$'\n'}
    while IFS= read -r value || [[ -n $value ]]; do
        [[ $value == "$wanted" ]] && return 0
    done <<<"$values"
    return 1
}

capture_command() {
    local budget=$1
    shift
    local code=0 out err
    local AUDIT_CAPTURE_LIMIT_BLOCKS=512
    ((AUDIT_COMMAND_COUNTER += 1))
    out="$AUDIT_WORK_DIR/cmd.$BASHPID.$AUDIT_COMMAND_COUNTER.out"
    err="$AUDIT_WORK_DIR/cmd.$BASHPID.$AUDIT_COMMAND_COUNTER.err"
    capture_file "$out" "$err" "$budget" "$@" || code=$?
    AUDIT_COMMAND_STDOUT=$(head -c 262144 -- "$out" 2>/dev/null)
    AUDIT_COMMAND_STDERR=$(head -c 8192 -- "$err" 2>/dev/null)
    if [[ $(wc -c <"$out") -gt 262144 ]]; then
        code=125
        AUDIT_COMMAND_STDERR+=' output exceeds collector limit'
    fi
    AUDIT_COMMAND_RC=$code
    rm -f -- "$out" "$err" "$out.timeout"
    return "$code"
}

capture_file() {
    local out=$1 err=$2 budget=$3 remaining
    shift 3
    if ((AUDIT_ITEM_DEADLINE > 0)); then
        remaining=$((AUDIT_ITEM_DEADLINE - SECONDS))
        if ((remaining <= 0)); then
            : >"$out"
            printf '%s\n' 'item time budget exhausted' >"$err"
            return 124
        fi
        ((remaining < budget)) && budget=$remaining
    fi
    (
        # Bound stdout and stderr on disk as well as the later in-memory read.
        ulimit -f "${AUDIT_CAPTURE_LIMIT_BLOCKS:-16384}" || exit 125
        local code=0 pid watch marker="$AUDIT_WORK_DIR/capture.$BASHPID.$RANDOM.timeout"
        if command -v timeout >/dev/null 2>&1; then
            timeout -k 2 "$budget" "$@" >"$out" 2>"$err" || code=$?
        else
            "$@" >"$out" 2>"$err" &
            pid=$!
            (
                sleep "$budget"
                if kill -0 "$pid" 2>/dev/null; then
                    : >"$marker"
                    kill_descendants "$pid"
                    kill -TERM "$pid" 2>/dev/null || :
                    sleep 2
                    kill -KILL "$pid" 2>/dev/null || :
                fi
            ) &
            watch=$!
            wait "$pid" || code=$?
            kill_descendants "$watch"
            kill -TERM "$watch" 2>/dev/null || :
            wait "$watch" 2>/dev/null || :
            [[ -f $marker ]] && code=124
        fi
        rm -f -- "$marker"
        exit "$code"
    )
}

collect_paths() {
    local destination=$1 root
    shift
    root=$1
    shift
    # The common collector supplies the item deadline and 16 MiB file limit.
    # Stop at 200,000 returned NUL records as an additional practical ceiling.
    capture_file "$destination" "$destination.err" "${AUDIT_CONFIG[scan_timeout_seconds]}" \
        "$BASH" --noprofile --norc -c '
            set -o pipefail
            find "$@" | {
                count=0
                while IFS= read -r -d "" record; do
                    ((count += 1))
                    ((count <= 200000)) || exit 125
                    printf "%s\0" "$record"
                done
            }
        ' -- "$root" -xdev "$@"
}

kill_descendants() {
    local parent=$1 child
    command -v ps >/dev/null 2>&1 || return 0
    while read -r child; do
        [[ $child =~ ^[0-9]+$ ]] || continue
        kill_descendants "$child"
        kill -TERM "$child" 2>/dev/null || :
    done < <(ps -eo pid=,ppid= 2>/dev/null | awk -v p="$parent" '$2==p {print $1}')
}

audit_cleanup() {
    local pid
    while read -r pid; do
        [[ $pid =~ ^[0-9]+$ ]] || continue
        kill_descendants "$pid"
        kill -TERM "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
    done < <(jobs -pr)
    if [[ -n $AUDIT_WORK_DIR && -d $AUDIT_WORK_DIR ]]; then rm -rf -- "$AUDIT_WORK_DIR"; fi
}

file_metadata() {
    local real
    real=$(target_path "$1") || return 2
    capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" stat -Lc '%u %g %a' -- "$real" || return 2
    read -r FILE_UID FILE_GID FILE_MODE <<<"$AUDIT_COMMAND_STDOUT"
    [[ $FILE_UID =~ ^[0-9]+$ && $FILE_GID =~ ^[0-9]+$ && $FILE_MODE =~ ^[0-7]{1,4}$ ]] || return 2
}

mode_within() {
    local actual=$1 allowed=$2
    [[ $actual =~ ^[0-7]{1,4}$ && $allowed =~ ^[0-7]{3,4}$ ]] || return 2
    (((8#$actual & ~8#$allowed) == 0))
}

check_file_rule() {
    local path=$1 allowed=$2 owners=${3:-0} optional=${4:-0}
    if ! path_exists "$path"; then
        if ((optional)); then
            emit_result GOOD '가이드상 파일 미존재 허용' "$path: 없음"
        else emit_result ERROR '필수 파일을 확인할 수 없음' "$path" '경로·권한·OS 제공 방식을 확인' MISSING_FILE; fi
        return
    fi
    if ! file_metadata "$path"; then
        emit_result ERROR '파일 Metadata 조회 실패' "$path" '읽기·stat 권한 확인' STAT_FAILED
        return
    fi
    if list_has "$owners" "$FILE_UID" && mode_within "$FILE_MODE" "$allowed"; then
        emit_result GOOD '소유자 및 권한이 가이드 범위 내' "$path uid=$FILE_UID gid=$FILE_GID mode=$FILE_MODE allowed=$allowed"
    else
        emit_result VULNERABLE '소유자 또는 허용 권한 Bit 초과' "$path uid=$FILE_UID gid=$FILE_GID mode=$FILE_MODE allowed=$allowed" '배포판 기본 설정·서비스 영향 및 승인 예외 확인'
    fi
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
        audit_log "    ${AUDIT_CONFIG_INFO[$key]}"
    done < <(printf '%s\n' "${!AUDIT_CONFIG[@]}" | sort)
}

audit_main() {
    local arg key value i id flag result count=0 full_json first=1 code status
    local show_only=0 validate_only=0
    trap audit_cleanup EXIT
    trap 'AUDIT_INTERRUPTED=1' INT TERM
    while (($#)); do
        arg=$1
        shift
        case $arg in
        --help | -h)
            audit_log '사용법: bash ciip_linux_2026.sh [--set key=value] [--show-config] [--validate-config]'
            show_config
            return 0
            ;;
        --show-config) show_only=1 ;;
        --validate-config) validate_only=1 ;;
        --set)
            (($#)) || {
                audit_log '--set key=value 필요'
                return 2
            }
            [[ $1 == *=* ]] || {
                audit_log '--set key=value 형식 필요'
                return 2
            }
            key=${1%%=*}
            value=${1#*=}
            shift
            [[ $key =~ ^[a-z_]+$ ]] || {
                audit_log '설정 Key 형식 오류'
                return 2
            }
            [[ -v AUDIT_CONFIG[$key] ]] || {
                audit_log "알 수 없는 설정: $key"
                return 2
            }
            AUDIT_CONFIG[$key]=$value
            ;;
        *)
            audit_log "알 수 없는 인자: $arg"
            return 2
            ;;
        esac
    done
    for key in command_timeout_seconds scan_timeout_seconds; do
        value=${AUDIT_CONFIG[$key]}
        [[ $value =~ ^[1-9][0-9]{0,4}$ ]] || {
            audit_log "$key: 양의 정수 필요"
            return 2
        }
        ((value <= 86400)) || {
            audit_log "$key: 범위 초과"
            return 2
        }
    done
    ((${AUDIT_CONFIG[command_timeout_seconds]} <= 3600)) || {
        audit_log '명령 Timeout 최대 3600초'
        return 2
    }
    [[ -n ${AUDIT_CONFIG[output_dir]} && ${AUDIT_CONFIG[output_dir]} != *$'\n'* ]] || {
        audit_log '출력 경로 오류'
        return 2
    }
    load_catalog || {
        audit_log '가이드 Catalog 오류'
        return 2
    }
    for ((i = 1; i <= 67; i++)); do
        printf -v id 'U-%02d' "$i"
        if [[ ${AUDIT_CONFIG[check_ids]} == ALL ]] || list_has "${AUDIT_CONFIG[check_ids]}" "$id"; then
            AUDIT_SELECTED+=("$id")
        else AUDIT_NOT_SELECTED+=("$id"); fi
    done
    if [[ ${AUDIT_CONFIG[check_ids]} != ALL ]]; then
        while IFS= read -r id; do
            [[ $id =~ ^U-[0-9]{2}$ ]] || {
                audit_log '항목 ID 형식 오류'
                return 2
            }
            [[ -v AUDIT_CATALOG_TITLE[$id] ]] || {
                audit_log "알 수 없는 항목: $id"
                return 2
            }
        done <<<"${AUDIT_CONFIG[check_ids]//,/$'\n'}"
    fi
    show_config
    ((show_only || validate_only)) && return 0
    readonly -A AUDIT_CONFIG AUDIT_CONFIG_INFO
    for key in awk sed stat find sort head date mktemp readlink grep cat rm mv wc chmod mkdir uname tr cut sleep; do
        command -v "$key" >/dev/null 2>&1 || {
            audit_log "필수 도구 없음: $key"
            return 2
        }
    done
    if ((EUID != 0)); then audit_log '주의: root가 아니며 일부 항목은 ERROR가 될 수 있습니다.'; fi
    [[ $(uname -s) == Linux ]] || {
        audit_log 'Linux Kernel이 필요합니다.'
        return 2
    }
    mkdir -p -- "${AUDIT_CONFIG[output_dir]}" || return 2
    AUDIT_OUTPUT_DIR=$(mktemp -d "${AUDIT_CONFIG[output_dir]%/}/audit.XXXXXXXX") || return 2
    AUDIT_OUTPUT_DIR=$(cd -- "$AUDIT_OUTPUT_DIR" && pwd -P) || return 2
    chmod 700 -- "$AUDIT_OUTPUT_DIR" || return 2
    AUDIT_WORK_DIR=$(mktemp -d "$AUDIT_OUTPUT_DIR/.work.XXXXXXXX") || return 2
    select_collectors
    platform_collect
    if ((AUDIT_NEED_ACCOUNTS || AUDIT_NEED_GROUPS || AUDIT_NEED_SHADOW)); then account_collect; fi
    scan_collect
    : >"$AUDIT_OUTPUT_DIR/items.jsonl"
    for id in "${AUDIT_SELECTED[@]}"; do
        ((AUDIT_INTERRUPTED)) && break
        AUDIT_CURRENT_ID=$id
        AUDIT_ITEM_TEXT_PATH="$AUDIT_WORK_DIR/$id.txt"
        flag=${id/U-/check_u_}
        result="$AUDIT_WORK_DIR/$id.json"
        if ! declare -F "$flag" >/dev/null; then
            emit_result ERROR '점검 함수 없음' "$flag" '' MISSING_IMPLEMENTATION >"$result"
        else
            # Isolated Scope: an unexpected exception/exit affects one item.
            (AUDIT_ITEM_DEADLINE=$((SECONDS + ${AUDIT_CONFIG[scan_timeout_seconds]})); "$flag") >"$result" 2>"$AUDIT_WORK_DIR/$id.err" || :
            count=$(wc -l <"$result")
            if [[ $count != 1 || $(head -c 6 "$result") != '{"id":' ]]; then
                emit_result ERROR '항목 실행 중 결과 계약 위반 또는 예외' "$(redact_text "$(head -c 8192 "$AUDIT_WORK_DIR/$id.err")")" 'Runtime/Script 오류 확인' CHECK_FAILED >"$result"
            fi
        fi
        cat -- "$result" >>"$AUDIT_OUTPUT_DIR/items.jsonl" || return 2
        audit_log "$id 완료"
    done
    full_json="$AUDIT_WORK_DIR/result.json"
    {
        printf '{"schema_version":"1.0","tool_version":%s,"guide_version":"2026","platform":"linux","os":%s,"kernel":%s,"runtime_scope":%s,"scan_scope":%s,"interrupted":%s,"selected_count":%d,"not_selected":[' \
            "$(json_quote "$AUDIT_VERSION")" "$(json_quote "$AUDIT_OS_DESCRIPTION")" "$(json_quote "$(uname -r)")" \
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
    report_text >"$AUDIT_OUTPUT_DIR/report.txt" || return 2
    audit_log "완료: $AUDIT_OUTPUT_DIR/result.json / report.txt"
    ((AUDIT_INTERRUPTED)) && return 130
    if grep -q '"status":"ERROR"' "$AUDIT_OUTPUT_DIR/items.jsonl"; then return 3; fi
    return 0
}

report_text() {
    local id
    printf 'CIIP Audit %s / Guide 2026\nOS: %s\nRuntime Scope: %s\nFilesystem Scope: %s\n\n' "$AUDIT_VERSION" "$AUDIT_OS_DESCRIPTION" "$AUDIT_RUNTIME_SCOPE" "$AUDIT_SCAN_SCOPE"
    for id in "${AUDIT_SELECTED[@]}"; do [[ -r $AUDIT_WORK_DIR/$id.txt ]] && cat -- "$AUDIT_WORK_DIR/$id.txt"; done
    printf '\n미선택 항목: %s\n' "${AUDIT_NOT_SELECTED[*]}"
}


# shellcheck shell=bash
# Capability discovery is independent of distribution and display language.
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
AUDIT_SCAN_COUNT=0
declare -a AUDIT_SCAN_ROOTS=()
declare -A AUDIT_SCAN_SELECTED=() AUDIT_SCAN_ITEM_COMPLETE=() AUDIT_SCAN_ITEM_CAPPED=()
declare -A AUDIT_SCAN_ITEM_COUNT=() AUDIT_SCAN_ITEM_UNAPPROVED=() AUDIT_SCAN_ITEM_ERROR=()
declare -a AUDIT_ORPHANS=() AUDIT_SPECIAL_FILES=() AUDIT_WORLD_FILES=() AUDIT_HIDDEN_FILES=()
declare -A AUDIT_UID_KNOWN=() AUDIT_SERVICE_STATE=() AUDIT_SERVICE_EVIDENCE=()

platform_collect() {
    local file id version name role output start=$SECONDS
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
            if ((SECONDS - start >= ${AUDIT_CONFIG[command_timeout_seconds]})); then
                AUDIT_PROCESS_COMPLETE=0
                break
            fi
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

service_definition() {
    case $1 in
    ssh)
        SERVICE_UNITS='sshd ssh dropbear'
        SERVICE_PROCESSES='sshd dropbear'
        SERVICE_PORTS='22'
        SERVICE_PACKAGES='openssh-server dropbear'
        ;;
    telnet)
        SERVICE_UNITS='telnet.socket telnet'
        SERVICE_PROCESSES='telnetd in.telnetd'
        SERVICE_PORTS='23'
        SERVICE_PACKAGES='telnetd telnet-server inetutils-telnetd'
        ;;
    ftp)
        SERVICE_UNITS='vsftpd proftpd pure-ftpd ftpd'
        SERVICE_PROCESSES='vsftpd proftpd pure-ftpd ftpd'
        SERVICE_PORTS='21'
        SERVICE_PACKAGES='vsftpd proftpd pure-ftpd'
        ;;
    nfs)
        SERVICE_UNITS='nfs-server nfs-kernel-server nfs'
        SERVICE_PROCESSES='nfsd rpc.nfsd'
        SERVICE_PORTS='2049'
        SERVICE_PACKAGES='nfs-kernel-server nfs-utils'
        ;;
    samba)
        SERVICE_UNITS='smb smbd samba'
        SERVICE_PROCESSES='smbd samba'
        SERVICE_PORTS='139 445'
        SERVICE_PACKAGES='samba samba-server'
        ;;
    r)
        SERVICE_UNITS='rsh.socket rlogin.socket rexec.socket rsh rlogin rexec'
        SERVICE_PROCESSES='rshd in.rshd rlogind in.rlogind rexecd in.rexecd'
        SERVICE_PORTS='512 513 514'
        SERVICE_PACKAGES='rsh-server rsh-redone-server'
        ;;
    finger)
        SERVICE_UNITS='finger.socket fingerd'
        SERVICE_PROCESSES='fingerd in.fingerd'
        SERVICE_PORTS='79'
        SERVICE_PACKAGES='fingerd finger-server'
        ;;
    dos)
        SERVICE_UNITS='echo.socket discard.socket daytime.socket chargen.socket'
        SERVICE_PROCESSES='in.chargend chargen'
        SERVICE_PORTS='7 9 13 19'
        SERVICE_PACKAGES=''
        ;;
    automount)
        SERVICE_UNITS='autofs automount'
        SERVICE_PROCESSES='automount automountd'
        SERVICE_PORTS=''
        SERVICE_PACKAGES='autofs'
        ;;
    rpc)
        SERVICE_UNITS='rusersd rwalld rstatd sprayd rpc.rusersd'
        SERVICE_PROCESSES='rpc.rusersd rpc.rwalld rpc.rstatd rpc.sprayd rusersd rwalld rstatd'
        SERVICE_PORTS=''
        SERVICE_PACKAGES='rusers-server rwall-server rstat-server'
        ;;
    nis)
        SERVICE_UNITS='ypserv ypbind yppasswdd'
        SERVICE_PROCESSES='ypserv ypbind yppasswdd'
        SERVICE_PORTS=''
        SERVICE_PACKAGES='ypserv ypbind nis'
        ;;
    tftp)
        SERVICE_UNITS='tftp.socket tftpd tftpd-hpa talk.socket ntalk.socket'
        SERVICE_PROCESSES='in.tftpd tftpd in.talkd talkd ntalkd'
        SERVICE_PORTS='69 517 518'
        SERVICE_PACKAGES='tftp-server tftpd tftpd-hpa talkd'
        ;;
    mail)
        SERVICE_UNITS='postfix sendmail exim exim4 opensmtpd'
        SERVICE_PROCESSES='sendmail exim exim4 smtpd'
        SERVICE_PORTS='25 465 587'
        SERVICE_PACKAGES='postfix sendmail exim exim4 opensmtpd'
        ;;
    dns)
        SERVICE_UNITS='named bind9 unbound pdns knot'
        SERVICE_PROCESSES='named unbound pdns_server knotd'
        SERVICE_PORTS='53'
        SERVICE_PACKAGES='bind9 bind unbound pdns knot'
        ;;
    snmp)
        SERVICE_UNITS='snmpd'
        SERVICE_PROCESSES='snmpd'
        SERVICE_PORTS='161'
        SERVICE_PACKAGES='snmpd net-snmp net-snmp-agent'
        ;;
    time)
        SERVICE_UNITS='chronyd chrony ntpd ntp ntpsec systemd-timesyncd openntpd ntpd-rs'
        SERVICE_PROCESSES='chronyd ntpd systemd-timesyn ntp-daemon'
        SERVICE_PORTS='123'
        SERVICE_PACKAGES='chrony ntp ntpsec openntpd ntpd-rs'
        ;;
    log)
        SERVICE_UNITS='rsyslog syslog-ng syslogd busybox-syslogd'
        SERVICE_PROCESSES='rsyslogd syslog-ng syslogd'
        SERVICE_PORTS=''
        SERVICE_PACKAGES='rsyslog syslog-ng sysklogd busybox-syslogd'
        ;;
    *) return 2 ;;
    esac
}

service_collect() {
    local role=$1 unit name port load active installed=0 stopped=0 active_found=0 port_found=0 info='' text
    service_definition "$role" || return 2
    for name in $SERVICE_PROCESSES; do
        if grep -Fxq -- "$name" <<<"$AUDIT_PROCESS_NAMES"; then
            active_found=1
            info+="process=$name "
        fi
    done
    if ((AUDIT_SYSTEMCTL_AVAILABLE)); then
        for unit in $SERVICE_UNITS; do
            [[ $unit == *.* ]] || unit+='.service'
            if ! capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" systemctl show "$unit" --no-pager --property=LoadState,ActiveState; then
                if ((AUDIT_COMMAND_RC == 124 || AUDIT_COMMAND_RC == 137)); then
                    AUDIT_SYSTEMCTL_AVAILABLE=0
                    break
                fi
                continue
            fi
            text=$AUDIT_COMMAND_STDOUT
            load=$(awk -F= '$1=="LoadState"{print $2}' <<<"$text")
            active=$(awk -F= '$1=="ActiveState"{print $2}' <<<"$text")
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
        fi
    done
    for port in $SERVICE_PORTS; do
        if awk -v p="$port" '$0 !~ /^(Active|Proto)/ {for(i=1;i<=NF;i++)if($i ~ (":" p "$") && i<=5)found=1} END{exit !found}' <<<"$AUDIT_SOCKET_DATA"; then
            port_found=1
            info+="listener=$port (소유 서비스 미확정) "
        fi
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

service_gate() {
    local role=$1
    case ${AUDIT_SERVICE_STATE[$role]:-UNKNOWN} in
    STOPPED | ABSENT)
        emit_result GOOD '서비스 비실행을 대체 조회로 확인' "${AUDIT_SERVICE_EVIDENCE[$role]}"
        return 1
        ;;
    RUNNING) return 0 ;;
    *)
        emit_result ERROR '서비스 실행 여부를 확정하지 못함' "${AUDIT_SERVICE_EVIDENCE[$role]:-수집 없음}" '명령·권한·Runtime 및 비표준 데몬 확인' SERVICE_UNRESOLVED
        return 1
        ;;
    esac
}

scan_collect() {
    local deadline=$((SECONDS + ${AUDIT_CONFIG[scan_timeout_seconds]}))
    local entry_limit=200000 mount_limit=1024 uid_limit=1024 metadata=0
    local spec id kind policy path root fs dev backing rest line
    local old_root old_dev old_backing source shadow covered index remaining fd pid rc stopped
    local status_file error_file record uid gid mode type value query_budget uid_queries=0
    local -a all_mounts=() candidate_paths=() candidate_devs=() candidate_roots=()
    local -a kept_devs=() kept_roots=() args=() filters=()
    local -A scan_approved=() scan_uid_error=() seen_mounts=()
    AUDIT_SCAN_ROOTS=()
    AUDIT_SCAN_SELECTED=()
    AUDIT_SCAN_ITEM_COMPLETE=()
    AUDIT_SCAN_ITEM_CAPPED=()
    AUDIT_SCAN_ITEM_COUNT=()
    AUDIT_SCAN_ITEM_UNAPPROVED=()
    AUDIT_SCAN_ITEM_ERROR=()
    # Read through the scan_result/scan_add_finding namerefs.
    # shellcheck disable=SC2034
    AUDIT_ORPHANS=() AUDIT_SPECIAL_FILES=() AUDIT_WORLD_FILES=() AUDIT_HIDDEN_FILES=()
    AUDIT_SCAN_COUNT=0
    for spec in U-15:AUDIT_ORPHANS: U-23:AUDIT_SPECIAL_FILES:approved_special_files \
        U-25:AUDIT_WORLD_FILES:approved_world_writable_paths U-33:AUDIT_HIDDEN_FILES:approved_hidden_paths; do
        IFS=: read -r id kind policy <<<"$spec"
        if [[ ${AUDIT_CONFIG[check_ids]} == ALL ]] || list_has "${AUDIT_CONFIG[check_ids]}" "$id"; then
            AUDIT_SCAN_SELECTED[$kind]=1
            AUDIT_SCAN_ITEM_COMPLETE[$kind]=1
            AUDIT_SCAN_ITEM_CAPPED[$kind]=0
            AUDIT_SCAN_ITEM_COUNT[$kind]=0
            AUDIT_SCAN_ITEM_UNAPPROVED[$kind]=0
            AUDIT_SCAN_ITEM_ERROR[$kind]=
            if [[ -n $policy ]]; then
                index=0
                while IFS= read -r path || [[ -n $path ]]; do
                    [[ -n $path ]] || continue
                    ((index += 1))
                    if ((index > entry_limit)); then
                        scan_incomplete '승인 목록 크기 제한' 1 "$kind"
                        break
                    fi
                    scan_approved["$kind|$path"]=1
                done <<<"${AUDIT_CONFIG[$policy]}"
            fi
        fi
    done
    if ((${#AUDIT_SCAN_SELECTED[@]} == 0)); then
        AUDIT_SCAN_SCOPE='파일 탐색 항목 미선택'
        return
    fi
    if [[ ${AUDIT_CONFIG[scan_roots]} == AUTO ]]; then
        AUDIT_SCAN_SCOPE='AUTO: 현재 Mount Namespace의 로컬 파일시스템; bind 별칭 중복 제외'
    else
        AUDIT_SCAN_SCOPE='사용자 지정 부분 범위: 전체 시스템 판정 불가'
    fi
    # Retain every mount path for explicit pruning, including remote and virtual
    # mounts. Whitelist known local filesystems instead of traversing an unknown
    # network filesystem under the label "local".
    if [[ -r /proc/self/mountinfo ]]; then
        index=0
        while read -r _ _ dev backing path _ rest; do
            ((index += 1))
            if ((index > mount_limit || SECONDS >= deadline)); then
                scan_incomplete 'Mount 목록 크기 또는 시간 제한' 1
                break
            fi
            printf -v path '%b' "$path"
            printf -v backing '%b' "$backing"
            all_mounts+=("$path")
            case $rest in '- '*) value=${rest#'- '} ;; *' - '*) value=${rest#*' - '} ;; *) scan_incomplete 'Mount 정보 해석 실패'; continue ;; esac
            fs=${value%% *}
            [[ ${AUDIT_CONFIG[scan_roots]} == AUTO ]] || continue
            case $path in /dev | /dev/* | /proc | /proc/* | /sys | /sys/*) continue ;; esac
            case $fs in
                ext2 | ext3 | ext4 | xfs | btrfs | zfs | f2fs | jfs | reiserfs | reiser4 | nilfs2 | vfat | msdos | exfat | ntfs | ntfs3 | fuseblk | overlay | aufs | tmpfs | ramfs | squashfs | erofs | iso9660 | udf) ;;
                proc | sysfs | devtmpfs | devpts | cgroup | cgroup2 | securityfs | debugfs | tracefs | pstore | mqueue | hugetlbfs | nfs | nfs4 | cifs | smb3 | fuse | fuse.* | autofs | rpc_pipefs | binfmt_misc | configfs | 9p | ceph | glusterfs | lustre | afs | nsfs | bpf | efivarfs | selinuxfs | smackfs | fusectl) continue ;;
                *) scan_incomplete "미확인 파일시스템 제외:$fs"; continue ;;
            esac
            candidate_paths+=("$path")
            candidate_devs+=("$dev")
            candidate_roots+=("$backing")
        done </proc/self/mountinfo
    else
        scan_incomplete 'Mount 목록을 읽지 못해 하위 Mount 제외를 보장하지 못함'
        [[ ${AUDIT_CONFIG[scan_roots]} == AUTO ]] && candidate_paths=(/)
    fi
    if [[ ${AUDIT_CONFIG[scan_roots]} != AUTO ]]; then
        candidate_paths=()
        while IFS= read -r root || [[ -n $root ]]; do
            [[ -n $root ]] || continue
            if [[ $root != /* || $root == *$'\n'* || $root == *'/../'* || $root == */.. ]]; then
                scan_incomplete '탐색 경로는 정규화 가능한 절대 경로여야 함'
                continue
            fi
            candidate_paths+=("$root")
        done <<<"${AUDIT_CONFIG[scan_roots]}"
    fi
    # A previous mount with the same device and a parent backing root covers a
    # bind alias only when its original path remains reachable (no overmount).
    for ((index=0; index<${#candidate_paths[@]}; index++)); do
        if ((SECONDS >= deadline)); then scan_incomplete 'Mount 범위 처리 시간 제한' 1; break; fi
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
            for path in "${all_mounts[@]}"; do
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
    ((${#AUDIT_SCAN_ROOTS[@]})) || { scan_incomplete '유효한 로컬 Mount 없음'; return; }
    if find /dev/null -maxdepth 0 -printf '' >/dev/null 2>&1; then metadata=1; fi
    if ((metadata)) && [[ ! -v AUDIT_SCAN_SELECTED[AUDIT_ORPHANS] ]]; then
        if [[ -v AUDIT_SCAN_SELECTED[AUDIT_SPECIAL_FILES] ]]; then filters+=(-type f '(' -perm -4000 -o -perm -2000 ')'); fi
        if [[ -v AUDIT_SCAN_SELECTED[AUDIT_WORLD_FILES] ]]; then
            ((${#filters[@]})) && filters+=(-o)
            filters+=(-type f -perm -0002)
        fi
        if [[ -v AUDIT_SCAN_SELECTED[AUDIT_HIDDEN_FILES] ]]; then
            ((${#filters[@]})) && filters+=(-o)
            filters+=(-name '.*')
        fi
        if [[ ! -v AUDIT_SCAN_SELECTED[AUDIT_SPECIAL_FILES] && ! -v AUDIT_SCAN_SELECTED[AUDIT_WORLD_FILES] ]]; then metadata=2; fi
    fi
    index=0
    for root in "${AUDIT_SCAN_ROOTS[@]}"; do
        remaining=$((deadline - SECONDS))
        if ((remaining <= 0)); then scan_incomplete '파일 탐색 전체 시간 제한' 1; break; fi
        query_budget=${AUDIT_CONFIG[command_timeout_seconds]}
        ((query_budget <= remaining)) || query_budget=$remaining
        if ! capture_command "$query_budget" readlink -f -- "$root"; then
            scan_incomplete "탐색 경로 해석 실패:$root"
            continue
        fi
        root=$AUDIT_COMMAND_STDOUT
        [[ $root == /* && -d $root ]] || { scan_incomplete "탐색 디렉터리 확인 실패:$root"; continue; }
        args=("$root" -xdev '(' -path "$(scan_find_pattern "$AUDIT_OUTPUT_DIR")")
        for path in /proc /sys /dev "${all_mounts[@]}"; do
            if [[ $path != "$root" && ($root == / || $path == "${root%/}/"*) ]]; then
                args+=(-o -path "$(scan_find_pattern "$path")")
            fi
        done
        args+=(')' -prune -o)
        ((${#filters[@]})) && args+=('(' "${filters[@]}" ')')
        case $metadata in
            1) args+=(-printf '%U:%G:%m:%y:%p\0') ;;
            2) args+=(-printf '%p\0') ;;
            *) args+=(-print0) ;;
        esac
        # Empty records count non-candidates without serializing their paths.
        ((${#filters[@]})) && args+=(-o -printf '\0')
        ((index += 1))
        status_file="$AUDIT_WORK_DIR/scan.$index.status"
        error_file="$AUDIT_WORK_DIR/scan.$index.err"
        remaining=$((deadline - SECONDS))
        if ((remaining <= 0)); then scan_incomplete '파일 탐색 전체 시간 제한' 1; break; fi
        exec {fd}< <(capture_file /dev/stdout "$error_file" "$remaining" find "${args[@]}"; printf '%s' "$?" >"$status_file")
        pid=$!
        stopped=0
        while :; do
            remaining=$((deadline - SECONDS))
            if ((remaining <= 0)); then scan_incomplete '파일 탐색 전체 시간 제한' 1; stopped=1; break; fi
            record=
            if ! IFS= read -r -d '' -t "$remaining" record <&"$fd"; then
                [[ -z $record ]] || scan_incomplete '불완전한 파일 Metadata 레코드'
                break
            fi
            if ((AUDIT_SCAN_COUNT >= entry_limit)); then scan_incomplete '전체 엔트리 200000개 제한' 1; stopped=1; break; fi
            ((AUDIT_SCAN_COUNT += 1))
            [[ -n $record ]] || continue
            if ((metadata == 1)); then
                uid=${record%%:*}; record=${record#*:}
                gid=${record%%:*}; record=${record#*:}
                mode=${record%%:*}; record=${record#*:}
                type=${record%%:*}; path=${record#*:}
            else
                path=$record
            fi
            if [[ -v AUDIT_SCAN_SELECTED[AUDIT_HIDDEN_FILES] && ${path##*/} == .* && ${path##*/} != . && ${path##*/} != .. ]]; then
                scan_add_finding AUDIT_HIDDEN_FILES "$path"
            fi
            # A hidden-path-only selection needs neither stat nor NSS.
            if [[ ! -v AUDIT_SCAN_SELECTED[AUDIT_ORPHANS] && ! -v AUDIT_SCAN_SELECTED[AUDIT_SPECIAL_FILES] && ! -v AUDIT_SCAN_SELECTED[AUDIT_WORLD_FILES] ]]; then continue; fi
            if ((metadata == 0)); then
                remaining=$((deadline - SECONDS))
                ((remaining > 0)) || { scan_incomplete '파일 Metadata 처리 시간 제한' 1; stopped=1; break; }
                query_budget=${AUDIT_CONFIG[command_timeout_seconds]}
                ((query_budget <= remaining)) || query_budget=$remaining
                if capture_command "$query_budget" stat -c '%u:%g:%a:%F' -- "$path"; then
                    IFS=: read -r uid gid mode type <<<"$AUDIT_COMMAND_STDOUT"
                else
                    for kind in AUDIT_ORPHANS AUDIT_SPECIAL_FILES AUDIT_WORLD_FILES; do
                        [[ -v AUDIT_SCAN_SELECTED[$kind] ]] && scan_incomplete '일부 파일 Metadata 수집 실패' 0 "$kind"
                    done
                    continue
                fi
            fi
            if [[ ! $uid =~ ^[0-9]+$ || ! $mode =~ ^[0-7]{1,4}$ ]]; then
                for kind in AUDIT_ORPHANS AUDIT_SPECIAL_FILES AUDIT_WORLD_FILES; do
                    [[ -v AUDIT_SCAN_SELECTED[$kind] ]] && scan_incomplete '파일 Metadata 해석 실패' 0 "$kind"
                done
                continue
            fi
            if [[ -v AUDIT_SCAN_SELECTED[AUDIT_ORPHANS] && ! -v AUDIT_UID_KNOWN[$uid] && ! -v scan_uid_error[$uid] ]]; then
                remaining=$((deadline - SECONDS))
                if ((uid_queries >= uid_limit || remaining <= 0)); then
                    scan_uid_error[$uid]=1
                    scan_incomplete 'UID 조회 개수 또는 시간 제한' 1 AUDIT_ORPHANS
                elif ! command -v getent >/dev/null 2>&1; then
                    scan_uid_error[$uid]=1
                    scan_incomplete 'NSS 소유자 확인 도구 없음' 0 AUDIT_ORPHANS
                else
                    ((uid_queries += 1))
                    query_budget=${AUDIT_CONFIG[command_timeout_seconds]}
                    ((query_budget <= remaining)) || query_budget=$remaining
                    if capture_command "$query_budget" getent passwd "$uid"; then
                        AUDIT_UID_KNOWN[$uid]=1
                    elif ((AUDIT_COMMAND_RC == 2)); then
                        AUDIT_UID_KNOWN[$uid]=0
                    else
                        scan_uid_error[$uid]=1
                        scan_incomplete '일부 UID/NSS 조회 실패' 0 AUDIT_ORPHANS
                    fi
                fi
            fi
            if [[ -v AUDIT_SCAN_SELECTED[AUDIT_ORPHANS] && ${AUDIT_UID_KNOWN[$uid]-unknown} == 0 ]]; then
                scan_add_finding AUDIT_ORPHANS "$path" "$path uid=$uid"
            fi
            if [[ $type == f || $type == 'regular file' || $type == 'regular empty file' ]]; then
                if [[ -v AUDIT_SCAN_SELECTED[AUDIT_SPECIAL_FILES] ]] && (((8#$mode & 06000) != 0)); then scan_add_finding AUDIT_SPECIAL_FILES "$path"; fi
                if [[ -v AUDIT_SCAN_SELECTED[AUDIT_WORLD_FILES] ]] && (((8#$mode & 0002) != 0)); then scan_add_finding AUDIT_WORLD_FILES "$path"; fi
            fi
        done
        exec {fd}<&-
        if ((stopped)); then
            kill_descendants "$pid"
            kill -TERM "$pid" 2>/dev/null || :
        fi
        wait "$pid" 2>/dev/null || :
        rc=125
        [[ -r $status_file ]] && IFS= read -r rc <"$status_file"
        [[ $rc == 0 ]] || scan_incomplete "find 실패 또는 중단(rc=$rc)" "$([[ $rc == 124 || $rc == 137 ]] && printf 1 || printf 0)"
        [[ ! -s $error_file ]] || scan_incomplete 'find 경로·권한 오류: 일부 범위 미수집'
        rm -f -- "$status_file" "$error_file"
        ((stopped)) && break
    done
}

scan_result() {
    local kind=$1 description=$2 policy_key=$3 item evidence='' count missing complete capped
    local -n findings=$kind
    count=${AUDIT_SCAN_ITEM_COUNT[$kind]:-0}
    missing=${AUDIT_SCAN_ITEM_UNAPPROVED[$kind]:-0}
    complete=${AUDIT_SCAN_ITEM_COMPLETE[$kind]:-0}
    capped=${AUDIT_SCAN_ITEM_CAPPED[$kind]:-0}
    evidence="scope=$AUDIT_SCAN_SCOPE entries=$AUDIT_SCAN_COUNT findings=$count unreviewed=$missing complete=$complete capped=$capped sample_count=${#findings[@]}"
    for item in "${findings[@]}"; do evidence+=$'\n'"$item"; done
    if ((complete == 0)); then
        emit_result ERROR '파일 탐색 일부 미완료; 확보한 증거 포함' "$evidence ${AUDIT_SCAN_ITEM_ERROR[$kind]-}" '범위·권한·시간·개수 제한·NSS 오류 확인 후 미수집 범위 재검사' INCOMPLETE_SCAN
    elif [[ ${AUDIT_CONFIG[scan_roots]} != AUTO ]]; then
        emit_result MANUAL '부분 탐색 범위 결과; 전체 시스템 판정 불가' "$evidence" '지정 범위의 발견 내용 검토 및 전체 범위 별도 확인'
    elif [[ $kind == AUDIT_ORPHANS && ${AUDIT_NSS_EXTERNAL:-0} == 1 && $count -gt 0 ]]; then
        emit_result MANUAL '소유 계정 미확인 파일 발견; 외부 NSS 검증 필요' "$evidence" 'LDAP/SSSD/NIS 연결 상태와 소유 계정의 존재 여부 대조'
    elif [[ $kind == AUDIT_ORPHANS && $count -gt 0 ]]; then
        emit_result VULNERABLE "$description 발견" "$evidence" '파일 소유자와 계정 DB 확인 후 정리'
    elif ((count == 0)); then
        emit_result GOOD "$description: 전체 검사 범위에서 미발견" "$evidence"
    elif ((missing == 0)) && [[ -n $policy_key ]]; then
        emit_result GOOD "$description: 사용자 승인 목록 기준 충족" "$evidence" '현재 입력된 정확한 경로 승인 목록을 기준으로 판정; 승인 근거·운영상 필요성은 사용자 책임으로 검토'
    else
        emit_result MANUAL "$description: 미승인 경로 검토 필요" "$evidence" '증거는 최대 100개 표본; 정확한 경로·운영상 필요성·승인 근거를 검토'
    fi
}


# shellcheck shell=bash
# Parse only include/substack and documented control tokens. Complex early jumps
# are exposed as MANUAL; no PAM configuration is executed or rewritten.
PAM_ROWS=
PAM_ERROR=
declare -A PAM_VISITED=()

pam_walk() {
    local path=$1 wanted=$2 depth=$3 file line type control module options include
    if ((depth > 20)); then
        PAM_ERROR+='PAM depth limit; '
        return
    fi
    [[ -v PAM_VISITED[$path] ]] && {
        PAM_ERROR+="PAM cycle:$path; "
        return
    }
    PAM_VISITED[$path]=1
    file=$(target_path "$path") || {
        PAM_ERROR+="PAM path:$path; "
        unset 'PAM_VISITED[$path]'
        return
    }
    [[ -r $file && -f $file ]] || {
        PAM_ERROR+="PAM read:$path; "
        unset 'PAM_VISITED[$path]'
        return
    }
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ $line =~ ^[[:space:]]*@include[[:space:]]+([^[:space:]]+) ]]; then
            include=${BASH_REMATCH[1]}
            [[ $include == /* ]] || include="/etc/pam.d/$include"
            pam_walk "$include" "$wanted" "$((depth + 1))"
            continue
        fi
        if [[ $line =~ ^[[:space:]]*-?([a-z]+)[[:space:]]+(\[[^]]+\]|[^[:space:]]+)[[:space:]]+([^[:space:]]+)(.*)$ ]]; then
            type=${BASH_REMATCH[1]}
            control=${BASH_REMATCH[2]}
            module=${BASH_REMATCH[3]}
            options=${BASH_REMATCH[4]}
            [[ $type == "$wanted" ]] || continue
            if [[ $control == include || $control == substack ]]; then
                include=$module
                [[ $include == /* ]] || include="/etc/pam.d/$include"
                pam_walk "$include" "$wanted" "$((depth + 1))"
            else
                module=${module##*/}
                PAM_ROWS+="$path|$type|$control|$module|$options"$'\n'
            fi
        else PAM_ERROR+="PAM syntax:$path; "; fi
    done <"$file"
    unset 'PAM_VISITED[$path]'
}

pam_load() {
    PAM_ROWS=
    PAM_ERROR=
    PAM_VISITED=()
    pam_walk "$1" "$2" 0
    [[ -z $PAM_ERROR && -n $PAM_ROWS ]]
}

pam_simple_password_policy() {
    # Return 0 only for an explicitly forced quality+history stack. Missing
    # values and alternate backends remain unknown, not insecure by default.
    local rows=$PAM_ROWS path type control module options index=0 q=0 h=0 early=0
    local quality='' history='' value minlen minclass dc lc uc oc remember root_quality=0 root_history=0
    local config_dir real
    while IFS='|' read -r path type control module options; do
        [[ -n $module ]] || continue
        ((index += 1))
        case $module in
        pam_pwquality.so | pam_cracklib.so)
            [[ $control == required || $control == requisite ]] || early=1
            q=$index
            quality+=$'\n'"$options"
            ;;
        pam_pwhistory.so)
            [[ $control == required || $control == requisite ]] || early=1
            h=$index
            history+=$'\n'"$options"
            ;;
        pam_unix.so)
            if [[ $control == sufficient && ($q == 0 || $h == 0) ]]; then early=1; fi
            ;;
        *) if [[ $q == 0 || $h == 0 ]]; then [[ $control == sufficient || $control == \[* ]] && early=1; fi ;;
        esac
    done <<<"$rows"
    ((q && h && !early)) || return 2
    quality="$(active_lines /etc/security/pwquality.conf 2>/dev/null)"$'\n'"$quality"
    history="$(active_lines /etc/security/pwhistory.conf 2>/dev/null)"$'\n'"$history"
    for config_dir in /etc/security/pwquality.conf.d /etc/security/pwhistory.conf.d; do
        real=$(target_path "$config_dir") || continue
        if [[ -d $real ]] && compgen -G "$real/*.conf" >/dev/null; then return 2; fi
    done
    minlen=$(option_number "$quality" minlen) || return 2
    minclass=$(option_number "$quality" minclass) || minclass=0
    dc=$(option_number "$quality" dcredit) || dc=0
    lc=$(option_number "$quality" lcredit) || lc=0
    uc=$(option_number "$quality" ucredit) || uc=0
    oc=$(option_number "$quality" ocredit) || oc=0
    remember=$(option_number "$history" remember) || return 2
    grep -Eq '(^|[[:space:]])enforce_for_root([[:space:]]|$)' <<<"$quality" && root_quality=1
    grep -Eq '(^|[[:space:]])enforce_for_root([[:space:]]|$)' <<<"$history" && root_history=1
    PAM_POLICY_EVIDENCE="stack=$rows minlen=$minlen minclass=$minclass credits=$dc/$lc/$uc/$oc remember=$remember root_quality=$root_quality root_history=$root_history"
    ((minlen >= 8 && remember >= 4 && (minclass >= 4 || (dc < 0 && oc < 0 && (lc < 0 || uc < 0))))) || return 1
    ((root_quality && root_history)) || return 2
    return 0
}


# shellcheck shell=bash
AUDIT_ACCOUNT_ROWS=
AUDIT_GROUP_ROWS=
AUDIT_SHADOW_ROWS=
AUDIT_ACCOUNTS_OK=0
AUDIT_GROUPS_OK=0
AUDIT_SHADOW_OK=0
AUDIT_NSS_EXTERNAL=0

account_collect() {
    local file line uid
    if ((AUDIT_NEED_ACCOUNTS)); then
        file=/etc/passwd
        if [[ -r $file ]] && awk -F: 'NF!=7 || $1=="" || $3!~/^[0-9]+$/ || $4!~/^[0-9]+$/ {bad=1} END{exit bad}' "$file"; then
            AUDIT_ACCOUNT_ROWS=$(awk -F: 'BEGIN{OFS=":"}{print $1,$3,$4,$6,$7}' "$file")
            [[ -n $AUDIT_ACCOUNT_ROWS ]] && AUDIT_ACCOUNTS_OK=1
            while IFS=: read -r _ uid _; do [[ $uid =~ ^[0-9]+$ ]] && AUDIT_UID_KNOWN[$uid]=1; done <<<"$AUDIT_ACCOUNT_ROWS"
        fi
    fi
    if ((AUDIT_NEED_GROUPS)); then
        file=/etc/group
        if [[ -r $file ]] && awk -F: 'NF!=4 || $3!~/^[0-9]+$/ {bad=1} END{exit bad}' "$file"; then
            AUDIT_GROUP_ROWS=$(awk -F: 'BEGIN{OFS=":"}{print $1,$3,$4}' "$file")
            AUDIT_GROUPS_OK=1
        fi
    fi
    if ((AUDIT_NEED_SHADOW)); then
        file=/etc/shadow
        if [[ -r $file ]]; then
            AUDIT_SHADOW_ROWS=$(awk -F: '
              NF!=9 {bad=1;next}
              {state="HASH";alg="unknown";hash=$2
               if(hash=="")state="EMPTY";else if(hash~/^[!*]/)state="LOCKED"
               else if(hash~/^\$/){split(hash,a,"$");alg=a[2]}else alg="DES_or_legacy"
               lo=$4;hi=$5
               if(lo~/^[0-9]+$/ && length(lo)<10)lo=sprintf("%.0f",lo+0)
               if(hi~/^[0-9]+$/ && length(hi)<10)hi=sprintf("%.0f",hi+0)
               print $1 ":" state ":" alg ":" lo ":" hi ":" $3}
              END{if(bad)exit 2}' "$file")
            [[ $? == 0 && -n $AUDIT_SHADOW_ROWS ]] && AUDIT_SHADOW_OK=1
        fi
    fi
    if ((AUDIT_NEED_ACCOUNTS || AUDIT_NEED_GROUPS || AUDIT_NEED_SHADOW)); then
        line=$(active_lines /etc/nsswitch.conf 2>/dev/null | awk '/^(passwd|group|shadow):/ {print}') || :
        if grep -Eq '(ldap|sss|nis|winbind|compat)' <<<"$line"; then AUDIT_NSS_EXTERNAL=1; fi
    fi
    return 0
}

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

check_u_01() {
    local state=${AUDIT_SERVICE_STATE[ssh]:-UNKNOWN} value evidence='' telnet=${AUDIT_SERVICE_STATE[telnet]:-UNKNOWN}
    case $state in
    RUNNING)
        if command -v sshd >/dev/null 2>&1; then
            if capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" sshd -T; then
                value=$(awk '$1=="permitrootlogin"{print $2;exit}' <<<"$AUDIT_COMMAND_STDOUT")
                evidence="OpenSSH effective PermitRootLogin=$value"
            else
                emit_result ERROR 'sshd 유효 설정 조회 실패' "${AUDIT_COMMAND_STDERR}" 'Host Key·설정·권한 확인' SSHD_QUERY_FAILED
                return
            fi
        else
            value=$(config_value /etc/ssh/sshd_config PermitRootLogin 2>/dev/null) || value=
            evidence="정적 PermitRootLogin=${value:-미설정}; Runtime 적용·Include 확인 필요"
        fi
        case ${value,,} in
        yes | prohibit-password | without-password | forced-commands-only)
            emit_result VULNERABLE 'root 직접 SSH 접속이 허용되는 설정' "$evidence" '비밀번호 인증만 금지해도 Public Key root 접속은 허용될 수 있음'
            return
            ;;
        no) ;;
        *)
            emit_result MANUAL 'root SSH 접속 차단을 확정할 수 없음' "$evidence" 'sshd -T 및 Match/Include·다른 SSH Provider 확인'
            return
            ;;
        esac
        if active_lines /etc/ssh/sshd_config 2>/dev/null | grep -qiE '^[[:space:]]*(Match|Include)[[:space:]]'; then
            emit_result MANUAL '전역 root 차단 확인; 조건부 설정 추가 확인 필요' "$evidence" 'Include 전체 및 연결 조건별 sshd -T -C 결과 확인'
            return
        fi
        ;;
    STOPPED | ABSENT) evidence="SSH $state" ;;
    *)
        emit_result ERROR 'SSH 실행 여부 미확정' "${AUDIT_SERVICE_EVIDENCE[ssh]:-수집 없음}" '' SERVICE_UNRESOLVED
        return
        ;;
    esac
    if [[ $telnet == RUNNING || ${AUDIT_SERVICE_STATE[r]:-UNKNOWN} == RUNNING ]]; then
        emit_result MANUAL '레거시 원격 터미널 root 제한 확인 필요' "$evidence; telnet=$telnet r=${AUDIT_SERVICE_STATE[r]:-UNKNOWN}" 'pam_securetty 적용 경로·securetty·rlogin 인증 확인'
    elif [[ $telnet == UNKNOWN || ${AUDIT_SERVICE_STATE[r]:-UNKNOWN} == UNKNOWN ]]; then
        emit_result MANUAL 'SSH 결과는 확보했으나 다른 원격 터미널 범위 미확정' "$evidence" 'Telnet/rlogin 및 SSH Provider 전체 확인'
    else emit_result GOOD '원격 root 직접 접속 경로가 비실행 또는 차단됨' "$evidence"; fi
}

pam_password_lines() {
    local path file
    for path in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/passwd /etc/pam.d/login; do
        file=$(target_path "$path") || continue
        [[ -f $file && -r $file ]] || continue
        active_lines "$path"
    done
}

option_number() {
    local text=$1 key=$2
    # Normalize decimal text lexically: 08 -> 8 and -003 -> -3, without octal parsing.
    awk -v k="$key" '
    {gsub(/=/," ");for(i=1;i<NF;i++)if($i==k && $(i+1)~/^-?[0-9]+$/){v=$(i+1);found=1}}
    END {
        if(!found)exit 1
        negative=(substr(v,1,1)=="-")
        if(negative)v=substr(v,2)
        sub(/^0+/,"",v)
        if(v=="")v="0"
        if(negative && v!="0")v="-" v
        print v
    }' <<<"$text"
}

check_u_02() {
    require_accounts || return
    if path_exists /etc/pam.d/passwd && pam_load /etc/pam.d/passwd password; then
        local rc=0 min max n state alg lo hi bad_age='' defaults_good=0
        pam_simple_password_policy || rc=$?
        min=$(config_value /etc/login.defs PASS_MIN_DAYS 2>/dev/null) || min=''
        max=$(config_value /etc/login.defs PASS_MAX_DAYS 2>/dev/null) || max=''
        if [[ $min =~ ^[0-9]+$ && $max =~ ^[0-9]+$ ]] && ((10#$min >= 1 && 10#$max >= 1 && 10#$max <= 90)); then defaults_good=1; fi
        if ((AUDIT_SHADOW_OK)); then
            while IFS=: read -r n state alg lo hi _; do
                [[ $state == HASH || $state == EMPTY ]] || continue
                if [[ ! $lo =~ ^[0-9]+$ || ! $hi =~ ^[0-9]+$ ]] || ((lo < 1 || hi < 1 || hi > 90)); then bad_age+="$n "; fi
            done <<<"$AUDIT_SHADOW_ROWS"
        fi
        if ((rc == 0 && defaults_good && AUDIT_SHADOW_OK)) && [[ -z $bad_age ]]; then
            account_emit GOOD 'passwd PAM의 필수 품질·이력·root 적용 및 사용기간 확인' "$PAM_POLICY_EVIDENCE PASS_MIN_DAYS=$min PASS_MAX_DAYS=$max"
            return
        elif ((rc == 1)); then
            emit_result VULNERABLE '적용 경로를 해석한 필수 PAM 비밀번호 정책이 수치 기준 미충족' "$PAM_POLICY_EVIDENCE"
            return
        elif ((rc == 0 && defaults_good)) && [[ -n $bad_age ]]; then
            emit_result VULNERABLE '기존 계정 비밀번호 사용기간이 기준 미충족' "$bad_age"
            return
        fi
    fi
    local pam quality='' value key minlen minclass dc oc lc uc remember min_days max_days bad='' ev='' name state alg age_min age_max
    pam=$(pam_password_lines)
    quality=$(active_lines /etc/security/pwquality.conf 2>/dev/null) || :
    # Drop-in graphs and provider precedence vary. Collect, never silently
    # claim this baseline parser implements all PAM control flow.
    if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_(pwquality|cracklib)\.so' <<<"$pam"; then
        emit_result MANUAL 'PAM 비밀번호 품질 Module의 유효 적용을 확인하지 못함' 'pwquality/cracklib 적용 경로 미확정' 'PAM 미사용 Provider·Include Chain·passwd 프로그램의 실제 정책 확인'
        return
    fi
    quality+=$'\n'"$(grep -E 'pam_(pwquality|cracklib)\.so' <<<"$pam")"
    minlen=$(option_number "$quality" minlen) || minlen=0
    minclass=$(option_number "$quality" minclass) || minclass=0
    dc=$(option_number "$quality" dcredit) || dc=0
    oc=$(option_number "$quality" ocredit) || oc=0
    lc=$(option_number "$quality" lcredit) || lc=0
    uc=$(option_number "$quality" ucredit) || uc=0
    remember=$(option_number "$(active_lines /etc/security/pwhistory.conf 2>/dev/null)" remember) || remember=0
    value=$(option_number "$(grep -E 'pam_(pwhistory|unix)\.so' <<<"$pam")" remember) && remember=$value
    min_days=$(config_value /etc/login.defs PASS_MIN_DAYS 2>/dev/null) || min_days=0
    max_days=$(config_value /etc/login.defs PASS_MAX_DAYS 2>/dev/null) || max_days=99999
    [[ $min_days =~ ^[0-9]+$ && $max_days =~ ^[0-9]+$ ]] || {
        emit_result ERROR '비밀번호 정책 숫자 Parsing 실패' '/etc/login.defs' '' PARSE_FAILED
        return
    }
    ((minlen >= 8 && remember >= 4 && 10#$min_days >= 1 && 10#$max_days >= 1 && 10#$max_days <= 90)) || bad+='길이/기억/기간 기본 설정; '
    ((minclass >= 4 || (dc < 0 && oc < 0 && (lc < 0 || uc < 0)))) || bad+='영문·숫자·특수문자 조합; '
    if ((AUDIT_SHADOW_OK)); then
        while IFS=: read -r name state alg age_min age_max _; do
            [[ $state == HASH || $state == EMPTY ]] || continue
            if [[ ! $age_min =~ ^[0-9]+$ || ! $age_max =~ ^[0-9]+$ ]] || ((age_min < 1 || age_max < 1 || age_max > 90)); then bad+="$name: 기존 계정 사용기간; "; fi
        done <<<"$AUDIT_SHADOW_ROWS"
    fi
    ev="minlen=$minlen minclass=$minclass dcredit=$dc ocredit=$oc lcredit=$lc ucredit=$uc remember=$remember min_days=$min_days max_days=$max_days"
    if [[ -n $bad ]]; then
        emit_result MANUAL '정적 기준 미충족 후보; 유효 정책 전체 확인 필요' "$ev; $bad" 'pwquality.conf.d·Module Option·PAM Include/Control·root 강제 적용·기존 계정 만료값 확인'
    else emit_result MANUAL '가이드 수치와 일치하는 설정 확보; PAM 유효 적용 확인 필요' "$ev" 'PAM Control Flow·Include Chain 및 root에 품질·이력 정책이 실제 강제되는지 확인'; fi
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
        preauth=0
        authfail=0
        unix_index=0
        reset=0
        index=0
        root_enforced=1
        deny=$default_deny
        while IFS='|' read -r path type control module options; do
            [[ -n $module ]] || continue
            ((index += 1))
            if [[ $module == pam_faillock.so ]]; then
                value=$(option_number "$options" deny) && deny=$value
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
        evidence+="$entry deny=${deny:-미확정} preauth=$preauth authfail=$authfail authsucc=$reset root_enforced=$root_enforced; "
        if [[ $deny =~ ^[0-9]+$ ]]; then
            if ((deny == 0 || deny > 10)); then
                emit_result VULNERABLE '사용 중인 PAM 경로의 잠금 비활성·10회 초과' "$evidence"
                return
            fi
        else complete=0; fi
        ((preauth && unix_index > preauth && authfail > unix_index && reset && root_enforced)) || complete=0
    done
    if ((checked && complete)); then
        account_emit GOOD '해석한 로그인 경로의 faillock 순서·임계값·root 적용 확인' "$evidence"
    else emit_result MANUAL '계정 잠금 수치 또는 실제 PAM 적용 경로 확인 필요' "$evidence" '다른 인증 Provider·PAM Control/Include·root 적용·실패 후 잠금/성공 후 초기화 확인'; fi
}

check_u_04() {
    require_accounts || return
    local file out
    file=$(target_path /etc/passwd) || {
        emit_result ERROR 'passwd 경로 오류' '' '' PATH_FAILED
        return
    }
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
    local count pam
    count=$(awk -F: '$2!=0 && $5!~/(nologin|false)$/ {n++}END{print n+0}' <<<"$AUDIT_ACCOUNT_ROWS")
    if ((count == 0 && AUDIT_NSS_EXTERNAL == 0)); then
        emit_result GOOD '일반 로그인 계정이 없는 root 전용 환경' '가이드 예외: 일반 계정 없음'
        return
    fi
    pam=$(active_lines /etc/pam.d/su 2>/dev/null) || pam=
    if grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' <<<"$pam"; then
        emit_result MANUAL 'su 그룹 제한 설정 확보' 'pam_wheel required 활성' 'include/substack·trust 옵션·그룹 실제 구성과 su 대체 경로 확인'
    else emit_result MANUAL 'su 사용자 제한 유효 설정 미확정' '명시적인 pam_wheel required를 확인하지 못함' 'PAM 이외 권한 제어 및 su 실행 권한 확인'; fi
}

check_u_07() {
    require_accounts || return
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
    ((AUDIT_GROUPS_OK)) || {
        emit_result ERROR '그룹 DB 수집 실패' '/etc/group' '' GROUP_DB_FAILED
        return
    }
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
    ((AUDIT_GROUPS_OK)) || {
        emit_result ERROR '그룹 DB 수집 실패' '' '' GROUP_DB_FAILED
        return
    }
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
    local name uid gid home shell out='' count=0
    if [[ -z ${AUDIT_CONFIG[nonlogin_accounts]} ]]; then
        emit_result MANUAL '로그인 불필요 계정의 정책 목록 필요' "$(cut -d: -f1,2,5 <<<"$AUDIT_ACCOUNT_ROWS")" '서비스 계정이라는 이유만으로 로그인 불필요를 추정하지 않음'
        return
    fi
    while IFS=: read -r name uid gid home shell; do
        list_has "${AUDIT_CONFIG[nonlogin_accounts]}" "$name" || continue
        ((count += 1))
        [[ $shell == */nologin || $shell == */false ]] || out+="$name shell=$shell"$'\n'
    done <<<"$AUDIT_ACCOUNT_ROWS"
    if [[ -n $out ]]; then
        account_emit VULNERABLE '로그인 불필요 계정에 로그인 Shell 부여' "$out"
    else account_emit GOOD '지정한 로그인 불필요 계정의 Shell 제한' "checked=$count"; fi
}

check_u_12() {
    local path file lines value found=0 bad='' evidence=''
    local -a paths=(/etc/profile /etc/bashrc /etc/bash.bashrc)
    file=$(target_path /etc/profile.d) || file=
    if [[ -d $file ]]; then
        for file in "$file"/*.sh; do
            [[ -f $file ]] || continue
            path=$file
            paths+=("$path")
        done
    fi
    for path in "${paths[@]}"; do
        lines=$(active_lines "$path" 2>/dev/null | grep -E '(^|[[:space:];])(export[[:space:]]+|readonly[[:space:]]+)?TMOUT=') || continue
        while IFS= read -r value; do
            value=${value#*TMOUT=}
            value=${value%%[;[:space:]]*}
            value=${value//\"/}
            value=${value//\'/}
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
    ((AUDIT_SHADOW_OK)) || {
        emit_result ERROR 'Hash 알고리즘 식별 정보 수집 실패' '/etc/shadow (Hash 원문은 반환하지 않음)' '' SHADOW_UNREADABLE
        return
    }
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

check_u_15() { scan_result AUDIT_ORPHANS '소유 계정 없는 파일·디렉터리' ''; }
check_u_16() { check_file_rule /etc/passwd 0644; }

check_u_17() {
    local dir real file bad='' seen=0 errors=0 evidence=''
    for dir in /etc/init.d /etc/rc.d/init.d /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/local.d; do
        real=$(target_path "$dir") || continue
        [[ -d $real ]] || continue
        local records="$AUDIT_WORK_DIR/startup.$BASHPID"
        if ! collect_paths "$records" "$real" -maxdepth 2 -type f -print0; then errors=1; fi
        while IFS= read -r -d '' file; do
            audit_within_deadline || { errors=1; break; }
            ((seen += 1))
            local path=$file
            if ! file_metadata "$path"; then
                errors=1
                continue
            fi
            if [[ $FILE_UID != 0 ]] || ! mode_within "$FILE_MODE" 0755; then [[ ${#bad} -ge 24000 ]] || bad+="$path uid=$FILE_UID mode=$FILE_MODE"$'\n'; fi
        done <"$records"
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE '시작 스크립트/Unit의 소유자 또는 쓰기 권한 위험' "$bad"
    elif ((errors || seen == 0)); then
        emit_result ERROR '시작 설정의 검사 범위 또는 Metadata 미확정' "checked=$seen" '' STARTUP_SCAN_INCOMPLETE
    else emit_result MANUAL '확인한 시작 스크립트·Unit Metadata 양호' "checked=$seen" 'Unit ExecStart·EnvironmentFile·Drop-in 및 다른 Init의 실제 실행 파일까지 확인'; fi
}

check_u_18() { check_file_rule /etc/shadow 0400; }
check_u_19() { check_file_rule /etc/hosts 0644; }

check_u_20() {
    local p count=0 bad='' errors=0
    for p in /etc/inetd.conf /etc/xinetd.conf; do
        path_exists "$p" || continue
        ((count += 1))
        if ! file_metadata "$p"; then
            errors=1
        elif [[ $FILE_UID != 0 ]] || ! mode_within "$FILE_MODE" 0600; then bad+="$p uid=$FILE_UID mode=$FILE_MODE"$'\n'; fi
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE 'inetd/xinetd 설정 권한 기준 초과' "$bad"
    elif ((errors)); then
        emit_result ERROR 'Metadata 실패' '' '' STAT_FAILED
    elif ((count)); then
        emit_result GOOD '확인한 inetd/xinetd 설정 권한 양호' "checked=$count"
    else emit_result MANUAL 'inetd/xinetd 설정 파일 없음' '' '서비스 미사용과 대체 설정·Include 경로를 확인'; fi
}

check_u_21() { check_syslog_permissions; }
check_u_22() { check_file_rule /etc/services 0644 "$(allowed_system_owners)"; }
check_u_23() { scan_result AUDIT_SPECIAL_FILES 'SUID/SGID 파일' approved_special_files; }

check_u_24() {
    require_accounts || return
    local name uid gid home shell real f path bad='' errors=0 seen=0
    while IFS=: read -r name uid gid home shell; do
        [[ $home == /* && $home != / ]] || continue
        real=$(target_path "$home") || continue
        [[ -d $real ]] || continue
        for f in .profile .bash_profile .bash_login .bashrc .bash_logout .cshrc .tcshrc .zshrc .zprofile .kshrc .login; do
            path="$home/$f"
            path_exists "$path" || continue
            ((seen += 1))
            if ! file_metadata "$path"; then
                errors=1
            elif [[ $FILE_UID != 0 && $FILE_UID != "$uid" ]] || ! mode_within "$FILE_MODE" 0755; then bad+="$name $path uid=$FILE_UID mode=$FILE_MODE"$'\n'; fi
        done
    done <<<"$AUDIT_ACCOUNT_ROWS"
    if [[ -n $bad ]]; then
        account_emit VULNERABLE '환경 파일 소유자 또는 비소유자 쓰기 권한 위험' "$bad"
    elif ((errors)); then
        emit_result ERROR '일부 환경 파일 조회 실패' "checked=$seen" '' STAT_FAILED
    else account_emit GOOD '확인한 계정 환경 파일 소유자·쓰기 권한 양호' "checked=$seen; Shell별 동적 Include는 별도 확인"; fi
}

check_u_25() { scan_result AUDIT_WORLD_FILES 'World-writable 일반 파일' approved_world_writable_paths; }

check_u_26() {
    local real path out='' count=0
    real=$(target_path /dev) || {
        emit_result ERROR '/dev 경로 확인 실패' '' '' PATH_FAILED
        return
    }
    [[ -d $real ]] || {
        emit_result ERROR '/dev 디렉터리 없음' '' '' PATH_FAILED
        return
    }
    local records="$AUDIT_WORK_DIR/dev.$BASHPID"
    if ! collect_paths "$records" "$real" -xdev -type f -print0; then
        emit_result ERROR '/dev 탐색 실패' '' '' INCOMPLETE_SCAN
        return
    fi
    while IFS= read -r -d '' path; do
        if ! audit_within_deadline; then
            emit_result ERROR '/dev 처리 시간 초과' "checked=$count; $out" '' INCOMPLETE_SCAN
            return
        fi
        path=$path
        ((count += 1))
        if ! list_has "${AUDIT_CONFIG[approved_device_files]}" "$path" && ((${#out} < 24000)); then out+="$path"$'\n'; fi
    done <"$records"
    if [[ -n $out ]]; then
        emit_result MANUAL '/dev 일반 파일의 정당성 확인 필요' "$out" 'udev 생성 파일 등 정상 용도를 검토; 존재 자체만으로 취약 단정 금지'
    else emit_result GOOD '/dev에서 미검토 일반 파일 미발견' "regular_files=$count"; fi
}

check_u_27() {
    service_gate r || return
    local name uid gid home shell path file out='' seen=0
    local -a paths=(/etc/hosts.equiv)
    while IFS=: read -r name uid gid home shell; do [[ $home == /* ]] && paths+=("$home/.rhosts"); done <<<"$AUDIT_ACCOUNT_ROWS"
    for path in "${paths[@]}"; do
        path_exists "$path" || continue
        ((seen += 1))
        if ! file_metadata "$path"; then
            emit_result ERROR 'rhosts Metadata 실패' "$path" '' STAT_FAILED
            return
        fi
        file=$(target_path "$path") || return
        if ! mode_within "$FILE_MODE" 0600 || grep -Eq '(^|[[:space:]])\+([[:space:]]|$)' "$file"; then out+="$path uid=$FILE_UID mode=$FILE_MODE +여부 확인"$'\n'; fi
    done
    if [[ -n $out ]]; then
        emit_result VULNERABLE 'r 계열 인증 파일 제한 미흡' "$out"
    else emit_result MANUAL 'r 계열 서비스 사용: 파일 소유 계정 및 신뢰 관계 검토 필요' "files=$seen" '소유자는 root/해당 계정인지, 허용 Host/User의 적절성 확인'; fi
}

check_u_28() { check_firewall_policy; }
check_u_29() { check_file_rule /etc/hosts.lpd 0600 0 1; }

check_u_30() {
    local p value found=0 bad='' evidence=''
    for p in /etc/login.defs /etc/profile /etc/bashrc /etc/bash.bashrc; do
        value=$(config_value "$p" UMASK 2>/dev/null) || continue
        found=1
        evidence+="$p UMASK=$value"$'\n'
        if [[ $value =~ ^[0-7]{3,4}$ ]]; then
            (((8#$value & 0022) == 0022)) || bad+="$p "
        else
            emit_result MANUAL 'Symbolic/동적 UMASK 유효값 확인 필요' "$evidence" '로그인 경로별 실제 umask 확인'
            return
        fi
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE 'UMASK가 Group/Other 쓰기를 차단하지 않음' "$evidence"
    elif ((found)); then
        emit_result MANUAL '가이드 범위의 UMASK 설정 확보' "$evidence" 'profile.d·사용자 Shell 초기화·서비스별 덮어쓰기 확인'
    else emit_result MANUAL 'UMASK 적용 경로 미확정' '' '로그인 Shell·PAM·서비스의 실제 UMASK 확인'; fi
}

check_u_31() {
    require_accounts || return
    local name uid gid home shell bad='' seen=0
    while IFS=: read -r name uid gid home shell; do
        [[ $shell == */nologin || $shell == */false ]] && continue
        [[ $home == /* ]] || {
            bad+="$name home=$home (절대 경로 아님)"$'\n'
            continue
        }
        path_exists "$home" || continue
        ((seen += 1))
        if ! file_metadata "$home"; then
            emit_result ERROR 'Home Metadata 조회 실패' "$name $home" '' STAT_FAILED
            return
        fi
        if [[ $FILE_UID != "$uid" ]] || (((8#$FILE_MODE & 0002) != 0)); then bad+="$name home=$home expected_uid=$uid uid=$FILE_UID mode=$FILE_MODE"$'\n'; fi
    done <<<"$AUDIT_ACCOUNT_ROWS"
    if [[ -n $bad ]]; then
        account_emit VULNERABLE 'Home 소유자·타 사용자 쓰기 권한 미흡' "$bad"
    else account_emit GOOD '확인한 로그인 계정 Home Metadata 양호' "checked=$seen"; fi
}

check_u_32() {
    require_accounts || return
    local name uid gid home shell out=''
    while IFS=: read -r name uid gid home shell; do
        [[ $shell == */nologin || $shell == */false ]] && continue
        if [[ $home != /* ]] || ! path_exists "$home"; then out+="$name home=$home"$'\n'; fi
    done <<<"$AUDIT_ACCOUNT_ROWS"
    if [[ -n $out ]]; then
        account_emit VULNERABLE '실재하지 않거나 유효하지 않은 로그인 Home' "$out"
    else account_emit GOOD '로컬 로그인 계정의 Home 존재 확인' 'UID 숫자 기준으로 계정을 누락하지 않음'; fi
}

check_u_33() { scan_result AUDIT_HIDDEN_FILES '숨김 파일·디렉터리' approved_hidden_paths; }


# shellcheck shell=bash
# Unknown provider/grammar returns MANUAL/ERROR instead of assumed defaults.
check_disabled_service() {
    local role=$1
    service_gate "$role" || return
    if list_has "${AUDIT_CONFIG[required_services]}" "$role"; then
        emit_result MANUAL '업무상 필요하다고 지정한 서비스가 실행 중' "${AUDIT_SERVICE_EVIDENCE[$role]}" '필요성·승인 근거·보완 통제를 검토; 자동 GOOD 면제 없음'
    else emit_result VULNERABLE '비활성화 대상 서비스가 실행 중' "${AUDIT_SERVICE_EVIDENCE[$role]}" '업무상 필요성과 서비스 중지 영향을 확인'; fi
}

check_u_34() { check_disabled_service finger; }
check_u_36() { check_disabled_service r; }
check_u_38() { check_disabled_service dos; }
check_u_39() { check_disabled_service nfs; }
check_u_41() { check_disabled_service automount; }
check_u_42() { check_disabled_service rpc; }
check_u_43() { check_disabled_service nis; }
check_u_44() { check_disabled_service tftp; }
check_u_52() { check_disabled_service telnet; }
check_u_58() { check_disabled_service snmp; }

ftp_config() {
    local line candidate='' path executable count=0
    local -a args=()
    FTP_CONFIG_PATH=
    runtime_provider ftp || return 2
    [[ $RUNTIME_PROVIDER == vsftpd ]] || return 2
    command -v ps >/dev/null 2>&1 || return 2
    # Query only this product; do not collect all process arguments.
    capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ps -C vsftpd -o args= || return 2
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        args=()
        read -r -a args <<<"$line"
        ((${#args[@]})) || continue
        executable=${args[0]##*/}
        # Session children may replace their process title; the listener is needed.
        [[ $executable == vsftpd: ]] && continue
        [[ $executable == vsftpd ]] || return 2
        case ${#args[@]} in
        1) path=/etc/vsftpd.conf ;;
        2) path=${args[1]}; [[ $path == /* ]] || return 2 ;;
        *) return 2 ;; # -o overrides, quoting, multiple configs: no guessed policy.
        esac
        [[ $path != *$'\n'* && $path != *'"'* && $path != *"'"* && $path != *'\'* ]] || return 2
        [[ -z $candidate || $candidate == "$path" ]] || return 2
        candidate=$path
        ((count += 1))
    done <<<"$AUDIT_COMMAND_STDOUT"
    ((count > 0)) && [[ -n $candidate ]] || return 2
    active_lines "$candidate" >/dev/null || return 2
    FTP_CONFIG_PATH=$candidate
    return 0
}

check_u_35() {
    local role unknown=0 bad='' evidence='' value
    for role in ftp nfs samba; do
        case ${AUDIT_SERVICE_STATE[$role]:-UNKNOWN} in
        STOPPED | ABSENT) evidence+="$role: 비실행 " ;;
        RUNNING)
            case $role in
            ftp)
                if ftp_config; then
                    value=$(config_value "$FTP_CONFIG_PATH" anonymous_enable 2>/dev/null) || value=
                    evidence+="vsftpd anonymous_enable=${value:-기본값 미확정} "
                    case ${value^^} in YES) bad+='FTP 익명 허용; ' ;; NO) ;; *) unknown=1 ;; esac
                else unknown=1; fi
                ;;
            nfs | samba)
                unknown=1
                evidence+="$role: 익명 UID·Guest·Share ACL 확인 필요 "
                ;;
            esac
            ;;
        *)
            unknown=1
            evidence+="$role: 실행 여부 미확정 "
            ;;
        esac
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE '공유 서비스 익명 접근 허용 설정' "$bad $evidence"
    elif ((unknown)); then
        emit_result MANUAL '공유 서비스 전체 익명 접근 제한 확인 필요' "$evidence" 'FTP Custom Config·Samba Guest mapping·NFS anonymous/export 접근 정책 확인'
    else emit_result GOOD '확인한 공유 서비스의 비실행 또는 익명 접근 차단' "$evidence"; fi
}

check_u_37() {
    local path dir real file seen=0 bad='' errors=0
    for path in /usr/bin/crontab /usr/bin/at /bin/crontab /bin/at; do
        path_exists "$path" || continue
        ((seen += 1))
        if ! file_metadata "$path"; then
            errors=1
        elif [[ $FILE_UID != 0 ]] || ! mode_within "$FILE_MODE" 0750; then [[ ${#bad} -ge 24000 ]] || bad+="$path uid=$FILE_UID mode=$FILE_MODE allowed=0750"$'\n'; fi
    done
    for path in /etc/crontab /etc/anacrontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
        path_exists "$path" || continue
        ((seen += 1))
        if ! file_metadata "$path"; then
            errors=1
        elif [[ $FILE_UID != 0 ]] || ! mode_within "$FILE_MODE" 0640; then [[ ${#bad} -ge 24000 ]] || bad+="$path uid=$FILE_UID mode=$FILE_MODE allowed=0640"$'\n'; fi
    done
    for dir in /etc/cron.d /var/spool/cron /var/spool/at /var/spool/cron/atjobs; do
        real=$(target_path "$dir") || continue
        [[ -d $real ]] || continue
        local records="$AUDIT_WORK_DIR/cron.$BASHPID"
        if ! collect_paths "$records" "$real" -type f -print0; then errors=1; fi
        while IFS= read -r -d '' file; do
            audit_within_deadline || { errors=1; break; }
            path=$file
            ((seen += 1))
            if ! file_metadata "$path"; then
                errors=1
            elif [[ $FILE_UID != 0 ]] || ! mode_within "$FILE_MODE" 0640; then [[ ${#bad} -ge 24000 ]] || bad+="$path uid=$FILE_UID mode=$FILE_MODE"$'\n'; fi
        done <"$records"
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE 'cron/at 명령·설정 권한 기준 초과' "$bad" 'OS 기본 SGID·사용자 crontab 운용과 공식 기준 차이 검토'
    elif ((errors)); then
        emit_result ERROR '예약 작업 Metadata 수집 실패' "checked=$seen" '' STAT_FAILED
    elif ((seen)); then
        emit_result GOOD '확인한 cron/at 명령·설정 권한이 기준 내' "checked=$seen"
    else emit_result MANUAL 'cron/at 제공 방식·미설치 여부 확인 필요' '' '다른 Scheduler 또는 비표준 설치 경로 확인'; fi
}

check_u_40() {
    service_gate nfs || return
    local path file text bad='' evidence='' count=0
    local -a paths=(/etc/exports)
    file=$(target_path /etc/exports.d) || file=
    if [[ -d $file ]]; then for file in "$file"/*.exports; do [[ -f $file ]] && paths+=("$file"); done; fi
    for path in "${paths[@]}"; do
        path_exists "$path" || continue
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
        if grep -Eq '(^|[[:space:]])\*\(' <<<"$text"; then bad+="$path: wildcard client; "; fi
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE 'NFS 권한 또는 Client 제한 미흡' "$bad $evidence" 'Netgroup·Subnet·IPv6·Root Squash 등 실제 Export ACL 검토'
    else emit_result MANUAL 'NFS 설정 증거 확보; 허용 Client의 적절성 검토 필요' "files=$count $evidence" 'exportfs -v의 적용 상태와 허용 Host·설정 파일 권한 대조'; fi
}

mail_provider() {
    local line executable path=/etc/mail/sendmail.cf count=0 daemon=0 i
    local -a args=()
    MAIL_PROVIDER=unknown
    MAIL_CONFIG_DIR=
    runtime_provider mail || return 0
    case $RUNTIME_PROVIDER in
    postfix)
        if postfix_runtime_scope; then MAIL_PROVIDER=postfix; fi
        ;;
    sendmail)
        command -v ps >/dev/null 2>&1 || return 0
        capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ps -C sendmail -o args= || return 0
        while IFS= read -r line; do
            [[ -n $line ]] || continue
            args=()
            read -r -a args <<<"$line"
            ((${#args[@]})) || continue
            executable=${args[0]##*/}
            # A rewritten title does not prove which -C/-O options started it.
            [[ $executable == sendmail ]] || return 0
            path=/etc/mail/sendmail.cf
            daemon=0
            for ((i = 1; i < ${#args[@]}; i++)); do
                case ${args[i]} in
                -bd | -bD) daemon=1 ;;
                -C) ((i += 1)); ((i < ${#args[@]})) || return 0; path=${args[i]} ;;
                -C*) path=${args[i]#-C} ;;
                -Ac | -O* | -o*) return 0 ;;
                esac
            done
            ((daemon)) || return 0
            # Existing Sendmail checks consume this canonical file only.
            [[ $path == /etc/mail/sendmail.cf ]] || return 0
            ((count += 1))
        done <<<"$AUDIT_COMMAND_STDOUT"
        ((count == 1)) || return 0
        active_lines /etc/mail/sendmail.cf >/dev/null || return 0
        MAIL_PROVIDER=sendmail
        ;;
    exim | opensmtpd) MAIL_PROVIDER=$RUNTIME_PROVIDER ;;
    esac
    return 0
}

postfix_value() {
    local key=$1
    [[ ${MAIL_PROVIDER:-unknown} == postfix && ${MAIL_CONFIG_DIR:-} == /* ]] || return 2
    command -v postconf >/dev/null 2>&1 || return 2
    capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" postconf -c "$MAIL_CONFIG_DIR" -h "$key" || return 2
    printf '%s' "$AUDIT_COMMAND_STDOUT"
}

check_u_45() {
    service_gate mail || return
    local versions
    versions=$(grep -Ei '(postfix|sendmail|exim|opensmtpd)' <<<"$AUDIT_PACKAGE_DATA")
    emit_result MANUAL '메일 Version 증거 확보; Vendor 보안 지원·Backport 확인 필요' "$versions" '해당 배포판 Security Advisory·지원 종료·적용 기록과 대조; 숫자 Version만으로 최신/취약 단정 금지'
}

check_u_46() {
    service_gate mail || return
    local data
    mail_provider
    if [[ $MAIL_PROVIDER == sendmail ]]; then
        data=$(active_lines /etc/mail/sendmail.cf 2>/dev/null | grep 'PrivacyOptions') || data=
        if grep -qi 'restrictqrun' <<<"$data"; then
            emit_result GOOD 'Sendmail 일반 사용자 Queue 실행 제한 설정' 'PrivacyOptions restrictqrun'
        else emit_result MANUAL 'Sendmail Queue 실행 제한 유효값 확인 필요' '명시적 restrictqrun 미확인' 'Sendmail Version·기본값·binary/Queue 권한 확인'; fi
    else emit_result MANUAL '메일 Provider의 일반 사용자 실행 제한 확인 필요' "provider=$MAIL_PROVIDER" 'Postfix/Exim 등의 Queue 실행·명령 권한·Daemon 권한을 Vendor 방식으로 확인'; fi
}

check_u_47() {
    service_gate mail || return
    local restrictions networks tokens token found=0 broad=0
    mail_provider
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
    case $MAIL_PROVIDER in
    postfix)
        value=$(postfix_value disable_vrfy_command) || {
            emit_result ERROR 'Postfix VRFY 유효값 조회 실패' '' '' POSTCONF_FAILED
            return
        }
        case ${value,,} in yes) emit_result GOOD 'Postfix VRFY 비활성 설정 확인' 'disable_vrfy_command=yes; Postfix는 EXPN 미제공' ;; no) emit_result VULNERABLE 'VRFY 비활성화되지 않음' 'disable_vrfy_command=no' ;; *) emit_result ERROR 'VRFY 설정 형식 미확정' '' '' PARSE_FAILED ;; esac
        ;;
    sendmail)
        value=$(active_lines /etc/mail/sendmail.cf 2>/dev/null | grep PrivacyOptions) || value=
        if grep -qi noexpn <<<"$value" && grep -qi novrfy <<<"$value"; then
            emit_result GOOD 'Sendmail EXPN/VRFY 제한 설정' 'PrivacyOptions noexpn,novrfy'
        else emit_result MANUAL 'Sendmail EXPN/VRFY 유효 제한 미확정' '명시적 Option 미확인' '실제 PrivacyOptions 기본값·Include·Daemon 적용 확인'; fi
        ;;
    *) emit_result MANUAL '메일 Provider별 EXPN/VRFY ACL 확인 필요' "provider=$MAIL_PROVIDER" '명령 지원 여부·거부 ACL·Version 확인' ;;
    esac
}

check_u_49() {
    service_gate dns || return
    emit_result MANUAL 'DNS 패치 정책·Vendor 지원 상태 확인 필요' "$(grep -Ei '(bind|unbound|pdns|knot)' <<<"$AUDIT_PACKAGE_DATA")" 'Vendor Advisory·지원 종료·실제 적용 기록을 확인; Resolver Client Version과 서버 Version을 구분'
}

dns_canonical_config() {
    local path
    DNS_CANONICAL=
    command -v named-checkconf >/dev/null 2>&1 || return 2
    for path in /etc/named.conf /etc/bind/named.conf; do
        path_exists "$path" || continue
        # -x prevents printing TSIG secrets; never fall back to unmasked -p.
        capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" named-checkconf -px "$path" || return 2
        DNS_CANONICAL=$AUDIT_COMMAND_STDOUT
        [[ -n $DNS_CANONICAL ]] && return 0
    done
    return 2
}

dns_acl_check() {
    local directive=$1 flat blocks
    service_gate dns || return
    if ! dns_canonical_config; then
        emit_result MANUAL 'DNS 유효 설정의 안전한 정규화가 필요' "$directive: Provider 또는 Canonical Parser 미지원" 'BIND named-checkconf -px 또는 Provider별 동일 기능으로 전체 Include/Zone/View ACL 확인'
        return
    fi
    flat=$(tr '\n' ' ' <<<"$DNS_CANONICAL")
    if grep -Eq "${directive}[[:space:]]*\{[[:space:]]*any[[:space:]]*;" <<<"$flat"; then
        emit_result VULNERABLE 'DNS ACL에 전체 허용 설정 발견' "$directive { any; }" '해당 Zone/View의 적용 범위와 승인 대상 확인'
    else
        blocks=$(grep -oE "${directive}[[:space:]]*\{[^}]*\}" <<<"$flat") || blocks=
        if [[ -n $blocks ]] && ! grep -Ev "${directive}[[:space:]]*\{[[:space:]]*none[[:space:]]*;[[:space:]]*\}" <<<"$blocks" | grep -q .; then
            emit_result MANUAL '명시적 DNS ACL은 none; 상속·다른 ACL 구문 검토 필요' "$blocks" 'Canonical 설정에서 모든 Zone/View가 해당 제한을 상속하는지 확인'
        else emit_result MANUAL 'DNS ACL의 승인 대상·TSIG·상속 관계 검토 필요' "${blocks:-명시적 ACL 없음}" '기본값을 추정하지 않고 Provider Version·모든 Zone/View 확인'; fi
    fi
}
check_u_50() { dns_acl_check allow-transfer; }
check_u_51() { dns_acl_check allow-update; }

check_u_53() {
    service_gate ftp || return
    local banner
    if ftp_config; then
        banner=$(config_value "$FTP_CONFIG_PATH" ftpd_banner 2>/dev/null) || banner=
        if [[ -z $banner ]]; then
            emit_result MANUAL 'FTP Banner의 실제 노출 내용 확인 필요' '명시적 ftpd_banner 없음' 'banner_file·Provider 기본값·접속 Banner를 확인'
        else emit_result MANUAL '사용자 지정 FTP Banner 설정 확보' "ftpd_banner=$banner" 'OS·제품·Version 정보 노출 여부와 banner_file Override 확인'; fi
    else emit_result MANUAL 'FTP Provider·실제 Banner 확인 필요' '' 'Custom 경로·ProFTPD/Pure-FTPd 등의 Banner 설정 확인'; fi
}

check_u_54() {
    service_gate ftp || return
    local enabled force_login force_data
    if ftp_config; then
        enabled=$(config_value "$FTP_CONFIG_PATH" ssl_enable 2>/dev/null) || enabled=
        force_login=$(config_value "$FTP_CONFIG_PATH" force_local_logins_ssl 2>/dev/null) || force_login=
        force_data=$(config_value "$FTP_CONFIG_PATH" force_local_data_ssl 2>/dev/null) || force_data=
        if [[ ${enabled^^} == NO ]]; then
            emit_result VULNERABLE '실행 중 vsftpd의 TLS 비활성 설정' 'ssl_enable=NO'
        elif [[ ${enabled^^} == YES && ${force_login^^} == YES && ${force_data^^} == YES ]]; then
            emit_result MANUAL 'TLS 강제 설정 확보; 익명·추가 Listener 확인 필요' 'ssl_enable/force_local_logins_ssl/force_local_data_ssl=YES' 'Anonymous TLS·실제 적용 Config·별도 FTP Instance 확인'
        else emit_result MANUAL '평문 FTP 허용 여부 미확정' "ssl_enable=${enabled:-default} login_tls=${force_login:-default} data_tls=${force_data:-default}" 'Provider의 실제 TLS 강제값 확인'; fi
    else emit_result MANUAL 'FTP TLS 정책을 Provider별로 확인' '' 'Port 21 실행만으로 평문 FTP라고 단정하지 않음'; fi
}

check_u_55() {
    service_gate ftp || return
    require_accounts || return
    local name uid gid home shell bad='' found=0
    while IFS=: read -r name uid gid home shell; do
        [[ $name == ftp || $name == anonymous ]] || continue
        found=1
        [[ $shell == */false || $shell == */nologin ]] || bad+="$name shell=$shell"$'\n'
    done <<<"$AUDIT_ACCOUNT_ROWS"
    if [[ -n $bad ]]; then
        emit_result VULNERABLE '확인한 FTP 계정에 로그인 Shell 부여' "$bad"
    else emit_result MANUAL '기본 FTP 계정 Shell 검사 완료; 실제 인증 계정 범위 확인 필요' "default_account_found=$found" 'FTP 가상 계정·PAM·매핑 UID 및 실제 서비스 계정 확인'; fi
}

check_u_56() {
    service_gate ftp || return
    emit_result MANUAL 'FTP에 실제 적용되는 Host/IP ACL 검토 필요' "${AUDIT_SERVICE_EVIDENCE[ftp]}" '방화벽·TCP Wrapper의 실제 연계·Provider ACL·IPv6·Custom Listener 확인. 사용자 차단 목록은 IP ACL 증거가 아님'
}

check_u_57() {
    service_gate ftp || return
    local enable deny file text
    if ftp_config; then
        enable=$(config_value "$FTP_CONFIG_PATH" userlist_enable 2>/dev/null) || enable=
        deny=$(config_value "$FTP_CONFIG_PATH" userlist_deny 2>/dev/null) || deny=
        file=$(config_value "$FTP_CONFIG_PATH" userlist_file 2>/dev/null) || file=
        if [[ ${enable^^} == YES && ${deny^^} == YES && $file == /* ]]; then
            text=$(active_lines "$file") || {
                emit_result ERROR 'FTP Userlist 읽기 실패' "$file" '' READ_FAILED
                return
            }
            if grep -Eq '^[[:space:]]*root[[:space:]]*$' <<<"$text"; then
                emit_result GOOD '명시적으로 활성화된 FTP Deny Userlist에 root 포함' "$file: userlist_enable=YES userlist_deny=YES"
            else emit_result VULNERABLE '활성 Deny Userlist에 root 미포함' "$file"; fi
        else emit_result MANUAL 'FTP root 차단의 실제 인증 경로 확인 필요' "userlist_enable=${enable:-default} userlist_deny=${deny:-default} file=${file:-default}" 'PAM pam_listfile·ftpusers·userlist 기본값 및 실제 적용을 확인'; fi
    else emit_result MANUAL 'FTP Provider의 root 차단 정책 확인' '' 'ProFTPD RootLogin·Pure-FTPd UID 제한·PAM 확인'; fi
}

snmp_config() {
    local p count=0
    SNMP_TEXT=
    SNMP_UNCERTAIN=0
    for p in /etc/snmp/snmpd.conf /etc/snmpd.conf; do
        path_exists "$p" || continue
        ((count += 1))
        local text
        text=$(active_lines "$p") || return 2
        SNMP_TEXT+=$'\n'"$text"
        grep -qiE '^[[:space:]]*(include|includeFile|includeDir|includeSearch)' <<<"$text" && SNMP_UNCERTAIN=1
    done
    ((count == 1)) || SNMP_UNCERTAIN=1
    ((count > 0))
}

check_u_59() {
    service_gate snmp || return
    if ! snmp_config; then
        emit_result ERROR 'SNMP 설정 수집 실패' '' '' READ_FAILED
        return
    fi
    if grep -qiE '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]' <<<"$SNMP_TEXT"; then
        emit_result VULNERABLE 'SNMP v1/v2c Community 인증 설정 발견' 'Community 원문은 출력하지 않음' 'v3 설정이 함께 있어도 v1/v2c 허용을 제거했는지 확인'
    else emit_result MANUAL '명시적 Community 설정 미발견; v3 전용 운용 확인 필요' "include_uncertain=$SNMP_UNCERTAIN" 'VACM Security Model·Custom Config·Daemon Option 및 실제 v1/v2 응답 제한 확인'; fi
}

community_strong() {
    local value=$1 length=${#1}
    [[ ${value,,} != public && ${value,,} != private && $value =~ [A-Za-z] && $value =~ [0-9] ]] || return 1
    if [[ $value =~ [^A-Za-z0-9] ]]; then ((length >= 8)); else ((length >= 10)); fi
}

check_u_60() {
    service_gate snmp || return
    snmp_config || {
        emit_result ERROR 'SNMP 설정 읽기 실패' '' '' READ_FAILED
        return
    }
    local directive secret source rest count=0 bad=0 ev=''
    while read -r directive secret source rest; do
        case ${directive,,} in
        rocommunity | rwcommunity | rocommunity6 | rwcommunity6)
            ((count += 1))
            if community_strong "$secret"; then
                ev+="$directive=[xxx] complexity=PASS "
            else
                bad=1
                ev+="$directive=[xxx] complexity=FAIL "
            fi
            ;;
        esac
        secret=
    done <<<"$SNMP_TEXT"
    if ((bad)); then
        emit_result VULNERABLE 'Community 복잡성 기준 미충족' "$ev"
    elif ((count && !SNMP_UNCERTAIN)); then
        emit_result GOOD '명시적 Community가 2026 복잡성 수치 충족' "$ev" 'SNMPv3 인증 비밀번호는 별도 정책 검토'
    else emit_result MANUAL 'SNMP Community/v3 비밀번호 전체 정책 확인 필요' "$ev" 'Include·com2sec·v3 USM 인증 방식·비밀번호 정책 확인'; fi
}

check_u_61() {
    service_gate snmp || return
    snmp_config || {
        emit_result ERROR 'SNMP 설정 읽기 실패' '' '' READ_FAILED
        return
    }
    local directive secret source rest broad=0 count=0 evidence=''
    while read -r directive secret source rest; do
        case ${directive,,} in
        rocommunity | rwcommunity | rocommunity6 | rwcommunity6)
            ((count += 1))
            case ${source:-default} in default | 0.0.0.0/0 | ::/0) broad=1 ;; esac
            evidence+="$directive community=[xxx] source=${source:-default}"$'\n'
            ;;
        com2sec | com2sec6)
            ((count += 1))
            case ${source:-default} in default | 0.0.0.0/0 | ::/0) broad=1 ;; esac
            evidence+="$directive source=${source:-default} community=[xxx]"$'\n'
            ;;
        esac
        secret=
    done <<<"$SNMP_TEXT"
    if ((broad)); then
        emit_result VULNERABLE 'SNMP 전체 Source 허용 설정' "$evidence"
    else emit_result MANUAL 'SNMP ACL 설정의 전체 적용 확인 필요' "rules=$count $evidence" 'view 존재만으로 양호 처리하지 않음. VACM·IPv6·Include·실제 Source 제한 확인'; fi
}

check_u_62() {
    local path content marker seen=0 found=0 evidence='' bad=0
    for path in /etc/issue /etc/issue.net /etc/motd; do
        path_exists "$path" || continue
        ((seen += 1))
        content=$(read_target "$path") || {
            emit_result ERROR 'Warning Banner 읽기 실패' "$path" '' READ_FAILED
            return
        }
        evidence+="$path bytes=${#content} "
        if [[ -n ${AUDIT_CONFIG[approved_banner_markers]} ]]; then
            found=1
            while IFS= read -r marker; do
                [[ -z $marker ]] && continue
                [[ $content == *"$marker"* ]] || found=0
            done <<<"${AUDIT_CONFIG[approved_banner_markers]}"
            ((found)) || bad=1
        fi
    done
    emit_result MANUAL '서버·실행 서비스별 Warning Banner 적용 확인 필요' "files=$seen marker_mismatch=$bad $evidence" '승인 문구를 입력하고 SSH Banner·Telnet·FTP·SMTP·DNS별 실제 노출·경고 내용을 검토. 파일 존재만으로 양호 판정하지 않음'
}

check_u_63() {
    local real path bad='' count=0
    if ! path_exists /etc/sudoers; then
        emit_result MANUAL 'sudoers 없음: sudo 미사용·대체 정책 확인 필요' '' 'sudo Plugin·sudoers.d·LDAP 정책 경로 확인'
        return
    fi
    local -a paths=(/etc/sudoers)
    real=$(target_path /etc/sudoers.d) || real=
    if [[ -d $real ]]; then
        for path in "$real"/*; do [[ -f $path ]] && paths+=("$path"); done
    fi
    for path in "${paths[@]}"; do
        if ! file_metadata "$path"; then
            emit_result ERROR 'sudoers Metadata 확인 실패' "$path" '' STAT_FAILED
            return
        fi
        ((count += 1))
        if [[ $FILE_UID != 0 ]] || ! mode_within "$FILE_MODE" 0640; then bad+="$path uid=$FILE_UID mode=$FILE_MODE"$'\n'; fi
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE 'sudoers 소유자·권한 기준 초과' "$bad"
    else emit_result GOOD '확인한 sudoers 소유자·권한 기준 충족' "files=$count; 0440/0400 등 더 제한적인 Bit 허용; 정당한 관리자 ALL/NOPASSWD 자체를 추가 취약 기준으로 삼지 않음"; fi
}


# shellcheck shell=bash
allowed_system_owners() {
    local name uid gid home shell out=0
    while IFS=: read -r name uid gid home shell; do
        [[ $name == bin || $name == sys ]] && out+=",$uid"
    done <<<"$AUDIT_ACCOUNT_ROWS"
    printf '%s' "$out"
}

check_syslog_permissions() {
    local p real file seen=0 bad='' errors=0 owners
    owners=$(allowed_system_owners)
    local -a paths=(/etc/rsyslog.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf)
    for p in /etc/rsyslog.d /etc/syslog-ng/conf.d; do
        real=$(target_path "$p") || continue
        [[ -d $real ]] || continue
        for file in "$real"/*.conf; do [[ -f $file ]] && paths+=("$file"); done
    done
    for p in "${paths[@]}"; do
        path_exists "$p" || continue
        ((seen += 1))
        if ! file_metadata "$p"; then
            errors=1
        elif ! list_has "$owners" "$FILE_UID" || ! mode_within "$FILE_MODE" 0640; then bad+="$p uid=$FILE_UID mode=$FILE_MODE"$'\n'; fi
    done
    if [[ -n $bad ]]; then
        emit_result VULNERABLE 'Syslog 설정 소유자·권한 기준 초과' "$bad" '가이드 허용 소유자 root/bin/sys를 이름으로 해석'
    elif ((errors)); then
        emit_result ERROR 'Syslog Metadata 수집 실패' '' '' STAT_FAILED
    elif ((seen)); then
        emit_result GOOD '확인한 Syslog 설정 Metadata 기준 충족' "files=$seen allowed_uids=$owners"
    else emit_result MANUAL 'Syslog 설정 경로·다른 Logger 사용 여부 확인 필요' '' 'journald·Custom Include·BusyBox syslogd 등의 설정 경로 확인'; fi
}

check_firewall_policy() {
    local evidence='' query_ok=0 tool
    for tool in nft iptables-save ip6tables-save ufw firewall-cmd; do
        command -v "$tool" >/dev/null 2>&1 || continue
        case $tool in
        nft) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" nft list ruleset || continue ;;
        iptables-save | ip6tables-save) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" "$tool" || continue ;;
        ufw) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ufw status verbose || continue ;;
        firewall-cmd) capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" firewall-cmd --list-all-zones || continue ;;
        esac
        query_ok=1
        evidence+="$tool:"$'\n'"${AUDIT_COMMAND_STDOUT:0:12000}"$'\n'
    done
    if ((query_ok)); then
        emit_result MANUAL '실제 Firewall 증거 수집 완료; 허용 정책과 순서 검토 필요' "$evidence" "allowed_management_cidrs=${AUDIT_CONFIG[allowed_management_cidrs]:-미입력}; IPv4/IPv6·Rule 순서·Default Policy·Cloud/상위 ACL 포함 확인"
    else emit_result ERROR '사용 가능한 Firewall 조회가 모두 실패하거나 도구 없음' '도구 없음은 차단/안전을 뜻하지 않음' '권한·Kernel·대체 Firewall·상위 ACL 확인' FIREWALL_QUERY_FAILED; fi
}

check_u_64() {
    local evidence file
    evidence="package_manager=$AUDIT_PACKAGE_MANAGER kernel=$(uname -r)"
    for file in /var/log/dpkg.log /var/log/apt/history.log /var/log/dnf.log /var/log/yum.log /var/log/pacman.log /var/log/apk.log; do
        if path_exists "$file" && file_metadata "$file"; then evidence+=$'\n'"$file uid=$FILE_UID mode=$FILE_MODE (내용·날짜·승인 기록 별도 확인)"; fi
    done
    emit_result MANUAL '패치 적용 정책·Vendor 권고·적용 기록 검토 필요' "$evidence" '온라인 갱신·패치 설치를 수행하지 않음. Vendor Backport·EOL·영향도 검토·적용 승인 기록과 대조; 업데이트 목록 0개만으로 GOOD 판정하지 않음'
}

check_u_65() {
    local tool source value evidence='' runtime=unknown config='' configured=0 policy_bad=0
    local -a paths=(/etc/chrony.conf /etc/chrony/chrony.conf /etc/ntp.conf /etc/ntpsec/ntp.conf /etc/openntpd/ntpd.conf /etc/systemd/timesyncd.conf /etc/ntpd-rs/ntp.toml)
    for source in "${paths[@]}"; do
        path_exists "$source" || continue
        value=$(active_lines "$source") || {
            emit_result ERROR '시간 동기화 설정 읽기 실패' "$source" '' READ_FAILED
            return
        }
        config+=$'\n'"$value"
        evidence+="$source:"$'\n'"$(grep -Ei '^[[:space:]]*(server|pool|peer|NTP=|FallbackNTP=)' <<<"$value")"$'\n'
    done
    while read -r tool source value; do
        case ${tool,,} in server | pool | peer)
            ((configured += 1))
            if [[ -n ${AUDIT_CONFIG[approved_time_sources]} ]] && ! list_has "${AUDIT_CONFIG[approved_time_sources]}" "$source"; then policy_bad=1; fi
            ;;
        esac
    done <<<"$config"
    if command -v chronyc >/dev/null 2>&1; then
            if capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" chronyc -n sources; then
                evidence+=$'\n'"chronyc sources:"$'\n'"$AUDIT_COMMAND_STDOUT"
                if grep -Eq '^[[:space:]]*[\^=#]\*' <<<"$AUDIT_COMMAND_STDOUT"; then runtime=synchronized; else runtime=not_synchronized; fi
            fi
        fi
        if [[ $runtime == unknown ]] && command -v ntpq >/dev/null 2>&1; then
            if capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ntpq -pn; then
                evidence+=$'\n'"ntpq peers:"$'\n'"$AUDIT_COMMAND_STDOUT"
                if grep -Eq '^[*o]' <<<"$AUDIT_COMMAND_STDOUT"; then runtime=synchronized; else runtime=not_synchronized; fi
            fi
        fi
        if [[ $runtime == unknown ]] && command -v timedatectl >/dev/null 2>&1; then
            if capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" timedatectl show --property=NTPSynchronized --value; then
                case $AUDIT_COMMAND_STDOUT in yes) runtime=synchronized ;; no) runtime=not_synchronized ;; esac
            fi
        fi
    evidence+=$'\n'"runtime=$runtime configured_sources=$configured"
    if [[ $runtime == not_synchronized ]]; then
        emit_result VULNERABLE '실제 시간 Source와 동기화되지 않음' "$evidence"
    elif ((policy_bad)); then
        emit_result VULNERABLE '입력한 승인 Source 목록과 설정 불일치' "$evidence" 'Pool Member IP와 승인 이름의 관계·동적 Include 확인'
    elif [[ $runtime == synchronized && -n ${AUDIT_CONFIG[approved_time_sources]} && $configured -ge 1 ]]; then
        emit_result MANUAL 'Runtime 동기화·승인 Source 설정 확보' "$evidence" 'Include/Drop-in·실제 선택 Source·Polling 주기·동기화 오차 기준 확인'
    else emit_result MANUAL '시간 동기화 정책 또는 Runtime 증거 미확정' "$evidence" '승인 Source·권고 서버 수·시간 오차·Polling 기준과 실제 적용값 확인'; fi
}

check_u_66() {
    local path real file policy line policy_index=0 evidence='' missing=0 files=0
    local -A matched_policy=()
    local -a paths=(/etc/rsyslog.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf /etc/systemd/journald.conf)
    for path in /etc/rsyslog.d /etc/syslog-ng/conf.d /etc/systemd/journald.conf.d; do
        real=$(target_path "$path") || continue
        [[ -d $real ]] || continue
        for file in "$real"/*.conf; do [[ -f $file ]] && paths+=("$file"); done
    done
    for path in "${paths[@]}"; do
        path_exists "$path" || continue
        real=$(target_path "$path") || {
            emit_result ERROR 'Logger 설정 수집 실패' "$path" '' READ_FAILED
            return
        }
        # Only numeric summaries and an allowlisted Storage value leave awk.
        # Required literal patterns are compared to the input, never copied out.
        if ! capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" awk '
            BEGIN {
                required_count=split(ARGV[1],required,"\n");ARGV[1]=""
                active=0;local_dest=0;remote_dest=0;storage="not_explicit"
            }
            {
                sub(/\r$/,"")
                if($0 ~ /^[[:space:]]*(#|;|$)/)next
                active++
                if($0 ~ /^[[:space:]]*[^[:space:]]+[[:space:]]+-?\// || $0 ~ /file[[:space:]]*\([[:space:]]*"\//)local_dest++
                if($0 ~ /^[[:space:]]*[^[:space:]]+[[:space:]]+@@?/ || tolower($0) ~ /type[[:space:]]*=[[:space:]]*"omfwd"/ || $0 ~ /(tcp|udp|network)[[:space:]]*\(/)remote_dest++
                if($0 ~ /^[[:space:]]*Storage[[:space:]]*=/) {
                    value=$0;sub(/^[^=]*=[[:space:]]*/,"",value);sub(/[[:space:]]*#.*/,"",value);sub(/[[:space:]]*$/,"",value)
                    storage=(value ~ /^(auto|volatile|persistent|none)$/ ? value : "other")
                }
                for(i=1;i<=required_count;i++)if(required[i]!="" && index($0,required[i]))matched[i]=1
            }
            END {
                printf "active_lines=%d local_destination_candidates=%d remote_destination_candidates=%d storage=%s\n",active,local_dest,remote_dest,storage
                for(i=1;i<=required_count;i++)if(matched[i])printf "policy_index=%d\n",i
            }' "${AUDIT_CONFIG[required_log_patterns]}" "$real"; then
            emit_result ERROR 'Logger 설정 수집 실패' "$path" '' READ_FAILED
            return
        fi
        evidence+="$path:"$'\n'"$AUDIT_COMMAND_STDOUT"$'\n'
        while IFS= read -r line; do
            if [[ $line =~ ^policy_index=([0-9]+)$ ]]; then matched_policy[${BASH_REMATCH[1]}]=1; fi
        done <<<"$AUDIT_COMMAND_STDOUT"
    done
    real=$(target_path /var/log) || real=
    if [[ -d $real ]]; then
        local records="$AUDIT_WORK_DIR/logger.$BASHPID"
        if ! collect_paths "$records" "$real" -maxdepth 2 -type f -size +0c -print0; then
            emit_result ERROR 'Log 파일 탐색 실패' "$evidence" '' INCOMPLETE_SCAN
            return
        fi
        while IFS= read -r -d '' file; do ((files += 1)); done <"$records"
        rm -f -- "$records" "$records.err"
    fi
    if [[ -n ${AUDIT_CONFIG[required_log_patterns]} ]]; then
        while IFS= read -r policy; do
            ((policy_index += 1))
            [[ -z $policy ]] && continue
            [[ -v matched_policy[$policy_index] ]] || missing=1
        done <<<"${AUDIT_CONFIG[required_log_patterns]}"
    fi
    emit_result MANUAL '로깅 설정·기록 파일 증거 확보; 정책과 실제 기록 검토 필요' "nonempty_log_files=$files required_pattern_missing=$missing $evidence" '설정 파일/Process 존재만으로 GOOD 판정하지 않음. 조직 정책·Facility/Level·실제 최근 기록·중앙 전송·journald 저장 방식 확인'
}

check_u_67() {
    local real file path bad='' seen=0 errors=0 start=$SECONDS records
    real=$(target_path /var/log) || {
        emit_result ERROR 'Log 경로 검증 실패' '' '' PATH_FAILED
        return
    }
    [[ -d $real ]] || {
        emit_result ERROR '/var/log 없음' '' '' PATH_FAILED
        return
    }
    records="$AUDIT_WORK_DIR/logs.$BASHPID"
    collect_paths "$records" "$real" -type f -print0 || errors=1
    while IFS= read -r -d '' file; do
        if ((SECONDS - start > ${AUDIT_CONFIG[scan_timeout_seconds]})); then
            errors=1
            break
        fi
        path=$file
        ((seen += 1))
        if ! file_metadata "$path"; then
            errors=1
        elif [[ $FILE_UID != 0 ]] || ! mode_within "$FILE_MODE" 0644; then [[ ${#bad} -ge 24000 ]] || bad+="$path uid=$FILE_UID mode=$FILE_MODE"$'\n'; fi
    done <"$records"
    rm -f -- "$records" "$records.err"
    if [[ -n $bad ]]; then
        emit_result VULNERABLE 'Log 파일 소유자 또는 권한이 공식 기준 초과' "${bad:0:22000}" 'syslog 등 서비스 소유권이 OS 기본값이어도 자동 면제하지 않음. Vendor 필요성과 승인 예외를 검토'
    elif ((errors)); then
        emit_result ERROR 'Log 파일 범위·Metadata 수집 미완료' "checked=$seen" '' INCOMPLETE_SCAN
    elif ((seen == 0)); then
        emit_result MANUAL 'Log 파일이 없어 소유자·권한 판정 대상 확인 필요' 'regular_log_files=0' '다른 경로·원격 전송·journald·실제 기록 여부 확인'
    else emit_result GOOD '확인한 /var/log 일반 파일의 소유자·권한 충족' "checked=$seen; 디렉터리/외부 Symlink 대상의 별도 검토 필요"; fi
}


target_path() {
    [[ $1 == /* && $1 != *$'\n'* ]] || return 2
    printf '%s' "$1"
}

audit_within_deadline() {
    ((AUDIT_INTERRUPTED == 0 && (AUDIT_ITEM_DEADLINE == 0 || SECONDS < AUDIT_ITEM_DEADLINE)))
}

select_collectors() {
    local id role roles
    for id in "${AUDIT_SELECTED[@]}"; do
        case $id in
        U-02 | U-03 | U-04 | U-05 | U-06 | U-07 | U-08 | U-09 | U-10 | U-11 | U-15 | U-21 | U-22 | U-24 | U-27 | U-31 | U-32 | U-55)
            AUDIT_NEED_ACCOUNTS=1 ;;
        esac
        case $id in U-08 | U-09) AUDIT_NEED_GROUPS=1 ;; esac
        case $id in U-02 | U-04 | U-13) AUDIT_NEED_SHADOW=1 ;; esac
        roles=
        case $id in
        U-01) roles='ssh telnet r' ;;
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

scan_incomplete() {
    local reason=$1 capped=${2:-0} only=${3:-} kind
    for kind in "${!AUDIT_SCAN_SELECTED[@]}"; do
        [[ -z $only || $kind == "$only" ]] || continue
        AUDIT_SCAN_ITEM_COMPLETE[$kind]=0
        ((capped)) && AUDIT_SCAN_ITEM_CAPPED[$kind]=1
        if [[ ${AUDIT_SCAN_ITEM_ERROR[$kind]-} != *"$reason"* ]]; then
            AUDIT_SCAN_ITEM_ERROR[$kind]="${AUDIT_SCAN_ITEM_ERROR[$kind]-}$reason; "
            AUDIT_SCAN_ITEM_ERROR[$kind]=${AUDIT_SCAN_ITEM_ERROR[$kind]:0:1500}
        fi
    done
}

scan_add_finding() {
    local kind=$1 path=$2 detail=${3:-$2}
    local -n samples=$kind
    AUDIT_SCAN_ITEM_COUNT[$kind]=$(( ${AUDIT_SCAN_ITEM_COUNT[$kind]:-0} + 1 ))
    # scan_approved is local to scan_collect; Bash's dynamic scope keeps the
    # exact path index private to this collection.
    if [[ ${scan_approved["$kind|$path"]-} != 1 ]]; then
        AUDIT_SCAN_ITEM_UNAPPROVED[$kind]=$(( ${AUDIT_SCAN_ITEM_UNAPPROVED[$kind]:-0} + 1 ))
        ((${#samples[@]} < 100)) && samples+=("$detail")
    fi
    return 0
}

scan_find_pattern() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\*/\\*}
    value=${value//\?/\\?}
    value=${value//\[/\\[}
    printf '%s' "$value"
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
        for name in $processes; do
            if grep -Fxq -- "$name" <<<"$AUDIT_PROCESS_NAMES"; then matched=1; fi
        done
        for unit in $units; do
            case $evidence in
            *" $unit=active "* | *" $unit=activating "* | *" $unit=reloading "*) matched=1 ;;
            esac
        done
        if ((matched)); then
            ((count += 1))
            RUNTIME_PROVIDER=$provider
        fi
    done <<<"$specs"
    if ((count != 1)); then RUNTIME_PROVIDER=unknown; return 2; fi
    return 0
}

postfix_runtime_scope() {
    # Bind postconf to the configuration of exactly one identified Postfix master.
    local pid executable directory='' candidate='' masters=0
    MAIL_CONFIG_DIR=
    command -v ps >/dev/null 2>&1 || return 2
    command -v postconf >/dev/null 2>&1 || return 2
    capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" ps -C master -o pid= || return 2
    local pids=$AUDIT_COMMAND_STDOUT
    while read -r pid; do
        [[ -n $pid ]] || continue
        [[ $pid =~ ^[1-9][0-9]*$ ]] || return 2
        executable=$(readlink -f -- "/proc/$pid/exe" 2>/dev/null) || return 2
        case $executable in */postfix/master | */postfix/*/master) ;; *) continue ;; esac
        ((masters += 1))
        # Whitelist one environment field. Other environment values are not saved.
        capture_command "${AUDIT_CONFIG[command_timeout_seconds]}" awk 'BEGIN{RS="\0"} /^MAIL_CONFIG=/{sub(/^MAIL_CONFIG=/,"");print;exit}' "/proc/$pid/environ" || return 2
        directory=$AUDIT_COMMAND_STDOUT
        [[ $directory == /* && $directory != *$'\n'* ]] || return 2
        [[ -z $candidate || $candidate == "$directory" ]] || return 2
        candidate=$directory
    done <<<"$pids"
    # Additional instances need their own review, not the primary main.cf values.
    ((masters == 1)) && [[ -n $candidate ]] || return 2
    active_lines "$candidate/main.cf" >/dev/null || return 2
    MAIL_CONFIG_DIR=$candidate
    return 0
}

audit_main "$@"
