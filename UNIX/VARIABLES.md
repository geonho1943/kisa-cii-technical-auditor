# 사용자 변수

단일 실행 파일 상단 AUDIT_CONFIG에서 편집합니다. CLI --set key=value가 해당 실행의 값을 덮어씁니다. 검증 후 readonly이며 export하지 않습니다. 공란 정책은 임의 추정하지 않습니다.

| Key | 기본값 | Type | 설명 | 예시 |
| --- | --- | --- | --- | --- |
| output_dir | ./audit-results | string | 결과 저장 경로. 접근 권한을 제한한 실행별 하위 폴더 생성 | ./audit-results |
| check_ids | ALL | ids | 검사할 공식 ID. ALL 또는 쉼표 구분. 미선택 항목은 별도 기록 | U-01,U-18 |
| command_timeout_seconds | 15 | seconds | 일부 서비스·네트워크 조회 명령의 제한 시간(초). 1~3600. timeout 명령이 없으면 직접 실행 | 15 |
| approved_log_accounts | (미입력) | list | U-67에서 root 외 로그 소유자로 승인할 계정명. 로컬 UID로 대조하며, 미입력 시 root만 허용 | syslog |
| scan_roots | AUTO | paths | AUTO=현재 Namespace의 로컬 Mount. 지정 시 줄바꿈 구분 절대 경로; 부분 범위로 표시 | AUTO |
| approved_accounts | (미입력) | list | 업무상 승인한 전체 계정. 줄바꿈 또는 쉼표 구분; 미입력 U-07 수동 확인 | root,appuser |
| approved_admin_accounts | (미입력) | list | 관리자 그룹에 허용할 계정; 미입력 U-08 수동 확인 | root,adminuser |
| approved_groups | (미입력) | list | 업무상 승인한 그룹; 미입력 U-09 수동 확인 | root,appgroup |
| nonlogin_accounts | (미입력) | list | 로그인이 불필요한 서비스 계정; 미입력 U-11 수동 확인 | daemon,appsvc |
| required_services | (미입력) | list | 업무상 필요한 서비스 역할. nfs,rpc,r,snmp,automount 등. 필요성은 자동 추정하지 않음 | nfs |
| approved_time_sources | (미입력) | list | 승인 NTP 서버/Pool 이름 또는 IP; 미입력 U-65 정책 확인 필요 | time.example.org |
| required_log_patterns | (미입력) | lines | 조직에서 요구하는 활성 로깅 설정 문자열. 줄바꿈 구분, Literal 일치 | authpriv.* |
| allowed_management_cidrs | (미입력) | list | U-28의 허용 관리망 CIDR. 미입력은 MANUAL. 단순 IPv4/IPv6 INPUT의 신규 TCP 21/22/23과 기본 DROP을 검사하며, 미해석 조건·다른 체인·외부 ACL은 추가 확인 | 192.0.2.0/24 |
| approved_special_files | (미입력) | paths | SUID/SGID가 승인된 파일의 정확한 경로. 줄바꿈 구분 | /usr/bin/passwd |
| approved_world_writable_paths | (미입력) | paths | 쓰기 허용 사유를 검토한 정확한 파일 경로. 하위 경로 자동 면제 없음 | /srv/share/file |
| approved_hidden_paths | (미입력) | paths | 검토 완료한 정확한 숨김 경로. 기본 OS 파일도 자동 승인하지 않음 | /root/.profile |
| approved_device_files | (미입력) | paths | 검토 완료한 /dev 일반 파일의 정확한 경로. 줄바꿈 구분 | /dev/example |
| approved_banner_markers | (미입력) | lines | U-62의 필수 경고 문자열. 미입력은 MANUAL. issue/issue.net의 전체 마커와 실행 중 SSH의 실제 Banner 파일 등을 확인 | 승인된 사용자 |

paths/lines 항목은 줄바꿈으로 구분합니다. 일반 list는 쉼표 또는 줄바꿈 구분입니다. 비밀번호/Hash/Token을 설정에 넣지 마십시오. 승인 경로 목록에는 필요성과 승인 근거를 검토한 정확한 경로만 입력합니다. U-23·U-25·U-33은 AUTO 범위의 탐색이 완전하고 모든 발견 경로가 승인 목록에 포함되면 사용자 승인 목록 기준으로 GOOD을 반환합니다. 부분 탐색이나 수집 오류는 승인 목록으로 면제하지 않습니다.

`command_timeout_seconds`는 getent, ss/netstat, systemctl, sshd -T, chronyc/ntpq/timedatectl, named-checkconf, nft/iptables-save/ip6tables-save/ufw/firewall-cmd, postconf에 적용합니다. find·stat·awk 등의 일반 조회나 전체 실행 시간에는 적용하지 않습니다. 파일 탐색 시간·건수 제한 설정은 제공하지 않습니다.

U-67은 타인 쓰기가 없고 소유자가 root 또는 승인 계정이면 권한 조건을 충족합니다. 그룹 쓰기와 wtmp/btmp의 0660은 허용하지만 소유자 조건도 충족해야 합니다. 승인 계정의 UID를 확인하지 못한 경우는 MANUAL이며, 확인된 위반이 있으면 VULNERABLE을 우선합니다.
