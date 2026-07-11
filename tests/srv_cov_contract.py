"""서버(SRV) linux 변형 DET 양극성 커버리지 픽스처 계약 (단일 진실원천).

각 DET 항목에 대해 good(위반없음→양호) / vuln(위반→취약) 합성 raw_output을 정의.

구조:
  SRV_COV[item_id] = {
      "good": <raw_output string>,      # 양호 유발 raw
      "vuln": <raw_output string>,      # 취약 유발 raw
      "good_verdict": "양호",            # 기대 verdict (good 입력)
      "vuln_verdict": "취약",            # 기대 verdict (vuln 입력)
      "note": "...",                     # 선택적 설명
  }

특수 verdict:
  - "양호"     : 위반 없음
  - "취약"     : 위반 확정
  - "판단보류" : (*) 수동 경로 또는 기능적 한계

미커버(UNCOVERED) 표시:
  항목에 "uncovered": True 가 있으면 skip 사유가 "uncovered_reason" 에 명시됨.

적용 범위: linux variant의 DET/DET-PARTIAL 항목 전수.
MANUAL/ABSENT 항목은 별도 MANUAL_HOLD_ITEMS에 명시.

판단방식:
  순수 DET  — SRV_auto_parse.check_SRV_NNN(raw_output)
  linux-override DET — SRV_Linux_parse.check_SRV_NNN(raw_output) (SRV-026/069/074/127/131)
  DET-PARTIAL — 서비스 inactive → 양호(DET), 서비스 active→수동(*)
"""
from __future__ import annotations

DELIMITER = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
D = DELIMITER


# ──────────────────────────────────────────────────────────────────────────────
# 순수 DET 항목 (default: DET, SRV_auto_parse 경로)
# ──────────────────────────────────────────────────────────────────────────────

# SRV-001: SNMP 서비스 — inactive→양호, v1/v2 설정 있음→취약
# check_SRV_001: split_output(output, 2), get_check_service(output, "snmp")
_SRV_001_GOOD = (
    # SNMP 서비스 없음 → 양호
    "-e [ snmp ][S]\n[ snmp ][E]\n"
    f"{D}\n"
    "# snmpd.conf empty\n"
)
_SRV_001_VULN = (
    # SNMP v1/v2 설정 있음 → 취약
    "-e [ snmp ][S]\nsnmpd 1234 root\n[ snmp ][E]\n"
    f"{D}\n"
    "------------\n[check v1v2]\nrocommunity public 0.0.0.0/0\n------------\n"
    "[check v3]\nauthNoPriv\n------------\n"
)

# SRV-004: SMTP 서비스 존재 → 취약 (업무상 사용 여부 확인)
# check_SRV_004: get_check_service(output, 'smtp|sendmail|postfix|exim')
_SRV_004_GOOD = "-e [ smtp|sendmail|postfix|exim ][S]\n[ smtp|sendmail|postfix|exim ][E]\n"
_SRV_004_VULN = (
    "-e [ smtp|sendmail|postfix|exim ][S]\n"
    "sendmail 1234 root\n"
    "[ smtp|sendmail|postfix|exim ][E]\n"
)

# SRV-008: SMTP 서비스 + 메일서버 설정 — sendmail maxdaemonchildren 등 0 설정→취약
# check_SRV_008: split_output(output, 4), get_check_service, get_smtp_type
# sendmail 경로: outputArr[1] 에서 check_str 항목 탐지
_SRV_008_GOOD = (
    # SMTP 없음 → 양호
    "-e [ smtp|sendmail|postfix|exim ][S]\n[ smtp|sendmail|postfix|exim ][E]\n"
    f"{D}\n"
    f"{D}\n"
    f"{D}\n"
)
_SRV_008_VULN = (
    # sendmail 실행 중 + maxdaemonchildren=0 → 취약
    "-e [ smtp|sendmail|postfix|exim ][S]\nsendmail 1234 root\n[ smtp|sendmail|postfix|exim ][E]\n"
    f"{D}\n"
    "O MaxDaemonChildren=0\nO ConnectionRateThrottle=1000\nO MinFreeBlocks=100\nO MaxHeadersLength=32768\nO MaxMessageSize=10485760\n"
    f"{D}\n"
    f"{D}\n"
)

# SRV-010: sendmail restrictqrun 설정 — 버그수정 확인(SRV-010-polarity)
# check_SRV_010: split_output, sendmail 탐지, PrivacyOptions restrictqrun 검사
_SRV_010_GOOD = (
    # sendmail 실행 + restrictqrun 있음 → 양호
    "-e [ smtp|sendmail|postfix|exim ][S]\nsendmail 12345 root\n[ smtp|sendmail|postfix|exim ][E]\n"
    + "\n" + D + "\n"
    + ""
    + "\n" + D + "\n"
    + "O PrivacyOptions=authwarnings,noexpn,novfry,noetrn,restrictqrun\n"
)
_SRV_010_VULN = (
    # sendmail 실행 + restrictqrun 없음 → 취약
    "-e [ smtp|sendmail|postfix|exim ][S]\nsendmail 12345 root\n[ smtp|sendmail|postfix|exim ][E]\n"
    + "\n" + D + "\n"
    + ""
    + "\n" + D + "\n"
    + "O PrivacyOptions=authwarnings,noexpn,novfry,noetrn\n"
)

# SRV-011: FTP 서비스 + ftpusers 파일에 root 존재 여부
# check_SRV_011: split_output(output, 2), get_check_service(output, 'ftp')
# FTP 없음 → 양호, FTP 있음 + ftpusers에 root → 양호, root 없음 → 취약
_SRV_011_GOOD = (
    # FTP 서비스 없음 → 양호
    "-e [ ftp ][S]\n[ ftp ][E]\n"
    f"{D}\n"
)
_SRV_011_VULN = (
    # FTP 있음 + ftpusers에 root 없음 → 취약
    "-e [ ftp ][S]\nvsftpd 1234 root\n[ ftp ][E]\n"
    f"{D}\n"
    "$ cat /etc/vsftpd/ftpusers\n"
    "anonymous\n"
    "ftp\n"
    "------------\n"
)

# SRV-012: FTP 없음→양호, .netrc 권한 취약→취약, .netrc 양호+내용확인필요→(*) handled=False
# check_SRV_012: get_check_service(output, 'ftp'), 파일권한 패턴
# 주의: FTP 없음 → 양호(DET), .netrc 권한취약 → 취약, .netrc 권한양호 → (*) handled=False
_SRV_012_GOOD = (
    # FTP 서비스 없음 → 양호
    "-e [ ftp ][S]\n[ ftp ][E]\n"
)
_SRV_012_VULN = (
    # FTP 있음 + .netrc 권한 취약(world readable)
    "-e [ ftp ][S]\nvsftpd 1234 root\n[ ftp ][E]\n"
    "-rw-r--r--  1 appuser appuser 123 Jan  1 00:00 /home/appuser/.netrc\n"
)

# SRV-015: NFS 서비스 — inactive→양호, active→취약
# check_SRV_015: split_output(output, 2), get_check_service(output, 'nfs')
_SRV_015_GOOD = (
    "-e [ nfs ][S]\n[ nfs ][E]\n"
    f"{D}\n"
)
_SRV_015_VULN = (
    "-e [ nfs ][S]\nnfsd 1234 root\n[ nfs ][E]\n"
    f"{D}\n"
)

# SRV-016: RPC 서비스 목록 — 전부 없으면 양호, 하나라도 있으면 취약
# check_SRV_016: get_check_service(output, rpc) for rpc in rpcinfo
_SRV_016_GOOD = "-e [ cms ][S]\n[ cms ][E]\n$ ps\nno rpc services\n"
_SRV_016_VULN = (
    "-e [ rusers ][S]\nrusers 1234 root\n[ rusers ][E]\n"
)

# SRV-025: r계열 서비스 — 모두 없으면 양호, 있고 +설정 있으면 취약
# check_SRV_025: split_output(cleaned, 2), get_check_service(outputArr[0], ...), '+'패턴
_SRV_025_GOOD = (
    "-e [ exec|rexec ][S]\n[ exec|rexec ][E]\n"
    "-e [ login|rlogin ][S]\n[ login|rlogin ][E]\n"
    "-e [ shell|rshell ][S]\n[ shell|rshell ][E]\n"
    f"{D}\n"
)
_SRV_025_VULN = (
    # rlogin 실행 중 + /etc/hosts.equiv에 '+' 있음 → 취약
    "-e [ login|rlogin ][S]\nrlogin 1234 root\n[ login|rlogin ][E]\n"
    f"{D}\n"
    "$ cat /etc/hosts.equiv\n"
    "+\n"
    "------------\n"
)

# SRV-028: telnet/ssh 서비스 + TMOUT 설정 — 서비스 없으면 양호, 있고 TMOUT<=900→양호, >900→취약
# check_SRV_028: split_output(output, 4)
#
# ── 실포맷 승격 (2026-07-11) ──────────────────────────────────────────────
# 도커 ubuntu:24.04 + fsi_unix.sh 원본 무수정 단일변수 재수집(out/srv_lab/promo/).
# sshd 실제 기동 상태에서 TMOUT 값만 단일 변경(600 ↔ 미설정)해 good/vuln 확보.
# 기존 out/srv_lab 실측 vuln 샘플은 PermitRootLogin+TMOUT 동시 변경(다변수 혼합)이라
# 픽스처 승격에는 부적합 → 이번 재수집으로 SRV-028만 단독 플립한 실측 CDATA로 교체.
# judge() 재검증: good→양호, vuln→취약 (verdict 플립 실확인, 아래 promo-*.xml 원본 보존).
_SRV_028_GOOD = (
    '\n-e [ telnet ][S]\n[ telnet ][E]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n$ echo $TMOUT\n600\n------------\n \n[ Common /etc/profile Setting ]\n \n[ Common login Setting ]\n \n[ All Users ..*profile Setting ]\n \n[ Common .profile Setting ]\n \n[ Common .login Setting ]\n \n[ All Users .login Setting ]\n \n[ Common shrc Setting ]\n \n[ All Users shrc Setting ]\n \n[ Current User Setting ]\n \n[ Current User Environment Variables ]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n-e [ ssh|ssh-server ][S]\n$ cat /etc/services | egrep ssh|ssh-server\n-e \n-e ssh\t\t22/tcp\t\t\t\t# SSH Remote Login Protocol\n$ netstat -an 2>&1\n-e \ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     \ntcp6       0      0 :::22                   :::*                    LISTEN     \n$ ps -ef | egrep sshd\n-e root        3931       1  0 00:49 ?        00:00:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups\n$ ps auxwww | egrep sshd\n-e root        3931  0.0  0.0  12048  2896 ?        Ss   00:49   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups\n[ ssh|ssh-server ][E]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n$ /etc/ssh/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\n#ClientAliveInterval 0\n#ClientAliveCountMax 3\nClientAliveInterval 300\nClientAliveCountMax 0\n------------\n$ /opt/ssh/etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /opt/ssh/etc/sshd_config: No such file or directory\n------------\n$ /etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /etc/sshd_config: No such file or directory\n------------\n$ /usr/local/etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /usr/local/etc/sshd_config: No such file or directory\n------------\n$ /usr/local/sshd/etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /usr/local/sshd/etc/sshd_config: No such file or directory\n------------\n$ /usr/local/ssh/etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /usr/local/ssh/etc/sshd_config: No such file or directory\n------------\n$ /etc/ssh/ssh_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\n------------\n\t\t\t\t'
)
_SRV_028_VULN = (
    '\n-e [ telnet ][S]\n[ telnet ][E]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n$ echo $TMOUT\n\n------------\n \n[ Common /etc/profile Setting ]\n \n[ Common login Setting ]\n \n[ All Users ..*profile Setting ]\n \n[ Common .profile Setting ]\n \n[ Common .login Setting ]\n \n[ All Users .login Setting ]\n \n[ Common shrc Setting ]\n \n[ All Users shrc Setting ]\n \n[ Current User Setting ]\n \n[ Current User Environment Variables ]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n-e [ ssh|ssh-server ][S]\n$ cat /etc/services | egrep ssh|ssh-server\n-e \n-e ssh\t\t22/tcp\t\t\t\t# SSH Remote Login Protocol\n$ netstat -an 2>&1\n-e \ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     \ntcp6       0      0 :::22                   :::*                    LISTEN     \n$ ps -ef | egrep sshd\n-e root        3931       1  0 00:49 ?        00:00:00 [sshd] <defunct>\nroot        9560       1  0 00:49 ?        00:00:00 [sshd] <defunct>\nroot       15193       1  0 00:49 ?        00:00:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups\n$ ps auxwww | egrep sshd\n-e root        3931  0.0  0.0      0     0 ?        Zs   00:49   0:00 [sshd] &lt;defunct&gt;\nroot        9560  0.0  0.0      0     0 ?        Zs   00:49   0:00 [sshd] &lt;defunct&gt;\nroot       15193  0.0  0.0  12048  2892 ?        Ss   00:49   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups\n[ ssh|ssh-server ][E]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n$ /etc/ssh/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\n#ClientAliveInterval 0\n#ClientAliveCountMax 3\nClientAliveInterval 300\nClientAliveCountMax 0\n------------\n$ /opt/ssh/etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /opt/ssh/etc/sshd_config: No such file or directory\n------------\n$ /etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /etc/sshd_config: No such file or directory\n------------\n$ /usr/local/etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /usr/local/etc/sshd_config: No such file or directory\n------------\n$ /usr/local/sshd/etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /usr/local/sshd/etc/sshd_config: No such file or directory\n------------\n$ /usr/local/ssh/etc/sshd_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\ncat: /usr/local/ssh/etc/sshd_config: No such file or directory\n------------\n$ /etc/ssh/ssh_config | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"\n------------\n\t\t\t\t'
)

# SRV-034: Automount 서비스 — inactive→양호, active→취약
# check_SRV_034: get_check_service(output, 'automountd|autofs')
_SRV_034_GOOD = "-e [ automountd|autofs ][S]\n[ automountd|autofs ][E]\n$ ps\n"
_SRV_034_VULN = "-e [ automountd|autofs ][S]\nautomountd 1234 root\n[ automountd|autofs ][E]\n"

# SRV-035: 불필요 서비스 목록 — 전부 없으면 양호, 하나라도 있으면 취약
# check_SRV_035: get_check_service(output, service) for services
_SRV_035_GOOD = "$ ps -ef\nroot /usr/sbin/sshd\n"  # 특정 취약 서비스 없음
_SRV_035_VULN = (
    # tftp 서비스 있음 → 취약
    "-e [ tftp ][S]\ntftpd 1234 root\n[ tftp ][E]\n"
)

# SRV-037: FTP 서비스 — inactive→양호, active→취약
# check_SRV_037: get_check_service(output, 'ftp')
_SRV_037_GOOD = "-e [ ftp ][S]\n[ ftp ][E]\n"
_SRV_037_VULN = "-e [ ftp ][S]\nvsftpd 1234 root\n[ ftp ][E]\n"

# SRV-062: DNS 서비스 + named.conf version 설정
# check_SRV_062: split_output(output, 2), options_dict_from_script_output
_SRV_062_GOOD = (
    # DNS 없음 → 양호
    "-e [ dns ][S]\n[ dns ][E]\n"
    f"{D}\n"
    "# named.conf empty\n"
)
_SRV_062_VULN = (
    # DNS 있음 + version 없음 → 취약
    "-e [ dns ][S]\nnamed 1234 root\n[ dns ][E]\n"
    f"{D}\n"
    "$ cat /etc/named.conf\n"
    "options {\n"
    "    recursion no;\n"
    "};\n"
)

# SRV-070: /etc/passwd 파일 내 패스워드 hash 존재 여부
# check_SRV_070: 정규식으로 hash 필드 길이 > 15 검사
_SRV_070_GOOD = (
    "$ cat /etc/passwd\n"
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
)
_SRV_070_VULN = (
    "$ cat /etc/passwd\n"
    "root:$6$abcdefghij$XYZabcdefghijk1234567890:0:0:root:/root:/bin/bash\n"
)

# SRV-081: Cron 파일 권한 — 3섹션(cron파일/at제어파일/cron제어파일)
# check_SRV_081: split_output(output, 3), 파일 권한 검사
_SRV_081_GOOD = (
    # 섹션1: cron 작업 파일 권한 양호 (others r/w 없음 — 640 이하)
    "$ ls -alL /etc/cron* /var/spool/cron/*\n"
    "-rw-r-----  1 root root 1024 Jan 1 00:00 /etc/crontab\n"
    "-rw-r-----  1 root root  512 Jan 1 00:00 /etc/cron.d/daily\n"
    f"{D}\n"
    # 섹션2: at 제어 파일 (소유자 root, 권한 640 이하)
    "$ ls -alL /etc/at.allow /etc/at.deny\n"
    "-rw-r-----  1 root root  100 Jan 1 00:00 /etc/at.allow\n"
    f"{D}\n"
    # 섹션3: cron allow/deny 파일 권한 (소유자 root, 권한 640 이하)
    "$ ls -alL /etc/cron.allow /etc/cron.deny\n"
    "-rw-r-----  1 root root  100 Jan 1 00:00 /etc/cron.allow\n"
)
_SRV_081_VULN = (
    # 섹션1: cron 파일 others write 있음 → 취약
    "$ ls -alL /etc/cron.d/\n"
    "-rw-rw-rw-  1 root root 1024 Jan 1 00:00 /etc/crontab\n"
    f"{D}\n"
    "$ ls -alL /etc/at.allow\n"
    "-rw-r-----  1 root root  100 Jan 1 00:00 /etc/at.allow\n"
    f"{D}\n"
    "$ ls -alL /etc/cron.allow\n"
    "-rw-r-----  1 root root  100 Jan 1 00:00 /etc/cron.allow\n"
)

# SRV-082: 시스템 주요 디렉터리 others 쓰기 권한
# check_SRV_082: 파일권한 패턴, 디렉터리만, others w 비트
_SRV_082_GOOD = (
    "$ ls -alLd /usr /bin /sbin /etc /var\n"
    "drwxr-xr-x  2 root root 4096 Jan  1 00:00 /etc\n"
    "drwxr-xr-x 12 root root 4096 Jan  1 00:00 /usr\n"
)
_SRV_082_VULN = (
    "$ ls -alLd /tmp/vuln\n"
    "drwxrwxrwx  2 root root 4096 Jan  1 00:00 /tmp/vuln\n"
)

# SRV-083: 스타트업 스크립트 others 쓰기 권한
# check_SRV_083: 파일권한 패턴, 파일만, others w 비트
_SRV_083_GOOD = (
    "$ ls -alL /etc/rc.d/\n"
    "-rwxr-xr-x  1 root root 1024 Jan 1 00:00 /etc/rc.d/rc.local\n"
    "-rwxr-xr-x  1 root root  512 Jan 1 00:00 /etc/init.d/sshd\n"
)
_SRV_083_VULN = (
    "$ ls -alL /etc/rc.d/\n"
    "-rwxrwxrwx  1 root root 1024 Jan 1 00:00 /etc/rc.d/rc.local\n"
)

# SRV-084: 시스템 파일 권한 — /etc/passwd(644), /etc/shadow(600), /etc/hosts(644) 등
# check_SRV_084: 각 파일 경로별 권한 검사
_SRV_084_GOOD = (
    "$ ls -alL /etc/passwd /etc/shadow /etc/hosts /etc/inetd.conf /etc/syslog.conf /etc/services\n"
    "-rw-r--r--  1 root root  2048 Jan 1 00:00 /etc/passwd\n"
    "-rw-------  1 root root  1024 Jan 1 00:00 /etc/shadow\n"
    "-rw-r--r--  1 root root   220 Jan 1 00:00 /etc/hosts\n"
    "-rw-------  1 root root   512 Jan 1 00:00 /etc/inetd.conf\n"
    "-rw-r--r--  1 root root   128 Jan 1 00:00 /etc/syslog.conf\n"
    "-rw-r--r--  1 root root 16000 Jan 1 00:00 /etc/services\n"
)
_SRV_084_VULN = (
    "$ ls -alL /etc/passwd\n"
    "-rw-rw-rw-  1 root root  2048 Jan 1 00:00 /etc/passwd\n"
)

# SRV-087: 컴파일러 others 실행 권한
# check_SRV_087: 파일권한 패턴, others x 비트
_SRV_087_GOOD = (
    "$ ls -alL /usr/bin/gcc /usr/bin/g++\n"
    "-rwxr-xr--  1 root root 1024 Jan 1 00:00 /usr/bin/gcc\n"
)
_SRV_087_VULN = (
    "$ ls -alL /usr/bin/gcc\n"
    "-rwxr-xr-x  1 root root 1024 Jan 1 00:00 /usr/bin/gcc\n"
)

# SRV-092: 홈 디렉터리 — 소유자 불일치/중복/others write 권한
# check_SRV_092: split_output(output, 3), 3섹션 검사
_SRV_092_GOOD = (
    # 섹션1: UID/홈디렉터리 소유자 일치 (스크립트 결과 비어있음)
    "$ find /home -maxdepth 1 -type d\n"
    f"{D}\n"
    # 섹션2: /etc/passwd 파싱 (uid>=1000 중복 홈 없음)
    "$ cat /etc/passwd\n"
    "appuser:x:1001:1001::/home/appuser:/bin/bash\n"
    "daemon:x:2:2:Daemon:/usr/sbin:/usr/sbin/nologin\n"
    f"{D}\n"
    # 섹션3: 홈 디렉터리 others write 없음
    "$ ls -ald /home/appuser\n"
    "drwxr-xr-x  3 appuser appuser 4096 Jan 1 00:00 /home/appuser\n"
)
_SRV_092_VULN = (
    # 섹션1: 비어있음
    "$ find /home\n"
    f"{D}\n"
    # 섹션2: /etc/passwd — 동일 uid 중복 없음
    "$ cat /etc/passwd\n"
    "appuser:x:1001:1001::/home/appuser:/bin/bash\n"
    f"{D}\n"
    # 섹션3: 홈 디렉터리 others write 있음 → 취약
    "$ ls -ald /home/appuser\n"
    "drwxrwxrwx  3 appuser appuser 4096 Jan 1 00:00 /home/appuser\n"
)

# SRV-093: 스크립트/로그 파일 others 쓰기 권한
# check_SRV_093: 파일권한 패턴, 파일만, others w 비트
_SRV_093_GOOD = (
    "$ ls -alL /etc/profile.d/\n"
    "-rw-r--r--  1 root root  512 Jan 1 00:00 /etc/profile.d/lang.sh\n"
)
_SRV_093_VULN = (
    "$ ls -alL /etc/profile.d/\n"
    "-rw-rw-rw-  1 root root  512 Jan 1 00:00 /etc/profile.d/vuln.sh\n"
)

# SRV-094: Cron 작업 참조 파일 others 쓰기 권한
# check_SRV_094: 파일권한 패턴, 파일만, others w 비트
_SRV_094_GOOD = (
    "$ ls -alL /usr/local/bin/backup.sh\n"
    "-rwxr-xr--  1 root root  512 Jan 1 00:00 /usr/local/bin/backup.sh\n"
)
_SRV_094_VULN = (
    "$ ls -alL /usr/local/bin/backup.sh\n"
    "-rwxrwxrwx  1 root root  512 Jan 1 00:00 /usr/local/bin/backup.sh\n"
)

# SRV-095: 존재하지 않는 UID/GID 소유자 파일 — 파일 있으면 취약
# check_SRV_095: 파일권한 패턴 (permission != "----------" 이면 취약)
_SRV_095_GOOD = (
    "$ find / -nouser -o -nogroup\n"
    "# no output (no orphan files)\n"
    "----------  0 0 0 0 Jan 1 00:00 (placeholder)\n"  # ---------- 라인은 무시
)
_SRV_095_VULN = (
    "$ find / -nouser -o -nogroup\n"
    "-rw-r--r--  1 9999 9999  512 Jan 1 00:00 /tmp/orphan_file\n"
)

# SRV-096: 사용자 환경 설정 파일 others r/w/x 권한
# check_SRV_096: file_path.endswith(('.profile', '.login', 'shrc')), others r|w|x
_SRV_096_GOOD = (
    "$ ls -alL /home/appuser/.profile /home/appuser/.bashrc\n"
    "-rw-r-----  1 appuser appuser  200 Jan 1 00:00 /home/appuser/.profile\n"
    "-rw-r-----  1 appuser appuser  512 Jan 1 00:00 /home/appuser/.bashrc\n"
)
_SRV_096_VULN = (
    "$ ls -alL /home/appuser/.profile\n"
    "-rw-r--r--  1 appuser appuser  200 Jan 1 00:00 /home/appuser/.profile\n"
)

# SRV-108: 로그 파일 권한 — 644/660/664 기준
# check_SRV_108: file_path 기반 btmp(660)/wtmp,lastlog(664)/기타(644)
_SRV_108_GOOD = (
    "$ ls -alL /var/log/messages /var/log/btmp /var/log/wtmp /var/log/lastlog\n"
    "-rw-r--r--  1 root root 102400 Jan 1 00:00 /var/log/messages\n"
    "-rw-rw----  1 root utmp   1024 Jan 1 00:00 /var/log/btmp\n"
    "-rw-rw-r--  1 root utmp   8192 Jan 1 00:00 /var/log/wtmp\n"
    "-rw-rw-r--  1 root utmp 292292 Jan 1 00:00 /var/log/lastlog\n"
)
_SRV_108_VULN = (
    "$ ls -alL /var/log/messages\n"
    "-rw-rw-rw-  1 root root 102400 Jan 1 00:00 /var/log/messages\n"
)

# SRV-121: PATH 환경변수 현재 디렉터리 포함 여부
# check_SRV_121: regex '$ echo $PATH' 다음 줄에서 '.:', './', '::' 탐지
_SRV_121_GOOD = (
    "$ echo $PATH\n"
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
)
_SRV_121_VULN = (
    "$ echo $PATH\n"
    "/usr/local/bin:.:/usr/sbin:/usr/bin\n"
)

# SRV-122: umask 설정 — 022 이상→양호, 022 미만→취약
# check_SRV_122: regex '$ umask' 다음 줄 숫자, < 22 → 취약
_SRV_122_GOOD = (
    "$ umask\n"
    "022\n"
)
_SRV_122_VULN = (
    "$ umask\n"
    "000\n"
)

# SRV-133: cron allow/deny 파일 존재 여부
# check_SRV_133: $ cat /etc/cron.allow 등 탐지
# allow 존재 → 양호, deny만 있고 내용 없음 → 취약, 둘 다 없음 → 양호
_SRV_133_GOOD = (
    # cron.allow 파일 존재 → 양호
    "$ cat /etc/cron.allow\n"
    "root\n"
    "------------\n"
    "$ cat /etc/cron.deny\n"
    "anonymous\n"
    "------------\n"
)
_SRV_133_VULN = (
    # cron.allow 없음 + cron.deny 내용 없음 → 취약
    "$ cat /etc/cron.allow\n"
    "cat: /etc/cron.allow: No such file or directory\n"
    "------------\n"
    "$ cat /etc/cron.deny\n"
    "------------\n"
)

# SRV-142: UID 중복 계정 — 중복 없으면 양호, 중복 있으면 취약
# check_SRV_142: /etc/passwd 패턴, uid_map 중복 검사
_SRV_142_GOOD = (
    "$ cat /etc/passwd\n"
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "appuser:x:1001:1001::/home/appuser:/bin/bash\n"
)
_SRV_142_VULN = (
    "$ cat /etc/passwd\n"
    "root:x:0:0:root:/root:/bin/bash\n"
    "fakroot:x:0:0:fake root:/home/fakroot:/bin/bash\n"
)

# SRV-147: SNMP 서비스 — inactive→양호, active→취약
# check_SRV_147: get_check_service(output, 'snmp')
_SRV_147_GOOD = "-e [ snmp ][S]\n[ snmp ][E]\n$ ps\n"
_SRV_147_VULN = "-e [ snmp ][S]\nsnmpd 1234 root\n[ snmp ][E]\n"

# SRV-158: Telnet 서비스 — inactive→양호, active→취약
# check_SRV_158: get_check_service(output, 'telnet')
_SRV_158_GOOD = "-e [ telnet ][S]\n[ telnet ][E]\n$ ps\n"
_SRV_158_VULN = "-e [ telnet ][S]\ntelnetd 1234 root\n[ telnet ][E]\n"

# SRV-161: FTP 서비스 + ftpusers 파일 권한 (root 소유, 640 이하)
# check_SRV_161: split_output(output, 2), ftp 서비스 + 파일 권한
_SRV_161_GOOD = (
    # FTP 없음 → 양호
    "-e [ ftp ][S]\n[ ftp ][E]\n"
    f"{D}\n"
)
_SRV_161_VULN = (
    # FTP 있음 + ftpusers 권한 취약
    "-e [ ftp ][S]\nvsftpd 1234 root\n[ ftp ][E]\n"
    f"{D}\n"
    "-rw-rw-rw-  1 root root  100 Jan 1 00:00 /etc/vsftpd/ftpusers\n"
)

# SRV-164: 그룹 구성원 존재 여부 (GID>=1000)
# check_SRV_164: split_output(output, 2), /etc/passwd + /etc/group 분석
_SRV_164_GOOD = (
    # /etc/passwd 섹션 — GID 1001 사용자 appuser
    "$ cat /etc/passwd\n"
    "appuser:x:1001:1001::/home/appuser:/bin/bash\n"
    f"{D}\n"
    # /etc/group 섹션 — GID 1001 그룹에 구성원 있거나 passwd에서 확인
    "$ cat /etc/group\n"
    "appgroup:x:1001:appuser\n"
)
_SRV_164_VULN = (
    # /etc/passwd 섹션 — GID 1001 사용자 없음
    "$ cat /etc/passwd\n"
    "root:x:0:0:root:/root:/bin/bash\n"
    f"{D}\n"
    # /etc/group 섹션 — GID 1001 그룹에 구성원 없고 passwd에도 없음 → 취약
    "$ cat /etc/group\n"
    "emptygroup:x:1001:\n"
)

# SRV-170: SMTP 서비스 + 배너 버전 노출 설정
# check_SRV_170: split_output(output, 4), sendmail SmtpGreetingMessage $v 검사
_SRV_170_GOOD = (
    # SMTP 없음 → 양호
    "-e [ smtp|sendmail|postfix|exim ][S]\n[ smtp|sendmail|postfix|exim ][E]\n"
    f"{D}\n"
    f"{D}\n"
    f"{D}\n"
)
_SRV_170_VULN = (
    # sendmail 실행 + SmtpGreetingMessage에 $v 있음 → 취약
    "-e [ smtp|sendmail|postfix|exim ][S]\nsendmail 1234 root\n[ smtp|sendmail|postfix|exim ][E]\n"
    f"{D}\n"
    "O SmtpGreetingMessage=$j Sendmail $v/$Z; $b\n"
    f"{D}\n"
    f"{D}\n"
)

# SRV-174: DNS 53번 포트 — 없으면 양호, 있으면 취약
# check_SRV_174: IP:53 패턴 탐지
_SRV_174_GOOD = (
    "$ ss -lntu\n"
    "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
)
_SRV_174_VULN = (
    "$ ss -lntu\n"
    "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n"
    "192.168.1.1:53 *:*\n"
)


# ──────────────────────────────────────────────────────────────────────────────
# DET-PARTIAL: good→양호(inactive DET), vuln→(*) uncovered 항목
# (SRV-021: FTP inactive→양호, SRV-073: 의심계정 없음→양호)
# ──────────────────────────────────────────────────────────────────────────────

# SRV-021: FTP inactive→양호, FTP active→(*) 수동 (DET-PARTIAL)
# check_SRV_021: get_check_service(output, 'ftp')
_SRV_021_GOOD = "-e [ ftp ][S]\n[ ftp ][E]\n$ ps\n"
# vuln: FTP active → (*) → handled=False → uncovered

# SRV-073: 관리자 그룹 의심계정 없음→양호, 2명 이상→(*) 수동 (DET-PARTIAL)
# check_SRV_073: $ cmd 탐지 후 /etc/group 형식 파싱
# good: wheel 그룹에 root만 있음 → 양호
_SRV_073_GOOD = (
    "$ cat /etc/group\n"
    "root:x:0:root\n"
    "wheel:x:10:root\n"
    "------------\n"
)
# vuln: wheel에 2명 이상 → (*) → handled=False → uncovered


# ──────────────────────────────────────────────────────────────────────────────
# DET-PARTIAL: linux_parse 오버라이드 항목 (SRV-026/069/074/127/131)
# ──────────────────────────────────────────────────────────────────────────────

# SRV-026: linux=DET (SRV_Linux_parse) — 텔넷/SSH root 로그인 통제
# check_SRV_026(Linux): split_output(output, 3), telnet/ssh 서비스 + securetty/PermitRootLogin
#
# ── 실포맷 승격 (2026-07-11) ──────────────────────────────────────────────
# 도커 ubuntu:24.04 + fsi_unix.sh 원본 무수정 단일변수 재수집(out/srv_lab/promo/).
# sshd 실제 기동 상태(ps -ef/netstat 리스닝 등 실측 라인 포함) 유지한 채
# PermitRootLogin 값만 단일 변경(no ↔ yes)해 good/vuln 확보 — 기존 out/srv_lab
# 실측 샘플은 good=서비스 자체 비활성(inactive), vuln=PermitRootLogin+TMOUT
# 동시 변경이라 "서비스 활성 상태에서의 단일변수 검증"을 못 담았음 → 이번 재수집으로 대체.
# judge() 재검증: good→양호, vuln→취약 (verdict 플립 실확인, 아래 promo-*.xml 원본 보존).
_SRV_026_GOOD = (
    '\n-e [ telnet ][S]\n[ telnet ][E]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n-e [ ssh|ssh-server ][S]\n$ cat /etc/services | egrep ssh|ssh-server\n-e \n-e ssh\t\t22/tcp\t\t\t\t# SSH Remote Login Protocol\n$ netstat -an 2>&1\n-e \ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     \ntcp6       0      0 :::22                   :::*                    LISTEN     \n$ ps -ef | egrep sshd\n-e root        3931       1  0 00:49 ?        00:00:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups\n$ ps auxwww | egrep sshd\n-e root        3931  0.0  0.0  12048  2896 ?        Ss   00:49   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups\n[ ssh|ssh-server ][E]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n$ cat /etc/securetty | egrep -i "(ptyp1|^pts)"\ncat: /etc/securetty: No such file or directory\n------------\n$ cat /etc/pam.d/remote | egrep -i "pam_securetty.so"\ncat: /etc/pam.d/remote: No such file or directory\n------------\n$ cat /etc/pam.d/login | egrep -i "pam_securetty.so"\n------------\n$ /etc/ssh/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\n#PermitRootLogin prohibit-password\n# the setting of "PermitRootLogin prohibit-password".\nPermitRootLogin no\n------------\n$ /opt/ssh/etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /opt/ssh/etc/sshd_config: No such file or directory\n------------\n$ /etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /etc/sshd_config: No such file or directory\n------------\n$ /usr/local/etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /usr/local/etc/sshd_config: No such file or directory\n------------\n$ /usr/local/sshd/etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /usr/local/sshd/etc/sshd_config: No such file or directory\n------------\n$ /usr/local/ssh/etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /usr/local/ssh/etc/sshd_config: No such file or directory\n------------\n$ /etc/ssh/ssh_config | egrep -i "(PermitRootLogin|denyuser)"\n------------\n\t\t\t\t'
)
_SRV_026_VULN = (
    '\n-e [ telnet ][S]\n[ telnet ][E]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n-e [ ssh|ssh-server ][S]\n$ cat /etc/services | egrep ssh|ssh-server\n-e \n-e ssh\t\t22/tcp\t\t\t\t# SSH Remote Login Protocol\n$ netstat -an 2>&1\n-e \ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     \ntcp6       0      0 :::22                   :::*                    LISTEN     \n$ ps -ef | egrep sshd\n-e root        3931       1  0 00:49 ?        00:00:00 [sshd] <defunct>\nroot        9560       1  0 00:49 ?        00:00:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups\n$ ps auxwww | egrep sshd\n-e root        3931  0.0  0.0      0     0 ?        Zs   00:49   0:00 [sshd] &lt;defunct&gt;\nroot        9560  0.0  0.0  12048  2892 ?        Ss   00:49   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups\n[ ssh|ssh-server ][E]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n$ cat /etc/securetty | egrep -i "(ptyp1|^pts)"\ncat: /etc/securetty: No such file or directory\n------------\n$ cat /etc/pam.d/remote | egrep -i "pam_securetty.so"\ncat: /etc/pam.d/remote: No such file or directory\n------------\n$ cat /etc/pam.d/login | egrep -i "pam_securetty.so"\n------------\n$ /etc/ssh/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\n#PermitRootLogin prohibit-password\n# the setting of "PermitRootLogin prohibit-password".\nPermitRootLogin yes\n------------\n$ /opt/ssh/etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /opt/ssh/etc/sshd_config: No such file or directory\n------------\n$ /etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /etc/sshd_config: No such file or directory\n------------\n$ /usr/local/etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /usr/local/etc/sshd_config: No such file or directory\n------------\n$ /usr/local/sshd/etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /usr/local/sshd/etc/sshd_config: No such file or directory\n------------\n$ /usr/local/ssh/etc/sshd_config | egrep -i "(PermitRootLogin|denyuser)"\ncat: /usr/local/ssh/etc/sshd_config: No such file or directory\n------------\n$ /etc/ssh/ssh_config | egrep -i "(PermitRootLogin|denyuser)"\n------------\n\t\t\t\t'
)

# SRV-069: linux=DET (SRV_Linux_parse) — 패스워드 최대변경기간+복잡도 설정
# check_SRV_069(Linux): split_output(output, 4)
# 4섹션: Debian pam / pwquality.conf / RHEL pam / chage 정보
_SRV_069_GOOD = (
    # 섹션0: /etc/pam.d/common-password — dcredit, ucredit 설정 + minlen=8
    "password requisite pam_pwquality.so retry=3 dcredit=-1 ucredit=-1 lcredit=-1 minlen=8\n"
    f"{D}\n"
    # 섹션1: /etc/security/pwquality.conf — 빈 (PAM에서 설정됨)
    "\n"
    f"{D}\n"
    # 섹션2: /etc/pam.d/system-auth — 빈
    "\n"
    f"{D}\n"
    # 섹션3: chage 정보 — max=90 → 양호
    "$ chage -l appuser\n"
    "Last password change: Jan 01, 2026\n"
    "Password expires: Apr 01, 2026\n"
    "Password inactive: never\n"
    "Account expires: never\n"
    "Minimum number of days between password change: 0\n"
    "Maximum number of days between password change: 90\n"
    "Number of days of warning before password expires: 7\n"
    "------------\n"
)
_SRV_069_VULN = (
    # 섹션0: pam — 복잡도 설정 없음
    "# no pwquality config\n"
    f"{D}\n"
    # 섹션1: pwquality.conf — 빈
    "\n"
    f"{D}\n"
    # 섹션2: system-auth — 빈
    "\n"
    f"{D}\n"
    # 섹션3: chage 정보 — max=99999 → 취약
    "$ chage -l baduser\n"
    "Last password change: Jan 01, 2026\n"
    "Password expires: never\n"
    "Password inactive: never\n"
    "Account expires: never\n"
    "Minimum number of days between password change: 0\n"
    "Maximum number of days between password change: 99999\n"
    "Number of days of warning before password expires: 7\n"
    "------------\n"
)

# SRV-074: linux=DET (SRV_Linux_parse) — 미사용/장기간 비로그인 계정
# check_SRV_074(Linux): split_output(output, 3)
# 3섹션: /etc/shadow epoch / /etc/passwd shell / lastlog 정보
# 취약 조건: epochDays - lastChangeDays > 90 또는 "never logged in" (non-root 계정)
_SRV_074_GOOD = (
    # 섹션0: shadow epoch — 최근 변경 (10일 전)
    "$ awk -F\":\" '{print $1 \"\\t\\t\" $3}' /etc/shadow\n"
    "daemon\t\t20000\n"  # nologin shell → 무시됨
    f"{D}\n"
    # 섹션1: passwd shell — 쉘 계정 없음(모두 nologin)
    "$ awk -F\":\" '{print $1 \"\\t\\t\" $7}' /etc/passwd\n"
    "root\t\t/usr/sbin/nologin\n"
    "daemon\t\t/usr/sbin/nologin\n"
    f"{D}\n"
    # 섹션2: lastlog — 빈 (shell 계정 없으므로 검사 안 함)
    "$ last -10 root\n\nwtmp begins Mon Jun 15 07:10:57 2026\n------------\n"
    "$ lastlog -u root\nUsername         Port     From             Latest\n"
    "root                                       **Never logged in**\n------------"
)
_SRV_074_VULN = {
    "uncovered": True,
    "uncovered_reason": (
        "SRV-074 vuln: epochDays 계산이 실행 시점에 의존(90일 초과 기준). "
        "합성 epoch 값이 현재 날짜와 연동되어야 하므로 정적 픽스처로 안정적 취약 유발 불가. "
        "good→양호 단방향 커버만 수행."
    ),
}

# SRV-127: linux=DET (SRV_Linux_parse) — 계정잠금 임계값(pam_faillock/tally)
# check_SRV_127(Linux): auth required pam_faillock.so deny=N + account required
_SRV_127_GOOD = (
    "$ grep auth /etc/pam.d/system-auth\n"
    "auth required pam_faillock.so preauth silent deny=5 unlock_time=900\n"
    "auth required pam_faillock.so authfail deny=5 unlock_time=900\n"
    "------------\n"
    "$ grep auth /etc/pam.d/password-auth\n"
    "auth required pam_faillock.so preauth silent deny=5 unlock_time=900\n"
    "------------\n"
    "$ grep account /etc/pam.d/system-auth\n"
    "account required pam_faillock.so\n"
    "------------\n"
    "$ grep account /etc/pam.d/password-auth\n"
    "account required pam_faillock.so\n"
    "------------\n"
)
_SRV_127_VULN = (
    # auth 설정 없음 → 취약
    "$ grep auth /etc/pam.d/system-auth\n"
    "# no pam_faillock configuration\n"
    "------------\n"
    "$ grep account /etc/pam.d/system-auth\n"
    "# no pam_faillock configuration\n"
    "------------\n"
)

# SRV-131: linux=DET (SRV_Linux_parse) — su 접근 제한(pam_wheel)
# check_SRV_131(Linux): split_output(output, 3), auth required pam_wheel.so
_SRV_131_GOOD = (
    # 섹션0: su 서비스 블록 (존재 여부 확인용)
    "-e [ su ][S]\n$ which su\n/usr/bin/su\n[ su ][E]\n"
    f"{D}\n"
    # 섹션1: /etc/pam.d/su pam_wheel 설정
    "$ cat /etc/pam.d/su\n"
    "auth required pam_wheel.so use_uid\n"
    "------------\n"
    f"{D}\n"
    # 섹션2: wheel 그룹 구성원
    "$ grep wheel /etc/group\n"
    "wheel:x:10:admin\n"
)
_SRV_131_VULN = (
    # 섹션0: su 서비스 블록
    "-e [ su ][S]\n$ which su\n/usr/bin/su\n[ su ][E]\n"
    f"{D}\n"
    # 섹션1: pam_wheel 미설정 → 취약
    "$ cat /etc/pam.d/su\n"
    "# no pam_wheel configuration\n"
    "------------\n"
    f"{D}\n"
    # 섹션2: wheel 그룹
    "$ grep wheel /etc/group\n"
    "wheel:x:10:\n"
)


# ──────────────────────────────────────────────────────────────────────────────
# DET-PARTIAL: 서비스 inactive→양호 경로 항목
# 서비스 inactive → result='N' → 양호(DET)
# 서비스 active → (*) 수동 → Low-1 가드 → handled=False
# ──────────────────────────────────────────────────────────────────────────────

# SRV-005: SMTP inactive → 양호 (DET-PARTIAL 서비스inactive경로)
_SRV_005_INACTIVE_GOOD = (
    "-e [ smtp|sendmail|postfix|exim ][S]\n[ smtp|sendmail|postfix|exim ][E]\n"
    f"{D}\n"
    f"{D}\n"
)

# SRV-006: SMTP inactive → 양호 (DET-PARTIAL)
_SRV_006_INACTIVE_GOOD = (
    "-e [ smtp|sendmail|postfix|exim ][S]\n[ smtp|sendmail|postfix|exim ][E]\n"
    f"{D}\n"
    f"{D}\n"
    f"{D}\n"
)

# SRV-007: SMTP inactive → 양호 (DET-PARTIAL)
#
# ── 실포맷 정정 (2026-07-11 발견·수정) ──────────────────────────────────
# 버그: 기존 합성 fixture는 delimiter 1개(2섹션)뿐이었으나 check_SRV_007은
# split_output(output, 4) — 최소 3개 delimiter(4섹션) 필요. 부족분 split은
# split_output()이 빈 리스트를 반환 → "(*) 수동 판단 필요: 출력 데이터가
# 예상된 형식으로 분리되지 않았습니다" 경로로 빠져 handled=False가 됨.
# 결과: 이 테스트는 SRV-007의 실제 "서비스 비활성→양호" 분기를 전혀 실행하지
# 않은 채 handled=False→skip 처리로만 통과해 왔음(거짓양호는 아니나 미검증 갭).
# out/srv_lab 실측 XML(SRV-007, 서비스 비활성) 기준 3-delimiter 구조로 교체.
_SRV_007_INACTIVE_GOOD = (
    '\n-e [ smtp|sendmail|postfix|exim ][S]\n[ smtp|sendmail|postfix|exim ][E]\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n$ sendmail -d0.1 &lt; /dev/null | grep -i version\n./fsi_unix.sh: 1139: sendmail: not found\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n$ postconf -d mail_version\n./fsi_unix.sh: 1149: postconf: not found\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n$ exim -bV\n./fsi_unix.sh: 1152: exim: not found\n\t\t\t\t'
)

# SRV-013: FTP inactive → 양호 (DET-PARTIAL)
_SRV_013_INACTIVE_GOOD = (
    "-e [ ftp ][S]\n[ ftp ][E]\n"
    f"{D}\n"
)

# SRV-014: NFS inactive → 양호 (DET-PARTIAL)
_SRV_014_INACTIVE_GOOD = (
    "-e [ nfs ][S]\n[ nfs ][E]\n"
    f"{D}\n"
    f"{D}\n"
)

# SRV-064: DNS inactive → 양호 (DET-PARTIAL)
_SRV_064_INACTIVE_GOOD = (
    "-e [ dns ][S]\n[ dns ][E]\n"
    f"{D}\n"
)


# ──────────────────────────────────────────────────────────────────────────────
# 통합 딕셔너리 — linux variant 기준
# ──────────────────────────────────────────────────────────────────────────────

SRV_COV: dict[str, dict] = {
    # ── 순수 DET 항목 ──────────────────────────────────────────────────────────
    "SRV-001": {
        "good": _SRV_001_GOOD,
        "vuln": _SRV_001_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "SNMP inactive→양호, v1/v2 설정→취약",
    },
    "SRV-004": {
        "good": _SRV_004_GOOD,
        "vuln": _SRV_004_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "SMTP 서비스 존재→취약",
    },
    "SRV-008": {
        "good": _SRV_008_GOOD,
        "vuln": _SRV_008_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "SMTP inactive→양호, sendmail maxdaemonchildren=0→취약",
    },
    "SRV-010": {
        "good": _SRV_010_GOOD,
        "vuln": _SRV_010_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "sendmail restrictqrun 존재→양호, 없음→취약(버그수정 회귀)",
    },
    "SRV-011": {
        "good": _SRV_011_GOOD,
        "vuln": _SRV_011_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "FTP inactive→양호, ftpusers root 없음→취약",
    },
    "SRV-012": {
        "good": _SRV_012_GOOD,
        "vuln": _SRV_012_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "FTP inactive→양호, FTP active+.netrc 권한취약→취약. "
            "FTP active+.netrc 권한양호 경로는 (*)→handled=False(미커버)."
        ),
    },
    "SRV-015": {
        "good": _SRV_015_GOOD,
        "vuln": _SRV_015_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "NFS inactive→양호, active→취약",
    },
    "SRV-016": {
        "good": _SRV_016_GOOD,
        "vuln": _SRV_016_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "RPC 서비스 없음→양호, rusers 있음→취약",
    },
    "SRV-025": {
        "good": _SRV_025_GOOD,
        "vuln": _SRV_025_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "r계열 모두 없음→양호, rlogin+hosts.equiv '+'→취약",
    },
    "SRV-028": {
        "good": _SRV_028_GOOD,
        "vuln": _SRV_028_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "telnet/ssh 없음→양호, telnet있고 TMOUT 없음→취약",
    },
    "SRV-034": {
        "good": _SRV_034_GOOD,
        "vuln": _SRV_034_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "automount inactive→양호, active→취약",
    },
    "SRV-035": {
        "good": _SRV_035_GOOD,
        "vuln": _SRV_035_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "불필요 서비스 없음→양호, tftp 있음→취약",
    },
    "SRV-037": {
        "good": _SRV_037_GOOD,
        "vuln": _SRV_037_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "FTP inactive→양호, active→취약",
    },
    "SRV-062": {
        "good": _SRV_062_GOOD,
        "vuln": _SRV_062_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "DNS inactive→양호, DNS active+version 없음→취약",
    },
    "SRV-070": {
        "good": _SRV_070_GOOD,
        "vuln": _SRV_070_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "/etc/passwd hash 없음→양호, hash 있음→취약",
    },
    "SRV-081": {
        "good": _SRV_081_GOOD,
        "vuln": _SRV_081_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "cron 파일 others 권한 없음→양호, 있음→취약(3섹션 중 섹션1)",
    },
    "SRV-082": {
        "good": _SRV_082_GOOD,
        "vuln": _SRV_082_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "시스템 디렉터리 others w 없음→양호, 있음→취약",
    },
    "SRV-083": {
        "good": _SRV_083_GOOD,
        "vuln": _SRV_083_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "스타트업 스크립트 others w 없음→양호, 있음→취약",
    },
    "SRV-084": {
        "good": _SRV_084_GOOD,
        "vuln": _SRV_084_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "시스템 파일 권한 양호(644/600 기준), /etc/passwd world-write→취약",
    },
    "SRV-087": {
        "good": _SRV_087_GOOD,
        "vuln": _SRV_087_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "컴파일러 others x 없음→양호, 있음→취약",
    },
    "SRV-092": {
        "good": _SRV_092_GOOD,
        "vuln": _SRV_092_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "홈 디렉터리 others w 없음→양호, 있음→취약(3섹션)",
    },
    "SRV-093": {
        "good": _SRV_093_GOOD,
        "vuln": _SRV_093_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "스크립트/로그 파일 others w 없음→양호, 있음→취약",
    },
    "SRV-094": {
        "good": _SRV_094_GOOD,
        "vuln": _SRV_094_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "cron 참조 파일 others w 없음→양호, 있음→취약",
    },
    "SRV-095": {
        "good": _SRV_095_GOOD,
        "vuln": _SRV_095_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "존재하지 않는 UID/GID 소유 파일 없음→양호, 있음→취약",
    },
    "SRV-096": {
        "good": _SRV_096_GOOD,
        "vuln": _SRV_096_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": ".profile others 읽기 없음→양호, 있음→취약",
    },
    "SRV-108": {
        "good": _SRV_108_GOOD,
        "vuln": _SRV_108_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "로그 파일 권한 644/660/664 기준 양호, world-write→취약",
    },
    "SRV-121": {
        "good": {
            "uncovered": True,
            "uncovered_reason": (
                "SRV-121 good: result='N'이라도 '(*) 다른 프로파일 수동 확인 필요' 부기로 "
                "Low-1 가드 발동 → handled=False(판단보류). "
                "good 양호 경로는 항상 (*) 동반 — 단방향 커버 불가. vuln→취약만 커버."
            ),
        },
        "vuln": _SRV_121_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "PATH '.:'탐지→취약(DET). good은 항상 (*) 부기→handled=False. "
            "vuln 단방향만 커버."
        ),
    },
    "SRV-122": {
        "good": {
            "uncovered": True,
            "uncovered_reason": (
                "SRV-122 good: umask>=022라도 '(*) 다른 프로파일 수동 확인 필요' 부기로 "
                "Low-1 가드 발동 → handled=False(판단보류). "
                "good 양호 경로는 항상 (*) 동반 — 단방향 커버 불가. vuln→취약만 커버."
            ),
        },
        "vuln": _SRV_122_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "umask<22→취약(DET). good은 항상 (*) 부기→handled=False. "
            "vuln 단방향만 커버."
        ),
    },
    "SRV-133": {
        "good": _SRV_133_GOOD,
        "vuln": _SRV_133_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "cron.allow 존재→양호, cron.deny만+내용없음→취약",
    },
    "SRV-142": {
        "good": _SRV_142_GOOD,
        "vuln": _SRV_142_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "UID 중복 없음→양호, root UID 중복→취약",
    },
    "SRV-147": {
        "good": _SRV_147_GOOD,
        "vuln": _SRV_147_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "SNMP inactive→양호, active→취약",
    },
    "SRV-158": {
        "good": _SRV_158_GOOD,
        "vuln": _SRV_158_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "Telnet inactive→양호, active→취약",
    },
    "SRV-161": {
        "good": _SRV_161_GOOD,
        "vuln": _SRV_161_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "FTP inactive→양호, FTP active+ftpusers 권한취약→취약",
    },
    "SRV-164": {
        "good": _SRV_164_GOOD,
        "vuln": _SRV_164_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "GID>=1000 그룹에 구성원 있음→양호, 없음→취약",
    },
    "SRV-170": {
        "good": _SRV_170_GOOD,
        "vuln": _SRV_170_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "SMTP inactive→양호, sendmail banner $v→취약",
    },
    "SRV-174": {
        "good": _SRV_174_GOOD,
        "vuln": _SRV_174_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "DNS 53번 포트 없음→양호, 있음→취약",
    },

    # ── DET-PARTIAL(linux-override) 항목 ──────────────────────────────────────
    "SRV-026": {
        "good": _SRV_026_GOOD,
        "vuln": _SRV_026_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "linux: SRV_Linux_parse. telnet/ssh 없음→양호, SSH PermitRootLogin yes→취약",
    },
    "SRV-069": {
        "good": _SRV_069_GOOD,
        "vuln": _SRV_069_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "linux: SRV_Linux_parse. dcredit+ucredit+lcredit+minlen=8 복잡도3+길이8→양호. "
            "복잡도0+max=99999→취약."
        ),
    },
    "SRV-074": {
        "good": _SRV_074_GOOD,
        "vuln": {  # vuln측은 별도로 uncovered 처리
            "uncovered": True,
            "uncovered_reason": (
                "SRV-074 vuln: epochDays 계산이 실행 시점에 의존. "
                "정적 픽스처로 '90일 초과' 취약 유발 시 CI 날짜 의존성 발생. "
                "good→양호 단방향 커버만 수행."
            ),
        },
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "linux: SRV_Linux_parse. 쉘 계정 없음(nologin만)→취약 없음→양호. "
            "vuln은 epochDays 의존성으로 uncovered."
        ),
    },
    "SRV-127": {
        "good": _SRV_127_GOOD,
        "vuln": _SRV_127_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "linux: SRV_Linux_parse. pam_faillock deny=5 + account required→양호, 없음→취약",
    },
    "SRV-131": {
        "good": _SRV_131_GOOD,
        "vuln": _SRV_131_VULN,
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "linux: SRV_Linux_parse. pam_wheel.so 설정→양호, 없음→취약",
    },

    # ── DET-PARTIAL: 서비스 inactive 경로 항목 (good 단방향) ──────────────────
    # 서비스 inactive → result='N' → 양호. 서비스 active → (*) 수동 → handled=False.
    # good(inactive)→양호, vuln은 active시 (*)→handled=False이므로 uncovered.
    "SRV-005": {
        "good": _SRV_005_INACTIVE_GOOD,
        "vuln": {
            "uncovered": True,
            "uncovered_reason": (
                "SRV-005: sendmail active→noexpn/novfry DET, postfix/exim active→(*) 수동. "
                "취약 경로 합성이 서비스 타입에 따라 다름. inactive→양호 단방향만 커버."
            ),
        },
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
    "SRV-006": {
        "good": _SRV_006_INACTIVE_GOOD,
        "vuln": {
            "uncovered": True,
            "uncovered_reason": "SRV-006: postfix(*) 경로 DET-PARTIAL. inactive→양호 단방향만 커버.",
        },
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
    "SRV-007": {
        "good": _SRV_007_INACTIVE_GOOD,
        "vuln": {
            "uncovered": True,
            "uncovered_reason": "SRV-007: SMTP active→(*) 패치버전 수동. inactive→양호 단방향만 커버.",
        },
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
    "SRV-013": {
        "good": _SRV_013_INACTIVE_GOOD,
        "vuln": {
            "uncovered": True,
            "uncovered_reason": "SRV-013: FTP active+anonymous 불분명시 (*) 수동. inactive→양호 단방향만.",
        },
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
    "SRV-014": {
        "good": _SRV_014_INACTIVE_GOOD,
        "vuln": {
            "uncovered": True,
            "uncovered_reason": "SRV-014: NFS 접근통제 적절성 (*) 수동경로. inactive→양호 단방향만.",
        },
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
    "SRV-064": {
        "good": _SRV_064_INACTIVE_GOOD,
        "vuln": {
            "uncovered": True,
            "uncovered_reason": "SRV-064: DNS active→패치버전 수동(*). inactive→양호 단방향만.",
        },
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # ── DET-PARTIAL: good→양호(DET), vuln→(*)→uncovered ─────────────────────
    # SRV-021: FTP inactive→양호(DET), FTP active→(*) 수동→handled=False
    "SRV-021": {
        "good": _SRV_021_GOOD,
        "vuln": {
            "uncovered": True,
            "uncovered_reason": "SRV-021: FTP active→(*) 수동경로. inactive→양호 단방향만 커버.",
        },
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "FTP inactive→양호, FTP active→(*)→handled=False",
    },

    # SRV-073: 관리자그룹 의심계정 없음→양호(DET), 2명이상→(*)→handled=False
    "SRV-073": {
        "good": _SRV_073_GOOD,
        "vuln": {
            "uncovered": True,
            "uncovered_reason": (
                "SRV-073: wheel 그룹 2명 이상 → (*) 수동경로 → handled=False. "
                "의심 계정 판단은 수동. good(wheel에 root만)→양호 단방향만 커버."
            ),
        },
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "관리자 그룹 의심계정 없음→양호, 2명 이상→(*)→handled=False",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# MANUAL/ABSENT 확인 항목 (양극성 대상 아님, handled=False 확인)
# ──────────────────────────────────────────────────────────────────────────────

MANUAL_HOLD_ITEMS = [
    # (item_id, variant, note)
    ("SRV-022", "linux", "MANUAL: 해시크랙 필요 (label C)"),
    ("SRV-027", "linux", "MANUAL: 수동 판단 필요 (label A LLM)"),
    ("SRV-075", "linux", "MANUAL: 해시크랙 필요 (label C)"),
    ("SRV-091", "linux", "MANUAL: SUID/SGID 수동 판단 (label A LLM)"),
    ("SRV-109", "linux", "MANUAL: syslog 설정 수동 확인 (label B 인터뷰)"),
    ("SRV-112", "linux", "MANUAL: cron 로그 수동 확인 (label B)"),
    ("SRV-115", "linux", "MANUAL: 로그 검토 수동 (label B)"),
    ("SRV-118", "linux", "MANUAL: 보안패치 인터뷰 (label B)"),
    ("SRV-144", "linux", "MANUAL: /dev 파일 수동 판단 (label A LLM)"),
    ("SRV-163", "linux", "MANUAL: 사용 주의사항 출력 수동 (label A LLM)"),
    ("SRV-165", "linux", "MANUAL: 쉘 계정 수동 판단 (항상 (*))"),
    ("SRV-166", "linux", "MANUAL: 숨김 파일 수동 판단 (항상 (*))"),
    ("SRV-175", "linux", "MANUAL: NTP 수동 확인"),
    # DET-PARTIAL 서비스active→수동 경로: handled=False 확인
    # SRV-021/073: SRV_COV에서 good→양호 커버, vuln uncovered 처리(여기선 제외)
    ("SRV-063", "linux", "DET-PARTIAL: DNS active+options탐지실패→(*)→handled=False"),
    ("SRV-066", "linux", "DET-PARTIAL: DNS active+options탐지실패→(*)→handled=False"),
    ("SRV-171", "linux", "DET-PARTIAL: FTP active→(*)→handled=False"),
    ("SRV-173", "linux", "DET-PARTIAL: DNS active→(*)→handled=False"),
    # ABSENT 항목 (비linux 변형에서 DET-PARTIAL linux-override가 MANUAL)
    ("SRV-026", "aix",   "DET-PARTIAL linux-override: aix=MANUAL → handled=False"),
    ("SRV-069", "aix",   "DET-PARTIAL linux-override: aix=MANUAL → handled=False"),
]
