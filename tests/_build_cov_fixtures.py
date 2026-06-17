"""LLM-production 항목 양극성 커버리지 픽스처 생성기 (1회성).
원본 linux-s-{sample,vuln}.xml 보존 → cov-{good,vuln}.xml 생성.
각 label-A 항목에 cov-good=명확한 양호, cov-vuln=명확한 취약 증거를 주입.
"""
import re
import os

BASE = "collected/server/linux"
GOOD_SRC = f"{BASE}/linux-s-sample.xml"
VULN_SRC = f"{BASE}/linux-s-vuln.xml"
GOOD_OUT = f"{BASE}/linux-s-cov-good.xml"
VULN_OUT = f"{BASE}/linux-s-cov-vuln.xml"

# ── 양호(cov-good) 주입 본문 ──
GOOD = {
    "SRV-006": """-e [ smtp|sendmail|postfix|exim ][S]
root  742  0.0  0.1  12345  6789 ?  Ss  10:10  0:00 /usr/sbin/sendmail-mta -bd -q1h
[ smtp|sendmail|postfix|exim ][E]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ cat /etc/mail/sendmail.cf | grep LogLevel | grep -v grep
O LogLevel=9
------------""",
    "SRV-027": """$ firewall-cmd --list-all
fsi.sh: 1500: firewall-cmd: not found
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ ls -aldL /etc/hosts.allow
-rw-r--r-- 1 root root 64 Jun 15 10:10 /etc/hosts.allow
$ cat /etc/hosts.allow
sshd: 10.10.0.0/24
ALL: 127.0.0.1
------------
$ ls -aldL /etc/hosts.deny
-rw-r--r-- 1 root root 32 Jun 15 10:10 /etc/hosts.deny
$ cat /etc/hosts.deny
ALL: ALL
------------""",
    "SRV-081": """$ ls -alLd /usr/bin/crontab
-rwxr-x--- 1 root root 43568 Mar  6 16:10 /usr/bin/crontab
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ ls -aldL /etc/at.allow
-rw-r----- 1 root root 0 Jun 15 10:10 /etc/at.allow
$ ls -aldL /etc/at.deny
-rw-r----- 1 root root 144 Jun 15 10:10 /etc/at.deny
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ ls -aldL /etc/cron.allow
-rw-r----- 1 root root 0 Jun 15 10:10 /etc/cron.allow
$ ls -aldL /etc/cron.deny
-rw-r----- 1 root root 0 Jun 15 10:10 /etc/cron.deny""",
    "SRV-112": """$ cat /etc/rsyslog.conf
# /etc/rsyslog.conf
*.info;mail.none;authpriv.none;cron.none    /var/log/messages
cron.*                                      /var/log/cron
------------
$ cat /etc/rsyslog.d/50-default.conf
cron.*    -/var/log/cron.log""",
    "SRV-144": """$ nice -n 5 find /dev -type f -exec ls -l {} \\; 2>/dev/null
------------
(검색 완료: /dev 경로에 일반 파일 없음 — 출력 결과 0건)""",
    "SRV-163": """$ cat /etc/motd
************************************************************
* Authorized access only. All activity may be monitored.  *
* 본 시스템은 인가된 사용자만 접근 가능하며 모든 활동이 기록·감시됩니다. *
************************************************************
------------
$ cat /etc/issue
Authorized uses only. All activity may be monitored and reported.
------------
$ cat /etc/issue.net
Authorized uses only. All activity may be monitored and reported.
------------""",
    "SRV-175": """$ ntpq -pn
     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
*time.bora.net   .GPS.            1 u   38   64  377    1.234   -0.045   0.123
------------
$ timedatectl
               NTP service: active
   System clock synchronized: yes
------------
date
Mon Jun 15 10:10:42 UTC 2026""",
}

# ── 취약(cov-vuln) 주입 본문 ──
VULN = {
    "SRV-006": """-e [ smtp|sendmail|postfix|exim ][S]
root  742  0.0  0.1  12345  6789 ?  Ss  10:10  0:00 /usr/sbin/sendmail-mta -bd -q1h
[ smtp|sendmail|postfix|exim ][E]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ cat /etc/mail/sendmail.cf | grep LogLevel | grep -v grep
O LogLevel=0
------------""",
    "SRV-027": """$ firewall-cmd --list-all
fsi.sh: 1500: firewall-cmd: not found
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ iptables -L -n
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
------------
$ ls -aldL /etc/hosts.allow
ls: cannot access '/etc/hosts.allow': No such file or directory
$ ls -aldL /etc/hosts.deny
ls: cannot access '/etc/hosts.deny': No such file or directory
------------""",
    "SRV-081": """$ ls -alLd /usr/bin/crontab
-rwsrwxrwx 1 root root 43568 Mar  6 16:10 /usr/bin/crontab
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ ls -aldL /etc/at.allow
-rw-rw-rw- 1 root root 12 Jun 15 10:10 /etc/at.allow
$ ls -aldL /etc/at.deny
-rw-rw-rw- 1 root root 144 Jun 15 10:10 /etc/at.deny
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ ls -aldL /etc/cron.allow
-rw-rw-rw- 1 root root 12 Jun 15 10:10 /etc/cron.allow
$ ls -aldL /etc/cron.deny
-rw-rw-rw- 1 root root 12 Jun 15 10:10 /etc/cron.deny""",
    "SRV-091": """$ nice -n 5 find $HOMEDIR -type f -a -perm -4000 -exec ls -alLd {} \\;
------------
$ nice -n 5 find /usr/bin -type f -a -perm -4000 -exec ls -alLd {} \\;
-rwsr-xr-x 1 root root 36360 Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 55544 Feb  6  2024 /usr/bin/passwd
-rwsr-xr-x 1 root root 39072 Mar  6 16:10 /usr/bin/mount
------------
$ nice -n 5 find / -type f -a -perm -4000 -exec ls -alLd {} \\; 2>/dev/null
-rwsr-xr-x 1 root root 1183448 Jun 15 10:10 /usr/bin/find
-rwsr-xr-x 1 root root 1234376 Jun 15 10:10 /tmp/.cache/rootbash
-rwsr-sr-x 1 root root  124680 Jun 15 10:10 /home/backdoor/.local/nc
------------""",
    "SRV-144": """$ nice -n 5 find /dev -type f -exec ls -l {} \\; 2>/dev/null
-rw-r--r-- 1 root root 4096 Jun 15 10:10 /dev/backdoor
-rwxr-xr-x 1 root root 8192 Jun 15 10:10 /dev/.hidden/shell""",
    "SRV-166": """$ ls -alL /home/backdoor
total 28
drwxr-x--- 3 root backdoor 4096 Jun 15 10:10 .
drwxr-xr-x 1 root root     4096 Jun 15 10:10 ..
-rw-r--r-- 1 root backdoor  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 root backdoor 3771 Jan  6  2022 .bashrc
-rw-r--r-- 1 root backdoor  807 Jan  6  2022 .profile
drwxr-xr-x 2 root backdoor 4096 Jun 15 10:10 .hidden
-rwxr-xr-x 1 root backdoor 8192 Jun 15 10:10 .bd.sh
------------
$ find / -type f -name ".*" 2>/dev/null | grep -vE "bash|profile|\\.cache|\\.config"
/home/backdoor/.bd.sh
/tmp/.x/.run
/var/tmp/.sniff.log
------------""",
    "SRV-175": """$ systemctl is-active systemd-timesyncd
inactive
$ systemctl is-active chronyd
inactive
$ systemctl is-active ntp
inactive
------------
$ timedatectl
                      Local time: Mon 2026-06-15 10:10:42 UTC
                     NTP service: inactive
                 System clock synchronized: no
------------
date
Mon Jun 15 10:10:42 UTC 2026""",
}


def replace_block(text, item_id, new_body):
    """item_id 의 <output><![CDATA[ ... ]]> 본문을 new_body로 교체. 정확히 1회."""
    pat = re.compile(
        r"(<id>\s*" + re.escape(item_id) + r"\s*</id>.*?<!\[CDATA\[)(.*?)(\]\]>)",
        re.DOTALL)
    new_text, n = pat.subn(lambda m: m.group(1) + "\n" + new_body + "\n\t\t\t\t" + m.group(3), text, count=1)
    if n != 1:
        raise SystemExit(f"FAIL: {item_id} 교체 {n}회 (1이어야 함)")
    return new_text


def build(src, out, edits, tag):
    text = open(src, encoding="utf-8", errors="replace").read()
    for iid, body in edits.items():
        text = replace_block(text, iid, body)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"{tag}: {out} 생성 — {len(edits)}개 항목 주입 ({', '.join(sorted(edits))})")


build(GOOD_SRC, GOOD_OUT, GOOD, "cov-good")
build(VULN_SRC, VULN_OUT, VULN, "cov-vuln")


def _self_validate():
    """생성 직후 계약(양극성+골드신호) 자가검증 — 재생성 시 단극성 손실 차단."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from judge_tool.profile import get_profile
    from judge_tool.parsers import server_xml
    from judge_tool.mapper import aggregate
    from tests.cov_contract import (
        LLM_PROD_ITEMS, VULN_SIGNALS, GOOD_SIGNALS)

    prof = get_profile("server")
    g = aggregate(server_xml.parse(GOOD_OUT), "linux", prof)
    v = aggregate(server_xml.parse(VULN_OUT), "linux", prof)

    def text(m, it):
        item = m.get(it)
        if not item:
            return ""
        return "\n".join((getattr(r, "evidence", "") or "") + (getattr(r, "detail", "") or "")
                         for r in item.resources)

    for it in LLM_PROD_ITEMS:
        gt, vt = text(g, it).strip(), text(v, it).strip()
        if not gt or not vt or gt == vt:
            raise SystemExit(f"VALIDATE FAIL: {it} 단극성/증거누락")
        if VULN_SIGNALS[it] and VULN_SIGNALS[it] not in vt:
            raise SystemExit(f"VALIDATE FAIL: {it} 취약단서 '{VULN_SIGNALS[it]}' 누락")
        if GOOD_SIGNALS[it] and GOOD_SIGNALS[it] not in gt:
            raise SystemExit(f"VALIDATE FAIL: {it} 양호단서 '{GOOD_SIGNALS[it]}' 누락")
    print(f"자가검증 통과: LLM-production {len(LLM_PROD_ITEMS)}항목 양극성+골드신호 OK")


_self_validate()
print("완료.")
