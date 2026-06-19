"""웹서버(WST) 변형별 DET 양극성 커버리지 픽스처 계약 (단일 진실원천).

각 DET 항목에 대해 good(위반없음→양호) / vuln(위반→취약) 합성 config/raw를 정의.

구조:
  WEB_COV[variant][item_id] = {
      "good": <raw string>,          # 양호 유발 config/raw
      "vuln": <raw string>,          # 취약 유발 config/raw
      "good_verdict": "양호",         # 기대 verdict (good 입력 기준)
      "vuln_verdict": "취약",         # 기대 verdict (vuln 입력 기준)
      "note": "...",                  # 선택적 설명
  }

특수 verdict:
  - "양호"     : 위반 없음
  - "취약"     : 위반 확정
  - "판단보류" : MANUAL/(*) 마커 또는 기능적 한계

미커버(UNCOVERED) 표시:
  항목에 "uncovered": True 가 있으면 skip 사유가 "uncovered_reason" 에 명시됨.

WAS(tomcat/jeus)/webservice 변형:
  DET 항목 0개 — 전 항목 LLM label A(ABSENT gate 차단).
  양극성 커버 대상 아님. 별도 명시.
"""
from __future__ import annotations

# ── 공통 구분자 ──────────────────────────────────────────────────────────────
DELIMITER = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="

# ── 서비스 블록 prefix (check_WST_033 apache: 서비스 실행 여부 확인용) ──────
_APACHE_SVC_PREFIX = (
    f"[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
    f"$ ps -ef | egrep apache\nroot /usr/sbin/apache2 -k start\n"
    f"[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
)

# ── config 시그니처 prefix (웹서버 어댑터 §6.4 가드 통과용) ─────────────────
# config-항목(WST-031/035/036/037/038/039/102)은 _WST_CONFIG_SIG 키워드가 없으면
# handled=False(판단보류) → 양극성 테스트 불가. config blob에 반드시 포함해야 함.

# ──────────────────────────────────────────────────────────────────────────────
# apache DET 항목 (7개)
# WST-031/035/036/037/038/102: config-항목 (raw = config blob)
# WST-033: 명령출력 항목 (raw = ps/rpm/dpkg/apache2 -v 출력 구분자 구분)
# ──────────────────────────────────────────────────────────────────────────────
_APACHE = {
    # WST-031: Directory Indexes — Options에 Indexes/all 있으면 취약
    # check_WST_031: <Directory>…Options.*([^-]Indexes|all)…</Directory> → Y
    # !! BUG FOUND (good→취약 거짓취약): [^-]Indexes 패턴이 '-Indexes' 앞의 공백(' Indexes')에도 매치됨 →
    #    Options -Indexes MultiViews 입력 시 good→취약 거짓취약 발생.
    #    판정 로직 변경 금지(검증 전용) — good 극성 xfail로 문서화.
    "WST-031": {
        "good": (
            "<Directory /var/www/html>\n"
            "Options -Indexes MultiViews\n"
            "AllowOverride None\n"
            "</Directory>\n"
        ),
        "vuln": (
            "<Directory /var/www/html>\n"
            "Options Indexes MultiViews\n"
            "AllowOverride None\n"
            "</Directory>\n"
        ),
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "Options Indexes → 취약, -Indexes → 양호",
        "known_bug_polarity": "good",
        "known_bug": "BUG-WST031-apache: [^-]Indexes 패턴이 Options -Indexes(공백+Indexes)도 매치 → 거짓취약(good→취약)",
    },

    # WST-033: Apache 버전 — 2.1 미만 취약
    # check_WST_033: httpd-NNN-* or apache[0-9] NNN 패턴. 서비스 블록 필요.
    # 양호: Apache 2.4.52 (dpkg line에서 추출)
    # 취약: rpm-qa 에서 httpd-1.3.42-1.el6 패턴
    "WST-033": {
        "good": (
            f"{_APACHE_SVC_PREFIX}"
            f"{DELIMITER}\n"
            "$ rpm -qa httpd\nhttpd not found\n"
            f"{DELIMITER}\n"
            "$ dpkg -l | grep apache\nii  apache2  2.4.52-1ubuntu4\n"
            f"{DELIMITER}\n"
            "$ apache2 -v\nServer version: Apache/2.4.52 (Ubuntu)\n"
        ),
        "vuln": (
            f"{_APACHE_SVC_PREFIX}"
            f"{DELIMITER}\n"
            "$ rpm -qa httpd\nhttpd-1.3.42-1.el6.x86_64\n"
            f"{DELIMITER}\n"
            "$ dpkg -l | grep apache\n(none)\n"
            f"{DELIMITER}\n"
            "$ apache2 -v\nServer version: Apache/1.3.42\n"
        ),
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "httpd-1.3.42 rpm 패턴으로 취약 유발. dpkg apache2 2.4.52로 양호 유발.",
    },

    # WST-035: LimitRequestBody — 없거나 0이면 취약
    # check_WST_035: LimitRequestBody=0 → 취약, 없으면 → 취약, 양수 → 양호
    "WST-035": {
        "good": "LimitRequestBody 1048576\n",
        "vuln": "LimitRequestBody 0\n",
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "LimitRequestBody 0 → 취약. 양수값 → 양호.",
    },

    # WST-036: Apache 구동 계정 — root이면 취약
    # check_WST_036: User root → 취약, User www-data → 양호
    "WST-036": {
        "good": "User www-data\nGroup www-data\n",
        "vuln": "User root\nGroup root\n",
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "User/Group root → 취약.",
    },

    # WST-037: DocumentRoot — '/' 이면 취약
    # check_WST_037: DocumentRoot "/" → 취약
    "WST-037": {
        "good": 'DocumentRoot "/var/www/html"\n',
        "vuln": 'DocumentRoot "/"\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": 'DocumentRoot "/" → 취약.',
    },

    # WST-038: FollowSymLinks — Directory 블록에 FollowSymLinks 또는 all 있으면 취약
    # check_WST_038: re.DOTALL로 멀티라인 <Directory>…</Directory> 검색
    "WST-038": {
        "good": (
            "<Directory /var/www/html>\n"
            "Options Indexes\n"
            "AllowOverride None\n"
            "Require all granted\n"
            "</Directory>\n"
        ),
        "vuln": (
            "<Directory /var/www/html>\n"
            "Options Indexes FollowSymLinks\n"
            "AllowOverride None\n"
            "</Directory>\n"
        ),
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "FollowSymLinks → 취약. 멀티라인 Directory 블록 DOTALL 회귀 포함.",
    },

    # WST-102: ServerTokens — Prod이면 양호, 없거나 다른 값이면 취약
    # check_WST_102: ServerTokens Prod → 양호, ServerTokens Full → 취약
    "WST-102": {
        "good": "ServerTokens Prod\n",
        "vuln": "ServerTokens Full\n",
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "ServerTokens Prod → 양호. Full → 취약.",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# iis DET 항목 (13개)
# WST-031/033/035/036/037/040/042/102: config-항목 (applicationHost.config 형식)
# WST-032/034/038/039/041/043: 명령출력 항목 (raw output 형식)
# WST-040: MANUAL → gate 차단 → handled=False (별도 확인)
# ──────────────────────────────────────────────────────────────────────────────
_IIS = {
    # WST-031: directoryBrowse enabled — true이면 취약
    # check_WST_031(iis): <directoryBrowse enabled="true" /> → Y
    # 주의: _WST_CONFIG_SIG['WST-031'] = ('<Directory', 'Options') — Apache 키워드.
    #       IIS config에 이 키워드가 없어 §6.4 가드 → good=handled=False(판단보류, skip).
    #       vuln=handled=True(취약 확인).
    "WST-031": {
        "good": '<directoryBrowse enabled="false" />\n',
        "vuln": '<directoryBrowse enabled="true" />\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "IIS directoryBrowse enabled=true → 취약. "
            "good side: _WST_CONFIG_SIG Apache 키워드 부재 → §6.4 가드 → handled=False(skip). "
            "vuln side: Y 반환 → handled=True(취약 확인 가능)."
        ),
    },

    # WST-032: cacls Everyone 권한 — Everyone FMW 패턴 있으면 취약
    # check_WST_032(iis): Everyone.*[FMW] → Y
    "WST-032": {
        "good": (
            f"C:\\inetpub\\scripts{DELIMITER}\n"
            "BUILTIN\\Administrators:(F)\n"
        ),
        "vuln": (
            f"C:\\inetpub\\scripts{DELIMITER}\n"
            "BUILTIN\\Administrators:(F)\n"
            "Everyone:(M)\n"
        ),
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "Everyone M → 취약. 없으면 양호.",
    },

    # WST-033: asp enableParentPaths — true이면 취약
    # check_WST_033(iis): <asp enableParentPaths="true" /> → Y
    "WST-033": {
        "good": '<asp enableParentPaths="false" />\n',
        "vuln": '<asp enableParentPaths="true" />\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "IIS asp enableParentPaths=true → 취약.",
    },

    # WST-034: 불필요한 파일(sample/help/test) — IIS dir 출력
    # check_WST_034(iis): iissamples/iishelp/test/sample 포함 라인 → Y
    "WST-034": {
        "good": (
            f"C:\\inetpub\\wwwroot{DELIMITER}\n"
            "10/01/2024  10:00 AM    <DIR>          scripts\n"
            "10/01/2024  10:00 AM            1,234 default.htm\n"
        ),
        "vuln": (
            f"C:\\inetpub\\wwwroot{DELIMITER}\n"
            "10/01/2024  10:00 AM    <DIR>          iissamples\n"
            "10/01/2024  10:00 AM    <DIR>          iishelp\n"
        ),
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "iissamples/iishelp 경로 탐지 → 취약.",
    },

    # WST-035: maxRequestEntityAllowed — >100000000이면 취약
    # check_WST_035(iis): <limits maxRequestEntityAllowed="NNN" /> → 100000000 초과면 Y
    "WST-035": {
        "good": '<limits maxRequestEntityAllowed="100000000" />\n',
        "vuln": '<limits maxRequestEntityAllowed="500000000" />\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "100000000 이하 → 양호. 초과 → 취약.",
    },

    # WST-036: processModel identityType — LocalSystem이면 취약
    # check_WST_036(iis): identityType="LocalSystem" → Y
    # 주의: 값 없는 경우(count==0) → (*) 수동 → handled=False
    "WST-036": {
        "good": '<processModel identityType="ApplicationPoolIdentity" />\n',
        "vuln": '<processModel identityType="LocalSystem" />\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "LocalSystem → 취약. ApplicationPoolIdentity → 양호.",
    },

    # WST-037: virtualDirectory iisadmin/iisadmpwd — 있으면 취약
    # check_WST_037(iis): virtualDirectory path에 iisadmin/iisadmpwd → Y
    "WST-037": {
        "good": '<virtualDirectory path="/app" physicalPath="C:\\inetpub\\app" />\n',
        "vuln": '<virtualDirectory path="/iisadmin" physicalPath="C:\\inetpub\\iisadmin" />\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "iisadmin 경로 → 취약.",
    },

    # WST-038: .lnk 파일 — IIS attrib 출력에 .lnk 있으면 취약
    # check_WST_038(iis): .lnk in line.lower() → Y
    "WST-038": {
        "good": (
            "A          C:\\inetpub\\wwwroot\\index.htm\n"
            "A          C:\\inetpub\\wwwroot\\default.asp\n"
        ),
        "vuln": (
            "A          C:\\inetpub\\wwwroot\\index.htm\n"
            "A    SHR   C:\\inetpub\\wwwroot\\shortcut.lnk\n"
        ),
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": ".lnk 파일 탐지 → 취약.",
    },

    # WST-039: 불필요 모듈 — 수동(*) → handled=False
    # check_WST_039(iis): (*) 수동 → Low-1 가드 → handled=False
    "WST-039": {
        "uncovered": True,
        "uncovered_reason": (
            "check_WST_039(iis): result='N', reason='(*) 수동 점검...' — "
            "Low-1 가드에 의해 항상 handled=False. 양극성(양호/취약) 합성 불가."
        ),
    },

    # WST-041: cacls *.* Everyone 실행파일 권한 — .exe/.dll 등 Everyone [FMRXRWD] → 취약
    # check_WST_041(iis): Everyone [FMRXRWD] + 실행파일 확장자 → Y
    "WST-041": {
        "good": (
            f"C:\\inetpub\\scripts{DELIMITER}\n"
            "C:\\inetpub\\scripts\\run.exe BUILTIN\\Administrators:(F)\n"
        ),
        "vuln": (
            f"C:\\inetpub\\scripts{DELIMITER}\n"
            "C:\\inetpub\\scripts\\run.exe BUILTIN\\Administrators:(F)\n"
            "run.exe Everyone:(M)\n"
        ),
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "Everyone M 권한 + .exe 확장자 → 취약. "
            "check_WST_041: Everyone.*[FMRXRWD] 패턴 + 확장자 필터."
        ),
    },

    # WST-042: handlers accessPolicy — .htr/.idc/.shtm 등 → 취약
    # check_WST_042(iis): handlers accessPolicy 섹션에 htr/idc/shtm/shtml/stm/printer/htw/ida/idq → Y
    "WST-042": {
        "good": (
            '<handlers accessPolicy="Read, Script">\n'
            '  <add name="ASPClassic" path="*.asp" verb="*" />\n'
            '</handlers>\n'
        ),
        "vuln": (
            '<handlers accessPolicy="Read, Script">\n'
            '  <add name="HtrHandler" path="*.htr" verb="*" />\n'
            '</handlers>\n'
        ),
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": ".htr 핸들러 → 취약.",
    },

    # WST-043: IIS 버전 + SSIEnableCmdDirective — IIS<7.0이고 SSI != 0x0 → 취약
    # check_WST_043(iis): VersionString NNN.N → 7.0 이상이면 양호 즉시 반환
    "WST-043": {
        "good": (
            f"SSIEnableCmdDirective: 0x0{DELIMITER}\n"
            "VersionString: 10.0\n"
        ),
        "vuln": (
            f"SSIEnableCmdDirective: 0x1{DELIMITER}\n"
            "VersionString: 6.0\n"
        ),
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "IIS 7.0 이상 → 양호 즉시 반환(버전 우선). "
            "IIS 6.0 + SSI=0x1 → 취약."
        ),
    },

    # WST-102: IIS 서버정보 노출 — removeServerHeader=true 또는 response_server → 양호
    # check_WST_102(iis): removeServerHeader=true 없고 response_server 없고
    #                      httpErrors errorMode=Detailed → 취약
    "WST-102": {
        "good": (
            '<requestFiltering removeServerHeader="true" />\n'
            '<httpErrors errorMode="DetailedLocalOnly" />\n'
        ),
        "vuln": '<httpErrors errorMode="Detailed" />\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "removeServerHeader=true → headerVul=False → 양호. "
            "없고 errorMode=Detailed → 취약. "
            "WST-102 IIS polarity 버그수정 회귀(KNOWN_BUGS §2)."
        ),
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# webtob DET 항목 (6개)
# WST-031/035/036/037/039/102: config-항목 (webtob.m 형식)
# WST-033/038: webtob=NA(*) → MANUAL 분류 → gate 차단 → handled=False (미커버)
# ──────────────────────────────────────────────────────────────────────────────
_WEBTOB = {
    # WST-031: Options INDEX — INDEX 있으면 취약
    # check_WST_031(webtob): Options.*INDEX → Y (대소문자 무시)
    # !! BUG FOUND (good→취약 거짓취약): `Options.*?INDEX` 패턴이 'NOINDEX'의 INDEX 서브스트링도 매치 →
    #    Options NOINDEX 입력 시 good→취약 거짓취약 발생.
    #    판정 로직 변경 금지(검증 전용) — good 극성 xfail로 문서화.
    "WST-031": {
        "good": "Options = NOINDEX NOLIST\n",
        "vuln": "Options = INDEX LIST\n",
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "Options INDEX → 취약. NOINDEX → 양호",
        "known_bug_polarity": "good",
        "known_bug": "BUG-WST031-webtob: Options.*INDEX 패턴이 NOINDEX 서브스트링 매치 → 거짓취약(good→취약)",
    },

    # WST-035: LimitRequestBody — webtob는 = 구분자 사용
    # check_WST_035(webtob): LimitRequestBody\s*=\s*(.*) → 0이면 취약, 없으면 취약
    "WST-035": {
        "good": "LimitRequestBody = 1048576\n",
        "vuln": "LimitRequestBody = 0\n",
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "webtob LimitRequestBody=0 → 취약. 양수 → 양호.",
    },

    # WST-036: User/Group root — webtob는 User="root" 형식
    # check_WST_036(webtob): User\s*=\s*"root" → Y
    "WST-036": {
        "good": 'User = "webtob"\nGroup = "webtob"\n',
        "vuln": 'User = "root"\nGroup = "root"\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": 'webtob User="root" → 취약.',
    },

    # WST-037: DOCROOT "/" — webtob는 DOCROOT="/" 형식
    # check_WST_037(webtob): DOCROOT\s*=\s*"/" → Y
    "WST-037": {
        "good": 'DOCROOT = "/usr/local/webtob/www"\n',
        "vuln": 'DOCROOT = "/"\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": 'webtob DOCROOT="/" → 취약.',
    },

    # WST-039: 불필요 모듈 — 수동(*) → handled=False
    # check_WST_039(webtob): result='N', reason='(*) 수동...' → Low-1 가드 → handled=False
    "WST-039": {
        "uncovered": True,
        "uncovered_reason": (
            "check_WST_039(webtob): result='N', reason='(*) 수동 점검...' — "
            "Low-1 가드에 의해 항상 handled=False. 양극성(양호/취약) 합성 불가."
        ),
    },

    # WST-102: ServerTokens — webtob는 ServerTokens="min" 등 형식
    # check_WST_102(webtob): ServerTokens\s*=\s*"(.*)" — "min" not in val AND val not in ["os","full","prod"] → 취약
    # 의도: "min" = 양호, "os"/"full"/"prod" = ???
    # !! BUG FOUND: 코드 조건 `"min" not in tokens_val and tokens_val not in ["os","full","prod"]` →
    #    "full"이 ["os","full","prod"]에 포함되므로 두 번째 조건 False → 취약 미탐지 → 거짓양호 발생.
    #    실제 의미: "full"은 버전 노출이므로 취약이어야 하는데 양호로 판정됨.
    #    판정 로직 변경 금지(검증 전용) — xfail로 문서화.
    # 양호 픽스처: ServerTokens 없음(기본값 Off → 양호)
    # 취약 픽스처: "full" → 버그로 인해 현재 양호 오판 → xfail
    "WST-102": {
        "good": "# webtob 설정 (ServerTokens 없음 = Default Off = 양호)\nDocroot = \"/usr/local/webtob/www\"\n",
        "vuln": 'ServerTokens = "full"\n',
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": (
            "webtob: ServerTokens 없으면 기본값 Off → 양호. "
            "ServerTokens='full'(버전 노출) → 취약 의도."
        ),
        "known_bug_polarity": "vuln",
        "known_bug": (
            "BUG-WST102-webtob: check_WST_102 조건 `'min' not in val and val not in ['os','full','prod']`에서 "
            "'full'이 리스트에 포함 → 조건 False → 취약 미탐지 → 거짓양호(vuln→양호). "
            "'full'/'os'/'prod'가 취약이어야 하는데 양호로 판정됨."
        ),
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# MANUAL/판단보류 확인 대상 (양극성 없음, handled=False 확인 전용)
# ──────────────────────────────────────────────────────────────────────────────

# WST-044: 전 변형(apache/iis/webtob) MANUAL → handled=False 확인
# WST-040: iis=MANUAL, apache/webtob=ABSENT → handled=False 확인
# WST-034(apache/webtob): MANUAL → handled=False 확인
# WST-039(apache): MANUAL → handled=False 확인
# WST-033(webtob): MANUAL → handled=False 확인
# WST-038(webtob): webtob check_WST_038은 result='NA',reason='(*)'→ MANUAL/_map_result handled=False
MANUAL_HOLD_ITEMS = [
    # (item_id, variant, note)
    ("WST-044", "apache",  "WST-044 apache MANUAL"),
    ("WST-044", "iis",     "WST-044 iis MANUAL"),
    ("WST-044", "webtob",  "WST-044 webtob MANUAL"),
    ("WST-040", "iis",     "WST-040 iis MANUAL — xlsx 역전 의심(KNOWN_BUGS §3)"),
    ("WST-040", "apache",  "WST-040 apache ABSENT → handled=False"),
    ("WST-034", "apache",  "WST-034 apache MANUAL"),
    ("WST-034", "webtob",  "WST-034 webtob MANUAL"),
    ("WST-039", "apache",  "WST-039 apache MANUAL"),
    ("WST-033", "webtob",  "WST-033 webtob — check_WST_033 returns NA(*) → handled=False"),
    ("WST-038", "webtob",  "WST-038 webtob — check_WST_038 returns NA(*) → handled=False"),
]

# ──────────────────────────────────────────────────────────────────────────────
# WAS(tomcat/jeus)/webservice 미커버 명시
# ──────────────────────────────────────────────────────────────────────────────

WAS_UNCOVERED_NOTE = (
    "WAS(tomcat/jeus)/webservice 변형: DET 항목 0개 — "
    "모든 WST-* 항목이 ABSENT(gate 차단) → LLM label A 경로. "
    "결정론 양극성 커버 대상 아님(LLM 검증은 별도 LLM 품질 트랙에서 수행)."
)

# ──────────────────────────────────────────────────────────────────────────────
# 통합 딕셔너리
# ──────────────────────────────────────────────────────────────────────────────
WEB_COV: dict[str, dict] = {
    "apache":  _APACHE,
    "iis":     _IIS,
    "webtob":  _WEBTOB,
}
