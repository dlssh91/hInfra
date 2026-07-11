#!/usr/bin/env bash
# ⚠️ DRAFT — 현장 협의 전 초안. 배포용 아님.
#
# fsec_network_collect.sh — 네트워크 장비(CISCO 우선) 관리호스트 실행형 수집기.
#
# 설계: docs/superpowers/specs/2026-07-02-remaining-domains-design.md §5-1.
# 항목↔명령 매핑표: scripts/net_collect_mapping.md (45항목 매핑 근거).
# 파서 계약(무변경): judge_tool/parsers/network_xml.py — 실제 기대 스키마는
#   <script><asset>..</asset><results><dump><items><id>..</id></items>
#   <output><![CDATA[..]]></output></dump>...</results></script>
# (설계문서 §5 요약 표기 "<dump><id>.." 는 근사 표현이며, 파서 소스가
#  유일한 진실원천이다 — mapping.md 하단 참조.)
#
# 실행 대상: 관리호스트(장비 자체가 아님). 장비에 셸이 없으므로 ssh client
# 역할만 하는 이 호스트에서 배치 실행한다.
#
# 사용법:
#   ./fsec_network_collect.sh --csv devices.csv --out-dir out/net [--mask]
#                              [--timeout 15] [--mock-dir mock/net]
#
# CSV 형식(devices.csv, 헤더 줄 1개 허용):
#   host,vendor,transport
#   router1.example.com,cisco,pubkey
#   192.168.1.10,cisco,interactive
#   switch2,juniper,pubkey        # cisco 외 벤더 → 명령 미실행, 활성화 게이트 대기(§5-3)
#
#   host      : ssh 접속 대상(호스트명/IP, ~/.ssh/config 별칭 포함, user@host 가능)
#   vendor    : 표시용 벤더명(대소문자 무관). "cisco" 계열만 명령 화이트리스트 실행.
#   transport : pubkey(공개키, 비대화식 BatchMode) | interactive(대화식, 암호 프롬프트 허용)
#               — 설계문서 "표준 ssh(공개키/대화식)" 문구를 그대로 두 값으로 대응.
#
# 명령 화이트리스트(CISCO, read-only show 계열만 — config 모드 진입 절대 금지):
#   show running-config / show version / show ip ssh / show snmp /
#   show ntp status / show logging / show interfaces description
#   (매핑 근거: scripts/net_collect_mapping.md)
#
# 실패 내성: 장비별 --timeout, 명령별 실패는 <error> 태그로 기록하고 해당
# 항목은 output 미채움 → judge_tool "증거 미수집 자동보류"로 흡수(판정 크래시 없음).
# <error>는 파서가 소비하지 않는 진단 전용 태그(파서 무변경 확인됨) — 운영자 참고용.
#
# 마스킹(--mask, 1차 방어 옵션, §5-4): type-7/community 등 대표 패턴만
# sed 정규식으로 치환하는 "참고용" 1차 방어. **최종 권위는 언제나
# judge_tool/parsers/network_xml.py의 16패턴(파서 2차 마스킹)이며, --mask
# 미사용이어도 파서가 반드시 재마스킹한다.** 이 옵션은 원본 비밀값이 수집
# 워크스테이션 디스크에 남는 노출 시간을 줄이기 위한 것뿐, 완전성을
# 보장하지 않는다(비교: network_xml.py 16패턴).
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

# ── 기본값 ────────────────────────────────────────────────────────────────
OUT_DIR="."
TIMEOUT=15
MASK=0
MOCK_DIR=""
CSV=""

usage() {
  cat <<EOF
사용법: $SCRIPT_NAME --csv <devices.csv> [--out-dir DIR] [--timeout SEC]
                      [--mask] [--mock-dir DIR]

  --csv PATH       장비 목록 CSV(host,vendor,transport). 필수.
  --out-dir DIR    장비별 XML 출력 디렉터리(기본: 현재 디렉터리).
  --timeout SEC    ssh 연결·명령 타임아웃(초, 기본 15).
  --mask           1차 마스킹(참고용, 파서 2차 마스킹이 최종 권위) 적용.
  --mock-dir DIR   ssh 대신 DIR/<host>/<slug>.txt 로컬 파일을 명령 출력으로
                   주입(장비 없이 회귀검증용, §검증(b)). <slug>는 CISCO_CMDS의
                   slug 필드 그대로(running_config/version/ip_ssh/snmp/
                   ntp_status/logging/int_desc).txt.
  -h, --help       이 도움말.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --csv) CSV="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --mask) MASK=1; shift ;;
    --mock-dir) MOCK_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$CSV" ]]; then
  echo "오류: --csv 필수." >&2
  usage >&2
  exit 2
fi
if [[ ! -f "$CSV" ]]; then
  echo "오류: CSV 파일을 찾을 수 없습니다: $CSV" >&2
  exit 2
fi
mkdir -p "$OUT_DIR"

# ── CISCO 명령 화이트리스트: "slug|명령|콤마구분 NET-id 목록" ───────────────
# 매핑 근거: scripts/net_collect_mapping.md (§5-1, 45항목 매핑표).
# NET-001/NET-056(인터뷰 전용)은 의도적으로 미포함 — 증거 미수집 자동보류로 흡수.
CISCO_CMDS=(
  "running_config|show running-config|NET-003,NET-004,NET-005,NET-006,NET-007,NET-008,NET-009,NET-010,NET-011,NET-012,NET-013,NET-014,NET-015,NET-016,NET-022,NET-026,NET-027,NET-030,NET-031,NET-033,NET-034,NET-035,NET-036,NET-037,NET-038,NET-039,NET-040,NET-041,NET-042,NET-043,NET-044,NET-045,NET-046,NET-047,NET-049,NET-050,NET-051,NET-052,NET-054,NET-057,NET-058"
  "version|show version|NET-048,NET-059"
  "ip_ssh|show ip ssh|NET-015"
  "snmp|show snmp|NET-003,NET-004,NET-005,NET-006"
  "ntp_status|show ntp status|NET-031"
  "logging|show logging|NET-033,NET-034,NET-035,NET-036,NET-037"
  "int_desc|show interfaces description|NET-052"
)

# 벤더 미지원 시(§5-3 활성화 게이트 대기) 여전히 emit할 전 수집대상 id
# (CISCO_CMDS 합집합, 인터뷰전용 2건 제외 — 43개). 파서가 dump 0건이면
# ReportError로 크래시하므로, 미지원 벤더도 반드시 id를 채워 <error>로
# "미수집(벤더 미지원)"임을 남긴다(실패 내성 요건).
UNSUPPORTED_VENDOR_IDS="NET-003,NET-004,NET-005,NET-006,NET-007,NET-008,NET-009,NET-010,NET-011,NET-012,NET-013,NET-014,NET-015,NET-016,NET-022,NET-026,NET-027,NET-030,NET-031,NET-033,NET-034,NET-035,NET-036,NET-037,NET-038,NET-039,NET-040,NET-041,NET-042,NET-043,NET-044,NET-045,NET-046,NET-047,NET-048,NET-049,NET-050,NET-051,NET-052,NET-054,NET-057,NET-058,NET-059"

# ── 유틸 ─────────────────────────────────────────────────────────────────

items_xml() {
  # "NET-001,NET-002" → "<id>NET-001</id><id>NET-002</id>"
  local ids="$1" out="" id
  IFS=',' read -ra _arr <<<"$ids"
  for id in "${_arr[@]}"; do
    out+="<id>${id}</id>"
  done
  printf '%s' "$out"
}

cdata_wrap() {
  # "]]>"는 CDATA 내부에 그대로 둘 수 없으므로 분할-재시작한다.
  local text="$1"
  printf '<![CDATA[%s]]>' "$(printf '%s' "$text" | sed 's/]]>/]]]]><![CDATA[>/g')"
}

xml_escape_attr() {
  # 태그 텍스트(hostname/vendor 등, CDATA 밖)용 최소 이스케이프.
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# 1차 마스킹(참고용) — 파서 2차 마스킹(network_xml.py 16패턴)이 최종 권위.
# 대표 패턴만 치환: enable secret/password, username 계정 password/secret,
# snmp community(public/private 제외), tacacs/radius key, isakmp/pre-shared-key,
# key-string, juniper $8$/$9$. 완전성 보장 안 함(§5-4).
mask_text() {
  sed -E '
    /snmp-server community[[:space:]]+(public|private)([[:space:]]|$)/{
    b pass
    }
    /set snmp community[[:space:]]+(public|private)[[:space:]]*$/{
    b pass
    }
    s/^([[:space:]]*enable (secret|password)( level [0-9]+)?( [0-9])?)[[:space:]]+[^[:space:]]+[[:space:]]*$/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*username [^[:space:]]+( privilege [0-9]+)? (password|secret)( [0-9])?)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*password( [07])?)[[:space:]]+[^[:space:]]+[[:space:]]*$/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*snmp-server community)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*set snmp community)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*(tacacs-server|radius-server)( host [^[:space:]]+)? key( [07])?)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*crypto isakmp key)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*pre-shared-key( (local|remote))?)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/(pre-shared-key (ascii-text|hexadecimal))[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*ntp authentication-key [0-9]+ [^[:space:]]+)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*key-string( [07])?)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*ppp chap password( [07])?)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/^([[:space:]]*ppp pap sent-username [^[:space:]]+ password( [07])?)[[:space:]]+[^[:space:]]+/\1 <MASKED_BY_COLLECTOR>/
    s/((plain-text-password|encrypted-password)[[:space:]]+)[^[:space:]]+/\1<MASKED_BY_COLLECTOR>/
    s/\$(8|9)\$[^[:space:];\"]+/<MASKED_BY_COLLECTOR>/
    :pass
  '
}

# IOS는 잘못된 명령을 exit 0으로도 돌려주는 경우가 있어("% Invalid input"),
# 셸 exit code만으로 실패를 완전히 판단할 수 없다(§ 협의 필요 잔여 결정사항).
# 대표적 오류 마커만 휴리스틱으로 잡아 <error>에 남기되 output은 참고용으로 보존한다.
looks_like_ios_error() {
  grep -Eq '% (Invalid input|Incomplete command|Ambiguous command)' <<<"$1"
}

# ── 명령 실행(실장비 ssh 또는 --mock-dir 로컬 주입) ─────────────────────────
# 반환: stdout에 캡처된 명령 출력. 실패 시 stderr에 사유 출력 + 비정상 종료코드.
run_remote() {
  local host="$1" transport="$2" cmd="$3" slug="$4"

  if [[ -n "$MOCK_DIR" ]]; then
    local f="$MOCK_DIR/${host}/${slug}.txt"
    if [[ -f "$f" ]]; then
      cat "$f"
      return 0
    fi
    echo "mock 파일 없음: $f" >&2
    return 1
  fi

  local ssh_opts=(-o ConnectTimeout="$TIMEOUT" -o StrictHostKeyChecking=accept-new)
  case "$transport" in
    pubkey) ssh_opts+=(-o BatchMode=yes -o PasswordAuthentication=no) ;;
    interactive) ssh_opts+=(-o BatchMode=no) ;;
    *)
      echo "알 수 없는 transport '$transport' (pubkey|interactive만 지원)" >&2
      return 2
      ;;
  esac
  timeout "$TIMEOUT" ssh "${ssh_opts[@]}" "$host" -- "$cmd"
}

# ── 장비 1대 처리 → XML 1개 파일 ─────────────────────────────────────────
process_host() {
  local host="$1" vendor="$2" transport="$3"
  local vendor_lc results_body="" ok=0 fail=0

  vendor_lc="$(echo "$vendor" | tr '[:upper:]' '[:lower:]')"

  local -a entries=()
  if [[ "$vendor_lc" == cisco* ]]; then
    entries=("${CISCO_CMDS[@]}")
  fi

  if [[ ${#entries[@]} -eq 0 ]]; then
    # 미지원 벤더: 명령 미실행. 파서가 dump 0건에서 크래시하지 않도록
    # 전 수집대상 id를 <error>로 채워 "증거 미수집" 상태를 명시적으로 남긴다.
    local items
    items="$(items_xml "$UNSUPPORTED_VENDOR_IDS")"
    results_body+="<dump><items>${items}</items><output><![CDATA[]]></output>"
    results_body+="<error>벤더 '$(xml_escape_attr "$vendor")' 명령 화이트리스트 미구현"
    results_body+="(cisco 외 9벤더는 §5-3 활성화 게이트 대기, scripts/net_collect_mapping.md 참조)</error></dump>"
    echo "[$host] 벤더 '$vendor' 미지원 — 명령 미실행, 전 항목 증거 미수집으로 기록" >&2
  else
    local entry slug cmd ids output rc
    for entry in "${entries[@]}"; do
      IFS='|' read -r slug cmd ids <<<"$entry"
      local items
      items="$(items_xml "$ids")"
      set +e
      output="$(run_remote "$host" "$transport" "$cmd" "$slug" 2>/tmp/fsec_net_err.$$)"
      rc=$?
      set -e
      if [[ $rc -eq 0 ]]; then
        ok=$((ok + 1))
        if [[ $MASK -eq 1 ]]; then
          output="$(printf '%s' "$output" | mask_text)"
        fi
        results_body+="<dump><items>${items}</items><output>$(cdata_wrap "$output")</output>"
        if looks_like_ios_error "$output"; then
          results_body+="<error>명령 '$(xml_escape_attr "$cmd")' 실행됨(exit 0)이나 IOS 오류 마커 감지 — 출력 확인 필요</error>"
        fi
        results_body+="</dump>"
      else
        fail=$((fail + 1))
        local errmsg
        errmsg="$(cat /tmp/fsec_net_err.$$ 2>/dev/null || true)"
        rm -f /tmp/fsec_net_err.$$
        results_body+="<dump><items>${items}</items><output><![CDATA[]]></output>"
        results_body+="<error>명령 '$(xml_escape_attr "$cmd")' 실패(exit=$rc, timeout=${TIMEOUT}s): $(xml_escape_attr "$errmsg")</error></dump>"
        echo "[$host] 명령 실패: $cmd (exit=$rc)" >&2
      fi
      rm -f /tmp/fsec_net_err.$$
    done
  fi

  local safe_host out_file
  safe_host="$(echo "$host" | tr -c 'A-Za-z0-9._-' '_')"
  out_file="${OUT_DIR}/${safe_host}-net-$(date +%Y%m%d).xml"

  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<script>\n'
    printf '<asset>\n'
    printf '<hostname>%s</hostname>\n' "$(xml_escape_attr "$host")"
    printf '<vendor>%s</vendor>\n' "$(xml_escape_attr "$vendor")"
    printf '</asset>\n'
    printf '<results>%s</results>\n' "$results_body"
    printf '</script>\n'
  } > "$out_file"

  echo "[$host] 완료 → $out_file (성공 ${ok}, 실패 ${fail})" >&2
}

# ── 메인: CSV 순회 ───────────────────────────────────────────────────────
line_no=0
while IFS=, read -r host vendor transport || [[ -n "$host" ]]; do
  line_no=$((line_no + 1))
  # 주석/빈 줄 skip
  [[ -z "${host// /}" || "$host" == \#* ]] && continue
  # 헤더 줄(1행에 한해 "host"로 시작) skip
  if [[ $line_no -eq 1 && "$(echo "$host" | tr '[:upper:]' '[:lower:]')" == "host" ]]; then
    continue
  fi
  if [[ -z "${vendor:-}" || -z "${transport:-}" ]]; then
    echo "경고: ${line_no}행 형식 오류(host,vendor,transport 3개 필드 필요) — 건너뜀: $host,$vendor,$transport" >&2
    continue
  fi
  process_host "$host" "$vendor" "$transport"
done < "$CSV"
