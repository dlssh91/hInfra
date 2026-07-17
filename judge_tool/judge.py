import json
import re
from typing import Dict

import requests

from judge_tool.models import (
    Criterion, EvidenceItem, Judgment, GOOD_STATUSES)

SYSTEM_PROMPT = (
    "당신은 전자금융기반시설 보안 취약점 평가자다. "
    "주어진 '판단기준'과 '점검 증거'만 근거로 해당 항목의 취약 여부를 판정한다. "
    "추측하지 말고 증거에 없는 사실을 지어내지 않는다. "
    "증거가 판단기준을 충족하면 '양호', 위배되면 '취약', "
    "근거가 부족하거나 관리체계(문서·인터뷰) 확인이 필요한 부분이면 '판단보류'로 판정한다. "
    "증거의 '[bad]', '[good]', '[review]', '[info]' 태그는 스크립트의 예비 분류일 뿐이며, "
    "판정은 반드시 evidence 안의 실제 값을 판단기준과 직접 대조하여 독립적으로 내려야 한다. "
    "특히 '[info]' 태그에 '인터뷰로 확인' 지시가 있으면 기술 증거만으로 단정하지 말고 '판단보류'로 처리한다. "
    "\n\n[환경변수 판단 예시 — 키 이름이 아니라 값을 보고 판단]\n"
    "• PASSWORD_LENGTH=32          → 숫자·설정값, 비밀번호 아님 → 민감정보 아님\n"
    "• SECRETS_MANAGER_ENDPOINT=https://secretsmanager.amazonaws.com → URL, 민감정보 아님\n"
    "• enc=AQICAH...               → AWS KMS 암호문(이미 암호화됨) → 민감정보 아님\n"
    "• DB_PASSWORD=MyP@ssw0rd!     → 평문 비밀번호 → 민감정보\n"
    "• API_KEY=sk-abc123XYZ...     → 평문 API 키 → 민감정보\n\n"
    "[계정·리소스 이름 판단 예시 — 이름만으로 단정 금지]\n"
    "• USER=test, test_admin 계정 존재 → 이름만으로 불필요 단정 불가, 담당자 인터뷰 필요 → 판단보류\n"
    "• 관리자 권한이 부여된 계정이 존재함 → '업무상 필요한지'는 기술 증거만으로 단정 불가, 담당자 인터뷰 확인 필요 → 판단보류\n"
    "• Lambda 함수명 'test', S3 버킷 생성일이 오래됨 → 불필요 여부는 담당자 인터뷰로 확인 → 판단보류\n\n"
    "[숫자 설정값 판단 예시 — '설정이 존재함'과 '기준을 충족함'은 다르다]\n"
    "• wait_timeout=28800 설정이 존재함 → 이것만으로 양호가 아님. 값 28800초 vs 기준 900초(15분) 비교 필요\n"
    "• wait_timeout=28800 > 900(기준) → 세션이 8시간 동안 유지됨 → 기준 초과 → 취약\n"
    "• wait_timeout=600 < 900(기준) → 세션이 10분 내 종료됨 → 기준 충족 → 양호\n"
    "• MAX_PASSWORD_ERRORS=3, 판단기준 5회 이하 → 3 ≤ 5 → 기준 충족 → 양호\n"
    "• default_password_lifetime=90일 설정 존재 → 90일마다 비밀번호 변경 강제됨 → 분기(90일) 1회 기준 충족 → 양호\n\n"
    "[빈 출력·수집 마커 판단 — '위반 없음(양호)'과 '데이터 없음(판단보류)'을 구별]\n"
    "• 위반 항목을 나열하는 점검에서, 명령이 정상 실행됐고(에러 메시지 없음) 출력이 비어 있으면 → 위반 0건 → 양호.\n"
    "  (예: '$ find /dev -type f -exec ls -l {} \\;' 한 줄만 있고 그 뒤 아무 출력도 없음 = 명령 정상 실행, 불필요 파일 없음 → 양호)\n"
    "  (예: 'find /dev -type f' 결과가 비어 있음 = 불필요 파일 없음 → 양호)\n"
    "• '[not exist]' 또는 '위반 목록: (비어있음)' 류 마커는 점검 스크립트가 '해당 위반 항목 없음'을 표시한 것 → 양호.\n"
    "• 단, 아래 경우는 양호로 단정 금지 → 판단보류:\n"
    "  - 점검 명령 자체가 수집에 실패(예: 'ntpq: not found'처럼 시간동기화 상태를 읽을 도구 자체가 없음 → NTP 설정 확인 불가)\n"
    "  - 점검 대상 설정 파일이 없어서 값을 읽을 수 없음(예: '/etc/rsyslog.conf: No such file' → 로그 설정 확인 불가)\n"
    "• 주의: '보안 기능이 미설치·미설정된 것이 확인됨'은 판단보류가 아닐 수 있다. 판단기준이 '방화벽/tcp-wrapper 등 접근통제 수단이 있어야 양호'인데 어떤 수단도 발견되지 않으면 → 취약일 수 있다.\n"
    "• 요약: '정상 실행 + 빈 결과 = 양호', '측정 도구/설정 파일 부재 = 판단보류', '보안 기능 자체 부재 = 취약 가능'. 셋을 혼동하지 말 것.\n\n"
    "[파일 권한 문자열(symbolic mode) 판독 — 끝 3자리가 others, 가운데 3자리가 group]\n"
    "• `-rwxrwxrwx`처럼 10자리 중 첫 자리는 파일 종류, 이어지는 9자리는 [소유자 rwx][그룹 rwx][others rwx] 순서다.\n"
    "• `-rw-r--r--` = 소유자 읽기·쓰기, 그룹 읽기, others 읽기 → others에 '읽기' 권한이 있다(8진수 644). 끝의 `r--`도 엄연한 권한이며 '권한 없음'이 절대 아니다.\n"
    "• `-rw-r-----` = 소유자 rw, 그룹 r, others 없음 → 8진수 640. 그룹 읽기 비트가 있으므로 600(`-rw-------`)이 아니다.\n"
    "• 8진수 환산: rwx=7, rw-=6, r-x=5, r--=4, -wx=3, -w-=2, --x=1, ---=0. 각 3자리 그룹을 따로 환산해 붙인다(예: `rw-r--r--`→644).\n"
    "• 판단기준이 'others 권한 없어야 양호'면 끝 3자리가 정확히 `---`일 때만 양호 — 끝자리에 r/w/x가 하나라도 있으면 취약.\n"
    "• ★흔한 오판 주의: 읽기(`r`)도 엄연한 권한이다. `-rw-r--r--`의 끝 `r--`는 'others에 읽기 권한 있음'이다. '실행(x)·쓰기(w)가 없으니 others 권한 없음'은 틀린 해석 — 읽기(r) 하나만 있어도 'others에 권한이 있는' 것이다. 따라서 '환경파일·설정파일에 others 권한이 없어야 양호'라는 기준에서 `-rw-r--r--`(644)는 others 읽기 권한이 있으므로 반드시 → 취약(양호 아님).\n"
    "• 판단기준이 '권한 NNN 이하'면 symbolic을 8진수로 환산해 NNN과 비교한다(예: 기준 644인데 `-rwxrwxrwx`=777 → 초과 → 취약).\n\n"
    "[서비스 상태 블록 마커 `[ 이름 ][S] … [ 이름 ][E]` 판독 — [S]와 [E] 사이가 실제 실행 상태]\n"
    "• 점검 스크립트는 서비스 실행 여부를 `[ 서비스명 ][S]`(블록 시작)와 `[ 서비스명 ][E]`(블록 끝) 사이에 출력한다.\n"
    "• [S]와 [E] 사이가 비어 있으면 → 해당 서비스가 실행 중이지 않음(프로세스·포트 미발견). [S] 줄에 나열된 서비스 '이름'은 점검 대상 목록일 뿐 '실행 중'이라는 뜻이 아니다.\n"
    "• 판단기준이 '불필요 서비스가 실행 중이면 취약'인데 모든 블록이 비어 있으면 → 실행 중 서비스 없음 → 양호. 블록이 비었는데 이름만 보고 '활성화 상태'라고 단정하지 말 것.\n\n"
    "반드시 아래 키를 가진 JSON 하나만 출력한다(설명·마크다운 금지):\n"
    '{"verdict": "양호|취약|판단보류", "confidence": 0.0~1.0, '
    '"rationale": "한국어 근거 2~4문장", '
    '"cited_evidence": ["인용한 리소스ID 또는 핵심 증거 문자열", ...]}'
)

# status 분류는 models.GOOD_STATUSES 를 단일 출처로 사용한다.
_GOOD = GOOD_STATUSES

# ── 컨텍스트 예산 계약 ──────────────────────────────────────────────────────
# 프롬프트 총량 ≈ SYSTEM_PROMPT(≈2k tok) + 판단기준/방법(≈1k tok)
#              + 증거(_RAW_EVIDENCE_CAP=24,000자 ≈ 최악 12k tok) + 응답 여유.
# Ollama는 num_ctx 미지정 시 기본값(대개 4096 tok)으로 **입력을 무음 절단**
# 하므로, 증거 뒷부분의 위반 행이 소실되어 거짓양호가 날 수 있다(C-1).
# _NUM_CTX는 위 총량을 덮도록 설정하며, _RAW_EVIDENCE_CAP을 늘릴 때는
# 반드시 이 값도 함께 재계산해야 한다.
_RAW_EVIDENCE_CAP = 24000
_NUM_CTX = 16384

# raw 증거 절단 마커(build_evidence_text_raw가 부착) — judge_item이 이
# 마커로 절단 발생을 감지해 evidence_truncated 플래그를 세운다(H-2).
_TRUNCATION_MARKER = "행 생략)"


def build_evidence_text(item: EvidenceItem, max_chars: int = 8000) -> str:
    """증거를 텍스트로 직렬화.

    증거가드 핵심계약: primary(취약 후보 = status가 good/info가 아닌 리소스)는
    max_chars를 **의도적으로 무시하고 전량 보존**한다. 상한(max_chars)은
    good/info(보조 증거)에만 적용되어 상한 내에서만 추가되고 나머지는 축약·생략된다.
    리소스가 하나도 없으면 "(증거 없음)"을 반환한다.
    C1 격리: is_raw_carrier=True 리소스는 LLM 증거에서 제외한다.
    """
    def fmt(r):
        return (f"- [{r.status}] {r.resource_id} :: {r.detail}\n"
                f"  evidence: {r.evidence}")

    # C1: carrier 제외 — LLM에 det_common 전용 더미 리소스가 들어가지 않게 한다.
    real_resources = [r for r in item.resources
                      if not getattr(r, "is_raw_carrier", False)]
    primary = [r for r in real_resources if r.status.lower() not in _GOOD]
    secondary = [r for r in real_resources if r.status.lower() in _GOOD]

    lines = [fmt(r) for r in primary]
    used = sum(len(l) for l in lines)
    shown_secondary = 0
    for r in secondary:
        block = fmt(r)
        if used + len(block) > max_chars:
            break
        lines.append(block)
        used += len(block)
        shown_secondary += 1

    omitted = len(secondary) - shown_secondary
    if omitted > 0:
        lines.append(f"... (양호/정보 리소스 {omitted}건 축약·생략됨)")
    # C1: carrier-only이거나 리소스 자체가 없으면 "(증거 없음)" 신호 복원
    if not real_resources:
        return "(증거 없음)"
    return "\n".join(lines)


def build_evidence_text_raw(item: EvidenceItem,
                            max_chars: int = _RAW_EVIDENCE_CAP) -> str:
    """원시증거(DB) 직렬화: 사전분류 status가 없으므로 전수 보존이 기본.

    context(QUERY/NOTE)를 상단에 두고 모든 행을 직렬화한다. 행이 한 그룹키로
    반복되는 결과(예: GRANTEE)는 그룹별 요약을 병기한다. 총량이 max_chars를
    넘으면 행을 잘라 "M행 중 N행 표시, K행 생략"을 명시한다.
    C1 격리: is_raw_carrier=True 리소스는 LLM 증거에서 제외한다.
    carrier-only이면 "(점검 결과 0건)" 신호를 반환한다(M3 해소).
    """
    head = (item.context + "\n") if item.context else ""
    # C1: carrier 제외 — det_common 전용 더미를 LLM 증거 텍스트에서 분리
    real_resources = [r for r in item.resources
                      if not getattr(r, "is_raw_carrier", False)]
    if not real_resources:
        return head + "(점검 결과 0건)"
    lines = [r.evidence if r.evidence else r.detail for r in real_resources]
    summary = _group_summary(real_resources)
    body_head = head + (summary + "\n" if summary else "")
    total = len(lines)
    shown, used = [], len(body_head)
    for ln in lines:
        if used + len(ln) + 1 > max_chars:
            break
        shown.append(ln)
        used += len(ln) + 1
    out = body_head + "\n".join(shown)
    if len(shown) < total:
        out += f"\n... ({total}행 중 {len(shown)}행 표시, {total - len(shown)}행 생략)"
    return out


def _group_summary(resources) -> str:
    """행들이 'GRANTEE' 같은 그룹키 + 값(PRIVILEGE_TYPE)을 가지면 그룹별
    값 집합 요약을 만든다. 해당 구조가 아니면 빈 문자열."""
    groups = {}
    for r in resources:
        try:
            d = json.loads(r.evidence)
        except Exception:  # noqa: BLE001
            return ""
        if not isinstance(d, dict) or "GRANTEE" not in d:
            return ""
        groups.setdefault(d.get("GRANTEE", ""), set()).add(
            d.get("PRIVILEGE_TYPE", ""))
    if not groups:
        return ""
    parts = ["[요약] 계정별 권한집합:"]
    for k, vs in groups.items():
        vlist = sorted(v for v in vs if v)
        shown = ", ".join(vlist[:12])
        if len(vlist) > 12:
            shown += f" ...(+{len(vlist) - 12})"
        line = f"  {k}: [{len(vlist)}]"
        parts.append(f"{line} {shown}" if shown else line)
    return "\n".join(parts)


def build_prompt(criterion: Criterion, item: EvidenceItem,
                 max_chars: int = 8000,
                 evidence_mode: str = "preclassified") -> str:
    scope_note = ""
    if criterion.is_mixed:
        scope_note = (
            "\n[중요] 이 항목은 '관리체계+스크립트' 혼합이다. "
            "판단기준 중 기술/스크립트로 확인 가능한 부분만 대조해 판정하고, "
            "관리체계(문서·정책·인터뷰) 영역은 판정 근거로 삼지 말 것.")
    if criterion.variant == "generic":
        scope_note += ("\n[중요] 장비 벤더 미식별 — 벤더중립 판단기준을 적용한다. "
                       "특정 벤더(Cisco 등) 명령 문법을 가정하지 말고, 증거 설정이 "
                       "판단기준의 보안 요구를 의미적으로 충족하는지로 판정하라. "
                       "장비 역할(라우터/스위치 등)에 명백히 해당 없는 기준이면 판단보류.")
    if evidence_mode == "raw":
        evidence = build_evidence_text_raw(item, max(max_chars, _RAW_EVIDENCE_CAP))
    else:
        evidence = build_evidence_text(item, max_chars)
    return (
        f"평가항목: {criterion.item_id} {criterion.item_name} "
        f"(위험도 {criterion.risk})\n"
        f"변형: {criterion.variant}\n"
        f"--- 판단기준 ---\n{criterion.standard}\n"
        f"--- 판단방법 ---\n{criterion.method}\n"
        f"{scope_note}\n"
        f"--- 점검 증거 ---\n{evidence}\n"
        f"--- 위 판단기준에 따라 JSON으로 판정하라. ---"
    )


def parse_json_lenient(text: str) -> Dict:
    """코드펜스/후행콤마/백틱을 허용하는 관대한 JSON 파서.

    복구는 단계적으로 시도한다:
      0) 원문 그대로 파싱.
      1) 후행 콤마만 제거하고 재시도(백틱은 그대로 보존 — 흔한 경우인
         '백틱 인용 + 후행콤마'를 evidence 손상 없이 복구).
      2) 그래도 실패하면 백틱→따옴표 치환까지 적용해 마지막 재시도
         (백틱이 키 구분자로 잘못 쓰인 비정상 출력 대비).

    모든 복구 시도가 실패하면 마지막 단계의 ``json.JSONDecodeError``를
    그대로 raise 한다. 호출부(Task 7)가 이를 잡아 처리할 책임을 진다.
    """
    t = text.strip()
    t = re.sub(r"^```(?:json)?", "", t).strip()
    t = re.sub(r"```$", "", t).strip()
    start, end = t.find("{"), t.rfind("}")
    if start != -1 and end != -1:
        t = t[start:end + 1]
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    # 1단계: 후행 콤마만 제거 (백틱 보존)
    t1 = re.sub(r",\s*([}\]])", r"\1", t)
    try:
        return json.loads(t1)
    except json.JSONDecodeError:
        pass
    # 2단계: 백틱 → 따옴표 치환까지 적용한 마지막 재시도
    t2 = t1.replace("`", '"')
    return json.loads(t2)


def _to_float(v, default: float = 0.0) -> float:
    """안전 float 캐스팅. 변환 불가 시 default 반환."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


_VALID_VERDICTS = {"양호", "취약", "판단보류"}
# verdict 정규화(M-1)에서 허용하는 잔여 접미(공백·구두점 제거 후).
# "양호함"→양호 같은 무해한 어미만 흡수하고, "양호하지 않음"처럼 의미가
# 뒤집힐 수 있는 꼬리는 절대 흡수하지 않는다(방향 뒤집힘 = 판정 오염).
_VERDICT_SUFFIX_OK = frozenset({"", "함", "임", "입니다", "합니다"})


def _normalize_verdict(v) -> str | None:
    """LLM verdict 어휘를 보수적으로 정규화한다. 확신 없으면 None(재시도).

    저성능 모델이 "양호함"/"판단 보류"/"취약." 같은 변형을 내면 정확일치
    검증에 걸려 정답이 판단보류로 새는 recall 손실이 있었다(M-1).
    허용: 표준 3어휘 + 내부공백 제거 + 무해 어미(_VERDICT_SUFFIX_OK).
    그 외(부정형·복합문 등)는 전부 None — 방향이 바뀔 여지는 흡수 금지.
    """
    if not isinstance(v, str):
        return None
    compact = v.strip().replace(" ", "")
    if compact in _VALID_VERDICTS:
        return compact
    # "판단보류"를 먼저 검사 — "판단"으로 시작하는 다른 어휘와의 혼동 방지.
    for base in ("판단보류", "양호", "취약"):
        if compact.startswith(base):
            rest = compact[len(base):].strip(" .!?()·")
            if rest in _VERDICT_SUFFIX_OK:
                return base
    return None
# 스크립트 status → 기대 verdict (비교 가능한 것만)
_STATUS_TO_VERDICT = {"good": "양호", "bad": "취약"}
_LOW_CONFIDENCE = 0.6


class OllamaClient:
    def __init__(self, url: str = "http://localhost:11434",
                 model: str = "qwen3-coder:30b", temperature: float = 0.0,
                 timeout: int = 120, num_ctx: int = _NUM_CTX):
        self.url = url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.num_ctx = num_ctx

    def chat(self, system: str, user: str) -> str:
        """판정용 호출 — JSON 출력을 Ollama format으로 문법 강제한다."""
        return self._chat(system, user, format_="json")

    def chat_text(self, system: str, user: str) -> str:
        """산문용 호출(인터뷰요약 등) — format 미강제.

        format:"json"을 걸면 모델이 산문을 낼 수 없어 SUMMARY_SYSTEM_PROMPT의
        'JSON 금지' 계약과 정면 충돌한다(H-1). 요약 경로는 반드시 이 메서드를
        사용해야 산문 출력이 가능하다.
        """
        return self._chat(system, user, format_=None)

    def _chat(self, system: str, user: str, format_) -> str:
        payload = {
            "model": self.model,
            "stream": False,
            # num_ctx 미지정 시 Ollama 기본(대개 4096 tok)이 대형 프롬프트를
            # 무음 절단해 증거 소실(거짓양호)이 날 수 있다 — 반드시 명시(C-1).
            "options": {"temperature": self.temperature,
                        "num_ctx": self.num_ctx},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if format_:
            payload["format"] = format_
        resp = requests.post(
            f"{self.url}/api/chat", json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    def health_check(self) -> None:
        """Ollama 서버 가동 여부와 self.model 존재 여부를 확인한다.

        신규 네트워크 접점을 추가하지 않는다 — 기존 self.url(보통
        localhost:11434) 에 GET /api/tags 만 호출한다(기존 chat()의
        POST /api/chat과 동일 호스트). 실패(서버 미가동/모델 미설치) 시
        RuntimeError를 던진다. 호출부(main.run)가 한글 안내로 감싼다.

        태그 비교는 ':latest' 등 접미사 차이를 허용하기 위해 콜론 앞
        base name까지 일치하면 통과로 본다(예: 'qwen3-coder:30b' 요청에
        'qwen3-coder:30b-q4' 태그만 있어도 base 'qwen3-coder' 일치로는
        통과시키지 않도록, base 비교는 원본 태그가 정확히 없을 때의
        완화 조건으로만 사용 — 정확한 태그 우선, 없으면 base 일치도 허용).
        """
        try:
            resp = requests.get(f"{self.url}/api/tags", timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:  # noqa: BLE001 - 서버 미가동/네트워크 오류 등 원인 다양
            raise RuntimeError(
                f"Ollama 서버({self.url})에 연결할 수 없습니다: {type(e).__name__}"
            ) from e
        names = {m.get("name", "") for m in (data.get("models") or [])
                if isinstance(m, dict)}
        base_names = {n.split(":")[0] for n in names}
        want = self.model
        # 태그가 명시된 요청(콜론 포함, 예: 'qwen3-coder:30b')은 정확 일치만
        # 허용한다 — ':7b'/':30b-q4' 등 다른 태그만 설치돼 있으면 chat()이
        # 404를 받아 "조용히 전부 판단보류"로 새므로 헬스체크가 반드시 거른다.
        # 태그 미지정 요청('qwen3-coder')일 때만 base 일치 완화를 적용한다.
        if ":" in want:
            if want in names:
                return
        else:
            if want in names or want in base_names:
                return
        installed = ", ".join(sorted(names)) or "(설치된 모델 없음)"
        raise RuntimeError(
            f"모델 '{want}'을 찾을 수 없습니다. 설치된 모델: {installed}")


SUMMARY_SYSTEM_PROMPT = (
    "당신은 전자금융기반시설 보안점검 보조자다. "
    "주어진 점검 증거를 요약 지시에 따라 평가자가 담당자 인터뷰에 활용할 수 있는 형태로 정리하라.\n\n"
    "【출력 형식 — 절대 규칙】\n"
    "- 출력은 반드시 순수 자연어 텍스트(문장 형식)여야 한다.\n"
    "- JSON·YAML·마크다운·불릿(-)·번호 목록은 일절 사용 금지.\n"
    "- 중괄호{}, 대괄호[]는 출력에 포함하지 말 것.\n"
    "- 올바른 예시: '계정 admin@%는 27개 권한을 보유한다. testuser는 SELECT 권한만 있다. 담당자에게 확인이 필요하다.'\n"
    "- 잘못된 예시: {\"admin\": [\"SELECT\", ...]} 또는 - admin: 권한 27개\n\n"
    "판정(양호/취약)을 내리지 말 것. 사실만 요약한다. "
    "한국어로 5~10문장 이내. 마지막 문장은 인터뷰 확인 사항을 명시한다."
)


def _strip_fences(text: str) -> str:
    t = text.strip()
    t = re.sub(r"^```(?:json)?", "", t).strip()
    return re.sub(r"```$", "", t).strip()


def _looks_like_json(text: str) -> bool:
    t = _strip_fences(text)
    return t.startswith("{") or t.startswith("[")


def _json_to_prose(text: str) -> str:
    """JSON 요약을 'key: value' 들여쓰기 줄글로 평탄화하는 최후 폴백.

    LLM이 산문 재요청까지 무시했을 때, Excel '인터뷰요약' 셀에서
    중괄호 덩어리 대신 사람이 읽을 수 있는 형태를 보장한다.
    파싱 불가면 원문을 그대로 반환한다.
    """
    try:
        data = json.loads(_strip_fences(text))
    except (json.JSONDecodeError, ValueError):
        return text
    out: list = []

    def render(obj, depth=0):
        pad = "  " * depth
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    out.append(f"{pad}{k}:")
                    render(v, depth + 1)
                else:
                    out.append(f"{pad}{k}: {v}")
        elif isinstance(obj, list):
            for v in obj:
                if isinstance(v, (dict, list)):
                    render(v, depth)
                else:
                    out.append(f"{pad}- {v}")
        else:
            out.append(f"{pad}{obj}")

    render(data)
    return "\n".join(out)


# 증거 행에서 '값' 토큰만 추출: 콜론 뒤의 따옴표 문자열(3자 이상).
# 키 이름(": 앞")을 제외해야 모든 행에 반복되는 키("rolname" 등)가 요약에
# 등장한다는 이유로 행이 '반영됨'으로 잘못 집계되는 것을 막는다.
# json.loads를 쓰지 않는 이유: PG 증거처럼 작은따옴표·NULL을 쓰는 유사
# JSON 행은 파싱이 전부 실패해 안전망이 무력화된다(실데이터에서 관측).
_VALUE_TOKEN = re.compile(r":\s*['\"]([^'\"]{3,})['\"]")


def _summary_coverage(item: EvidenceItem, summary: str):
    """요약이 증거 행들을 얼마나 반영했는지 추정. (covered, total) 반환.

    각 증거 행의 값 토큰 중 하나라도 요약에 등장하면 그 행은 '반영됨'으로
    센다. 토큰을 못 뽑는 행은 분모에서 제외한다. LLM이 증거 첫 행만
    요약하는 실패 모드(PG Aurora DBM-003에서 관측)를 감지하는 안전망.
    """
    covered = total = 0
    for r in item.resources:
        tokens = _VALUE_TOKEN.findall(r.evidence or "")
        if not tokens:
            continue
        total += 1
        if any(t in summary for t in tokens):
            covered += 1
    return covered, total


def _summary_prompt(criterion: Criterion, evidence: str) -> str:
    instruction = (criterion.summary_instruction
                   or "증거를 간결하게 요약하라. 판정하지 말 것.")
    return (
        f"평가항목: {criterion.item_id} {criterion.item_name}\n"
        f"--- 점검 증거 ---\n{evidence}\n"
        f"--- 요약 지시 ---\n{instruction}"
    )


def summarize_item(criterion: Criterion, item: EvidenceItem, client,
                   evidence_mode: str = "raw") -> str:
    """B항목: LLM으로 증거를 요약하여 인터뷰 보조 텍스트 반환.

    견고성 계약:
    - 1차 호출 실패(ReadTimeout 등) → 증거를 8000자로 줄여 1회 재시도,
      성공 시 '일부만 요약됨' 표시. 그래도 실패하면 [요약 실패] 마커.
    - 출력이 JSON이면 위반을 명시해 산문으로 1회 재요청, 그래도 JSON이면
      코드에서 'key: value' 줄글로 평탄화(_json_to_prose).
    """
    # 대형 증거 타임아웃 대비 축소 사다리: 전체 → 8000자 → 3000자.
    # (Oracle DBM-004 실데이터에서 8000자도 타임아웃하는 사례 관측)
    if evidence_mode == "raw":
        sizes = (_RAW_EVIDENCE_CAP, 8000, 3000)
        build = build_evidence_text_raw
    else:
        sizes = (8000, 4000, 2000)
        build = build_evidence_text

    # 산문 계약: format:"json" 강제가 없는 chat_text를 우선 사용한다(H-1).
    # 테스트 더블 등 chat_text가 없는 클라이언트는 chat으로 폴백(하위호환).
    chat = getattr(client, "chat_text", None) or client.chat

    out = None
    truncated = False
    last_err: Exception = RuntimeError("미시도")
    for i, max_chars in enumerate(sizes):
        prompt = _summary_prompt(criterion, build(item, max_chars))
        try:
            out = chat(SUMMARY_SYSTEM_PROMPT, prompt)
            truncated = i > 0
            break
        except Exception as e:  # noqa: BLE001
            last_err = e
    if out is None:
        return f"[요약 실패: {type(last_err).__name__}]"

    if _looks_like_json(out):
        try:
            retry = prompt + ("\n\n[재요청] 직전 응답이 JSON 형식이었다. "
                              "중괄호·대괄호·따옴표 키 없이 한국어 줄글 "
                              "문장으로만 다시 작성하라.")
            out2 = chat(SUMMARY_SYSTEM_PROMPT, retry)
            out = out2 if not _looks_like_json(out2) else _json_to_prose(out2)
        except Exception:  # noqa: BLE001 - 재요청 실패 시 1차 응답 평탄화
            out = _json_to_prose(out)

    if truncated:
        out += "\n(주의: 증거가 커서 일부 행만 요약에 반영됨)"

    # 요약-증거 커버리지 안전망: 증거가 3행 이상인데 절반 미만만 반영되면
    # 평가자가 원본 증거를 대조하도록 경고를 부착한다.
    covered, total = _summary_coverage(item, out)
    if total >= 3 and covered < total * 0.5:
        out += (f"\n(주의: 증거 {total}행 중 {covered}행만 요약에 반영된 "
                f"것으로 보임 — 원본 증거 대조 필요)")
    return out


def judge_item(criterion: Criterion, item: EvidenceItem, client,
               max_chars: int = 8000, retries: int = 2,
               evidence_mode: str = "preclassified") -> Dict:
    """LLM 호출 후 검증된 판정 dict 반환. JSON 실패 시 재시도.

    JSON 파싱 실패만 재시도하며, 네트워크/HTTP 예외(requests 예외) 및
    응답 구조 오류는 호출부(Task 9) 책임으로 전파한다.
    """
    prompt = build_prompt(criterion, item, max_chars, evidence_mode)
    # H-2: raw 증거가 상한에 걸려 잘렸으면(뒷행 위반 소실 가능) 플래그를
    # 세워 reconcile이 needs_review를 강제하게 한다. 마커 재검출을 위해
    # build_prompt와 동일 인자로 증거만 재직렬화한다(순수 문자열 연산).
    evidence_truncated = False
    if evidence_mode == "raw":
        ev = build_evidence_text_raw(item, max(max_chars, _RAW_EVIDENCE_CAP))
        evidence_truncated = _TRUNCATION_MARKER in ev
    last_err = None
    for _ in range(retries + 1):
        raw = client.chat(SYSTEM_PROMPT, prompt)
        try:
            data = parse_json_lenient(raw)
        except json.JSONDecodeError as e:
            last_err = e
            continue
        # 유효 JSON이지만 객체(dict)가 아닌 경우(예: ["양호"], 스칼라):
        # data.get(...) 이 AttributeError 를 던지므로 가드 후 재시도.
        if not isinstance(data, dict):
            last_err = ValueError("JSON 객체 아님")
            continue
        verdict = _normalize_verdict(data.get("verdict"))
        if verdict is not None:
            data["verdict"] = verdict
            data["confidence"] = _to_float(data.get("confidence", 0.0))
            data.setdefault("rationale", "")
            data.setdefault("cited_evidence", [])
            data["evidence_truncated"] = evidence_truncated
            return data
        last_err = ValueError(f"잘못된 verdict: {data.get('verdict')}")
    # 모든 시도 실패 → 판단보류로 안전 처리.
    # 보안: 예외 본문에는 LLM 응답 원문(evidence 반향 가능)이 섞일 수 있으므로
    # 예외 타입명/고정문구만 노출하고 raw 응답은 rationale 에 넣지 않는다.
    err_name = type(last_err).__name__ if last_err is not None else "Unknown"
    return {"verdict": "판단보류", "confidence": 0.0,
            "rationale": f"LLM 응답 파싱 실패({err_name})", "cited_evidence": [],
            "evidence_truncated": evidence_truncated}


def reconcile(llm: Dict, criterion: Criterion, item: EvidenceItem, *,
              status_available: bool = True,
              flag_vulnerable_for_review: bool = False,
              empty_means_good: bool = False) -> Judgment:
    if status_available:
        script_status = item.overall_status
        expected = _STATUS_TO_VERDICT.get(script_status)
    else:
        script_status = None
        expected = None
    verdict = llm.get("verdict", "판단보류")
    confidence = _to_float(llm.get("confidence", 0.0))
    rationale = llm.get("rationale", "")

    if expected is None:
        agreement = "N/A"
    else:
        agreement = "일치" if verdict == expected else "불일치"

    # spec 6.7: script_status 가 "error" 이거나 증거가 전혀 없으면 신뢰할 수
    # 없으므로 LLM verdict 와 무관하게 판단보류로 강제하고 검토 대상으로 표시.
    # 단 empty_means_good(위반 0건=양호 후보)면 무증거 강제 보류에서 제외.
    # cited_evidence 는 보존한다.
    # C1 격리: carrier 리소스는 실증거가 아니므로 no_evidence 판정에서 제외.
    # carrier-only(실증거 0건)인 경우 no_evidence=True → LLM 양호 무검증 통과 차단.
    real_evidence = [r for r in item.resources
                     if not getattr(r, "is_raw_carrier", False)]
    no_evidence = (not real_evidence) and not empty_means_good
    if (script_status == "error" or no_evidence) and verdict != "판단보류":
        verdict = "판단보류"
        reason = "증거 없음" if no_evidence else "스크립트 점검 오류(error)"
        note = f"[자동 판단보류: {reason}]"
        rationale = f"{rationale} {note}".strip()

    # H-2: 증거가 상한 절단된 판정은 LLM이 위반 행을 못 봤을 수 있다 —
    # verdict는 유지하되 반드시 사람 검토로 보내고 근거에 명시한다.
    evidence_truncated = bool(llm.get("evidence_truncated"))
    if evidence_truncated:
        rationale = (f"{rationale} [주의: 증거 일부가 분량 상한으로 절단되어 "
                     f"판정에 미반영됐을 수 있음 — 원본 증거 대조 필요]").strip()

    needs_review = (
        agreement == "불일치"
        or confidence < _LOW_CONFIDENCE
        or criterion.is_mixed
        or verdict == "판단보류"
        # script_status 가 good/bad 로 매핑되지 않으면(미지/review/error 등)
        # 양호/취약 자동 대조가 불가하므로 사람 검토가 필요하다.
        or expected is None
        or (flag_vulnerable_for_review and verdict == "취약")
        or evidence_truncated
    )
    return Judgment(
        item_id=criterion.item_id,
        item_name=criterion.item_name,
        variant=criterion.variant,
        risk=criterion.risk,
        verdict=verdict,
        confidence=confidence,
        rationale=rationale,
        cited_evidence=list(llm.get("cited_evidence", [])),
        scope="스크립트 부분만" if criterion.is_mixed else "스크립트 전체",
        management_review_needed=criterion.is_mixed,
        script_status=script_status,
        agreement=agreement,
        needs_review=needs_review,
    )
