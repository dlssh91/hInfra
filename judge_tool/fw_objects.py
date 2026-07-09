"""FW 그룹객체(named object) 해석 테이블 — B′-3b.

방화벽 정책 export에는 흔히 주소/서비스를 "그룹명"(named object)으로 참조한다
(예: `WEB_SERVERS_GRP`, `HTTP_SVC`). fw_policy.resolve_policies()는 IP/CIDR/
포트로 직접 파싱되지 않는 토큰을 일단 `unresolved_src/dst/svc`에 보존만
한다(B′-3a). 이 모듈은 그 미해석 토큰을 **실제로 해석**하기 위한 인프라다 —
사용자가 `--aux-objects <파일>`로 그룹정의 매핑을 제공하면, resolve_policies가
그룹→멤버로 치환해 unresolved가 실판정(src_ips/dst_ips/dst_ports)으로
복귀한다.

⚠️ 실 방화벽 export 포맷은 벤더/버전마다 상이하고 현 데이터셋(ref/FW)에는
객체/그룹 정의 시트가 아예 없음이 확인됐다(2026-07-10 Fable 실사). 그래서
이 모듈은 실 export 포맷 어댑터가 아니라 **우리가 정의한 캐노니컬 YAML
포맷**을 로드한다 — 실 객체 export 어댑터는 현장 요청 대기 중인 후속 과제.

캐노니컬 YAML 포맷::

    address:
      WEB_GRP: ["10.0.1.0/24", "DMZ_GRP"]   # 값 = IP/CIDR/범위 문자열 또는
                                             # 다른 객체명(중첩 그룹 참조)
      DMZ_GRP: ["172.16.0.0/16"]
    service:
      WEB_SVC: ["80", "443", "ALT_SVC"]
      ALT_SVC: ["8080"]

최상위는 `address`/`service` 두 섹션(둘 다 선택, 없으면 빈 매핑으로 간주).
각 섹션은 {객체명: [문자열, ...]} 매핑이어야 한다. 값 리스트의 각 원소는
IP/CIDR/포트 문자열이거나 같은 섹션 내 다른 객체명(중첩)일 수 있다.

로드 실패는 **조용히 빈 테이블로 넘어가지 않는다**(fail-closed) — 파일
부재, YAML 파싱 오류, 스키마 불일치(최상위가 dict가 아님 / 섹션이 dict가
아님 / 값이 문자열 리스트가 아님) 모두 `judge_tool.errors.ReportError`로
명확히 알린다. `--aux-objects`를 잘못 지정했는데 조용히 무시되어 "치환이
안 되는데 이유를 모르는" 상황을 막기 위함이다.
"""
from dataclasses import dataclass, field
from typing import Dict, List

import yaml

from judge_tool.errors import ReportError

# 중첩 그룹 해석 깊이 상한. 이 값을 초과하는 체인은 순환은 아니더라도
# 비정상적으로 깊은 설계 오류로 간주해 미해석 취급한다(부분 확장 금지).
_MAX_DEPTH = 8


@dataclass
class ObjectTable:
    """그룹객체 정의 테이블 — {객체명: [멤버 문자열, ...]} 두 섹션."""
    address: Dict[str, List[str]] = field(default_factory=dict)
    service: Dict[str, List[str]] = field(default_factory=dict)


class UnresolvableError(Exception):
    """그룹 해석이 순환 참조 또는 깊이초과로 불가능함을 알리는 신호.

    `resolve_name()` 내부에서 발생하며, 호출측(`fw_policy.resolve_policies`)이
    이를 잡아 해당 토큰 전체를 미해석으로 유지한다(부분 결과 반환 금지).
    """


def load_aux_objects(path: str) -> ObjectTable:
    """캐노니컬 YAML 파일을 읽어 ObjectTable로 반환.

    fail-closed: 파일 부재/YAML 오류/스키마 불일치는 모두 명확한 메시지의
    `ReportError`로 던진다(조용한 빈 테이블 반환 금지).
    """
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise ReportError(
            f"--aux-objects 파일을 찾을 수 없습니다: {path}"
        ) from e
    except yaml.YAMLError as e:
        raise ReportError(
            f"--aux-objects 파일 YAML 파싱 오류: {path} ({e})"
        ) from e
    except OSError as e:
        raise ReportError(
            f"--aux-objects 파일을 열 수 없습니다: {path} "
            f"({type(e).__name__})"
        ) from e

    if raw is None:
        raise ReportError(f"--aux-objects 파일이 비어 있습니다: {path}")
    if not isinstance(raw, dict):
        raise ReportError(
            f"--aux-objects 스키마 오류: 최상위는 매핑(address/service)이어야 "
            f"합니다: {path}"
        )

    address = _validated_section(raw.get("address", {}) or {}, "address", path)
    service = _validated_section(raw.get("service", {}) or {}, "service", path)
    return ObjectTable(address=address, service=service)


def _validated_section(
    section: object, name: str, path: str
) -> Dict[str, List[str]]:
    """address/service 섹션 스키마 검증: {str: [str, ...]} 매핑이어야 함."""
    if not isinstance(section, dict):
        raise ReportError(
            f"--aux-objects 스키마 오류: '{name}' 섹션은 매핑이어야 합니다: "
            f"{path}"
        )
    for key, members in section.items():
        if not isinstance(key, str):
            raise ReportError(
                f"--aux-objects 스키마 오류: '{name}' 섹션의 키는 문자열이어야 "
                f"합니다({key!r}): {path}"
            )
        if not isinstance(members, list) or not all(
            isinstance(m, str) for m in members
        ):
            raise ReportError(
                f"--aux-objects 스키마 오류: '{name}.{key}' 값은 문자열 "
                f"리스트여야 합니다: {path}"
            )
    return section


def resolve_name(table: ObjectTable, kind: str, name: str) -> List[str]:
    """table의 kind("address"|"service") 섹션에서 name을 재귀 해석.

    중첩 그룹(멤버가 다시 같은 섹션의 다른 객체명인 경우)을 leaf(더 이상
    그 섹션의 키가 아닌 문자열 — IP/CIDR/포트 또는 테이블에 없는 미지
    토큰)까지 재귀적으로 펼쳐 leaf 문자열 리스트로 반환한다.

    visited-set으로 순환 참조를 감지하고, 재귀 깊이가 `_MAX_DEPTH`(8)를
    넘으면 `UnresolvableError`를 던진다 — 부분 결과를 반환하지 않고
    호출측이 원 토큰 전체를 미해석으로 유지하게 한다.
    """
    section = table.address if kind == "address" else table.service
    return _expand_member(section, name, visited=frozenset(), depth=0)


def _expand_member(
    section: Dict[str, List[str]],
    member: str,
    visited: "frozenset[str]",
    depth: int,
) -> List[str]:
    if member not in section:
        # 그 섹션의 키가 아님 = leaf(비객체 토큰). IP/포트 파싱 가능여부는
        # 호출측(resolve_policies)이 판단한다.
        return [member]
    if depth >= _MAX_DEPTH:
        raise UnresolvableError(
            f"중첩 그룹 해석 깊이 상한({_MAX_DEPTH}) 초과: '{member}'"
        )
    if member in visited:
        raise UnresolvableError(f"순환 참조 감지: '{member}'")

    next_visited = visited | {member}
    out: List[str] = []
    for child in section[member]:
        out.extend(_expand_member(section, child, next_visited, depth + 1))
    return out
