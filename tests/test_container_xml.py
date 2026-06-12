"""container_xml 파서 단위 테스트 (작업⑤).

합성 XML 문자열로 실데이터 없이 실행한다.
"""
import pytest

from judge_tool.errors import ReportError
from judge_tool.parsers.container_xml import detect_variant, parse


# ─ 합성 XML 헬퍼 ──────────────────────────────────────────────────────────────

def _xml(variant_tag="", platform="", role="", dumps=None, encoding="UTF-8"):
    """합성 컨테이너 XML 문자열."""
    asset_extra = ""
    if variant_tag:
        asset_extra += f"<variant>{variant_tag}</variant>\n"
    if platform:
        asset_extra += f"<platform>{platform}</platform>\n"
    if role:
        asset_extra += f"<role>{role}</role>\n"

    if dumps is None:
        dumps = [("PRCC-001", "kubectl get clusterrolebinding -o json")]

    dump_xml = ""
    for ids, output in dumps:
        if isinstance(ids, str):
            ids = [ids]
        id_tags = "".join(f"<id>{i}</id>" for i in ids)
        dump_xml += f"""
<dump>
<items>{id_tags}</items>
<output><![CDATA[{output}]]></output>
</dump>
"""
    return f"""<?xml version="1.0" encoding="{encoding}"?>
<script>
<asset>
<hostname>k8s-master-01</hostname>
{asset_extra}
</asset>
<results>{dump_xml}</results>
</script>
"""


def _write(tmp_path, content, name="report.xml"):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# ─ detect_variant ─────────────────────────────────────────────────────────────

def test_detect_variant_direct_k8s_master(tmp_path):
    p = _write(tmp_path, _xml(variant_tag="k8s_master"))
    assert detect_variant(p) == "k8s_master"


def test_detect_variant_direct_docker_linux(tmp_path):
    p = _write(tmp_path, _xml(variant_tag="docker_linux"))
    assert detect_variant(p) == "docker_linux"


def test_detect_variant_direct_docker_short(tmp_path):
    """약식 'docker' → 'docker_linux'."""
    p = _write(tmp_path, _xml(variant_tag="docker"))
    assert detect_variant(p) == "docker_linux"


def test_detect_variant_platform_role_k8s_master(tmp_path):
    p = _write(tmp_path, _xml(platform="k8s", role="master"))
    assert detect_variant(p) == "k8s_master"


def test_detect_variant_platform_role_eks_worker(tmp_path):
    p = _write(tmp_path, _xml(platform="eks", role="worker"))
    assert detect_variant(p) == "eks_worker"


def test_detect_variant_platform_role_aks_master(tmp_path):
    p = _write(tmp_path, _xml(platform="aks", role="master"))
    assert detect_variant(p) == "aks_master"


def test_detect_variant_platform_role_ocp_worker(tmp_path):
    p = _write(tmp_path, _xml(platform="ocp", role="worker"))
    assert detect_variant(p) == "ocp_worker"


def test_detect_variant_kubernetes_long_form(tmp_path):
    p = _write(tmp_path, _xml(platform="Kubernetes", role="control-plane"))
    assert detect_variant(p) == "k8s_master"


def test_detect_variant_docker_no_role(tmp_path):
    """docker 플랫폼은 role 없어도 docker_linux 반환."""
    p = _write(tmp_path, _xml(platform="docker"))
    assert detect_variant(p) == "docker_linux"


def test_detect_variant_openshift_master(tmp_path):
    p = _write(tmp_path, _xml(platform="openshift", role="master"))
    assert detect_variant(p) == "ocp_master"


def test_detect_variant_unknown_none(tmp_path):
    """platform/role/variant 없음 → None."""
    p = _write(tmp_path, _xml())
    assert detect_variant(p) is None


def test_detect_variant_platform_only_non_docker_none(tmp_path):
    """k8s + role 없음 → 조합 불가 → None."""
    p = _write(tmp_path, _xml(platform="k8s"))
    assert detect_variant(p) is None


def test_detect_variant_direct_overrides_platform_role(tmp_path):
    """direct variant가 platform+role보다 우선."""
    p = _write(tmp_path, _xml(
        variant_tag="eks_master",
        platform="k8s", role="worker",  # 이쪽이면 k8s_worker
    ))
    assert detect_variant(p) == "eks_master"


# ─ parse ──────────────────────────────────────────────────────────────────────

def test_parse_basic(tmp_path):
    p = _write(tmp_path, _xml(dumps=[("PRCC-001", "kubectl output here")]))
    result = parse(p)
    assert len(result) == 1
    cid, resources, ctx = result[0]
    assert cid == "PRCC-001"
    assert ctx is None
    assert len(resources) == 1
    assert "kubectl output here" in resources[0].evidence


def test_parse_multiple_dumps(tmp_path):
    p = _write(tmp_path, _xml(dumps=[
        ("PRCC-001", "output A"),
        ("PRCC-002", "output B"),
        ("PRCC-003", "output C"),
    ]))
    result = parse(p)
    ids = [r[0] for r in result]
    assert ids == ["PRCC-001", "PRCC-002", "PRCC-003"]


def test_parse_multi_id_dump(tmp_path):
    """한 dump에 id 여러 개 → 각 id가 같은 output을 공유."""
    p = _write(tmp_path, _xml(dumps=[
        (["PRCC-001", "PRCC-002"], "shared output"),
    ]))
    result = parse(p)
    assert len(result) == 2
    assert result[0][0] == "PRCC-001"
    assert result[1][0] == "PRCC-002"
    assert result[0][1][0].evidence == result[1][1][0].evidence


def test_parse_empty_output_no_resources(tmp_path):
    """output이 공백뿐 → resources=[] (판단보류 가드 동작)."""
    p = _write(tmp_path, _xml(dumps=[("PRCC-007", "   ")]))
    result = parse(p)
    assert result[0][1] == []


def test_parse_resource_id_counter(tmp_path):
    """같은 cid가 여러 dump에 등장해도 resource_id 고유 보장."""
    p = _write(tmp_path, _xml(dumps=[
        ("PRCC-001", "output A"),
        ("PRCC-001", "output B"),
    ]))
    result = parse(p)
    rids = [r[1][0].resource_id for r in result if r[1]]
    assert rids[0] == "PRCC-001#0"
    assert rids[1] == "PRCC-001#1"


def test_parse_no_dump_raises(tmp_path):
    """dump 없는 XML → ReportError."""
    content = """<?xml version="1.0"?>
<script><asset><hostname>h</hostname></asset><results></results></script>"""
    p = _write(tmp_path, content)
    with pytest.raises(ReportError):
        parse(p)


def test_parse_invalid_xml_raises(tmp_path):
    p = _write(tmp_path, "not xml at all <<broken>>")
    with pytest.raises(ReportError):
        parse(p)


def test_parse_nonexistent_path_raises():
    with pytest.raises((ReportError, FileNotFoundError, OSError)):
        parse("/nonexistent/container.xml")


# ─ 민감 마스킹 ────────────────────────────────────────────────────────────────

def test_parse_masks_long_hex(tmp_path):
    hex_secret = "a" * 40  # 40자 hex → 마스킹
    p = _write(tmp_path, _xml(dumps=[("PRCC-001", f"token: {hex_secret}")]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert hex_secret not in ev
    assert "<REDACTED>" in ev


def test_parse_masks_crypt_hash(tmp_path):
    crypt = "$6$rounds=5000$salt12345678$" + "A" * 43 + "B" * 43
    p = _write(tmp_path, _xml(dumps=[("PRCC-007", f"root:{crypt}:18000:")]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert crypt not in ev
    assert "<REDACTED 해시>" in ev


def test_parse_masks_pem_key(tmp_path):
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    p = _write(tmp_path, _xml(dumps=[("PRCC-012", pem)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "MIIEowIBAAKCAQEA" not in ev
    assert "BEGIN RSA PRIVATE KEY" in ev  # 마커는 보존
    assert "<REDACTED>" in ev


def test_parse_preserves_normal_output(tmp_path):
    normal = "NAME                  ROLE\nk8s-master  control-plane"
    p = _write(tmp_path, _xml(dumps=[("PRCC-001", normal)]))
    result = parse(p)
    assert normal in result[0][1][0].evidence


def test_parse_masks_jwt_token(tmp_path):
    """ServiceAccount/Bearer JWT 토큰 마스킹 (H1 수정)."""
    jwt = ("eyJhbGciOiJSUzI1NiIsImtpZCI6Imtl"
           ".eyJpc3MiOiJrdWJlcm5ldGVzL3Nlcn"
           ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    p = _write(tmp_path, _xml(dumps=[("PRCC-001", f"token: {jwt}")]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert jwt not in ev
    assert "<REDACTED JWT>" in ev


def test_parse_masks_k8s_secret_base64(tmp_path):
    """kubectl Secret YAML data 블록 base64 값 마스킹 (H1 수정)."""
    yaml_output = (
        "apiVersion: v1\n"
        "data:\n"
        "  tls.crt: MIIFwDCCA6ugAwIBAgIIAkW2ENHJLQ==\n"
        "  tls.key: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==\n"
        "kind: Secret\n"
    )
    p = _write(tmp_path, _xml(dumps=[("PRCC-001", yaml_output)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "MIIFwDCCA6ugAwIBAgIIAkW2ENHJLQ==" not in ev
    assert "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==" not in ev
    assert "<REDACTED base64>" in ev
    assert "apiVersion" in ev     # 비밀 아닌 필드 보존
    assert "kind: Secret" in ev


def test_parse_short_base64_not_masked(tmp_path):
    """짧은 값(<20자)은 마스킹하지 않는다."""
    output = "  name: my-secret\n  namespace: default\n"
    p = _write(tmp_path, _xml(dumps=[("PRCC-001", output)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "my-secret" in ev
    assert "default" in ev


def test_parse_base64_no_false_positive_pure_digits(tmp_path):
    """순수 숫자 값(resourceVersion 등)은 base64 오탐되지 않는다."""
    output = "  resourceVersion: 12345678901234567890123\n  generation: 9876543210987654321\n"
    p = _write(tmp_path, _xml(dumps=[("PRCC-001", output)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "12345678901234567890123" in ev
    assert "<REDACTED base64>" not in ev


def test_parse_base64_no_false_positive_url_path(tmp_path):
    """소문자 URL 경로(k8s selfLink 등)는 base64 오탐되지 않는다."""
    # 소문자+숫자+슬래시만 → _is_base64_like=False (대문자 없음, 패딩 없음)
    output = "  selfLink: /api/v1/namespaces/default/pods/mypodname123456789012345\n"
    p = _write(tmp_path, _xml(dumps=[("PRCC-001", output)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "mypodname" in ev
    assert "<REDACTED base64>" not in ev


def test_parse_euc_kr_encoding(tmp_path):
    """EUC-KR 인코딩 XML 파싱 + 마스킹 체이닝 확인."""
    jwt = ("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Q"
           ".eyJzdWIiOiJzeXN0ZW1zZXJ2aWNlYWNjb3"
           ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    cdata = f"token: {jwt}"
    # EUC-KR XML 바이트 직접 작성: CDATA에 ASCII만 쓰면 인코딩 무관
    content = (
        b'<?xml version="1.0" encoding="euc-kr"?>\n'
        b'<script>\n'
        b'<asset><hostname>test</hostname>'
        b'<variant>k8s_master</variant></asset>\n'
        b'<results>\n'
        b'<dump><items><id>PRCC-001</id></items>'
        b'<output><![CDATA[' + cdata.encode("ascii") + b']]></output></dump>\n'
        b'</results>\n</script>\n'
    )
    p = tmp_path / "euckr.xml"
    p.write_bytes(content)
    result = parse(str(p))
    assert result[0][0] == "PRCC-001"
    ev = result[0][1][0].evidence
    assert jwt not in ev
    assert "<REDACTED JWT>" in ev


# ─ 파서 레지스트리 등록 확인 ──────────────────────────────────────────────────

def test_parser_registry():
    from judge_tool.parsers import get_parser
    parser = get_parser("container_xml")
    assert hasattr(parser, "parse")
    assert hasattr(parser, "detect_variant")
