"""server_xml.py raw_evidence 분리 테스트 (§7 누출 경계 검증).

검증:
  - shadow 해시/개인키가 든 가짜 서버 XML → parse()
  - evidence(마스킹본): <REDACTED 있음, 원문 비밀 없음
  - raw_evidence: 원문 비밀 있음 (분리 검증)
  - 빈 output → raw_evidence=None
  - evidence 필드가 ResourceEvidence의 공식 필드로 노출됨(누출 경계)
"""
import os
import textwrap
import tempfile

import pytest

from judge_tool.parsers.server_xml import parse


def _make_server_xml(output_cdata: str, item_ids=("SRV-070",)) -> str:
    """가짜 서버 XML 문자열 생성 헬퍼."""
    ids_xml = "".join(f"<id>{i}</id>" for i in item_ids)
    return textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <script>
          <asset>
            <hostname>test-host</hostname>
            <os>Linux x86_64</os>
          </asset>
          <results>
            <dump>
              <items>{ids_xml}</items>
              <output><![CDATA[{output_cdata}]]></output>
            </dump>
          </results>
        </script>
    """)


def _write_tmp_xml(content: str) -> str:
    """임시 XML 파일 경로 반환 (테스트 후 정리)."""
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


class TestRawEvidenceSeparation:
    """§7 raw_evidence 분리 계약 검증."""

    def test_shadow_hash_masked_in_evidence(self):
        """shadow 해시가 evidence(마스킹본)에 나타나지 않는다."""
        secret = "root:$6$rounds=5000$saltvalue123$abcdefghijklmnopqrstuvwxyz012345678901234567890123456789012:0:0:root:/root:/bin/bash"
        xml_content = _make_server_xml(secret)
        path = _write_tmp_xml(xml_content)
        try:
            results = parse(path)
            assert results, "dump 결과가 있어야 함"
            res = results[0][1][0]
            # evidence에 원문 해시 없음
            assert "$6$rounds=5000$saltvalue123$" not in res.evidence, \
                "evidence(마스킹본)에 shadow 해시 원문이 노출되면 안 됨"
            # evidence에 REDACTED 있음
            assert "<REDACTED" in res.evidence, \
                "evidence(마스킹본)에 마스킹 토큰이 있어야 함"
        finally:
            os.unlink(path)

    def test_shadow_hash_present_in_raw_evidence(self):
        """shadow 해시 원문이 raw_evidence에 있다."""
        secret = "root:$6$rounds=5000$saltvalue123$abcdefghijklmnopqrstuvwxyz012345678901234567890123456789012:0:0:root:/root:/bin/bash"
        xml_content = _make_server_xml(secret)
        path = _write_tmp_xml(xml_content)
        try:
            results = parse(path)
            res = results[0][1][0]
            assert res.raw_evidence is not None, "raw_evidence가 None이면 안 됨"
            assert "$6$rounds=5000$saltvalue123$" in res.raw_evidence, \
                "raw_evidence에 shadow 해시 원문이 있어야 함"
        finally:
            os.unlink(path)

    def test_private_key_masked_in_evidence(self):
        """SSH 개인키 블록이 evidence에 노출되지 않는다."""
        secret_body = "AAAA" + "B" * 100 + "CCCC"  # 가짜 키 본문
        output = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{secret_body}\n"
            "-----END RSA PRIVATE KEY-----\n"
            "other output"
        )
        xml_content = _make_server_xml(output)
        path = _write_tmp_xml(xml_content)
        try:
            results = parse(path)
            res = results[0][1][0]
            assert secret_body not in res.evidence, \
                "evidence에 개인키 본문이 노출되면 안 됨"
            assert "<REDACTED>" in res.evidence, \
                "evidence에 REDACTED 마커가 있어야 함"
        finally:
            os.unlink(path)

    def test_private_key_present_in_raw_evidence(self):
        """SSH 개인키 원문이 raw_evidence에 있다."""
        secret_body = "AAAA" + "B" * 100 + "CCCC"
        output = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{secret_body}\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        xml_content = _make_server_xml(output)
        path = _write_tmp_xml(xml_content)
        try:
            results = parse(path)
            res = results[0][1][0]
            assert res.raw_evidence is not None
            assert secret_body in res.raw_evidence, \
                "raw_evidence에 개인키 원문이 있어야 함"
        finally:
            os.unlink(path)

    def test_empty_output_raw_evidence_is_none(self):
        """빈 output → raw_evidence=None."""
        xml_content = textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <script>
              <asset>
                <hostname>test-host</hostname>
                <os>Linux x86_64</os>
              </asset>
              <results>
                <dump>
                  <items><id>SRV-001</id></items>
                  <output><![CDATA[   ]]></output>
                </dump>
                <dump>
                  <items><id>SRV-002</id></items>
                  <output><![CDATA[some output]]></output>
                </dump>
              </results>
            </script>
        """)
        path = _write_tmp_xml(xml_content)
        try:
            results = parse(path)
            # SRV-001: 빈 output → resources 빈 리스트, raw_evidence 없음
            srv001_results = [(r, evs) for r, evs, _ in results if r == "SRV-001"]
            assert srv001_results, "SRV-001 결과 있어야 함"
            _, evs = srv001_results[0]
            assert evs == [], "빈 output → resources 빈 리스트"
            # SRV-002: 출력 있음 → raw_evidence 있음
            srv002_results = [(r, evs) for r, evs, _ in results if r == "SRV-002"]
            assert srv002_results
            _, evs2 = srv002_results[0]
            assert evs2, "출력 있는 항목은 resources 있어야 함"
            assert evs2[0].raw_evidence is not None
        finally:
            os.unlink(path)

    def test_evidence_and_raw_are_different_when_masked(self):
        """마스킹이 발생하면 evidence와 raw_evidence가 다르다."""
        # 32+ 연속 hex → 마스킹 대상
        long_hex = "a" * 40  # SHA1 해시 길이
        output = f"hash value: {long_hex}"
        xml_content = _make_server_xml(output)
        path = _write_tmp_xml(xml_content)
        try:
            results = parse(path)
            res = results[0][1][0]
            assert long_hex not in res.evidence, \
                "evidence에 긴 hex가 마스킹되지 않음"
            assert long_hex in res.raw_evidence, \
                "raw_evidence에 원문 hex가 있어야 함"
            assert res.evidence != res.raw_evidence
        finally:
            os.unlink(path)

    def test_no_sensitive_data_raw_evidence_equals_output(self):
        """민감 정보 없으면 evidence == raw_evidence (마스킹 없음)."""
        output = "root:x:0:0:root:/root:/bin/bash\nno secrets here"
        xml_content = _make_server_xml(output)
        path = _write_tmp_xml(xml_content)
        try:
            results = parse(path)
            res = results[0][1][0]
            # 민감 정보 없으면 마스킹 없어 둘 다 동일
            assert res.evidence == res.raw_evidence, \
                "민감 정보 없으면 evidence == raw_evidence"
        finally:
            os.unlink(path)

    def test_raw_evidence_not_in_multiple_items_from_same_dump(self):
        """같은 dump의 여러 id가 각각 raw_evidence를 가진다."""
        secret = "root:$6$salt$" + "x" * 86 + ":0:0:root:/root:/bin/bash"
        xml_content = _make_server_xml(secret, item_ids=("SRV-070", "SRV-071"))
        path = _write_tmp_xml(xml_content)
        try:
            results = parse(path)
            assert len(results) == 2
            for cid, evs, _ in results:
                assert evs, f"{cid}에 resources 있어야 함"
                assert evs[0].raw_evidence is not None, f"{cid} raw_evidence 있어야 함"
                assert "$6$salt$" in evs[0].raw_evidence
        finally:
            os.unlink(path)
