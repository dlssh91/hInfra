# 네트워크 장비(CISCO) 45항목 ↔ show 명령 매핑표 — DRAFT (초안)

> **⚠️ 현장 협의 전 초안. 배포용 아님.**
> 실장비 검증 없이 평가기준 텍스트(`ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호)
> 평가자용_2603개정.xlsx` "네트워크 장비" 시트)만으로 구성한 매핑이다. IOS 버전/모델별
> 명령 가용성·출력 포맷 차이는 실수집 샘플 확보 후 재검증 필요(§7-4 참조).
>
> 소스: `docs/superpowers/specs/2026-07-02-remaining-domains-design.md` §5-1.
> 대상: `scripts/fsec_network_collect.sh`(bash 수집기), CISCO 변형만(45항목 전부
> `평가대상(CISCO)` 컬럼='o' — 나머지 9벤더는 §5-3 활성화 게이트 대기, 미구현).

## 명령 화이트리스트 (read-only show 계열, config 모드 진입 없음)

| slug          | 명령                          | 용도 |
|---------------|-------------------------------|------|
| running_config| `show running-config`          | 설정 기반 판정 대다수(아래 41항목) |
| version       | `show version`                | 패치/EOL(NET-048/059) |
| ip_ssh        | `show ip ssh`                 | SSH 활성·버전 실측(NET-015 보조) |
| snmp          | `show snmp`                   | SNMP 런타임 상태(NET-003~006 보조) |
| ntp_status    | `show ntp status`             | NTP 동기화 실측(NET-031 보조) |
| logging       | `show logging`                | 로깅 실측 상태(NET-033~037 보조) |
| int_desc      | `show interfaces description` | 미사용 인터페이스(NET-052, 기준문 "sh int desc" 그대로) |

보조 명령(ip_ssh/snmp/ntp_status/logging/int_desc)은 `show running-config` 판정을
대체하지 않고 **동일 항목에 dump를 추가로 쌓아 증거를 보강**한다(같은 cid가 여러
dump에 등장 → network_xml이 `{cid}#0`, `{cid}#1`, ... 로 유일성 보장, 회귀 테스트
`test_resource_id_unique_across_dumps` 계약과 일치).

## 항목별 매핑

| 항목ID  | 평가항목명(요약)                         | 매핑 명령                          | 비고 |
|---------|-------------------------------------------|-------------------------------------|------|
| NET-001 | 네트워크 장비 설정 백업 여부              | **없음(인터뷰 전용)**               | network.yaml TODO B후보. 명령 증거 없음 → 증거 미수집 자동보류로 흡수(의도된 동작) |
| NET-003 | 안전한 네트워크 모니터링(SNMP) 서비스 사용 | running_config + snmp               | |
| NET-004 | SNMP 커뮤니티 권한 설정 적정성            | running_config + snmp               | |
| NET-005 | SNMP 접근통제(ACL) 설정 여부              | running_config + snmp               | |
| NET-006 | 외부인터페이스 SNMP 접근 차단 여부        | running_config + snmp               | |
| NET-007 | Local 사용자 생성 및 권한관리 여부        | running_config                      | |
| NET-008 | 강화된 인증기능(AAA) 사용 여부            | running_config                      | |
| NET-009 | 중복 비밀번호 및 비밀번호 미설정 금지     | running_config                      | 마스킹 동등성 보존 대상(NET-009) |
| NET-010 | enable secret 설정 여부                   | running_config                      | |
| NET-011 | 안전한 암호화 알고리즘 설정 여부          | running_config                      | |
| NET-012 | 비밀번호 복잡도 정책 준수 여부            | running_config                      | 정책 명령(`security passwords ...`) 노출 시에만 판정 가능 |
| NET-013 | 원격 관리(VTY) 접근 통제 여부             | running_config                      | |
| NET-014 | 세션 타임아웃 설정 여부                   | running_config                      | |
| NET-015 | VTY 안전하지 않은 프로토콜(TELNET) 제한   | running_config + ip_ssh             | |
| NET-016 | 불필요한 AUX 포트 차단 여부               | running_config                      | |
| NET-022 | 불필요한 Source 라우팅 차단               | running_config                      | |
| NET-026 | Proxy ARP 차단 설정 여부                  | running_config                      | |
| NET-027 | IP Directed Broadcast 차단                | running_config                      | |
| NET-030 | 불필요한 서비스 비활성화 여부             | running_config                      | |
| NET-031 | NTP 설정 및 시각 동기화 여부              | running_config + ntp_status         | |
| NET-033 | 로깅 활성화 설정 여부                     | running_config + logging            | |
| NET-034 | 로깅 메시지 시간(timestamp) 설정          | running_config + logging            | |
| NET-035 | 로깅 버퍼 사이즈 설정 여부                | running_config + logging            | |
| NET-036 | 원격 로그서버 연동 설정 여부              | running_config + logging            | |
| NET-037 | 콘솔 로깅 레벨 설정 적정성                | running_config + logging            | |
| NET-038 | 외부 인터페이스 ingress 필터              | running_config                      | |
| NET-039 | 외부 인터페이스 egress 필터               | running_config                      | |
| NET-040 | 스푸핑 방지 필터 설정 여부                | running_config                      | |
| NET-041 | IP 멀티캐스트 차단 설정 여부              | running_config                      | |
| NET-042 | ICMP 차단 설정 여부                       | running_config                      | |
| NET-043 | ICMP redirect 차단 설정 여부              | running_config                      | |
| NET-044 | ICMP unreachable 차단 설정 여부           | running_config                      | |
| NET-045 | ICMP mask-reply 차단 설정 여부            | running_config                      | |
| NET-046 | ICMP timestamp/information 차단           | running_config                      | |
| NET-047 | DDoS 공격 차단 필터링 설정 여부           | running_config                      | |
| NET-048 | 주기적 보안패치/벤더 권고 적용 여부       | version                             | label D 후보(patch_check, `network.yaml` TODO) |
| NET-049 | 명령어 실행 권한 제한 여부                | running_config                      | |
| NET-050 | 로그온 시 경고메시지(banner) 설정 여부    | running_config                      | |
| NET-051 | tcp keepalives 사용 설정 여부             | running_config                      | |
| NET-052 | 미사용 인터페이스 비활성화 설정 여부      | int_desc + running_config           | 기준문이 "sh int desc" 명시 |
| NET-054 | 스위치/허브 보안(port-security 등) 설정   | running_config                      | |
| NET-056 | 비밀번호 주기적 변경관리 여부             | **없음(인터뷰 전용)**               | network.yaml TODO B후보 |
| NET-057 | 취약한 서비스(CDP/LLDP/TFTP 등) 비활성화  | running_config                      | |
| NET-058 | 계정 잠금 임계값 설정 여부                | running_config                      | |
| NET-059 | 서비스 지원종료(EOL) 장비 교체 여부       | version                             | label D 후보(eol_check, eol.yaml CISCO 테이블 추가 선행) |

집계: running_config 41항목(NET-001/048/056/059 제외 41개), version 2항목(048/059),
보조(ip_ssh/snmp/ntp_status/logging/int_desc) 총 11항목 중복 보강, 인터뷰 전용 2항목
(001/056)은 수집기가 의도적으로 미수집 → judge_tool "증거 미수집 자동보류"로 흡수.

## 스크립트-파서 계약 (network_xml.py 재확인, 파서 무변경)

`judge_tool/parsers/network_xml.py` 실제 기대 스키마(문서 헤더·`parse()`/`detect_variant()`
구현 확인, 2026-07-11 기준):

```xml
<?xml version="1.0" encoding="UTF-8|euc-kr"?>
<script>
  <asset>
    <hostname>..</hostname>
    <vendor>Cisco Systems</vendor>   <!-- vendor/os/model 중 하나에 Cisco 토큰 있으면 cisco, 없으면 generic -->
    <model>Catalyst 3750</model>
    <version>IOS 15.2</version>
  </asset>
  <results>
    <dump>
      <items><id>NET-001</id>[<id>NET-002</id>..]</items>
      <output><![CDATA[ raw show 출력 ]]></output>
    </dump>
    ...
  </results>
</script>
```

작업 지시서(§5)의 단순화된 표기 `<dump><id>NET-xxx</id><output>...`(설계 초안 요약)와
달리, **실제 파서는 `<results>` 래퍼 + `<dump><items><id>...` 중첩 구조를 요구**하고
`<dump>` 바로 아래 `<id>`가 아니라 `<items>` 하위에 `<id>`가 온다. 본 문서·스크립트는
이 실제 스키마를 기준으로 한다(파서 소스가 유일한 진실원천).
