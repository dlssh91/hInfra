# WAS 설정파일 별도수집 갭 — 실증 리포트 (2026-07-17)

## 배경
사용자 지적: "WAS 등은 설정파일을 별도로 받아야 한다고 기준서에 적혀있다. 별도로 받아서
판단하도록 진행하라." → 기준서(평가기준 xlsx) 판단방법 전수 확인 + 도커 실증.

## 1. 기준서가 지목하는 WAS 설정파일 (판단방법 원문에서 추출)

| 항목 | tomcat | jeus | webtob | 현 수집기 상태 |
|---|---|---|---|---|
| WST-031 디렉터리 리스팅 | web.xml | — | web.xml | **미수집** |
| WST-035 업로드 용량 | — | domain.xml | domain.xml | jeus만 부분수집 |
| WST-036 프로세스 권한 | — | — | httpd.conf | (webtob) |
| WST-037 경로 설정 | server.xml | — | server.xml | ✅ server.xml 수집중 |
| WST-044 기본계정 | tomcat-users.xml | accounts.xml | — | ✅ tomcat-users.xml 수집중 |
| WST-102 정보노출 | server.xml | — | httpd.conf | ✅ server.xml 수집중 |
| WST-121 프록시 | — | — | httpd-vhosts.conf | **미수집** |
| WST-122 SSI | web.xml | — | — | **미수집** |
| WST-123 에러페이지 | web.xml | jeus-web.xml | web.xml | **미수집** |
| WST-124 LDAP | server.xml | server.xml | — | ✅ server.xml 수집중 |

핵심 갭: **web.xml**(WST-031/122/123)·jeus **domain.xml/jeus-web.xml/accounts.xml**·webtob
**httpd-vhosts.conf**를 수집기(fsi_unix.sh)가 안 떠온다. 기존 수집은 tomcat conf에서
tomcat-users.xml·server.xml **2개뿐**.

## 2. judge_tool 판정 쪽은 이미 준비 완료 (코드 변경 불필요)
`parsers/_common.parse_dumps`가 **완전 id-generic** — `<dump><items><id>WST-XXX</id></items>
<output>…</output>` 형태면 항목 불문 증거로 추출해 판정 라우팅(WST-122/123=label A LLM,
WST-031=det_common)에 넘긴다. **수집만 되면 판정된다.** → 갭은 100% 수집 계층.

## 3. 도커 실증 (tomcat:9 + fsi_unix.sh 패치본)
수집기에 web.xml 수집 블록(WST-031/122/123)을 추가한 패치본으로 재수집 → 판정:
- **결과**: WST-031/122/123 모두 "증거 미수집 판단보류" → **증거 실제 전달됨**(LLM이 web.xml의
  listings/error-page 내용을 근거로 언급). 배관 검증 성공.
- **패치**: `_wst_dump_webxml()` 헬퍼(CATALINA_HOME 도출 후 conf/web.xml + webapps/*/WEB-INF/
  web.xml를 cat, WST-102와 동일 마스킹) → WST-031/122/123 dump 블록에서 호출.
  (패치본 스크래치 보존: `fsi_unix_webxml_patch.sh`. 필드 스크립트=외부 산출물이라 judge_tool 미커밋.)

## 4. 실증 중 발견한 정련 포인트
- **web.xml 보일러플레이트 비대**: tomcat 기본 conf/web.xml = 216KB, 그중 **mime-mapping
  2044개**가 보안무관 보일러플레이트. 24000자 raw 상한(judge.py `_RAW_EVIDENCE_CAP`) 초과 →
  H-2 절단 가드 발동(정상 동작). 보안 관련 지시자(listings@5354·SSI·error-page)는 앞 6KB에
  다 있어 **판정엔 지장 없으나** 절단 플래그가 노이즈. → **수집 시 mime-mapping 제거**
  (`grep -v mime-mapping` 등) 권장. 수집 계층 정련(judge_tool 아님).
- 판정 품질 자체는 production qwen3-coder:30b 필요(이번 실증은 qwen2.5-coder:3b 프록시라
  "증거부족" punt — 배관 검증용이지 품질 측정 아님).

## 5. 조치 방향
- **필드 스크립트팀(외부)**: fsi_unix.sh에 web.xml(+jeus/webtob 설정파일) 수집 추가.
  패치 초안 제공(위 §3). mime-mapping 필터 포함 권장(§4).
- **judge_tool(이 저장소)**: 변경 불필요. 수집 보강 후 실샘플 확보되면 web_cov_contract에
  tomcat WST-031/122/123 양극성 추가로 정식 실검증완료 승격.
