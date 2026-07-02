# 잔여 도메인 스크립트·활성화 구현설계 (서버/웹-WAS/컨테이너/OS가상화/네트워크/비FW 정보보호시스템)

> 작성: 2026-07-02 (Fable 설계). 전제: 8개 도메인 코드 구조(파서+Profile+item_configs+테스트)는 전부 완료.
> 병목은 코드가 아니라 **도메인별 수집 스크립트·실수집 샘플**(PROGRESS.md 로드맵 확정 사실).
> 공통 원칙: 기존분류 따라가기 + 양극성 픽스처/듀얼런 안전망(운영 컨셉 2026-06-17) · 거짓양호 봉쇄 · LLM은 맥락 항목만(qwen3-coder:30b).

## 도메인별 현황 × 다음 액션 요약

| 도메인 | 구조 | 스크립트 | 샘플 | 다음 액션(설계 §) |
|---|---|---|---|---|
| 서버(OS) | ✅(5변형, cov 계약 완료) | ✅ fsi_unix.sh/fsi_win.bat | ❌ | §1 자가수집(도커/VM) |
| 웹서버-WAS | ✅(11변형, Phase3 SHIP) | ✅(서버 스크립트 공유) | △ apache만 | §2 자가수집 확대 |
| 컨테이너 | ✅(9변형) | ✅ fsec_container_script.sh | ❌ | §3 kind 클러스터 실증 |
| OS 가상화 | ✅(3변형) | ✅ vmware.ps1/xen.sh | ❌ | §4 현장 샘플 대기 + 선행 보강 |
| 네트워크 장비 | ✅(cisco+generic) | ❌ | ❌ | §5 수집 스크립트 신규 설계 |
| 정보보호시스템(비FW) | △ iss_device 스텁 | ❌ | ❌ | §6 수집 방식 확정 |

## §1 서버(OS) — 도커/VM 자가수집으로 샘플 확보 (DB 도커 실증 패턴 재사용)

DB 도메인에서 검증된 "도커 실데이터 재검토 트랙" 패턴을 서버에 적용.
1. **Linux**: ubuntu/rocky 컨테이너(또는 로컬 VM)에서 `scripts/서버/fsi_unix.sh` 실행 → `{hostname}-s-{date}.xml` 실샘플 확보. 컨테이너 한계(systemd/커널 항목)는 "미수집→보류" 동작 확인용으로도 가치 있음.
2. **검증 시나리오**: (a) detect_variant 실포맷 확인(M2 게이트 — `<asset><os>` 실제 문자열), (b) 마스킹 실검증(crypt/PEM, L2 평문 시크릿 갭), (c) 양극성 — 컨테이너에 의도적 취약설정 주입(good/vuln 두 상태 수집)해 cov 계약 픽스처를 실포맷으로 업그레이드.
3. **Windows/AIX/HP-UX/Solaris**: 로컬 재현 불가 → 현장 샘플 요청 목록에 등재(§7). win은 로컬 Windows VM 보유 시 fsi_win.bat 시도.
4. 잔여 게이트 처리 순서: M2(변형 오식별) → empty_means_good 식별(fsi_unix.sh 위반필터형 명령 분석) → L2 마스킹 확장 → M-c(개인키 백트래킹, 대용량 방어).

## §2 웹서버-WAS — apache 외 10변형 샘플 확대

1. **도커로 가능**: tomcat, nginx(변형 존재 시), apache 변형 OS(이미 확보). JEUS/WebtoB는 라이선스 필요 → 현장 요청.
2. **IIS**: Windows VM 필요. WST-040 xlsx 역전(판단기준/판단방법 셀) **사용자 확인 게이트** — 확인 전 MANUAL 유지.
3. 각 변형 샘플 확보 시: WST 결정론(det_adapters/webwas.py) 실포맷 검증 + 합성 픽스처 57건을 실데이터 기반으로 승격.

## §3 컨테이너 — kind 클러스터 실증 (가장 저비용으로 샘플 창출 가능)

1. **선행(코드, 샘플 확보 전 즉시 가능)**: `profile.normalize_id`에 `PRC-C-NNN`→`PRCC-NNN` 정규화 보강(★활성화 차단 갭, PROGRESS ⑤-0). 회귀테스트 포함.
2. kind(또는 minikube) 클러스터 + docker에서 `fsec_container_script.sh` 실행 → 실 XML 확보 → (a) `<id>` 실표기 확인, (b) detect_variant(`<asset><variant>` vs `<platform>+<role>`) 확정, (c) 민감 마스킹(secret/configmap) 검증.
3. container.yaml 50항목 라벨분류(판단기준 정독, B/C/D 후보 분리) → 양극성 픽스처(good/vuln 클러스터 설정) → cov 계약 테스트(srv/db 패턴 동형).

## §4 OS 가상화 — 로컬 재현 불가, 현장 샘플 선행

ESXi/vCenter/XenServer는 랩 구축 비용이 큼(중첩가상화·라이선스) → **현장 샘플 요청이 임계경로**.
샘플 대기 중 선행 가능한 것:
1. 컬럼 역전(판단방법 col15/17/19 < 판단기준 col16/18/20) 회귀 핀 테스트 유지([[osvirt-column-inversion]]).
2. 하이퍼바이저 특화 마스킹 패턴 초안(vpxuser/SSO 토큰 — Opus [L1] 최우선) — 공개 문서의 토큰 형태 기준으로 패턴 작성, 실데이터 확보 시 검증.
3. osvirt.yaml 35항목 사전 라벨분류(판단기준 원문만으로 B/C/D 후보: PRCV-003/022=B, 패치성=D).

## §5 네트워크 장비 — 수집 스크립트 신규 설계 (스크립트·샘플 모두 부재)

장비에 셸이 없어 on-host 수집 불가 → **관리호스트 실행형 수집기** 신규 설계.
1. **수집기 형태(권고)**: bash + 표준 ssh(공개키/대화식) 기반 `fsec_network_collect.sh`.
   - 입력: 장비 목록 CSV(host,vendor,transport). 출력: 장비별 XML 엔벨로프(`<asset><vendor>` + `<dump><id>NET-xxx</id><output><![CDATA[...]]></output></dump>`) — 현 network_xml PROVISIONAL 가정과 일치 → **파서 무변경**.
   - 명령 화이트리스트: **read-only show 계열만**(cisco: show running-config, show version, show ip ssh, show snmp, show ntp status, show logging 등 45항목 매핑표 별도 산출). config 모드 진입 금지.
   - 실패 내성: 장비별 타임아웃·명령별 실패 기록(<error> 태그) — 미수집은 judge_tool "증거 미수집 자동보류"로 흡수.
2. **폴백 경로(수집기 배포 불가 현장)**: 수기 템플릿 — 운영자가 show 출력 텍스트를 항목별로 붙여넣는 xlsx/txt 템플릿 + 변환기(`scripts/net_manual_to_xml.py`)로 동일 엔벨로프 생성. 두 경로 모두 파서 입력 계약 동일.
3. **판정 측 잔여**: cisco 외 9벤더 VariantSpec(std/method 18/19 공유라 등록 위주) → 실수요 벤더부터. generic 폴백은 영구 유지. network.yaml 45항목 라벨분류(NET-001=B, NET-048=D patch, NET-059=D eol[CISCO Lifecycle 테이블 eol.yaml 추가 선행], NET-056=B).
4. **마스킹**: 수집기 단계에서 1차(type-7/community 등 정규식 치환 옵션) + 파서 16패턴 2차 — 이중 방어. Opus 재리뷰 잔존 갭(F5 단일행 secret, bgp neighbor password 인라인)은 실 config 확보 시 보강.
5. **버전별 기준선 정제(사용자 제안 2026-07-02)**: Cisco 등은 버전계열별 공홈 안내서(hardening guide)가 원문으로 산재 → 점검자 개별 검색 부담. **prep 단계에서 정제해 `net_baseline.yaml`류 정적 기준선**(버전계열×항목 기대설정, as_of 스탬프+출처 URL — eol.yaml/[[patch-eol-baseline-policy]] 패턴) 구축. 기계적 지시(예: `no ip http server`)는 det 판정, 맥락 항목은 **정제 발췌를 qwen3 프롬프트에 주입**해 판정(런타임 온라인 조회 금지). 단계: ① 실수집 샘플 버전 인벤토리 → ② 상위 빈도 버전만 정제(전수 금지) → ③ 버전 미식별 시 generic 폴백+판단보류 가드. 분기별 as_of 갱신.

## §6 정보보호시스템 비-FW 5변형 (VPN/IDS/IPS/DDoS/WAF)

1. **수집 방식 확정이 선행**: 이 장비군은 CLI보다 관리 UI export(정책/설정 리포트)가 일반적 → 장비별 export 포맷 수집 요청(§7) 후 어댑터 설계. FW의 "정책 export + 포맷 sniff + capability 맵" 패턴 재사용.
2. iss.yaml 주석 처리된 5변형 등록은 실샘플 확보 후(추측 구현 금지). 그 전까지 비-FW 장비는 `iss_device`(iss_xml) 경로 + 증거 미수집 자동보류가 정답 동작.
3. FW 그룹객체 확장(fw-implementation-design §B-1) 완료 후 착수 — ObjectTable/aux 인프라를 공유하게 설계.

## §7 현장(담당자) 요청 목록 — 도구 외부 의존성 일괄

1. 서버: AIX/HP-UX/Solaris/Windows 실수집 샘플(`{hostname}-s-{date}.xml`).
2. 웹-WAS: IIS/WebtoB/JEUS/Tomcat 실수집 샘플 + WST-040 기준 xlsx 셀 역전 여부 확인.
3. OS가상화: ESXi/vCenter/Xen 수집 결과 1식(+ 수집 스크립트 실행 환경 확인).
4. 네트워크: 수집기 배포 가능 여부(ssh 접근·계정) 또는 수기 템플릿 채택 결정, 대상 벤더 목록.
5. 정보보호시스템: VPN/IDS/IPS/DDoS/WAF 장비별 관리 UI export 샘플(헤더 확인용 — FW와 동일 대외비 경계 적용 [[fw-data-confidential-header-only]]).
6. 기존 백로그: DB 수집 스크립트 보완(PG DBM-005/006/019, MSSQL DBM-013/019/035/036, Oracle DBM-013), mysql.sql 2건 수정 반영, MariaDB 인코딩 재수집.

## 실행 우선순위 권고 (Fable)

1. **방화벽 Phase A/B** (별도 설계문서) — 샘플 있고 즉시 진행 가능, ★현재 다음 착수.
2. **컨테이너 normalize_id 갭 수정**(코드만, 30분급) + kind 실증 — 자가수집 가능한 유일한 미검증 도메인.
3. **서버/웹-WAS 리눅스 자가수집**(도커) — cov 픽스처의 실포맷 승격 + M2/마스킹 게이트 해소.
4. **네트워크 수집기 설계서 확정 → 담당자 협의** — 외부 의존이라 조기 착수(리드타임 김).
5. OS가상화·비FW 정보보호시스템 — 현장 샘플 도착 시. 대기 중 선행과제(§4-2/3, §6-1)만.
