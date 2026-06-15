# 점검 결과파일 획득 현황 (2026-06-15)

자동판정 8개 도메인 × 점검대상별로 **점검 결과파일 획득 여부**를 분류한다.
획득 경로: ① Docker 실행 수집(collected/), ② 제공받은 실샘플(results/·ref/FW/).
이후 작업: 획득한 결과로 **스크립트 결과 유효성을 local LLM이 얼마나 잘 판단하는지** 검토.

## 폴더 배치
- `collected/` — 신규 Docker 수집 (쓰기 가능, 본 디렉터리)
- `results/` — 기존 제공 실샘플 (불변 계약, 그대로 유지)
- `ref/FW/` — 방화벽 정책 샘플 (불변)
- `scripts/check_scripts/{cloud,server,db,virtualization}` — 제공 점검 스크립트

---

## ✅ 결과파일 획득 (점검 가능)

| 분야 | 점검대상 | 획득 경로 | 위치 | 파서 검증 |
|---|---|---|---|---|
| 클라우드 | AWS | 제공 실샘플 | results/Public Cloud/aws_report_*.xml | (기검증) |
| 클라우드 | Azure | 제공 실샘플 | results/Public Cloud/azure_report_*.xml | (기검증) |
| DB | MySQL 네이티브 | **Docker 수집** | collected/db/mysql_native/ | db_json ✓ 25항목 마스킹 |
| DB | MySQL RDS/Aurora/Azure | 제공 실샘플 | results/DB/MySQL/ | (기검증) |
| DB | MariaDB 네이티브 | **Docker 수집** | collected/db/mariadb_native/ | db_json ✓ 26항목 마스킹 |
| DB | MariaDB RDS | 제공 실샘플 | results/DB/MariaDB/ | (기검증) |
| DB | PostgreSQL 네이티브 | **Docker 수집** | collected/db/postgresql_native/ | db_json ✓ 21항목 마스킹 |
| DB | PostgreSQL RDS/Aurora/Azure | 제공 실샘플 | results/DB/PostgreSQL/ | (기검증) |
| DB | MS-SQL 네이티브 | **Docker 수집** | collected/db/mssql_native/ | db_json ✓ 18항목 마스킹 |
| DB | MS-SQL RDS | 제공 실샘플 | results/DB/MS-SQL/ | (기검증) |
| DB | Oracle 네이티브 | **Docker 수집** | collected/db/oracle_native/ | db_json ✓ 27항목(일부 23c 권한차) |
| DB | Oracle RDS | 제공 실샘플 | results/DB/Oracle/ | (기검증) |
| 서버 | Linux | **Docker 수집** | collected/server/linux/ | server_xml ✓ SRV67+WST7 |
| 웹서버-WAS | Apache (on Linux) | **Docker 수집** | collected/web/apache_linux/ | webwas_xml ✓ WST 7종 증거적재 |
| 컨테이너 | k8s_master | **Docker 수집(kind)** | collected/container/k8s_master/ | container_xml ✓ 39항목, 기준매칭 36/39 |
| 정보보호(방화벽) | FW 정책 | 제공 실샘플 | ref/FW/보안장비 결과/ (20+건) | (정책 export 방식) |

## ❌ 결과파일 미획득

| 분야 | 점검대상 | 미획득 사유 |
|---|---|---|
| 서버/웹 | AIX·HP-UX·Solaris | POWER/PA-RISC/SPARC 독자 아키텍처 — Docker 이미지 없음 (출력포맷은 Linux 동일→파서 호환) |
| 서버/웹 | Windows·IIS | Windows 컨테이너는 mac/linux Docker 불가 (fsi_win.bat 실 Windows 필요) |
| 웹서버-WAS | WebtoB·JEUS | TmaxSoft 상용 — 공개 이미지 없음 |
| DB | Tibero | 상용 — 이미지 없음 (profile excluded) |
| OS 가상화 | vCenter·ESXi·XenServer | 하이퍼바이저 실인프라 필요 (중첩가상화 비현실적). Xen 스크립트는 서버 동일 XML→파서 호환 |
| 컨테이너 | EKS/AKS/OCP/k8s_worker/Docker | k8s_master는 kind로 수집 완료(위). 나머지 변형은 실 클라우드(EKS/AKS)·OCP·워커노드 필요 |
| 네트워크 | Cisco·generic | 실장비 필요 + 점검 스크립트 미제공 |
| 정보보호 | VPN·IDS·IPS·DDoS·WAF | 실장비 필요 + 점검 스크립트 미제공 |

---

## 수집 중 발견·처리한 갭
1. **제어문자(수정완료)** — 서버 출력 CDATA의 ANSI escape(`\x1b`)가 XML 파싱 실패 →
   `cloud_xml.sanitize`에 XML 1.0 불법 제어문자 제거 추가(전 XML 파서 공통, 커밋됨).
2. **DB 환경변수 주입(MySQL/MariaDB)** — 점검 .sql이 `detect_and_set_environment`를
   정의만 하고 CALL 안 함 → `mysql <` 직접 실행 시 `SET @db_environment_state=0` 주입 필요.
   (PostgreSQL/MS-SQL/Oracle은 스크립트가 환경 자동감지.)
3. **MS-SQL sqlcmd prefix** — 출력에 `[Microsoft][ODBC Driver 18...]` 메시지 prefix가
   섞임 → 정제(sed) 후 순수 JSON. 실수집 시 동일 정제 필요.
4. **컨테이너 ID 표기갭(수정완료)** — 스크립트·출력 `<id>`가 `PRC-C-001` 표기(kind 실수집으로
   확정), 기준/파서는 `PRCC-001`. `normalize_id`가 글자그룹 중간 하이픈을 흡수·제거하도록
   수정(`PRC-C-001`→`PRCC-001`) → 기준매칭 0→36/39 복구. 단일 글자그룹 도메인은 동작 불변.
   또 출력 `<asset>`에 variant 태그 없음 → 파일명(`...-k8s_master-...`)의 filename_markers로 식별.
5. **Oracle 23c 권한차** — gvenzl/oracle-free(23c)에서 일부 `sys.user$` 직접접근 ORA-06550.
   실 12c/19c 환경에선 정상. 대부분 항목 정상 수집.
