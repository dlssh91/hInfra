"""컨테이너(PRCC) k8s_master/docker_linux 변형 DET 양극성 커버리지 픽스처 계약
(단일 진실원천). srv_cov_contract.py / db_cov_contract.py 동형 패턴.

배경(§3-2 실증 전제):
  - 실 XML 포맷: <script><asset><app>{k8s_master|docker}</app></asset>
    <results><dump><items><id>PRC-C-NNN</id><field>{role}</field>...</items>
    <output><![CDATA[...]]></output></dump>...</results></script>
    (out/kind_lab/ 실샘플 2종 — kind 클러스터 실수집, 포맷 진실원천으로 참조).
  - judge()는 item_id="PRCC-NNN"(정규화 후), variant="k8s_master"|"docker_linux"로
    호출된다(container.py:_VARIANT_TO_SAPP가 "docker_linux"→"docker"로 매핑 후
    vendor autoAnalysis(sApp=...) 호출; gate()는 원본 variant 문자열 사용).
  - F8 명령실패 가드(_is_command_failure_output)가 최근 추가됨 — 아래 픽스처는
    전부 "정상 출력"(명령 성공, 값 유/무)을 모사하며 오류출력 패턴
    (^error:\\s / Cannot connect to the Docker daemon / Error response from
    daemon / permission denied / command not found / connection refused)을
    포함하지 않는다(포함 시 F8 가드에 의해 handled=False로 새어 계약이 깨짐).

범위(사용자 지시): container.yaml 50항목 중 **실증된 2변형만**(k8s_master,
docker_linux). 나머지 7변형(k8s_worker/eks_master/eks_worker/aks_master/
aks_worker/ocp_master/ocp_worker)은 실샘플 미확보 — 미커버로 명시(§3-3 범위 외).

구조:
  CONTAINER_COV[item_id][variant] = {
      "good": <raw_output string>,       # 양호 유발 raw (result='N' 유도)
      "vuln": <raw_output string>,       # 취약 유발 raw (result='Y' 유도)
      "good_verdict": "양호",
      "vuln_verdict": "취약",
      "note": "...",                      # autoAnalysis.py 분기 근거 요약
  }
  또는 극성별 {"uncovered": True, "uncovered_reason": "..."} (양극성 제공 불가).

DET_SOURCE.yaml 분류(judge_tool/vendor/common/DET_SOURCE.yaml:1020-1370) 요약:
  k8s_master: DET 32개 / MANUAL 5개(004,022,024,039,045) / ABSENT 13개
  docker_linux: DET 31개 / MANUAL 1개(011) / ABSENT 18개
  (2026-07-11: PRCC-045 k8s_master DET→MANUAL 강등 — 아래 "수정됨" 항목 참조.
  k8s_master DET 33→32, MANUAL 4→5.)
  MANUAL/ABSENT 조합은 CONTAINER_MANUAL_HOLD_ITEMS에 별도 등재(gate 차단 확인용,
  양극성 대상 아님 — det_adapters/base.py classify()가 gate에서 handled=False
  반환하므로 judge() 결과는 raw_output 내용과 무관하게 항상 판단보류/LLM폴백).

수정됨(벤더 버그, §3-3 — 2026-07-11 VENDOR-EDIT(bug) 완료):
  - PRCC-023/035/036/037/038 docker_linux 분기(R-PRCC-NOTEXIST, KNOWN_BUGS.md 참조):
    autoAnalysis.py가 "미존재" 판정을 "[does not exist]"/"does not exist" 문자열로만
    검사했으나, 실 수집 스크립트(out/kind_lab/829d2152a3d6-docker-*.xml 실측)의
    실제 마커는 "[not exist]"("does" 없음)이다. 수정 전에는 **real 데이터에서 이
    마커가 절대 매치되지 않아 docker_linux는 이 5항목에서 항상 result='Y'(취약)로
    판정**되었다(방향=과판정/false-vuln, 거짓양호 아님). 수정: 구마커 유지 + 신마커
    "[not exist]" OR 추가 인식(autoAnalysis.py:777·980·1015·1037·1056). 아래 good
    픽스처는 실 마커("[not exist]")로 재작성해 실 데이터 기준 정상 동작을 검증한다.
  - PRCC-045 k8s_master(§3-3 항목2, VENDOR-EDIT 아님 — gate 라우팅 조정):
    코드(:1136)는 "spec.hostUTS:'true'"를 검사하나 실 수집스크립트
    (out/kind_lab/prcc-lab-control-plane-k8s_master-*.xml 실측)는
    `.securityContext.hostUTS`를 조회 — 코드 마커가 실 데이터에 영구 부재해
    k8s_master가 실제 상태와 무관하게 **항상 result='N'(양호)로 고정**되었다
    (거짓양호, High). 게다가 vanilla Kubernetes PodSpec에는 hostUTS 필드 자체가
    표준으로 없어(host 네임스페이스 공유는 hostPID/hostIPC/hostNetwork 3종만
    표준) 결정론 검증이 구조적으로 불가능. 수정: DET_SOURCE.yaml PRCC-045
    k8s_master를 DET→MANUAL 강등(fail-closed) — gate가 handled=False 반환,
    §18.3 라벨 라우팅(label A)으로 LLM 폴백. docker_linux/ocp_master는 실
    마커가 코드와 일치해 정상 동작하므로 변경하지 않았다. 아래 PRCC-045
    k8s_master 항목은 CONTAINER_COV에서 CONTAINER_MANUAL_HOLD_ITEMS로 이동.

주의(벤더 버그 발견 — 수정 금지·보고만, 안전 방향):
  - PRCC-031 k8s_master 분기: 4개 if 조건 모두 `".runAsUser:''"` 등을
    `in vulOutput` 없이 **문자열 리터럴 자체**로 and 연산 — 항상 truthy이므로
    runAsUser 값 검사가 사실상 죽은 코드(no-op)다. 즉 실제로는
    `.runAsNonRoot:'false'` 또는 `.runAsNonRoot:''` 단독 존재만으로 Y가
    결정되고 runAsUser 조합은 무관하다(안전 방향 — 과소판정 아님, 다만 판정
    근거 문구가 부정확할 수 있음).
"""
from __future__ import annotations

# ── 미커버 variant(설계 범위 — 실샘플 미확보) ──────────────────────────────
UNCOVERED_VARIANTS_REASON = (
    "실샘플 미확보(k8s_worker/eks_master/eks_worker/aks_master/aks_worker/"
    "ocp_master/ocp_worker) — §3-3 범위는 k8s_master/docker_linux 2종만"
)

CONTAINER_COV: dict[str, dict[str, dict]] = {}


def _add(item_id: str, variant: str, spec: dict) -> None:
    CONTAINER_COV.setdefault(item_id, {})[variant] = spec


# ──────────────────────────────────────────────────────────────────────────
# PRCC-001: cluster-admin 역할 부여 여부 (k8s_master DET)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-001", "k8s_master", {
    "good": (
        "F_PRC_C_001 : k8s_master\n"
        "# Command : kubectl get clusterrolebindings ...\n"
        "관리자 역할이 부여된 롤 바인딩:\n"
        "Cluster Role Name: some-other-role\n"
        "ROLE: view\n"
    ),
    "vuln": (
        "F_PRC_C_001 : k8s_master\n"
        "# Command : kubectl get clusterrolebindings ...\n"
        "관리자 역할이 부여된 롤 바인딩:\n"
        "flag: [X]\n"
        "Cluster Role Name: cluster-admin\n"
        "ROLE: cluster-admin\n"
        "Kind: Group\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'ROLE: cluster-admin' 부재→양호, 존재→취약(:39-45)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-002: Role/ClusterRole 과도권한("*") (k8s_master DET)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-002", "k8s_master", {
    "good": (
        'F_PRC_C_002 : k8s_master\n# Command : kubectl get clusterroles ...\n'
        'Resources: ["configmaps"]\nAPIGroups: [""]\n'
    ),
    "vuln": (
        'F_PRC_C_002 : k8s_master\n# Command : kubectl get clusterroles ...\n'
        'Pod: cluster-admin\nVerbs: ["*"]\nAPIGroups: ["*"]\nResources: ["*"]\n'
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": '\'["*"]\' 부재→양호, 존재→취약(:58-61)',
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-003: 기본 서비스계정(default) 사용 (k8s_master DET)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-003", "k8s_master", {
    "good": (
        "F_PRC_C_003 : k8s_master\n# Command : kubectl get pods -A ...\n"
        "Namespace: kube-system\nPod: coredns-x\n -Service Account: coredns\n"
    ),
    "vuln": (
        "F_PRC_C_003 : k8s_master\n# Command : kubectl get pods -A ...\n"
        "Namespace: default\nPod: myapp\n"
        "Service Account:default\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'Service Account:default' 부재→양호, 존재→취약(:71-74)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-005: 컨트롤러 서비스계정 자격증명(use-service-account-credentials)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-005", "k8s_master", {
    "good": (
        "F_PRC_C_005 : k8s_master\n# Command : ps -ef | grep controller-manager ...\n"
        "root kube-controller-manager --use-service-account-credentials=true "
        "--leader-elect=true\n"
    ),
    "vuln": (
        "F_PRC_C_005 : k8s_master\n# Command : ps -ef | grep controller-manager ...\n"
        "root kube-controller-manager --leader-elect=true\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'--use-service-account-credentials=true' 존재→양호, 부재→취약(:99-102)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-006: 서비스계정 토큰 자동마운트(automountServiceAccountToken)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-006", "k8s_master", {
    "good": (
        "F_PRC_C_006 : k8s_master\n# Command : kubectl get pods --all-namespaces ...\n"
        "automountServiceAccountToken이 true인 파드 목록:\n"
        "[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_006 : k8s_master\n# Command : kubectl get pods --all-namespaces ...\n"
        "automountServiceAccountToken이 true인 파드 목록:\n"
        "flag: [X]\n"
        "Namespace: default\nPod: myapp\n -automountServiceAccountToken: true\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'[X]' 부재→양호, 존재→취약(:112-114)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-007: 시스템 주요 설정파일 권한 (k8s_master DET + docker_linux DET)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-007", "k8s_master", {
    # 주의: autoAnalysis는 vulOutput 전체를 split('\n')해 "파일 한 줄"로 취급한다
    # (:118-119) — 헤더/커맨드 라인을 섞으면 그 라인 자체가 "root:root 없는 파일"로
    # 오판정(거짓취약)된다. 실 샘플(out/kind_lab)도 이 항목 output은 헤더 없이
    # 권한행만으로 구성됨 — 픽스처를 그 형태로 맞춘다("root:root" 문자열 자체가
    # 증거가드 패턴이라 별도 헤더 불필요).
    "good": (
        "600 root:root [/etc/kubernetes/manifests/kube-apiserver.yaml]\n"
        "600 root:root [/etc/kubernetes/manifests/kube-scheduler.yaml]\n"
        "600 root:root [/etc/kubernetes/scheduler.conf]\n"
        "600 root:root [/etc/kubernetes/manifests/kube-controller-manager.yaml]\n"
        "600 root:root [/etc/kubernetes/controller-manager.conf]\n"
        "600 root:root [/etc/kubernetes/manifests/etcd.yaml]\n"
        "600 root:root [/etc/kubernetes/admin.conf]\n"
        "644 root:root [/etc/containerd/config.toml]\n"
    ),
    "vuln": (
        "600 root:root [/etc/kubernetes/manifests/kube-scheduler.yaml]\n"
        "777 nobody:nobody [/etc/kubernetes/manifests/kube-apiserver.yaml]\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "파일별 root:root 소유+임계권한 이하→양호. root:root 아니거나 "
        "임계권한 초과(kube-apiserver.yaml>600 등)→취약(:117-161, 실샘플 형식 검증됨)"
    ),
})
_add("PRCC-007", "docker_linux", {
    "good": (
        "644 root:root [/etc/docker/daemon.json]\n"
        "660 root:root [/var/run/docker.sock]\n"
        "755 root:root [/etc/docker]\n"
    ),
    "vuln": (
        "777 root:root [/etc/docker/daemon.json]\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "daemon.json<=644 / docker.sock<=660 / /etc/docker<=755 + root:root→양호, "
        "초과→취약(:196-210). 헤더 라인 없이 권한행만(위 k8s_master와 동일 사유)."
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-008: 서비스 바인딩 주소 제한(bind-address)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-008", "k8s_master", {
    "good": (
        "F_PRC_C_008 : k8s_master\n# Command : ps -ef | grep scheduler ...\n"
        "root kube-scheduler --bind-address=127.0.0.1 --leader-elect=true\n"
    ),
    "vuln": (
        "F_PRC_C_008 : k8s_master\n# Command : ps -ef | grep scheduler ...\n"
        "root kube-scheduler --bind-address=0.0.0.0 --leader-elect=true\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'bind-address=0.0.0.0'→취약, 그 외(127.0.0.1 등)→양호(:398-404)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-009: 시스템 주요 이벤트 로그(audit-log-path/audit-policy-file, docker
# 로그레벨)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-009", "k8s_master", {
    "good": (
        "F_PRC_C_009 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --audit-policy-file=/etc/kubernetes/audit-policy.yaml "
        "--audit-log-path=/var/log/kubernetes/audit.log\n"
    ),
    "vuln": (
        "F_PRC_C_009 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --advertise-address=172.18.0.2\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "audit-policy-file+audit-log-path 존재→양호, 부재→취약(:418-424)",
})
_add("PRCC-009", "docker_linux", {
    "good": (
        "F_PRC_C_009 : docker\n# Command : ps -ef | grep dockerd ...\n"
        '["--log-level"] : notice\n'
    ),
    "vuln": (
        "F_PRC_C_009 : docker\n# Command : ps -ef | grep dockerd ...\n"
        '["--log-level"] : warn\n'
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "로그레벨 warn/error/fatal 미포함→양호, 포함→취약(:434-440)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-010: 비휘발성 경로 내 로그파일 저장 (k8s_master DET)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-010", "k8s_master", {
    "good": (
        "F_PRC_C_010 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --audit-log-path=/var/log/kubernetes/audit.log\n"
    ),
    "vuln": (
        "F_PRC_C_010 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --audit-log-path=/tmp/audit.log\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "audit-log-path 부재→취약, 존재+휘발성경로(/tmp 등) 미포함→양호, "
        "휘발성경로 포함→취약(:485-492)"
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-012: API 통신 보안 프로토콜(TLS) (k8s_master DET + docker_linux DET)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-012", "k8s_master", {
    "good": (
        "F_PRC_C_012 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --tls-cert-file=/etc/kubernetes/pki/apiserver.crt "
        "--tls-private-key-file=/etc/kubernetes/pki/apiserver.key\n"
    ),
    "vuln": (
        "F_PRC_C_012 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --advertise-address=172.18.0.2\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "tls-cert-file+tls-private-key-file 존재→양호, 부재→취약(:535-541)",
})
_add("PRCC-012", "docker_linux", {
    "good": (
        "F_PRC_C_012 : docker\n# Command : ps -ef | grep dockerd ...\n"
        '["--tlsverify"] : --tlscacert\n'
        '["--tlscacert"] : /certs/server/ca.pem\n'
        '["--tlscert"] : /certs/server/cert.pem\n'
        '["--tlskey"] : /certs/server/key.pem\n'
    ),
    "vuln": (
        "F_PRC_C_012 : docker\n# Command : ps -ef | grep dockerd ...\n"
        '["--tlsverify"] : [X]\n'
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": 'TLS 플래그 값 존재(비-[X])→양호, "[X]"(미설정) 존재→취약(:555-560)',
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-013: Anonymous 계정 API 접속 제한(anonymous-auth)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-013", "k8s_master", {
    "good": (
        "F_PRC_C_013 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --anonymous-auth=false\n"
    ),
    "vuln": (
        "F_PRC_C_013 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --anonymous-auth=true\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'--anonymous-auth' 부재 또는 =true→취약, =false→양호(:569-575)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-014: API 요청 타임아웃(request-timeout, 60초 초과 취약)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-014", "k8s_master", {
    "good": (
        "F_PRC_C_014 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --request-timeout=30s\n"
    ),
    "vuln": (
        "F_PRC_C_014 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --request-timeout=120s\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "--request-timeout 초단위 환산 <=60s→양호, >60s→취약(:610-625)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-015: 안전한 인증 모드(authorization-mode != AlwaysAllow)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-015", "k8s_master", {
    "good": (
        "F_PRC_C_015 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --authorization-mode=Node,RBAC\n"
    ),
    "vuln": (
        "F_PRC_C_015 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --authorization-mode=AlwaysAllow\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "authorization-mode 부재 또는 AlwaysAllow→취약, 그 외→양호(:641-646)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-016: 서비스계정 토큰 검증(service-account-lookup)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-016", "k8s_master", {
    "good": (
        "F_PRC_C_016 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --authorization-mode=Node,RBAC\n"
    ),
    "vuln": (
        "F_PRC_C_016 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --service-account-lookup=false\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'--service-account-lookup=false' 부재→양호, 존재→취약(:675-677)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-017: k8s_master="pass"(no-op) — DET_SOURCE(:1314)에 이미 명시된
# 항목 자체 특이사항: 코드가 k8s_master 분기에서 아무 조건도 검사하지 않음
# (평가항목 아님 취급, 항상 result='N'). vuln 유발 불가(구조적).
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-017", "k8s_master", {
    "good": (
        "F_PRC_C_017 : k8s_master\n# Command : kubectl get nodes ...\n"
        "read-only-port 관련 점검은 k8s_master에 적용되지 않음(pass)\n"
    ),
    "vuln": {
        "uncovered": True,
        "uncovered_reason": (
            "PRCC-017 k8s_master 분기는 'pass'(no-op, :685-686) — 아무 위반조건도 "
            "검사하지 않아 항상 result='N'(양호) 고정. 코드 구조상 vuln 유발 불가"
            "(DET_SOURCE.yaml:1314 주석 '평가항목 아님 취급'과 일치). good만 커버."
        ),
    },
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "k8s_master=pass 분기(항상 N). 실질 판정은 k8s_worker 등 타 variant.",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-019: docker daemon root 실행 (docker_linux DET)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-019", "docker_linux", {
    "good": (
        "F_PRC_C_019 : docker\n# Command : ps -ef | grep dockerd ...\n"
        "1000 dockerd --host=unix:///var/run/docker.sock\n"
    ),
    "vuln": (
        "F_PRC_C_019 : docker\n# Command : ps -ef | grep dockerd ...\n"
        "0 root dockerd --host=unix:///var/run/docker.sock\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'root' 문자열 부재→양호, 존재→취약(:737-739)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-020: 실험적 기능(experimental) 비활성화
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-020", "docker_linux", {
    "good": (
        "F_PRC_C_020 : docker\n# Command : docker info --format ...\n"
        "ExperimentalBuild: false\n"
    ),
    "vuln": (
        "F_PRC_C_020 : docker\n# Command : docker info --format ...\n"
        "ExperimentalBuild: true\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'true' 문자열 부재→양호, 존재→취약(:743-745)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-021: userland-proxy 사용 제한
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-021", "docker_linux", {
    "good": (
        'F_PRC_C_021 : docker\n# Command : ps -ef | grep dockerd ...\n'
        '["--userland-proxy"] : false\n'
    ),
    "vuln": (
        'F_PRC_C_021 : docker\n# Command : ps -ef | grep dockerd ...\n'
        '["--userland-proxy"] : true\n'
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "userland-proxy 값 false(미매치 [X]도 취약)→양호, true→취약(:749-757)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-022: 레지스트리 보안 프로토콜(insecure-registry) — docker_linux DET
# (k8s_master은 MANUAL, hold 리스트로)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-022", "docker_linux", {
    "good": (
        'F_PRC_C_022 : docker\n# Command : ps -ef | grep dockerd ...\n'
        '["--insecure-registry"] : [X]\n'
    ),
    "vuln": (
        'F_PRC_C_022 : docker\n# Command : ps -ef | grep dockerd ...\n'
        '["--insecure-registry"] : myregistry.local:5000\n'
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "insecure-registry 미설정([X])→양호, 값 설정→취약(:764-768)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-023: 사용자 정의 네트워크(기본 브릿지) 사용 — docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-023", "docker_linux", {
    "good": (
        "F_PRC_C_023 : docker\n# Command : docker network inspect bridge ...\n"
        "기본 네트워크 브릿지를 사용하는 컨테이너 목록:\n"
        "[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_023 : docker\n# Command : docker network inspect bridge ...\n"
        "bridge: map[com.docker.network.bridge.default_bridge:true]\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "'default_bridge:true' 부재 AND ('does not exist' 또는 '[not exist]') 존재"
        "→양호, 그 외→취약(:773-782). R-PRCC-NOTEXIST 수정(2026-07-11, KNOWN_BUGS.md):"
        " 실 수집스크립트 마커 '[not exist]'(out/kind_lab/829d2152a3d6-docker-*.xml"
        " 실측)를 OR로 추가 인식 — good 픽스처는 실 마커로 작성해 실 데이터 기준"
        " 정상 동작(양호)을 검증."
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-024: 컨테이너간 통신 제한(icc) — docker_linux DET (k8s_master MANUAL)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-024", "docker_linux", {
    "good": (
        "F_PRC_C_024 : docker\n# Command : docker network inspect ...\n"
        "bridge: map[com.docker.network.bridge.enable_icc:false]\n"
    ),
    "vuln": (
        "F_PRC_C_024 : docker\n# Command : docker network inspect ...\n"
        "bridge: map[com.docker.network.bridge.enable_icc:true]\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'enable_icc:true' 부재→양호, 존재→취약(:791-793)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-025: 불필요한 프로파일링(profiling) 비활성화 — k8s_master DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-025", "k8s_master", {
    "good": (
        "F_PRC_C_025 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --profiling=false\n"
        "profiling: false\n"
    ),
    "vuln": (
        "F_PRC_C_025 : k8s_master\n# Command : ps -ef | grep apiserver ...\n"
        "root kube-apiserver --profiling=true\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "--profiling=true 또는 profiling:true→취약, --profiling/profiling: 부재→"
        "취약, 값이 false로 명시→양호(:806-820)"
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-026: privileged 플래그 제거 — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-026", "k8s_master", {
    "good": (
        "F_PRC_C_026 : k8s_master\n# Command : kubectl get pod ...\n"
        "privileged 모드가 설정된 컨테이너 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_026 : k8s_master\n# Command : kubectl get pod ...\n"
        "privileged 모드가 설정된 컨테이너 목록:\n"
        "flag: [X]\nContainer: app | -securityContext.privileged:'true'\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'flag: [X]' 부재→양호, 존재→취약(:824-826)",
})
_add("PRCC-026", "docker_linux", {
    "good": (
        "F_PRC_C_026 : docker\n# Command : docker inspect ...\n"
        "Container: app | Privileged: false\n"
    ),
    "vuln": (
        "F_PRC_C_026 : docker\n# Command : docker inspect ...\n"
        "Container: app | Privileged: true\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'Privileged: true' 부재→양호, 존재→취약(:829-831)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-027: 과도한 커널 접근 권한(capabilities.add) — k8s_master DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-027", "k8s_master", {
    "good": (
        "F_PRC_C_027 : k8s_master\n# Command : kubectl get pod ...\n"
        "capabilities.add에 값이 존재하는 컨테이너 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_027 : k8s_master\n# Command : kubectl get pod ...\n"
        "capabilities.add에 값이 존재하는 컨테이너 목록:\n"
        "Container: app | -securityContext.capabilities.add:'[SYS_ADMIN]'\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "위험 capability(SYS_ADMIN 등) 목록 부재→양호, 존재→취약(:840-844)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-028: 불필요한 커널 접근 권한(capabilities.drop 부재) — k8s_master DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-028", "k8s_master", {
    "good": (
        "F_PRC_C_028 : k8s_master\n# Command : kubectl get pod ...\n"
        "capabilities.drop 값이 존재하지 않는 컨테이너 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_028 : k8s_master\n# Command : kubectl get pod ...\n"
        "capabilities.drop 값이 존재하지 않는 컨테이너 목록:\n"
        "Container: app | -securityContext.capabilities.drop:''\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "\"capabilities.drop:''\" 부재→양호, 존재→취약(:853-855)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-029: 권한 상승(allowPrivilegeEscalation) — k8s_master DET + docker DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-029", "k8s_master", {
    "good": (
        "F_PRC_C_029 : k8s_master\n# Command : kubectl get pod ...\n"
        "Container: app | -securityContext.allowPrivilegeEscalation:'false'\n"
    ),
    "vuln": (
        "F_PRC_C_029 : k8s_master\n# Command : kubectl get pod ...\n"
        "Container: app | -securityContext.allowPrivilegeEscalation:'true'\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "allowPrivilegeEscalation:''(미지정) 또는 'true'→취약, 'false'→양호(:865-870)",
})
_add("PRCC-029", "docker_linux", {
    "good": (
        'F_PRC_C_029 : docker\n# Command : ps -ef | grep dockerd ...\n'
        '["--no-new-privileges"] : true\n'
        "'no-new-privileges' 설정이 활성화되어 있습니다.\n"
    ),
    "vuln": (
        'F_PRC_C_029 : docker\n# Command : ps -ef | grep dockerd ...\n'
        '["--no-new-privileges"] : [X]\n'
        "[*] 'no-new-privileges' 설정이 활성화되어 있지 않습니다.(false)\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "no-new-privileges 값 존재(비-[X])+'(false)'/'false' 부재→양호, "
        "'(false)' 존재(또는 미설정)→취약(:873-880, 실 kind_lab 도커샘플과 동형)"
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-030: seccomp 활성화 — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-030", "k8s_master", {
    "good": (
        "F_PRC_C_030 : k8s_master\n# Command : kubectl get pod ...\n"
        "Container: app | -securityContext.seccompProfile.type:'RuntimeDefault'\n"
    ),
    "vuln": (
        "F_PRC_C_030 : k8s_master\n# Command : kubectl get pod ...\n"
        "Container: app | -securityContext.seccompProfile.localhostProfile:''\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "\"seccompProfile.localhostProfile:''\" 부재→양호, 존재→취약(:889-891)",
})
_add("PRCC-030", "docker_linux", {
    "good": (
        "F_PRC_C_030 : docker\n# Command : docker info --format ...\n"
        "[name=apparmor name=seccomp,profile=default name=cgroupns]\n"
    ),
    "vuln": (
        "F_PRC_C_030 : docker\n# Command : docker inspect ...\n"
        "Container app: seccomp=unconfined\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'seccomp=unconfined'/'profile=unconfined' 부재→양호, 존재→취약(:894-899)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-031: 컨테이너 관리자 권한 실행 — k8s_master DET + docker_linux DET
# ⚠️ k8s_master 코드 버그(runAsUser 조건 no-op, 파일 상단 주석 참조) —
# good/vuln은 실제 코드 동작(runAsNonRoot 단독 결정)에 맞춰 구성.
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-031", "k8s_master", {
    "good": (
        "F_PRC_C_031 : k8s_master\n# Command : kubectl get pod ...\n"
        "Container: app | -securityContext.runAsNonRoot:'true'| "
        "-securityContext.runAsUser:'1000'\n"
    ),
    "vuln": (
        "F_PRC_C_031 : k8s_master\n# Command : kubectl get pod ...\n"
        "Container: app | -securityContext.runAsNonRoot:'false'| "
        "-securityContext.runAsUser:'1000'\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "runAsNonRoot:'false' 또는 ''(미지정)→취약(runAsUser 값 무관 — 코드 버그, "
        "파일 상단 주석 참조), runAsNonRoot:'true'→양호(:903-914)"
    ),
})
_add("PRCC-031", "docker_linux", {
    "good": (
        "F_PRC_C_031 : docker\n# Command : docker inspect ...\n"
        "Container id: app Config.User: appuser\n"
    ),
    "vuln": (
        "F_PRC_C_031 : docker\n# Command : docker exec ... /proc/1/status ...\n"
        "app | UID: 0\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'| UID: 0' 부재+Config.User가 root/빈값 아님→양호, 'UID: 0'존재→취약(:917-924)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-032: 상태 보존(live-restore) — docker_linux DET (k8s_master ABSENT)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-032", "docker_linux", {
    "good": (
        'F_PRC_C_032 : docker\n# Command : docker info --format ...\n'
        '["--live-restore"] : true\nLive Restore 기능이 활성화되어 있습니다.\n'
    ),
    "vuln": (
        "F_PRC_C_032 : docker\n# Command : docker info --format ...\n"
        "Live Restore 기능이 비활성화되어 있습니다: [.LiveRestoreEnabled] : false\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "'false' 문자열 부재 AND live-restore 값 존재(비-[X])→양호, 'false' 존재"
        "(또는 값 부재)→취약(:933-939, 실 kind_lab 도커샘플 vuln과 동형)"
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-033: 재시작 정책(restartPolicy) — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-033", "k8s_master", {
    "good": (
        "F_PRC_C_033 : k8s_master\n# Command : kubectl get pod ...\n"
        "재시작 설정이 Never인 파드 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_033 : k8s_master\n# Command : kubectl get pod ...\n"
        "재시작 설정이 Never인 파드 목록:\n"
        " -spec.restartPolicy:Never\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'.restartPolicy:Never' 부재→양호, 존재→취약(:943-945)",
})
_add("PRCC-033", "docker_linux", {
    "good": (
        "F_PRC_C_033 : docker\n# Command : docker inspect ...\n"
        "app | always MaximumRetryCount=3\n"
    ),
    "vuln": (
        "F_PRC_C_033 : docker\n# Command : docker inspect ...\n"
        "app | RestartPolicy Name: no MaximumRetryCount=0\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'RestartPolicy Name: no'/'MaximumRetryCount: 0' 부재→양호, 존재→취약(:948-954)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-034: HEALTHCHECK — docker_linux DET (k8s_master ABSENT)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-034", "docker_linux", {
    "good": (
        "F_PRC_C_034 : docker\n# Command : docker inspect ...\n"
        "app | healthy\n"
    ),
    "vuln": (
        "F_PRC_C_034 : docker\n# Command : docker inspect ...\n"
        "app | no healthcheck\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'| no healthcheck' 부재→양호, 존재→취약(:963-965)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-035: 시스템 디렉터리 마운트 제거 — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-035", "k8s_master", {
    "good": (
        "F_PRC_C_035 : k8s_master\n# Command : kubectl get pod ...\n"
        "시스템 디렉터리가 마운트된 컨테이너 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_035 : k8s_master\n# Command : kubectl get pod ...\n"
        "시스템 디렉터리가 마운트된 컨테이너 목록:\n"
        "Container: app | -VolumeMounts: [hostvol:/etc]|Volumes: [hostvol:/etc:Directory]\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "시스템 디렉터리 경로(/boot,/dev,/etc,/lib,/proc,/sys,/usr) 부재→양호, 존재→취약(:969-974)",
})
_add("PRCC-035", "docker_linux", {
    "good": (
        "F_PRC_C_035 : docker\n# Command : docker inspect ...\n"
        "시스템 디렉터리가 마운트된 컨테이너 :\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_035 : docker\n# Command : docker inspect ...\n"
        "app: /etc:/host-etc\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "'[does not exist]' 또는 '[not exist]' 존재→양호, 둘 다 부재→취약"
        "(:979-985). R-PRCC-NOTEXIST 수정(2026-07-11): 실 마커 '[not exist]'"
        "(out/kind_lab/829d2152a3d6-docker-*.xml 실측)를 OR로 추가 인식 — good"
        " 픽스처는 실 마커로 재작성해 실 데이터 기준 정상 동작(양호) 검증."
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-036: CRI socket 볼륨 마운트 제거 — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-036", "k8s_master", {
    "good": (
        "F_PRC_C_036 : k8s_master\n# Command : kubectl get pod ...\n"
        "CRI Socket 볼륨이 마운트된 컨테이너 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_036 : k8s_master\n# Command : kubectl get pod ...\n"
        "CRI Socket 볼륨이 마운트된 컨테이너 목록:\n"
        "Container: app | Volumes: [sockvol:/var/run/docker.sock]\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'docker.sock'/'containerd.sock' 부재→양호, 존재→취약(:1001-1006)",
})
_add("PRCC-036", "docker_linux", {
    "good": (
        "F_PRC_C_036 : docker\n# Command : docker inspect ...\n"
        "CRI 소켓 볼륨이 마운트된 컨테이너 :\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_036 : docker\n# Command : docker inspect ...\n"
        "app | /var/run/docker.sock:/var/run/docker.sock\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "'[does not exist]' 또는 '[not exist]' 존재→양호, 둘 다 부재→취약"
        "(:1014-1020). R-PRCC-NOTEXIST 수정(2026-07-11): 실 마커 '[not exist]' "
        "OR 추가 인식 — good 픽스처는 실 마커로 재작성."
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-037: 읽기전용 루트파일시스템 — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-037", "k8s_master", {
    "good": (
        "F_PRC_C_037 : k8s_master\n# Command : kubectl get pod ...\n"
        "읽기 전용 모드가 아닌 컨테이너 목록:\n"
        "Container: app | -securityContext.readOnlyRootFilesystem:True\n"
    ),
    "vuln": (
        "F_PRC_C_037 : k8s_master\n# Command : kubectl get pod ...\n"
        "읽기 전용 모드가 아닌 컨테이너 목록:\n"
        "Container: app | -securityContext.readOnlyRootFilesystem:False\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "readOnlyRootFilesystem 값이 줄끝 빈값 또는 False→취약, True(등)→양호"
        "(:1019-1025, re.MULTILINE)"
    ),
})
_add("PRCC-037", "docker_linux", {
    "good": (
        "F_PRC_C_037 : docker\n# Command : docker inspect ...\n"
        "루트 파일 시스템 읽기 전용 모드 마운트 컨테이너 목록: \n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_037 : docker\n# Command : docker inspect ...\n"
        "app(sha256:abc) | false\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "'[does not exist]' 또는 '[not exist]' 존재→양호, 둘 다 부재→취약"
        "(:1036-1042). R-PRCC-NOTEXIST 수정(2026-07-11): 실 마커 '[not exist]' "
        "OR 추가 인식 — good 픽스처는 실 마커로 재작성."
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-038: 마운트 전파 모드(Bidirectional) — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-038", "k8s_master", {
    "good": (
        "F_PRC_C_038 : k8s_master\n# Command : kubectl get pod ...\n"
        "마운트 전파 모드(mountPropagation)가 Bidirectional인 컨테이너 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_038 : k8s_master\n# Command : kubectl get pod ...\n"
        "마운트 전파 모드(mountPropagation)가 Bidirectional인 컨테이너 목록:\n"
        "Container: app | -mountPropagation: Bidirectional\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'mountPropagation: Bidirectional' 부재→양호, 존재→취약(:1039-1041)",
})
_add("PRCC-038", "docker_linux", {
    "good": (
        "F_PRC_C_038 : docker\n# Command : docker inspect ...\n"
        "컨테이너의 마운트 전파 모드 확인:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_038 : docker\n# Command : docker inspect ...\n"
        "app: shared\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "'[does not exist]' 또는 '[not exist]' 존재→양호, 둘 다 부재→취약"
        "(:1055-1061). R-PRCC-NOTEXIST 수정(2026-07-11): 실 마커 '[not exist]' "
        "OR 추가 인식 — good 픽스처는 실 마커로 재작성."
    ),
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-039: 불필요한 외부 장치(HostConfig.Devices) — docker_linux DET
# (k8s_master은 MANUAL, hold 리스트로)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-039", "docker_linux", {
    "good": (
        "F_PRC_C_039 : docker\n# Command : docker inspect ...\n"
        " .HostConfig.Devices: []\n"
    ),
    "vuln": (
        "F_PRC_C_039 : docker\n# Command : docker inspect ...\n"
        " .HostConfig.Devices: [/dev/sda]\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "HostConfig.Devices 빈 목록([])→양호, 값 존재→취약(:1059-1063)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-040: 불필요한 AUFS 스토리지 드라이버 — docker_linux DET
# (k8s_master은 이 항목에서 ABSENT, 오직 k8s_worker만 DET)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-040", "docker_linux", {
    "good": (
        "F_PRC_C_040 : docker\n# Command : docker info\n"
        "Storage Driver: overlayfs\n"
    ),
    "vuln": (
        "F_PRC_C_040 : docker\n# Command : docker info\n"
        "Storage Driver: aufs\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'aufs' 문자열 부재→양호, 존재→취약(:1067-1069)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-041: 사용자 네임스페이스(userns-remap) — docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-041", "docker_linux", {
    "good": (
        "F_PRC_C_041 : docker\n# Command : docker info --format ...\n"
        "userns-remap active: dockremap\n"
        " .HostConfig.UsernsMode: 1000:1000\n"
    ),
    "vuln": (
        "F_PRC_C_041 : docker\n# Command : docker info --format ...\n"
        " .HostConfig.UsernsMode: host\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'host'/'default'/'deactivated' 부재→양호, 존재→취약(:1073-1079)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-042: 호스트 PID 네임스페이스 공유 — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-042", "k8s_master", {
    "good": (
        "F_PRC_C_042 : k8s_master\n# Command : kubectl get pod ...\n"
        "호스트 PID 네임스페이스(hostPID)가 true인 파드 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_042 : k8s_master\n# Command : kubectl get pod ...\n"
        "호스트 PID 네임스페이스(hostPID)가 true인 파드 목록:\n"
        " -spec.hostPID:'true'\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "\"spec.hostPID:'true'\" 부재→양호, 존재→취약(:1083-1085)",
})
_add("PRCC-042", "docker_linux", {
    "good": (
        "F_PRC_C_042 : docker\n# Command : docker inspect ...\n"
        "app: PidMode: \n"
    ),
    "vuln": (
        "F_PRC_C_042 : docker\n# Command : docker inspect ...\n"
        "app: PidMode: host\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'host' 부재→양호, 존재→취약(:1088-1090)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-043: 호스트 IPC 네임스페이스 공유 — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-043", "k8s_master", {
    "good": (
        "F_PRC_C_043 : k8s_master\n# Command : kubectl get pod ...\n"
        "호스트 IPC 네임스페이스(hostIPC)가 true인 파드 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_043 : k8s_master\n# Command : kubectl get pod ...\n"
        "호스트 IPC 네임스페이스(hostIPC)가 true인 파드 목록:\n"
        " -spec.hostIPC:'true'\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "\"spec.hostIPC:'true'\" 부재→양호, 존재→취약(:1100-1102)",
})
_add("PRCC-043", "docker_linux", {
    "good": (
        "F_PRC_C_043 : docker\n# Command : docker inspect ...\n"
        "app | .HostConfig.IpcMode: \n"
    ),
    "vuln": (
        "F_PRC_C_043 : docker\n# Command : docker inspect ...\n"
        "app | .HostConfig.IpcMode: host\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'host' 부재→양호, 존재→취약(:1105-1107)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-044: 호스트 네트워크 네임스페이스 공유 — k8s_master DET + docker DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-044", "k8s_master", {
    "good": (
        "F_PRC_C_044 : k8s_master\n# Command : kubectl get pod ...\n"
        "호스트 네트워크 네임스페이스(hostNetwork)가 true인 파드 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_044 : k8s_master\n# Command : kubectl get pod ...\n"
        "호스트 네트워크 네임스페이스(hostNetwork)가 true인 파드 목록:\n"
        " -spec.hostNetwork:'true'\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "\"spec.hostNetwork:'true'\" 부재→양호, 존재→취약(:1116-1118)",
})
_add("PRCC-044", "docker_linux", {
    "good": (
        "F_PRC_C_044 : docker\n# Command : docker inspect ...\n"
        "app(sha256:abc) | NetworkMode: bridge\n"
    ),
    "vuln": (
        "F_PRC_C_044 : docker\n# Command : docker inspect ...\n"
        "app(sha256:abc) | NetworkMode: host\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'host' 부재→양호, 존재→취약(:1120-1123)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-045: 호스트 UTS 네임스페이스 공유 — docker_linux DET만(k8s_master는
# 2026-07-11 DET→MANUAL 강등, 아래 참조 — CONTAINER_MANUAL_HOLD_ITEMS로 이동).
#
# ✅ 수정 완료(§3-3 항목2, 2026-07-11 — 방향=거짓양호, 심각도 High):
#   코드는 "spec.hostUTS:'true'"를 검사(:1136)했으나, 실 수집스크립트
#   (out/kind_lab/prcc-lab-control-plane-k8s_master-*.xml 실측, PRC-C-045 output)의
#   실제 jsonpath는 `-securityContext.hostUTS:'{.securityContext.hostUTS}'`로
#   "securityContext.hostUTS" 접두를 사용한다 — "spec.hostUTS"가 아니다.
#   PRCC-042/043/044(hostPID/hostIPC/hostNetwork)는 실 스크립트가 "spec.xxx"
#   접두를 정확히 쓰는 반면(코드와 일치), PRCC-045만 "securityContext.hostUTS"로
#   달라 코드 문자열이 실 데이터에서 절대 매치되지 않아 k8s_master는 실제
#   hostUTS 공유 여부와 무관하게 **항상 result='N'(양호)**로 고정되었다(거짓양호).
#   게다가 hostUTS는 vanilla Kubernetes Pod API의 표준 필드가 아니어서
#   (.spec.hostUTS도 .securityContext.hostUTS도 존재하지 않음 — 표준 필드는
#   hostPID/hostIPC/hostNetwork 3종뿐) 결정론 검증이 구조적으로 불가능하다.
#   수정: DET_SOURCE.yaml PRCC-045 k8s_master를 DET→MANUAL 강등(fail-closed) —
#   gate가 handled=False 반환 → §18.3 라벨 라우팅(label A)으로 LLM 폴백.
#   docker_linux/ocp_master는 실 마커가 코드와 일치해 정상 동작하므로 변경 없음.
#   k8s_master 양극성 픽스처는 CONTAINER_MANUAL_HOLD_ITEMS로 이동(아래 참조).
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-045", "docker_linux", {
    "good": (
        "F_PRC_C_045 : docker\n# Command : docker inspect ...\n"
        "app | UTSMode: \n"
    ),
    "vuln": (
        "F_PRC_C_045 : docker\n# Command : docker inspect ...\n"
        "app | UTSMode: host\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'UTSMode: host' 부재→양호, 존재→취약(:1141-1143)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-046: 불필요한 HostPort — k8s_master DET (docker_linux ABSENT)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-046", "k8s_master", {
    "good": (
        "F_PRC_C_046 : k8s_master\n# Command : kubectl get pod ...\n"
        "hostPort를 사용하는 컨테이너 목록:\n[not exist]\n"
    ),
    "vuln": (
        "F_PRC_C_046 : k8s_master\n# Command : kubectl get pod ...\n"
        "hostPort를 사용하는 컨테이너 목록:\n"
        "flag: [X]\nContainer: app | -containerPort: 8080| -hostPort: 8080\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'[X]' 부재→양호, 존재→취약(:1152-1154)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-047: 컨테이너 메모리 사용 제한 — k8s_master DET + docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-047", "k8s_master", {
    "good": (
        "F_PRC_C_047 : k8s_master\n# Command : kubectl get pod ...\n"
        "컨테이너의 메모리 사용 제한 미설정 컨테이너 목록:\n"
        "Container: app | -resources.limits.memory:'512Mi'\n"
    ),
    "vuln": (
        "F_PRC_C_047 : k8s_master\n# Command : kubectl get pod ...\n"
        "컨테이너의 메모리 사용 제한 미설정 컨테이너 목록:\n"
        "Container: app | -resources.limits.memory:'0'\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "resources.limits.memory가 '0' 또는 ''→취약, 그 외 값→양호(:1162-1167)",
})
_add("PRCC-047", "docker_linux", {
    "good": (
        "F_PRC_C_047 : docker\n# Command : docker inspect ...\n"
        "app | Memory: 536870912\n"
    ),
    "vuln": (
        "F_PRC_C_047 : docker\n# Command : docker inspect ...\n"
        "app | Memory: 0\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "'Memory: 0' 부재→양호, 존재→취약(:1170-1172)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-048: 부적절한 cgroup(CgroupParent) — docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-048", "docker_linux", {
    "good": (
        "F_PRC_C_048 : docker\n# Command : docker inspect ...\n"
        "app | CgroupParent: docker\n"
    ),
    "vuln": (
        "F_PRC_C_048 : docker\n# Command : docker inspect ...\n"
        "app | CgroupParent: custom-cgroup\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "CgroupParent가 'docker' 또는 공백→양호, 그 외 값→취약(:1181-1184)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-049: PID 제한(PidsLimit) — docker_linux DET
# (k8s_master ABSENT — 이 항목은 k8s_worker에서만 DET)
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-049", "docker_linux", {
    "good": (
        "F_PRC_C_049 : docker\n# Command : docker inspect ...\n"
        "app | PidsLimit: 512\n"
    ),
    "vuln": (
        "F_PRC_C_049 : docker\n# Command : docker inspect ...\n"
        "app | PidsLimit: 0\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": "PidsLimit 값이 0/-1/<nil>/'no limit'/공백 중 하나→취약, 실값→양호(:1199-1202)",
})

# ──────────────────────────────────────────────────────────────────────────
# PRCC-050: ulimit 설정(default-ulimit + HostConfig.Ulimits) — docker_linux DET
# ──────────────────────────────────────────────────────────────────────────
_add("PRCC-050", "docker_linux", {
    "good": (
        'F_PRC_C_050 : docker\n# Command : ps -ef | grep dockerd ...\n'
        '["default-ulimit"] : 65535\n'
        "HostConfig.Ulimits: []\n"
    ),
    "vuln": (
        'F_PRC_C_050 : docker\n# Command : ps -ef | grep dockerd ...\n'
        '["default-ulimit"] : [X]\n'
        "HostConfig.Ulimits: null\n"
    ),
    "good_verdict": "양호", "vuln_verdict": "취약",
    "note": (
        "default-ulimit 부재([X]) AND HostConfig.Ulimits 부재(빈/no/<nil>/null)"
        "→취약(둘 다 만족해야). default-ulimit 값 존재 시 양호(:1206-1212)"
    ),
})


# ──────────────────────────────────────────────────────────────────────────────
# MANUAL/ABSENT 조합(k8s_master/docker_linux) — 양극성 대상 아님.
# gate()가 raw_output 내용과 무관하게 handled=False 반환(§18.1 C1).
# (item_id, variant, note)
# ──────────────────────────────────────────────────────────────────────────────
CONTAINER_MANUAL_HOLD_ITEMS: list[tuple[str, str, str]] = [
    # ── k8s_master: MANUAL(5) ──────────────────────────────────────────────
    ("PRCC-004", "k8s_master", "MANUAL: result='M' 직접 반환(:83-85)"),
    ("PRCC-022", "k8s_master", "MANUAL: k8s 계열 전부 result='M'(:760-762)"),
    ("PRCC-024", "k8s_master", "MANUAL: 'No resources' 아니면 M(보수분류, :781-788)"),
    ("PRCC-039", "k8s_master", "MANUAL: k8s/ocp/eks/aks master 전부 result='M'(:1054-1056)"),
    ("PRCC-045", "k8s_master",
     "MANUAL(2026-07-11 DET→MANUAL 강등, §3-3 항목2): 코드 마커 \"spec.hostUTS:"
     "'true'\"(:1136)가 실 수집스크립트 jsonpath '.securityContext.hostUTS'와 "
     "불일치 + vanilla k8s PodSpec에 hostUTS 표준 필드 부재 → 결정론 검증 구조적"
     " 불가, fail-closed로 gate 차단(→label A LLM 폴백). 거짓양호 High 차단."),
    # ── k8s_master: ABSENT(13, DET_SOURCE.yaml 미기재) ─────────────────────
    ("PRCC-011", "k8s_master", "ABSENT: docker_linux만 정의(DET_SOURCE.yaml:1365)"),
    ("PRCC-018", "k8s_master", "ABSENT: k8s_worker/ocp_worker/eks_worker/aks_worker만 정의"),
    ("PRCC-019", "k8s_master", "ABSENT: docker_linux만 정의"),
    ("PRCC-020", "k8s_master", "ABSENT: docker_linux만 정의"),
    ("PRCC-021", "k8s_master", "ABSENT: docker_linux만 정의"),
    ("PRCC-023", "k8s_master", "ABSENT: docker_linux만 정의"),
    ("PRCC-032", "k8s_master", "ABSENT: docker_linux만 정의"),
    ("PRCC-034", "k8s_master", "ABSENT: docker_linux만 정의"),
    ("PRCC-040", "k8s_master", "ABSENT: k8s_worker/docker_linux 등만 정의(k8s_master 아님)"),
    ("PRCC-041", "k8s_master", "ABSENT: docker_linux만 정의"),
    ("PRCC-048", "k8s_master", "ABSENT: docker_linux만 정의"),
    ("PRCC-049", "k8s_master", "ABSENT: k8s_worker/docker_linux만 정의(k8s_master 아님)"),
    ("PRCC-050", "k8s_master", "ABSENT: docker_linux만 정의"),

    # ── docker_linux: MANUAL(1) ─────────────────────────────────────────────
    ("PRCC-011", "docker_linux", "MANUAL: json-file 아니면 result='M'(보수분류, :524-531)"),
    # ── docker_linux: ABSENT(18, DET_SOURCE.yaml 미기재) ────────────────────
    ("PRCC-001", "docker_linux", "ABSENT: master 계열(k8s/eks/aks/ocp)만 정의"),
    ("PRCC-002", "docker_linux", "ABSENT: master 계열만 정의"),
    ("PRCC-003", "docker_linux", "ABSENT: master 계열만 정의"),
    ("PRCC-004", "docker_linux", "ABSENT: k8s_master(MANUAL)/ocp_master(DET)만 정의"),
    ("PRCC-005", "docker_linux", "ABSENT: k8s_master/ocp_master만 정의"),
    ("PRCC-006", "docker_linux", "ABSENT: k8s_master/eks_master/aks_master만 정의"),
    ("PRCC-008", "docker_linux", "ABSENT: k8s_master/ocp_master만 정의"),
    ("PRCC-010", "docker_linux", "ABSENT: k8s_master/k8s_worker/ocp_master/ocp_worker만 정의"),
    ("PRCC-013", "docker_linux", "ABSENT: master/worker 계열만 정의(docker 없음)"),
    ("PRCC-014", "docker_linux", "ABSENT: k8s_master/ocp_master/ocp_worker만 정의"),
    ("PRCC-015", "docker_linux", "ABSENT: k8s_master/k8s_worker/ocp_master/eks_worker/aks_worker만 정의"),
    ("PRCC-016", "docker_linux", "ABSENT: k8s_master/ocp_master만 정의"),
    ("PRCC-017", "docker_linux", "ABSENT: k8s_master(pass)/worker 계열만 정의(docker 없음)"),
    ("PRCC-018", "docker_linux", "ABSENT: worker 계열만 정의(docker 없음)"),
    ("PRCC-025", "docker_linux", "ABSENT: k8s_master만 정의"),
    ("PRCC-027", "docker_linux", "ABSENT: master 계열(k8s/eks/aks/ocp)만 정의"),
    ("PRCC-028", "docker_linux", "ABSENT: master 계열만 정의"),
    ("PRCC-046", "docker_linux", "ABSENT: master 계열만 정의"),
]
