import re
import json
import traceback

###########
# 설명: 문자열로 된 결과를 딕셔너리로 변환
###########
def parseOutput(policy_str):
    policy = {}
    for line in policy_str.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if ':' not in line:
            continue
        try:
            key, value = line.split(":", 1)
            key = key.strip().strip('[]')  # 대괄호 제거
            value = value.strip()
            policy[key] = value
        except ValueError as e:
            print(f"Error parsing line: '{line}'. Error: {e}")
            continue
    return policy

# 파라미터: sApp(자산종류), vulKey(취약점ID), vulOutput(스크립트결과)
# 설명: 자산 종류, 취약점 ID로 분기하여 스크립트 결과 내 특정 문자열이 있는지 판별
###########
def autoAnalysis(sApp,vulKey,vulOutput):
    autoResult={"result":"N", "point":""}
    vulOutput = vulOutput.split('######')[0] #설명부분 제거
    autoTarget = ["k8s_master", "k8s_worker", "docker", "ocp_master", "ocp_worker","vcenter", "esxi", "xenserver", "eks_master", "eks_worker", "aks_master", "aks_worker"]
    print(sApp+" "+vulKey+"...")

    try:
        if sApp in autoTarget:
            if "PRCC-001" in vulKey:
                if "k8s_master" in sApp or "ocp_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "ROLE: cluster-admin" in vulOutput:
                        #스크립트 결과 내 cluster-admin이 존재하면 취약
                        autoResult["result"] = "Y"
                        autoResult["point"] = "cluster-admin이 부여된 role 존재"
                    else:
                        autoResult["result"] = "N"
                        autoResult["point"] = "cluster-admin이 부여된 role 존재하지 않음"
                # elif "ocp_master" in sApp:
                #     if "ROLE: cluster-admin" in vulOutput:
                #         autoResult["result"] = "Y"
                #         autoResult["point"] = "cluster-admin이 부여된 role 존재"
                #
                # elif "eks_master" in sApp:
                #     if "ROLE: cluster-admin" in vulOutput:
                #         autoResult["result"] = "Y"
                #         autoResult["point"] = "cluster-admin이 부여된 role 존재"

            elif "PRCC-002" in vulKey:
                if "k8s_master" in sApp or "ocp_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "[\"*\"]" in vulOutput:
                        #스크립트 결과 내 ["*"]이 존재하면 취약
                        autoResult["result"] = "Y"
                        autoResult["point"] = "과도한 권한(\"*\") 부여된 role 존재"

                # elif "ocp_master" in sApp:
                #     if "[\"*\"]" in vulOutput:
                #         #스크립트 결과 내 ["*"]이 존재하면 취약
                #         autoResult["result"] = "Y"
                #         autoResult["point"] = "과도한 권한(\"*\") 부여된 role 존재"

            elif "PRCC-003" in vulKey:
                if "k8s_master" in sApp or "ocp_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "Service Account:default" in vulOutput:
                        #스크립트 결과 내 Account:default이 존재하면 취약
                        autoResult["result"] = "Y"
                        autoResult["point"] = "기본서비스 계정(default)을 사용하는 컨테이너 존재"
                #
                # elif "ocp_master" in sApp:
                #     if "Service Account:default" in vulOutput:
                #         #스크립트 결과 내 Account:default이 존재하면 취약
                #         autoResult["result"] = "Y"
                #         autoResult["point"] = "기본서비스 계정(default)을 사용하는 컨테이너 존재"

            elif "PRCC-004" in vulKey:
                if "k8s_master" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                elif "ocp_master" in sApp:
                    matches = re.findall(r'\[--token-auth-file] : (?!\[X]).*', vulOutput)
                    if matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "--token-auth-file 파일 존재"
                    if "flag: [X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "authentication-operator가 False로 설정됨,"+autoResult["point"]


            elif "PRCC-005" in vulKey:
                if "k8s_master" in sApp:
                    if "--use-service-account-credentials=true" not in vulOutput:
                        #스크립트 결과 내 값이 false이면 취약
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'use-service-account-credentials'가 false로 설정"

                elif "ocp_master" in sApp:
                    if "[\"true\"]" not in vulOutput:
                        #스크립트 결과 내 값이 false이면 취약
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'use-service-account-credentials'가 false로 설정"

            elif "PRCC-006" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "automountServiceAccountToken이 true인 파드가 존재"

            if "PRCC-007" in vulKey:
                if "k8s_master" in sApp:
                    files = vulOutput.split('\n')
                    files = [item for item in files if item] #리스트에서 빈 값 제거

                    for file in files:
                        permission=file.split(" ")
                        if "root:root" not in file:
                            autoResult["result"] = "Y"
                            autoResult["point"] = file+","+autoResult["point"]
                        elif "kube-apiserver.yaml" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kube-controller-manager.yaml" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kube-scheduler.yaml" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "etcd.yaml" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "admin.conf" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "scheduler.conf" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "controller-manager.conf" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "crio.conf" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "config.toml" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                elif "k8s_worker" in sApp:
                    files = vulOutput.split('\n')
                    files = [item for item in files if item] #리스트에서 빈 값 제거
                    for file in files:
                        permission=file.split(" ")
                        if "root:root" not in file:
                            autoResult["result"] = "Y"
                            autoResult["point"] = file+","+autoResult["point"]
                        elif "config.yaml" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kubeadm.conf" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kubelet.conf" in file:
                            if int(permission[0]) > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "config.toml" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "crio.conf" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]

                elif "docker" in sApp:
                    files = vulOutput.split('\n')
                    files = [item for item in files if item] #리스트에서 빈 값 제거
                    for file in files:
                        permission=file.split(" ")
                        if "root:root" not in file:
                            autoResult["result"] = "Y"
                            autoResult["point"] = file+","+autoResult["point"]
                        elif "daemon.json" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "docker.sock" in file:
                            if int(permission[0]) > 660:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "/etc/docker]" in file:
                            if int(permission[0]) > 755:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]

                elif "ocp_master" in sApp:
                    # '###' 또는 '####' 혹은 '###' 등으로 시작하는 라인은 제거
                    # 먼저 CDATA에서 데이터를 가져오되, 시작부분에 '###' 혹은 '####'로 이루어진 라인은 삭제합니다.
                    # 먼저 줄 단위로 분리한 후 필터링 합니다.

                    # 먼저 "###" 라인을 구분자로 데이터를 분리하는 코드에서
                    # 인덱스 에러 등이 발생하지 않도록 검사합니다.
                    parts = vulOutput.split('###')
                    if len(parts) < 2:
                        files = vulOutput.splitlines()  # '###'가 없는 경우 전체 줄 사용
                    else:
                        # 분리된 두번째 부분에서 첫 번째 줄 제거
                        files = parts[1].splitlines()
                        if files and re.fullmatch(r'#+', files[0].strip()):
                            del files[0]

                    # 빈 줄 제거
                    files = [line for line in files if line.strip()]

                    # 정규표현식을 사용하여 permission 값을 추출하는 함수 정의
                    def extract_permission(line):
                        """
                        각 줄에서 permission 숫자를 추출합니다.
                        예: '600:root:root [/etc/...]' 또는 '[/etc/...] 600:root:root' 형태에도 대응.
                        """
                        # \b(\d+): 매칭해서 permission 번호 추출
                        match = re.search(r'\b(\d+):', line)
                        if match:
                            return match.group(1)
                        return None

                    # 파일 경로 (또는 식별자) 추출 함수
                    def extract_filepath(line):
                        """
                        파일 경로 문자열을 대괄호 [] 안에 있는 경우와 없는 경우 모두 처리합니다.
                        """
                        # 대괄호 안에 경로가 있는 경우 먼저 시도합니다.
                        match = re.search(r'\[([^\]]+)\]', line)
                        if match:
                            return match.group(1)
                        # 그렇지 않으면, 공백을 기준으로 마지막 요소를 경로로 간주
                        parts = line.split()
                        if parts:
                            return parts[-1]
                        return ''

                    for file in files:
                        # 파일 내 공백이 혼합되어 있을 수 있으므로 strip 및 재정리
                        line = file.strip()
                        permission_str = extract_permission(line)
                        if permission_str is None:
                            continue  # permission 숫자 추출 실패 시 다음 라인 처리

                        try:
                            permission_val = int(permission_str)
                        except ValueError:
                            # 정수가 아닌 경우 건너뜁니다.
                            continue

                        filepath = extract_filepath(line)

                        # 조건 검사: "root:root"가 존재하지 않으면 무조건 Y 처리
                        if "root:root" not in line:
                            autoResult["result"] = "Y"
                            autoResult["point"] = f"{line},{autoResult['point']}"
                        # 각 파일별 조건 적용
                        elif "kube-apiserver-pod.yaml" in line:
                            if permission_val > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = f"{line},{autoResult['point']}"
                        elif "kube-controller-manager-pod.yaml" in line:
                            if permission_val > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = f"{line},{autoResult['point']}"
                        elif "controller-manager-kubeconfig/kubeconfig" in line:
                            if permission_val > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = f"{line},{autoResult['point']}"
                        elif "kube-scheduler-pod.yaml" in line:
                            if permission_val > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = f"{line},{autoResult['point']}"
                        elif "etcd-pod.yaml" in line:
                            if permission_val > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = f"{line},{autoResult['point']}"
                        elif "scheduler-kubeconfig/kubeconfig" in line:
                            if permission_val > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = f"{line},{autoResult['point']}"
                        elif "kubernetes/kubeconfig" in line:
                            if permission_val > 600:
                                autoResult["result"] = "Y"
                                autoResult["point"] = f"{line},{autoResult['point']}"
                        elif "crio.conf" in line:
                            if permission_val > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = f"{line},{autoResult['point']}"

                elif "ocp_worker" in sApp:
                    files = vulOutput.split('###')[1].split("\n")

                    del files[0]

                    files = [item for item in files if item] #리스트에서 빈 값 제거
                    for file in files:

                        permission=file.split(" ")
                        permission = [item for item in permission if item]
                        permission = permission[1].split(":")[0]
                        print(permission)
                        if "root:root" not in file:
                            autoResult["result"] = "Y"
                            autoResult["point"] = file+","+autoResult["point"]
                        elif "kubelet.service" in file:
                            if int(permission) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kubelet.conf" in file:
                            if int(permission) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kubelet/config.json" in file:
                            if int(permission) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "crio.conf" in file:
                            if int(permission) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]

                elif "eks_worker" in sApp:
                    files = vulOutput.split('\n')[3:]
                    files = [item for item in files if item] #리스트에서 빈 값 제거

                    for file in files:
                        permission=file.split(" ")
                        if "root:root" not in file:
                            autoResult["result"] = "Y"
                            autoResult["point"] = file+","+autoResult["point"]
                        elif "kubelet.service" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kubeconfig" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kubelet/config.json" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "containerd/config.toml" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]

                elif "aks_worker" in sApp:
                    files = vulOutput.split('\n')[3:]
                    files = [item for item in files if item] #리스트에서 빈 값 제거

                    for file in files:
                        permission=file.split(" ")
                        if "root:root" not in file:
                            autoResult["result"] = "Y"
                            autoResult["point"] = file+","+autoResult["point"]
                        elif "kubelet.service" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kubeconfig" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "kubernetes/azure.json" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]
                        elif "containerd/config.toml" in file:
                            if int(permission[0]) > 644:
                                autoResult["result"] = "Y"
                                autoResult["point"] = file+","+autoResult["point"]


            elif "PRCC-008" in vulKey:
                if "k8s_master" in sApp:
                    if "bind-address=0.0.0.0" in vulOutput:
                        #스크립트 결과 내 bind-address=127.0.0.1값이 0.0.0.0이면 취약
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'bind-address'가 0.0.0.0으로 설정"
                    elif "--bind-address" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'bind-address'가 존재하지 않음(default)"

                elif "ocp_master" in sApp:
                    if "[\"10257\"]" not in vulOutput:
                        #스크립트 결과 내 bind-address=127.0.0.1값이 0.0.0.0이면 취약
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'secure-port'가 10257이 아닌 포트로 설정"

                    if "bindAddress" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "불필요한 bind address 설정 존재,"+autoResult["point"]

            elif "PRCC-009" in vulKey:
                if "k8s_master" in sApp:
                    if "--audit-policy-file" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'audit-policy-file'이 존재하지 않음"

                    if "--audit-log-path" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'audit-log-path'가 존재하지 않음,"+autoResult["point"]

                elif "k8s_worker" in sApp:
                    if "--v=" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "--v 설정이 존재 하지 않음(default 0)"
                    elif "--v=1" in vulOutput or "--v=0" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "--v=2 미만으로 설정"

                elif "docker" in sApp:
                    levs=['warn', 'error', 'fatal']

                    for lev in levs:
                        if lev in vulOutput:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "로그레벨이 '"+lev+"'로 설정 됨,"+autoResult["point"]

                elif "ocp_master" in sApp:
                    if "\"audit-log-path\":[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'audit-log-path'가 존재하지 않음"

                    if "\"audit-policy-file\":[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'audit-policy-file'가 존재하지 않음,"+autoResult["point"]

                elif "ocp_worker" in sApp or "aks_worker" in sApp:
                    if "--v=" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "--v 설정이 존재 하지 않음(default 0)"
                    elif "--v=1" in vulOutput or "--v=0" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "--v=2 미만으로 설정"

                elif "eks_master" in sApp:
                    if "No log types" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "활성화된 로그타입 없음"

                    if "group does not exist." in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "CloudWatch 로그 그룹이 존재하지 않음,"+autoResult["point"]

                elif "eks_worker" in sApp:
                    vulOutput = vulOutput.split("\n")
                    vulOutput = [item for item in vulOutput if item] #리스트에서 빈 값 제거
                    count = vulOutput.count("No result")
                    if count == 3:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "로그 설정이 존재하지 않음"

                elif "aks_master" in sApp:
                    if "flag: [X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "로그 설정이 존재하지 않음"

            elif "PRCC-010" in vulKey:
                if "k8s_master" in sApp:
                    volatile_paths=["/tmp", "/var/tmp", "/run", "/dev/shm", "/dev/pts"] #휘발성 경로 목록

                    if "--audit-log-path" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'audit-log-path'가 존재하지 않음,"+autoResult["point"]
                    else:
                        for path in volatile_paths:
                            if path in vulOutput:
                                autoResult["result"] = "Y"
                                autoResult["point"] = "휘발성 경로 '"+path+"' 존재,"+autoResult["point"]

                elif "k8s_worker" in sApp:
                    volatile_paths=["/tmp", "/var/tmp", "/run", "/dev/shm", "/dev/pts"] #휘발성 경로 목록
                    matches = re.findall(r'log-file"] : (?!\[X\]).*', vulOutput) #log-file"] : [X]가 아닌 값을 찾음
                    if matches:
                        for match in matches:
                            for path in volatile_paths:
                                if path in match:
                                    autoResult["result"] = "Y"
                                    autoResult["point"] = match+"내 휘발성 경로 '"+path+"' 존재,"+autoResult["point"]
                    else:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "log-file 설정이 존재하지 않음"

                elif "ocp_master" in sApp:
                    volatile_paths=["/tmp", "/var/tmp", "/run", "/dev/shm", "/dev/pts"] #휘발성 경로 목록

                    if "\"audit-log-path\":[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'audit-log-path'가 존재하지 않음"
                    else:
                        for path in volatile_paths:
                            if path in vulOutput:
                                autoResult["result"] = "Y"
                                autoResult["point"] = "휘발성 경로 '"+path+"' 존재,"+autoResult["point"]

                elif "ocp_worker" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

            elif "PRCC-011" in vulKey:
                if "docker" in sApp:
                    matches = re.findall(r'\["log-driver"\] : (?!\[X\]).*', vulOutput)
                    if not matches or "json-file" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "json-file로 로그를 저장하고 있음(default json-file)"
                    else:
                        autoResult["result"] = "M"
                        autoResult["point"] = "원격 로그 저장 설정 확인 필요"

            elif "PRCC-012" in vulKey:
                if "k8s_master" in sApp:
                    if "--tls-cert-file" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'--tls-cert-file'이 존재하지 않음"

                    if "--tls-private-key-file" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'tls-private-key-file'이 존재하지 않음,"+autoResult["point"]

                elif "k8s_worker" in sApp:
                    matches = re.findall(r'tls-cert-file"] : (?!\[X\]).*', vulOutput)
                    if not matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "tls-cert-file 설정이 존재하지 않음"

                    matches = re.findall(r'tls-private-key-file"] : (?!\[X\]).*', vulOutput)
                    if not matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "tls-private-key-file 설정이 존재하지 않음,"+autoResult["point"]

                elif "docker" in sApp:
                    matches = re.findall(r'\["--\w+"\] : \[X\]', vulOutput)  #: [X]인 값만 찾음
                    #print(matches)
                    if matches:
                        autoResult["result"] = "Y"
                        for match in matches:
                            autoResult["point"] = match+","+autoResult["point"]

                if "eks_master" in sApp:
                    if "https://" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "API서버 endpoint가 https로 설정 되어 있지 않음"

            elif "PRCC-013" in vulKey:
                if "k8s_master" in sApp:
                    if "--anonymous-auth" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'--anonymous-auth'가 존재하지 않음(default: true)"

                    if "--anonymous-auth=true" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'--anonymous-auth'가 'true'로 설정되어 있음"

                elif "k8s_worker" in sApp:
                    matches1 = re.findall(r'\["anonymous-auth"\] : (?!\[X\]).*', vulOutput)
                    matches2 = re.findall(r'\["anonymous"\] : (?!\[X\]).*', vulOutput)

                    if not matches1 and not matches2:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "anonymous-auth 설정이 존재하지 않음"

                elif "ocp_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'anonymous-auth'가 true로 설정되어 있음"

                elif "ocp_worker" in sApp or "aks_worker" in sApp:
                    if "false" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'anonymous-auth'가 false로 설정되어 있지 않음"

                if "eks_master" in sApp:
                    if "forbidden" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'anonymous'의 API 접속이 허용되어 있음"

                elif "eks_worker" in sApp:
                    vulOutput = vulOutput.split("\n")
                    vulOutput = [item for item in vulOutput if item] #리스트에서 빈 값 제거
                    count = vulOutput.count("No result")
                    if count == 2:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "Anonymous 접속 제한 설정이 존재하지 않음"

            elif "PRCC-014" in vulKey:
                if "k8s_master" in sApp:
                    timeout = re.findall(r"--request-timeout=(\d+)([smh])", vulOutput) #출력 결과 내 --request-timeout= 부분만 추출

                    for value, unit in timeout:
                        # 시간 값을 초 단위로 변환
                        value = int(value)
                        if unit == 'm':
                            timeout_seconds = value * 60
                        elif unit == 'h':
                            timeout_seconds = value * 3600
                        else:
                            timeout_seconds = value

                        # 60초 초과 여부 확인
                        if timeout_seconds > 60:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "--request-timeout="+str(value)+unit

                elif "ocp_master" in sApp:
                    timeout = re.findall(r"\"min-request-timeout\":\[\"(\d+)\"\]", vulOutput)

                    if int(timeout[0]) > 60:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "min-request-timeout="+timeout[0]

                elif "ocp_worker" in sApp:
                    if "AlwaysAllow" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'authorization-mode'가 AlwaysAllow로 설정되어 있음"

            elif "PRCC-015" in vulKey:
                if "k8s_master" in sApp:
                    if "--authorization-mode" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'--authorization-mode'가 존재하지 않음(default: AlwaysAllow)"
                    elif "AlwaysAllow" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'--authorization-mode'가 'AlwaysAllow'설정되어 있음"

                elif "k8s_worker" in sApp:
                    matches = re.findall(r'\["authorization"\] : (?!\[X\]).*', vulOutput)

                    if not matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "authorization 설정이 존재하지 않음(default AlwaysAllow)"
                    elif "AlwaysAllow" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'--authorization-mode'가 'AlwaysAllow'설정되어 있음"

                elif "ocp_master" in sApp:
                    if "AlwaysAllow" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'authorization-mode'가 'AlwaysAllow'설정되어 있음"

                if "eks_worker" in sApp:
                    if "AlwaysAllow" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'--authorization-mode'가 'AlwaysAllow'설정되어 있음"

                if "aks_worker" in sApp:
                    if "flag: [x]" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'--authorization-mode'가 'AlwaysAllow'설정되어 있음"

            elif "PRCC-016" in vulKey:
                if "k8s_master" in sApp:
                    if "--service-account-lookup=false" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'--service-account-lookup'이 'false'로 설정되어 있음"

                elif "ocp_master" in sApp:
                    if "\"service-account-lookup\":[\"false\"]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'service-account-lookup'이 'false'로 설정되어 있음"

            elif "PRCC-017" in vulKey:
                if "k8s_master" in sApp:
                    pass
                elif "k8s_worker" in sApp:
                    matches1 = re.findall(r'\["read-only-port"\] : (?!\[X\]).*', vulOutput)
                    matches2 = re.findall(r'\["readOnlyPort"\] : (?!\[X\]).*', vulOutput)

                    if not matches1 and not matches2:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'read-only-port' 및 'readOnlyPort' 값이 존재하지 않음(default 10255)"
                    elif "read-only-port=0" not in vulOutput and "readOnlyPort: 0" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'read-only-port' 또는 'readOnlyPort' 값이 0으로 설정되어 있지 않음"

                elif "ocp_worker" in sApp:
                    if "[\"0\"]" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'kubelet-read-only-port'가 0으로 설정되어 있지 않음"

                elif "eks_worker" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                elif "aks_worker" in sApp:
                    if "=0" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'kubelet-read-only-port'가 0으로 설정되어 있지 않음"

            elif "PRCC-018" in vulKey:
                if "k8s_worker" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                elif "ocp_worker" in sApp:
                    if "false" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'makeIPTablesUtilChains'가 false로 설정되어 않음"

                elif "eks_worker" in sApp:
                    vulOutput = vulOutput.split("\n")
                    vulOutput = [item for item in vulOutput if item] #리스트에서 빈 값 제거
                    count = vulOutput.count("No result")
                    if count == 2:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "makeIPTablesUtilChains 설정이 존재하지 않음(default: true)"

                elif "aks_worker" in sApp:
                    if "No result" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "makeIPTablesUtilChains 설정이 존재하지 않음(default: true)"

            elif "PRCC-019" in vulKey:
                if "docker" in sApp:
                    if "root" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "docker daemon이 root로 실행중"

            elif "PRCC-020" in vulKey:
                if "docker" in sApp:
                    if "true" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "experimental이 true로 설정됨"

            elif "PRCC-021" in vulKey:
                if "docker" in sApp:
                    matches = re.findall(r'userland-proxy"] : (?!\[X\]).*', vulOutput)
                    if not matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "userland-proxy 설정이 존재하지 않음(default true)"
                    else:
                        for match in matches:
                            if "true" in match:
                                autoResult["result"] = "Y"
                                autoResult["point"] = "userland-proxy가 true로 설정됨"

            elif "PRCC-022" in vulKey:
                if "k8s" in sApp or "ocp" in sApp or "eks" in sApp or "aks" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                elif "docker" in sApp:
                    matches = re.findall(r'insecure-registry"] : (?!\[X\]).*', vulOutput)
                    if matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "insecure-registry가 설정됨"


            elif "PRCC-023" in vulKey:
                if "docker" in sApp:
                    if "default_bridge:true" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "기본 네트워크 인터페이스 사용이 설정됨"

                    if "does not exist" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "기본 네트워크 인터페이스를 사용하는 컨테이너 존재,"+autoResult["point"]

            elif "PRCC-024" in vulKey:
                if "k8s_master" in sApp or "ocp_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "No resources" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "networkpolicy가 존재하지 않음"
                    else:
                        autoResult["result"] = "M"
                        autoResult["point"] = "수동점검 필요"

                elif "docker" in sApp:
                    if "enable_icc:true" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = " icc 옵션이 활성화 되어있음"

                elif "ocp_master" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                if "eks_master" in sApp:
                    if "No resources" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "networkpolicy가 존재하지 않음"

            elif "PRCC-025" in vulKey:
                if "k8s_master" in sApp:
                    if "--profiling=true" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'profiling'이 'true'로 설정되어 있음"

                    elif "profiling: true" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'profiling'이 'true'로 설정되어 있음"

                    elif "--profiling" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'profiling'이 설정되어 있지 않음(default: true)"

                    elif "profiling: " not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'profiling'이 설정되어 있지 않음(default: true)"

            elif "PRCC-026" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "flag: [X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'privileged'가 'true'로 설정된 컨테이너 존재"

                elif "docker" in sApp:
                    if "Privileged: true" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = " 'privileged' 값이 true로 설정된 컨테이너 존재"

                elif "ocp_master" in sApp:
                    if "SCC: " in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'privileged'가 'true'인 SCC가 적용된 컨테이너 존재"

            elif "PRCC-027" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    capabilities=["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_CHROOT", "DAC_OVERRIDE", "SETUID", "SETGID", "SYS_MODULE"]
                    for cap in capabilities:
                        if cap in vulOutput:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "'capabilities.add'에 "+cap+ "이 할당 된 컨테이너 존재,"+autoResult["point"]

                elif "ocp_master" in sApp:
                    if "SCC: " in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "높은수준의 커널 접근권한이 허용된 SCC가 적용된 컨테이너 존재"

            elif "PRCC-028" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "capabilities.drop:''" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "capabilities.drop 값이 존재하지 않는 컨테이너가 존재"

                elif "ocp_master" in sApp:
                    if "SCC: " in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "높은수준의 커널 접근권한을 제거하지 않은 SCC가 적용된 컨테이너 존재"


            elif "PRCC-029" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "allowPrivilegeEscalation:''" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'allowPrivilegeEscalation'가 설정 되어 있지 않은 컨테이너 존재(default: true),"+autoResult["point"]
                    if "allowPrivilegeEscalation:'true'" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'allowPrivilegeEscalation'가 true로 설정 되어 있는 컨테이너 존재,"+autoResult["point"]

                elif "docker" in sApp:
                    matches = re.findall(r'no-new-privileges"] : (?!\[X\]).*', vulOutput)

                    if not matches or "(false)" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = " 'no-new-privileges' 값이 설정 되어 있지 않음(default 비활성화)"
                    elif "false" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = " 'no-new-privileges' 값이 false로 설정되어 있음"

                elif "ocp_master" in sApp:
                    if "SCC: " in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "allowPrivilegeEscalation'가 true로 설정 되어 있는 SCC가 적용된 컨테이너 존재"

            elif "PRCC-030" in vulKey:
                if "k8s_master" in sApp:
                    if "seccompProfile.localhostProfile:''" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'seccompProfile'이 설정되어 있지 않음"

                elif "docker" in sApp:
                    if "seccomp=unconfined" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "seccomp=unconfined인 컨테이너 존재"
                    if "profile=unconfined" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "profile=unconfined인 컨테이너 존재,"+autoResult["point"]

            elif "PRCC-031" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if ".runAsNonRoot:'false'" in vulOutput and ".runAsUser:''":
                        autoResult["result"] = "Y"
                        autoResult["point"] = " 'runAsNonRoot=false' & 'runAsUser' 미지정 컨테이너가 존재,"+autoResult["point"]
                    if ".runAsNonRoot:'false'" in vulOutput and ".runAsUser:'0'":
                        autoResult["result"] = "Y"
                        autoResult["point"] = " 'runAsNonRoot=false' & 'runAsUser=0' 컨테이너가 존재,"+autoResult["point"]
                    if ".runAsNonRoot:''" in vulOutput and ".runAsUser:''":
                        autoResult["result"] = "Y"
                        autoResult["point"] = " 'runAsNonRoot' 미지정 & 'runAsUser' 미지정 컨테이너가 존재,"+autoResult["point"]
                    if ".runAsNonRoot:''" in vulOutput and ".runAsUser:'0'":
                        autoResult["result"] = "Y"
                        autoResult["point"] = " 'runAsNonRoot' 미지정 & 'runAsUser'가 0인 컨테이너가 존재,"+autoResult["point"]

                elif "docker" in sApp:
                    if "| UID: 0" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "관리자 권한 실행 컨테이너 존재"

                    matches = re.findall(r'Config\.User:\s*(root|$)', vulOutput) #Config.User: root 이거나 Config.User: 인 경우
                    if matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "관리자 권한 설정 컨테이너 존재,"+autoResult["point"]

                elif "ocp_master" in sApp:
                    if "SCC: " in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "MustRunAsNonRoot 미설정 SCC가 적용된 컨테이너 존재"

            elif "PRCC-032" in vulKey:
                if "docker" in sApp:
                    matches = re.findall(r'live-restore"] : (?!\[X\]).*', vulOutput)
                    if "false" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "LiveRestoreEnabled 설정이 false로 설정됨"
                    elif not matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "LiveRestoreEnabled 설정이 존재하지 않음(default false)"

            elif "PRCC-033" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if ".restartPolicy:Never" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "spec.restartPolicy가 Never로 설정되는 Pod 존재"

                elif "docker" in sApp:
                    if "RestartPolicy Name: no" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "RestartPolicy Name 설정이 no로 설정된 컨테이너 존재"

                    if "MaximumRetryCount: 0" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "MaximumRetryCount 설정이 0으로 설정된 컨테이너 존재,"+autoResult["point"]

                elif "ocp_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "restartPolicy가  Never로 설정되는 Pod 존재"

            elif "PRCC-034" in vulKey:
                if "docker" in sApp:
                    if "| no healthcheck" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "헬스체크를 하지 않는 컨테이너 존재"

            elif "PRCC-035" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    dirs=["/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr"]

                    for dir in dirs:
                        if dir in vulOutput:
                            autoResult["result"] = "Y"
                            autoResult["point"] = dir+ "이(가) 마운트된 컨테이너 존재,"+autoResult["point"]

                elif "docker" in sApp:
                    if "[does not exist]" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "시스템 디렉터리가 마운트된 컨테이너 존재"

                elif "ocp_master" in sApp:
                    dirs = ["/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr"]

                    vulOutput = vulOutput.split("Pod: ")[2:]
                    for output in vulOutput:
                        podName = output.split("\n")[0].strip()
                        hostPath = output.split("Host Path: ")[1].split("Mount Path:")[0].strip()
                        mountPath = output.split("Mount Path:")[1].strip()

                        hostPath = re.findall(r'"path":"(.*?)"', hostPath)
                        mountPath = re.findall(r'"mountPath":"(.*?)"', mountPath)

                        for hp in hostPath:
                            if hp in dirs:
                                if hp in mountPath:
                                    autoResult["result"] = "Y"
                                    autoResult["point"] = podName+"에 시스템 디렉토리 '"+hp+"'가 마운트 되어 있음,"+autoResult["point"]

            elif "PRCC-036" in vulKey:
                if "k8s_master" in sApp:
                    socks=["docker.sock", "containerd.sock"]

                    for sock in socks:
                        if sock in vulOutput:
                            autoResult["result"] = "Y"
                            autoResult["point"] = sock+ "이 마운트된 컨테이너 존재,"+autoResult["point"]

                elif "docker" in sApp:
                    if "[does not exist]" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "CRI 소켓 볼륨이 마운트된 컨테이너 존재"

                elif "ocp_master" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

            elif "PRCC-037" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if re.search(r'securityContext\.readOnlyRootFilesystem:\s*$', vulOutput, re.MULTILINE | re.IGNORECASE):
                        autoResult["result"] = "Y"
                        autoResult["point"] = "readOnlyRootFilesystem이 빈칸으로(default: false) 설정된 컨테이너 존재,"+autoResult["point"]

                    if re.search(r'securityContext\.readOnlyRootFilesystem:False\s*$', vulOutput, re.MULTILINE | re.IGNORECASE):
                        autoResult["result"] = "Y"
                        autoResult["point"] = "readOnlyRootFilesystem이 False로 설정된 컨테이너 존재,"+autoResult["point"]

                elif "docker" in sApp:
                    if "[does not exist]" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'ReadonlyRootfs'가 false로 설정된 컨테이너 존재"

                elif "ocp_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'readOnlyRootFilesystem'이 true로 설정되는 컨테이너 존재"

            elif "PRCC-038" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "mountPropagation: Bidirectional" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "mountPropagation:Bidirectional이 설정되어 있음"

                elif "docker" in sApp:
                    if "[does not exist]" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "마운트 전파 모드가 shared로 설정된 컨테이너 존재"

                elif "ocp_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "마운트 전파 모드가 'Bidirectional'인 컨테이너 존재"

            elif "PRCC-039" in vulKey:
                if "k8s_master" in sApp or "ocp_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                elif "docker" in sApp:
                    matches = re.findall(r' .HostConfig.Devices: (?!\[\]).*', vulOutput)
                    #print(matches)
                    if matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'HostConfig.Devices'에 불필요한 장치가 마운트되어 있는 컨테이너 존재"

            elif "PRCC-040" in vulKey:
                if "k8s_worker" in sApp or "docker" in sApp or "ocp_worker" in sApp or "eks_worker" in sApp or "aks_worker" in sApp:
                    if "aufs" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "aufs 설정 존재"

            elif "PRCC-041" in vulKey:
                if "docker" in sApp:
                    if "host" in vulOutput or "default" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "UsernsMode가 'host' 또는 'default'로 설정된 컨테이너가 존재"

                    if "deactivated" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "userns-remap이 비활성화 되어 있음,"+autoResult["point"]

            elif "PRCC-042" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp  or "aks_master" in sApp:
                    if "spec.hostPID:'true'" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "spec.hostPID:'true'로 설정되어 있는 컨테이너 존재"

                elif "docker" in sApp:
                    if "host" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "HostConfig.PidMode가 'host'로 설정된 컨테이너가 존재"

                elif "ocp_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'allowHostPID' 값이 없거나 true로 설정되어 있는 SCC가 적용 되어 있는 컨테이너 존재"


            elif "PRCC-043" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "spec.hostIPC:'true'" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "spec.hostIPC:'true'로 설정되어 있는 컨테이너 존재"

                elif "docker" in sApp:
                    if "host" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "HostConfig.IpcMode가 'host'로 설정된 컨테이너가 존재"

                elif "ocp_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'allowHostIPC' 값이 없거나 true로 설정되어 있는 SCC가 적용 되어 있는 컨테이너 존재"

            elif "PRCC-044" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "spec.hostNetwork:'true'" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "spec.hostNetwork:'true'로 설정되어 있는 컨테이너 존재"

                elif "docker" in sApp:
                    if "host" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "NetworkMode가 'host'로 설정된 컨테이너가 존재"

                    if "enable_icc:true" in vulOutput and "NetworkMode: default" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "NetworkMode가 'bridge(default)'이며 icc옵션이 true로 설정된 컨테이너가 존재,"+autoResult["point"]

                elif "ocp_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'allowHostNetwork'값이 true로 설정되어 있는 SCC가 적용 되어 있는 컨테이너 존재"

            elif "PRCC-045" in vulKey:
                if "k8s_master" in sApp or "k8s_master" in sApp:
                    if "spec.hostUTS:'true'" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "spec.hostUTS:'true'로 설정되어 있는 컨테이너 존재"

                elif "docker" in sApp:
                    if "UTSMode: host" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "UTSMode가 'host'로 설정된 컨테이너가 존재"

                elif "ocp_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'hostUTS'가 'true'로 설정되어 있는 컨테이너 존재"

            elif "PRCC-046" in vulKey:
                if "k8s_master" in sApp or "ocp_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "hostPort를 사용하는 컨테이너 존재"

                # elif "ocp_master" in sApp:
                #     autoResult["result"] = "M"
                #     autoResult["point"] = "수동점검 필요"

            elif "PRCC-047" in vulKey:
                if "k8s_master" in sApp or "eks_master" in sApp or "aks_master" in sApp:
                    if "resources.limits.memory:'0'" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "resources.limits.memory:'0'로 설정되어 있는 컨테이너 존재"
                    if "resources.limits.memory:''" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "resources.limits.memory:''로 설정되어 있는 컨테이너 존재,"+autoResult["point"]

                elif "docker" in sApp:
                    if "Memory: 0" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "컨테이너의 메모리 무제한 사용(Memory=0) 가능한 컨테이너가 존재"

                elif "ocp_master" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "'resources.limits.memory'가 0(무제한)으로 설정되어 있는 컨테이너 존재"

            elif "PRCC-048" in vulKey:
                if "docker" in sApp:
                    matches = re.findall(r'.*CgroupParent: (?!docker|\s).*', vulOutput)
                    if matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "부적절한 cgroup이 설정된 컨테이너가 존재"

            elif "PRCC-049" in vulKey:
                if "k8s_worker" in sApp:
                    matches1 = re.findall(r'\["pod-pids-limit"\] : (?!\[X\]).*', vulOutput)
                    matches2 = re.findall(r'\["podPidsLimit"\] : (?!\[X\]).*', vulOutput)

                    if not matches1 and not matches2:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "PID 제한 설정이 존재하지 않음(default -1)"
                    elif "-1" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "PID 제한 설정이 -1로 설정됨"

                elif "docker" in sApp:
                    matches = re.findall(r'.*PidsLimit: (0|-1|<nil>|no limit|\s)', vulOutput)
                    if matches:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "부적절한 PidsLimit 설정 존재"

            elif "PRCC-050" in vulKey:
                if "docker" in sApp:
                    matches1 = re.findall(r'default-ulimit"] : (\[X\]).*', vulOutput)
                    matches2 = re.findall(r'HostConfig.Ulimits: (\[\]|no|<nil>|null).*', vulOutput)
                    #print(matches1)
                    #print(matches2)
                    if matches1 and matches2:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "Docker 데몬에 'default-ulimit' 옵션이 존재않고, 'ulimit' 옵션이 존재하지 않는 컨테이너 존재"


            if "PRCV-001" in vulKey:
                if "vcenter" in sApp or "esxi" in sApp or "xenserver" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

            elif "PRCV-002" in vulKey:
                if "vcenter" in sApp or "esxi" in sApp or "xenserver" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

            elif "PRCV-003" in vulKey:
                if "vcenter" in sApp or "esxi" in sApp or "xenserver" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"


            elif "PRCV-004" in vulKey:
                if "vcenter" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    #print("output : ", output)

                    min_length = int(output.get("MinLength", 0))
                    min_numeric = int(output.get("MinNumericCount", 0))
                    min_special = int(output.get("MinSpecialCharCount", 0))
                    min_uppercase = int(output.get("MinUppercaseCount", 0))
                    min_lowercase = int(output.get("MinLowercaseCount", 0))

                    if not min_length >= 10 and (min_numeric == 0 or min_special == 0) and (min_uppercase >= 1 or min_lowercase >= 1):
                        autoResult["result"] = "Y"
                        autoResult["point"] = "패스워드 길이가 10자리 이하임(2가지 문자 조합)"+","+autoResult["point"]
                    if not min_length >= 8 and (min_numeric >= 1 and min_special >= 1) and (min_uppercase >= 1 or min_lowercase >= 1):
                        autoResult["result"] = "Y"
                        autoResult["point"] = "패스워드 길이가 8자리 이하임(3가지 문자 조합)"+","+autoResult["point"]

                elif "esxi" in sApp:
                    output = vulOutput.split("### results ###")[1].split(":")[1].replace("min",",min").split(",")

                    #N0 = output[0].replace("retry=","") #재시도 횟수
                    N1 = output[1].replace("min=","")   #단일 문자 최소 길이
                    N2 = output[2]                      #두 가지 문자 최소 길이
                    #N3 = output[3]                      #비밀번호 최소 길이
                    N4 = output[4]                      #세 가지 문자 최소 길이
                    N5 = output[5]                      #네 가지 문자 최소길이

                    if "disable" not in N1:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "단일 문자 조합일떄 비밀번호 허용"+","+autoResult["point"]
                    if "disable" not in N2:
                        if int(N2) < 10 :
                            autoResult["result"] = "Y"
                            autoResult["point"] = "두 가지 문자 조합일떄 비밀번호 최소 길이가 10자리 미만"+","+autoResult["point"]

                    if "disable" not in N4 or "disable" not in N5:
                        if int(N4) < 8 or int(N5) < 8:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "세 가지 이상 문자 조합일떄 비밀번호 최소 길이가 8자리 미만"+","+autoResult["point"]

                elif "xenserver" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

            elif "PRCV-005" in vulKey:
                if "vcenter" in sApp or "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    password_lifetime = int(output.get("PasswordLifetimeDays", 0))
                    if password_lifetime > 90:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "패스워드 변경주기가 90일을 초과"

                elif "xenserver" in sApp:
                    output = parseOutput(vulOutput.split("$ chage -l [user]")[1])
                    for val in output:
                        if int(output[val]) > 90:
                            autoResult["result"] = "Y"
                            autoResult["point"] = val+": "+output[val]+","+autoResult["point"]

            elif "PRCV-006" in vulKey:
                if "vcenter" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    passwordHistory = int(output.get("ProhibitedPreviousPasswordsCount", 0))
                    if passwordHistory == 0:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "비밀번호 재사용 횟수가 설정되어 있지 않음"

                elif "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    passwordHistory = int(output.get("Security.PasswordHistory", 0))
                    if passwordHistory == 0:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "비밀번호 재사용 횟수가 설정되어 있지 않음"

                elif "xenserver" in sApp:
                    if "remember=" not in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "비밀번호 재사용 횟수가 제한되어 있지 않음"

            elif "PRCV-007" in vulKey:
                if "vcenter" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])

                    autoUnlockIntervalSec = int(output.get("AutoUnlockIntervalSec", 0))
                    failedAttemptIntervalSec = int(output.get("FailedAttemptIntervalSec", 0))
                    maxFailedAttempts = int(output.get("MaxFailedAttempts", 0))

                    if autoUnlockIntervalSec == 0:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "잠금해제 시간이 0으로 설정됨,"+autoResult["point"]

                    if failedAttemptIntervalSec < 900:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "실패 시간 간격이 15분(900초) 미만으로 설정됨 ,"+autoResult["point"]

                    if maxFailedAttempts > 5:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "최대 로그인 시도 횟수가 5회 초과로 설정됨,"+autoResult["point"]

                elif "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1].split("----")[0])
                    lockFail = int(output.get("Security.AccountLockFailures", 0))

                    if lockFail > 5:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "로그인 시도 횟수가 5회 설정되어 있음"

                    output = parseOutput(vulOutput.split("### results ###")[2])
                    lockTime = int(output.get("Security.AccountUnlockTime", 0))

                    if lockTime < 900:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "계정 잠금 시간이 15분 미만으로 설정되어 있음," + autoResult["point"]

                elif "xenserver" in sApp:
                    deny_list = re.findall(r'^.*\b(deny=\d+)\b', vulOutput, flags=re.MULTILINE)
                    unlock_list = re.findall(r'^.*\b(unlock_time=\d+)\b', vulOutput, flags=re.MULTILINE)

                    for deny in deny_list:
                        deny = deny.split("=")
                        if int(deny[1]) > 5:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "최대 로그인 시도 횟수가 5회 초과로 설정됨,"+autoResult["point"]
                            break

                    for unlock in unlock_list:
                        unlock = unlock.split("=")
                        if int(unlock[1]) < 900:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "계정 잠금 시간이 15분 미만으로 설정되어 있음,"+autoResult["point"]
                            break


            elif "PRCV-008" in vulKey:
                    if "esxi" in sApp:
                        if "lockdownDisabled" in vulOutput:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "잠금모드가 비활성화 되어있음"
                        else:
                            autoResult["result"] = "M"
                            autoResult["point"] = "예외 사용자 확인 필요"

            elif "PRCV-009" in vulKey:
                if "vcenter" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                elif "esxi" in sApp:
                    vulOutput = vulOutput.strip()
                    vulOutput = vulOutput.split("\n\n")[1:]
                    data = {}
                    for v in vulOutput:
                        lines = v.strip().splitlines()
                        if lines:
                            section_name = lines[0].strip("[]")
                            data[section_name] = {}

                            for line in lines[1:]:
                                if ":" in line:
                                    key, value = line.split(":", 1)
                                    data[section_name][key.strip()] = value.strip()

                    for key, value in data.items():
                        allIpValue = value.get("AllowedHosts(AllIp)")
                        if allIpValue.lower() == "true":
                            autoResult["result"] = "Y"
                            autoResult["point"] = key + "가 모든 IP 주소에서 접근을 허용하고 있음"+","+autoResult["point"]
                    autoResult["point"] = "관리용도 IP 확인 필요"+","+autoResult["point"]

                elif "xenserver" in sApp:
                    vulOutput = vulOutput.split("\n")

                    for out in vulOutput:
                        if "(-)IP Address" in out:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "IP 제한이 설정 되어 있지 않음 있음"+","+autoResult["point"]
                        elif "(-)'pam" in out:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "ssh에 정책 적용이 되어 있지 않음"+","+autoResult["point"]



            elif "PRCV-010" in vulKey:
                if "esxi" in sApp:
                    if "lockdownDisabled" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "잠금모드가 비활성화 되어있음"

            elif "PRCV-011" in vulKey:
                if "vcenter" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                elif "esxi" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                elif "xenserver" in sApp:
                    if "(-)'Banner'" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "Banner 설정이 안되어 있음"+","+autoResult["point"]


            elif "PRCV-012" in vulKey:
                if "vcenter" in sApp:
                    output = vulOutput.split("### results ###")[1].replace("\n","")

                    if output == "":
                        autoResult["result"] = "Y"
                        autoResult["point"] = "NTP 설정이 없음"

                elif "esxi" in sApp:
                    if "[X]" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "NTP가 비활성화 되어있음"

                elif "xenserver" in sApp:
                    if "(-)ntp" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "ntp 설정이 안되어 있음"+","+autoResult["point"]

            elif "PRCV-013" in vulKey:
                if "vcenter" in sApp:
                    autoResult["result"] = "M"
                    autoResult["point"] = "수동점검 필요"

                elif "esxi" in sApp:
                    vulOutput = vulOutput.strip()
                    vulOutput = vulOutput.split("\n")[1:]
                    data = {}
                    for v in vulOutput:
                        lines = v.strip().splitlines()
                        for line in lines:
                            if ":" in line:
                                key, value = line.split(":", 1)
                                data[key.strip()] = value.strip()
                    if data["enable"] == "true":
                        if data["communities"].lower() != "":
                            autoResult["result"] = "Y"
                            autoResult["point"] = "SNMP v2를 사용중"

                elif "xenserver" in sApp:
                    if "(+)snmp" in vulOutput:
                        autoResult["result"] = "N"
                        autoResult["point"] = "snmp를 사용하지 않음"+","+autoResult["point"]

            elif "PRCV-014" in vulKey:
                if "vcenter" in sApp:
                    output = vulOutput.split("### results ###")[1]
                    if "true" in output.lower():
                        autoResult["result"] = "Y"
                        autoResult["point"] = "MOB가 활성화 되어 있음"

                elif "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    enableMob = output.get("Config.HostAgent.plugins.solo.enableMob", 0)

                    if str(enableMob).lower() == "true":
                        autoResult["result"] = "Y"
                        autoResult["point"] = "enableMob 값이 true로 설정되어 있음"

            elif "PRCV-015" in vulKey:
                if "esxi" in sApp:
                    if vulOutput.strip().lower() == "community supported":
                        autoResult["result"] = "Y"
                        autoResult["point"] = "VIB 승인 레벨이 Community Supported로 설정되어 있음"

            elif "PRCV-016" in vulKey:
                if "vcenter" in sApp:
                    output = vulOutput.split("### results ###")[1]
                    if "true" in output.lower():
                        autoResult["result"] = "Y"
                        autoResult["point"] = "CEIP가 활성화 되어 있음"

                elif "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    ceipOpt = int(output.get("UserVars.HostClientCEIPOptIn", 0))
                    if ceipOpt == 0 or ceipOpt == 1:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "CEIP 기능이 활성화되어 있음"

            elif "PRCV-017" in vulKey:
                if "vcenter" in sApp:
                    output = vulOutput.split("### results ###")[1]
                    if int(output) > 900:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "세션 타임아웃 설정이 15분(900초) 이상으로 설정됨"

                elif "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    timeOut = int(output.get("UserVars.HostClientSessionTimeout", 0))
                    if timeOut > 900:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "HostClientSessionTimeout 값이 15분(900초)을 초과"

            elif "PRCV-018" in vulKey:
                if "esxi" in sApp:
                    vulOutput = vulOutput.strip()
                    vulOutput = vulOutput.split("\n\n\n\n")[0:]
                    data = {}
                    for v in vulOutput:
                        lines = v.strip("\n").splitlines()
                        if lines:
                            section_name = lines[0].strip("[]")
                            data[section_name] = {}

                            for line in lines[1:]:
                                if ":" in line:
                                    key, value = line.split(":", 1)
                                    data[section_name][key.strip()] = value.strip()

                    for key, value in data.items():
                        running = value.get("Running")
                        if running.lower() == "true":
                            autoResult["result"] = "Y"
                            autoResult["point"] = key + "가 활성화 되어 있음 있음"+","+autoResult["point"]

            if "PRCV-019" in vulKey:
                if "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    timeOut = int(output.get("UserVars.ESXiShellTimeOut", 0))
                    if timeOut > 3600 or timeOut == 0:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "ESXiShellTimeOut 값이  0이거나  3600초를 초과"

            elif "PRCV-020" in vulKey:
                if "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    timeOut = int(output.get("UserVars.ESXiShellInteractiveTimeOut", 0))
                    if timeOut > 900 or timeOut == 0:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "ESXiShellInteractiveTimeOut 값이  0이거나  900초를 초과"

            elif "PRCV-021" in vulKey:
                if "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    timeOut = int(output.get("UserVars.DcuiTimeOut", 0))
                    if timeOut > 600 :
                        autoResult["result"] = "Y"
                        autoResult["point"] = "DcuiTimeOut 값이 600초를 초과"

                elif "xenserver" in sApp:
                    if "(-)'TMOUT'" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "TMOUT 설정이 안되어 있음"+","+autoResult["point"]

            elif "PRCV-022" in vulKey:
                if "vcenter" in sApp:
                    output = vulOutput.split("### results ###")[1].replace("\n","")
                    if "none" in output.lower() or "error" in output.lower() or "warning" in output.lower():
                        autoResult["result"] = "Y"
                        autoResult["point"] = "로그 설정이 info 보다 낮은 단계로 설정됨"

                elif "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    logHost = output.get("Syslog.global.logHost", 0)
                    if logHost == "" :
                        autoResult["result"] = "Y"
                        autoResult["point"] = "Syslog.global.logHost가 설정되어 있지 않음"

                elif "xenserver" in sApp:
                    if "(-)remote" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "원격 로그 서버 설정이 안되어 있음"+","+autoResult["point"]

            elif "PRCV-023" in vulKey:
                if "vcenter" in sApp:
                    output = vulOutput.split("### results ###")[1].strip()
                    if output.lower() == "error" or output.lower() == "warning" :
                        autoResult["result"] = "Y"
                        autoResult["point"] = "Log level이 너무 낮은 수준(error 또는 warning)으로 설정되어 있음"

                elif "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    logLevel = output.get("Config.HostAgent.log.level", 0)
                    if logLevel.lower() == "error" or logLevel.lower() == "warning" :
                        autoResult["result"] = "Y"
                        autoResult["point"] = "Log level이 너무 낮은 수준(error 또는 warning)으로 설정되어 있음"

                elif "xenserver" in sApp:
                    if "(-)logging" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "로깅 설정이 되어 있지 않음"+","+autoResult["point"]

            elif "PRCV-024" in vulKey:
                if "esxi" in sApp:
                    output = parseOutput(vulOutput.split("### results ###")[1])
                    logDir = output.get("Syslog.global.logDir", 0)
                    volatile_paths=["/tmp", "/var/tmp", "/run", "/dev/shm", "/dev/pts", "/scratch/"] #휘발성 경로 목록
                    for path in volatile_paths:
                        if path in logDir:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "휘발성 경로 '"+path+"' 존재,"+autoResult["point"]

                elif "xenserver" in sApp:
                    if "(-)logging" in vulOutput:
                        autoResult["result"] = "Y"
                        autoResult["point"] = "로깅 설정이 되어 있지 않음"+","+autoResult["point"]

                    volatile_paths=["/tmp", "/var/tmp", "/run", "/dev/shm", "/dev/pts", "/scratch/"] #휘발성 경로 목록
                    for path in volatile_paths:
                        if path in vulOutput:
                            autoResult["result"] = "Y"
                            autoResult["point"] = "휘발성 경로 '"+path+"' 존재"+", "+autoResult["point"]

            elif "PRCV-025" in vulKey:
                if "vcenter" in sApp:
                    output = vulOutput.split("### results ###")[1].replace("\n","")
                    if "https" not in output.lower():
                        autoResult["result"] = "Y"
                        autoResult["point"] = "api URL이 HTTP를 사용하고 있음"

                elif "esxi" in sApp:
                    if  " code: 000" in vulOutput :
                        autoResult["result"] = "Y"
                        autoResult["point"] = "api URL이 HTTP를 허용하고 있음"

            elif "PRCV-026" in vulKey:
                if "esxi" in sApp:
                    vulOutput = vulOutput.strip()
                    vulOutput = vulOutput.split("\n\n")
                    data = {}
                    section_list = []
                    network = ""
                    partition = ""
                    for v in vulOutput:
                        lines = v.strip("\n").splitlines()
                        if lines:
                            section_name = lines[0].split()[4]
                            section_list.append(section_name)
                            data[section_name] = {}
                            for line in lines[1:]:
                                if ":" in line:
                                    key, value = line.split(":", 1)
                                    data[section_name][key.strip()] = value.strip()

                    for list in section_list:
                        if "network" in list:
                            network = data["network"]["Enabled"]
                        if "partition" in list:
                            partition = data["partition"]["Active"]

                    if (network.lower() == "false" or network.lower() == "") and (partition.lower() == "false" or partition == ""):
                        autoResult["result"] = "Y"
                        autoResult["point"] = "core dump가 비활성화 되어 있음 있음"

                elif "PRCV-027" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        vulOutput = vulOutput.split("\n")[2:]
                        for v in vulOutput:
                            v = v.split()
                            vm = v[0]
                            conf = v[1]
                            result = v[2]
                            if result.lower() != "true" :
                                autoResult["result"] = "Y"
                                autoResult["point"] = "가상머신 "+vm+"의 "+conf+"값이 false로 설정 되어 있음,"+autoResult["point"]

                elif "PRCV-028" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        vulOutput = vulOutput.split("\n")[2:]
                        for v in vulOutput:
                            v = v.split()
                            vm = v[0]
                            conf = v[1]
                            result = v[2]
                            if result.lower() != "true" :
                                autoResult["result"] = "Y"
                                autoResult["point"] = "가상머신 "+vm+"의 "+conf+"값이 false로 설정 되어 있음,"+autoResult["point"]

                elif "PRCV-029" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        if vulOutput != "":
                            vulOutput = vulOutput.split("\n")

                            for v in vulOutput:
                                v = v.split(";")[0].split("Name=")
                                vm = v[0]
                                device = v[1]
                                if device != "":
                                    autoResult["result"] = "Y"
                                    autoResult["point"] = "가상머신 "+vm+"에 "+device+"가 마운트 되어 있음,"+autoResult["point"]

                elif "PRCV-030" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        vulOutput = vulOutput.split("\n")[2:]
                        for v in vulOutput:
                            v = v.split()
                            vm = v[0]
                            conf = v[1]
                            result = v[2]
                            if result.lower() == "false" :
                                autoResult["result"] = "Y"
                                autoResult["point"] = "가상머신 "+vm+"의 "+conf+"값이 false로 설정 되어 있음,"+autoResult["point"]

                elif "PRCV-031" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        vulOutput = vulOutput.split("\n")[2:]
                        for v in vulOutput:
                            v = v.split()
                            vm = v[0]
                            conf = v[1]
                            result = v[2]
                            if result.lower() == "false" :
                                autoResult["result"] = "Y"
                                autoResult["point"] = "가상머신 "+vm+"의 "+conf+"값이 false로 설정 되어 있음,"+autoResult["point"]

                elif "PRCV-032" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        vulOutput = vulOutput.split("\n")[2:]
                        for v in vulOutput:
                            v = v.split()
                            vm = v[0]
                            conf = v[1]
                            result = v[2]
                            if result.lower() == "true" :
                                autoResult["result"] = "Y"
                                autoResult["point"] = "가상머신 "+vm+"의 "+conf+"값이 true로 설정 되어 있음,"+autoResult["point"]

                elif "PRCV-033" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        vulOutput = vulOutput.split("\n")[2:]
                        for v in vulOutput:
                            v = v.split()
                            vm = v[0]
                            conf = v[1]
                            result = v[2]
                            if result.lower() == "false" :
                                autoResult["result"] = "Y"
                                autoResult["point"] = "가상머신 "+vm+"의 "+conf+"값이 false로 설정 되어 있음,"+autoResult["point"]

                elif "PRCV-034" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        vulOutput = vulOutput.split("\n")[2:]
                        for v in vulOutput:
                            v = v.split(",")
                            vSwitch = v[0].strip()
                            conf = v[1]
                            if "true" in conf.lower() :
                                autoResult["result"] = "Y"
                                autoResult["point"] = vSwitch+"의 "+conf+","+autoResult["point"]

                elif "PRCV-035" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        vulOutput = vulOutput.split("\n")[2:]
                        for v in vulOutput:
                            v = v.split(",")
                            vSwitch = v[0].strip()
                            conf = v[1]
                            if "true" in conf.lower() :
                                autoResult["result"] = "Y"
                                autoResult["point"] = vSwitch+"의 "+conf+","+autoResult["point"]

                elif "PRCV-036" in vulKey:
                    if "esxi" in sApp:
                        vulOutput = vulOutput.strip()
                        vulOutput = vulOutput.split("\n")[2:]
                        for v in vulOutput:
                            v = v.split(",")
                            vSwitch = v[0].strip()
                            conf = v[1]
                            if "true" in conf.lower() :
                                autoResult["result"] = "Y"
                                autoResult["point"] = vSwitch+"의 "+conf+","+autoResult["point"]
        else:
            print(sApp+"은 자동분석 대상이 아닙니다.")
    except Exception as e:
        print(f"exception: {e}")
        traceback.print_exc()

    autoResult["point"] = re.sub(r',$', '', autoResult["point"]) #맨 뒤 , 삭제
    return autoResult
