#!/bin/bash

#################################################################
# 금융보안원 퍼블릭 클라우드(AWS) 취약점 분석 스크립트
# 최종 수정: 2025-12-30
#################################################################

# SSL 경고 메시지 억제
# - "Unverified HTTPS request" 텍스트를 포함한 Python 경고만 억제
# - AWS API 오류, 권한 오류 등 실제 오류는 정상 출력됨
export PYTHONWARNINGS="ignore:Unverified HTTPS request"

# --- [0] AWS 자격 증명 입력 (ReadOnlyAccess 권한 필요) ---
echo "AWS 자격 증명을 입력하세요."
read -p "AWS Access Key ID: " AWS_ACCESS_KEY_ID
read -sp "AWS Secret Access Key: " AWS_SECRET_ACCESS_KEY
echo "" # 비밀번호 입력 후 줄바꿈
read -p "Default Region Name [ap-northeast-2]: " AWS_DEFAULT_REGION

# 기본 리전 값이 없으면 ap-northeast-2로 설정
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-ap-northeast-2}

# 입력받은 키를 환경변수로 설정
export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION

# 필수 값이 비어있는지 확인
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ] || [ -z "$AWS_DEFAULT_REGION" ]; then
    echo "[ERROR] Access Key, Secret Key, Region은 필수 입력값입니다. 스크립트를 종료합니다."
    exit 1
fi

# 자격 증명이 유효한지 확인
echo "[INFO] 입력된 자격 증명을 확인 중입니다."
USER_info=$(aws sts --no-verify-ssl get-caller-identity)
echo "${USER_info}"
if ! aws sts --no-verify-ssl get-caller-identity > /dev/null 2>&1; then
    echo "[ERROR] 자격 증명이 유효하지 않거나 권한이 부족합니다. 스크립트를 종료합니다."
    exit 1
fi
echo "[INFO] 자격 증명 확인 완료. 점검을 시작합니다."
echo "--------------------------------------------------------"

# --- [1] 설정 및 초기화 ---
USER_NAME=$(aws sts --no-verify-ssl get-caller-identity --query 'Arn' --output text | awk -F'/' '{print $NF}')
DATE=$(date +%Y%m%d_%H%M%S)
OUTFILE="aws_report_${DATE}_${USER_NAME}.xml"

# 전체 시작 시간 기록
TOTAL_START_TIME=$(date +%s)
TOTAL_START_TIME_STR=$(date '+%Y-%m-%d %H:%M:%S')

# 스크립트 실행 시 XML 파일의 최상단 루트 요소를 생성합니다.
echo '<?xml version="1.0" encoding="UTF-8"?>' > "$OUTFILE"
echo '<AuditReport>' >> "$OUTFILE"

# Metadata 섹션 추가
echo '  <Metadata>' >> "$OUTFILE"
echo '    <ScriptVersion>v251230_optimized</ScriptVersion>' >> "$OUTFILE"
echo "    <AssessmentDate>$(date +"%Y-%m-%d %H:%M:%S")</AssessmentDate>" >> "$OUTFILE"
echo "    <AssessmentDateUTC>$(date -u +"%Y-%m-%dT%H:%M:%SZ")</AssessmentDateUTC>" >> "$OUTFILE"

# AWS 계정 ID 조회
ACCOUNT_ID=$(aws sts --no-verify-ssl get-caller-identity --query Account --output text 2>/dev/null)
if [ -n "$ACCOUNT_ID" ]; then
    echo "    <AWSAccountID>${ACCOUNT_ID}</AWSAccountID>" >> "$OUTFILE"
else
    echo "    <AWSAccountID>Unknown</AWSAccountID>" >> "$OUTFILE"
fi

echo "    <Region>${AWS_DEFAULT_REGION}</Region>" >> "$OUTFILE"

# 계정 별칭 조회 (있으면 추가)
ACCOUNT_ALIAS=$(aws iam --no-verify-ssl list-account-aliases --query 'AccountAliases[0]' --output text 2>/dev/null)
if [ -n "$ACCOUNT_ALIAS" ] && [ "$ACCOUNT_ALIAS" != "None" ]; then
    echo "    <AccountAlias>${ACCOUNT_ALIAS}</AccountAlias>" >> "$OUTFILE"
fi

echo '  </Metadata>' >> "$OUTFILE"

echo "  <Timestamp>$(date -u +"%Y-%m-%dT%H:%M:%SZ")</Timestamp>" >> "$OUTFILE"
echo '  <CheckList>' >> "$OUTFILE"

# IAM 자격 증명 보고서를 미리 생성하여 전역 변수에 저장
echo "[INFO] IAM 자격 증명 보고서를 생성합니다."
aws iam --no-verify-ssl generate-credential-report > /dev/null 2>&1 && sleep 5
G_CREDENTIAL_REPORT=$(aws iam --no-verify-ssl get-credential-report --query Content --output text 2>/dev/null | base64 -d)
if [ -z "$G_CREDENTIAL_REPORT" ]; then
    echo "[ERROR] IAM 자격 증명 보고서를 준비하지 못했습니다. 관련 점검을 건너뜁니다."
fi

# 취약 항목 출력을 위한 헬퍼 함수
print_summary() {
    local summary_string=$1
    if [ -n "$summary_string" ]; then
        echo "      <Summary>"
        local summary_keys=$(echo -e "$summary_string" | cut -d'|' -f1,2 | sort -u)
        # for 루프에서 따옴표 없이 사용하면 summary_keys의 줄바꿈을 기준으로 반복
        for key in $summary_keys; do
            local current_status=$(echo "$key" | cut -d'|' -f1)
            
            # 'good'이나 'info' 상태는 Summary에 표시하지 않음
            if [[ "$current_status" != "good" && "$current_status" != "info" ]]; then
                local current_service=$(echo "$key" | cut -d'|' -f2)
                
                # cut으로 ID를 뽑은 후, sort -u 로 중복을 제거하고, paste로 합침
                local resource_ids=$(echo -e "$summary_string" | grep "^${key}|" | cut -d'|' -f3 | sort -u | paste -sd, -)
                
                echo "        <Finding status='${current_status}' service='${current_service}' resourceIds='${resource_ids}'/>"
            fi
        done
        echo "      </Summary>"
    fi
}

# 전역 변수로 시작 시간 저장
G_START_TIME=0
G_START_TIME_STR=""

# 실행 시간 측정을 위한 헬퍼 함수
# 점검 함수 시작 시 호출
start_timer() {
    G_START_TIME=$(date +%s)
    G_START_TIME_STR=$(date '+%Y-%m-%d %H:%M:%S')
}

# 점검 함수 종료 직전 호출하여 시간 정보 출력
end_timer_and_print() {
    local end_time=$(date +%s)
    local end_time_str=$(date '+%Y-%m-%d %H:%M:%S')
    local duration=$((end_time - G_START_TIME))
    
    echo "      <ExecutionTime>"
    echo "        <StartTime>${G_START_TIME_STR}</StartTime>"
    echo "        <EndTime>${end_time_str}</EndTime>"
    echo "        <DurationSecs>${duration}</DurationSecs>"
    echo "      </ExecutionTime>"
}

# JSON 문자열의 가독성을 높이기 위한 헬퍼 함수
format_json() {
    local json_string="$1"
    if [ -z "$json_string" ]; then
        echo "N/A"
        return
    fi
    # 중괄호{}, 대괄호[], 쉼표 뒤에 줄바꿈 및 기본 들여쓰기 추가
    echo "$json_string" | sed \
        -e 's/{"/{\n  "/g' \
        -e 's/,"/,\n  "/g' \
        -e 's/\[{/\[\n  {/g' \
        -e 's/}]/\n  }\n]/g' \
        -e 's/}/\n}/g'
}

# --- [2] 점검 함수 정의 ---

check_pism_001() {
    local check_id="pism_001"
    local check_name="통신구간 암호화 미적용"
    {
        start_timer
        local summary_string=""

        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws s3 ls, aws s3api get-bucket-policy]]></Command>"
        echo "      <Results>"
        
        local service="S3"
        ERROR_MSG=$(mktemp)
        S3_BUCKETS_OUTPUT=$(aws s3 --no-verify-ssl ls 2>"$ERROR_MSG")
        CMD_EXIT_CODE=$?
        if [ $CMD_EXIT_CODE -ne 0 ]; then
            local resource_id="S3 Buckets"
            ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
            if echo "$ERROR_DETAIL" | grep -qi "AccessDenied\|not authorized"; then
                status="error"; detail="권한 부족 (AccessDenied) - IAM 정책 확인 필요"
            else
                status="error"; detail="버킷 목록 조회 중 오류 발생"
            fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
            rm -f "$ERROR_MSG"
        else
            rm -f "$ERROR_MSG"
            S3_BUCKETS=$(echo "$S3_BUCKETS_OUTPUT" | awk '{print $3}')
            if [ -z "$S3_BUCKETS" ]; then
                local resource_id="N/A"
                status="info"; detail="S3 버킷 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No S3 buckets found.]]></Evidence></Item>"
            else
                for BUCKET_NAME in $S3_BUCKETS; do
                    local status="bad"
                    local detail="버킷 정책 부재 또는 HTTPS 강제 조건 부재"
                    local evidence=""

                    POLICY_OUTPUT=$(aws s3api --no-verify-ssl get-bucket-policy --bucket "$BUCKET_NAME" 2>/dev/null)
                    
                    if echo "$POLICY_OUTPUT" | grep -q 'NoSuchBucketPolicy'; then
                        detail="버킷 정책 미존재"
                        evidence="$POLICY_OUTPUT"$'\n'
                    elif echo "$POLICY_OUTPUT" | grep -q 'AccessDenied'; then
                        status="error"
                        detail="버킷 정책 조회 권한 부족"
                        evidence="$POLICY_OUTPUT"$'\n'
                    elif echo "$POLICY_OUTPUT" | grep -q 'Error'; then
                        status="error"
                        detail="정책 조회 중 오류 발생"
                        evidence="$POLICY_OUTPUT"$'\n'
                    else
                        local policy_doc=$(echo "$POLICY_OUTPUT" | awk -F'"Policy":' '{print $2}' | sed 's/^"//;s/"}$//' | sed -e 's/\\n/\n/g' -e 's/\\"/"/g')
                        
                        evidence=$'\n'$(format_json "$policy_doc")$'\n'
                        
                        if echo "$policy_doc" | tr -d ' \n' | grep -q '"Effect":"Deny"' && echo "$policy_doc" | tr -d ' \n' | grep -q '"aws:SecureTransport":"false"'; then
                            status="good"; detail="버킷 정책을 통해 HTTP 접근 명시적으로 차단"
                        fi
                    fi
                    
                    summary_string+="${status}|${service}|${BUCKET_NAME}\n"
                    echo "        <Item status=\"${status}\"><ResourceID>${BUCKET_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
                done
            fi
        fi
        echo "      </Results>"
        
        print_summary "$summary_string"
        
        
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_005] 가상자원에 대한 퍼블릭 액세스 허용
check_pism_005() {
    local check_id="pism_005"
    local check_name="가상자원에 대한 퍼블릭 액세스 허용"
    {
        start_timer
        local summary_string=""

        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws ec2 describe-instances, aws ec2 describe-snapshot-attribute, aws ec2 describe-snapshots, aws rds describe-db-clusters, aws rds describe-db-instances, aws s3 ls, aws s3api get-public-access-block]]></Command>"
        echo "      <Results>"

        # --- S3 Public Access Block 점검 ---
        local service="S3"
        echo "        <SubCheck service=\"${service}\">"
        ERROR_MSG=$(mktemp)
        S3_BUCKETS_OUTPUT=$(aws s3 --no-verify-ssl ls 2>"$ERROR_MSG")
        CMD_EXIT_CODE=$?
        if [ $CMD_EXIT_CODE -ne 0 ]; then
            local resource_id="S3 Buckets"; local status="error"
            ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
            if echo "$ERROR_DETAIL" | grep -qi "AccessDenied\|not authorized"; then
                local detail="권한 부족 (AccessDenied) - IAM 정책 확인 필요"
            else
                local detail="목록 조회 오류"
            fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
            rm -f "$ERROR_MSG"
        else
            rm -f "$ERROR_MSG"
            S3_BUCKETS=$(echo "$S3_BUCKETS_OUTPUT" | awk '{print $3}')
            if [ -z "$S3_BUCKETS" ]; then
                local resource_id="N/A"; local status="info"; local detail="점검할 S3 버킷 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No S3 buckets found.]]></Evidence></Item>"
            else
                for BUCKET_NAME in $S3_BUCKETS; do
                    PAB_OUTPUT=$(aws s3api --no-verify-ssl get-public-access-block --bucket "$BUCKET_NAME" 2>/dev/null)
                    EXIT_CODE=$?
                    if [ $EXIT_CODE -eq 0 ]; then
                        if echo "$PAB_OUTPUT" | grep -q ': false'; then status="bad"; detail="4개의 퍼블릭 액세스 차단 옵션 중 일부 또는 전부 비활성화"; else status="good"; detail="모든 퍼블릭 액세스 차단 옵션 활성화"; fi
                    else
                        if echo "$PAB_OUTPUT" | grep -q "NoSuchPublicAccessBlockConfiguration"; then status="bad"; detail="퍼블릭 액세스 차단 설정 비활성화";
                        elif echo "$PAB_OUTPUT" | grep -q "AccessDenied"; then status="error"; detail="권한이 부족하여 옵션 조회 불가";
                        else status="Error"; detail="설정을 조회하는 중 오류 발생"; fi
                    fi
                    summary_string+="${status}|${service}|${BUCKET_NAME}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${BUCKET_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${PAB_OUTPUT}]]></Evidence></Item>"
                done
            fi
        fi
        echo '        </SubCheck>'

        # --- EC2 인스턴스 퍼블릭 IP 점검 ---
        local service="EC2_Instance"
        echo "        <SubCheck service=\"${service}\">"
        ERROR_MSG=$(mktemp)
        EC2_INSTANCES_OUTPUT=$(aws ec2 --no-verify-ssl describe-instances --filters "Name=instance-state-name,Values=running" --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress]' --output json 2>"$ERROR_MSG")
        CMD_EXIT_CODE=$?
        if [ $CMD_EXIT_CODE -ne 0 ]; then
            local resource_id="EC2 Instances"; local status="error"
            ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
            if echo "$ERROR_DETAIL" | grep -qi "AccessDenied\|not authorized"; then
                local detail="권한 부족 (AccessDenied) - IAM 정책 확인 필요"
            else
                local detail="목록 조회 오류"
            fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
            rm -f "$ERROR_MSG"
        else
            rm -f "$ERROR_MSG"
            EC2_INSTANCES=$(echo "$EC2_INSTANCES_OUTPUT" | jq -c '.[]' 2>/dev/null)
            if [ -z "$EC2_INSTANCES" ]; then
                local resource_id="N/A"; local status="info"; local detail="점검할 실행 중인 EC2 인스턴스 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No running EC2 instances found.]]></Evidence></Item>"
            else
                for instance in $EC2_INSTANCES; do
                    INSTANCE_ID=$(echo "$instance" | jq -r '.[0]')
                    PUBLIC_IP=$(echo "$instance" | jq -r '.[1] // empty')
                    if [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "null" ]; then
                        status="bad"; detail="퍼블릭 IP 할당됨 (${PUBLIC_IP})"
                    else
                        status="good"; detail="퍼블릭 IP 미할당"
                    fi
                    summary_string+="${status}|${service}|${INSTANCE_ID}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${INSTANCE_ID}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[PublicIpAddress: ${PUBLIC_IP}]]></Evidence></Item>"
                done
            fi
        fi
        echo '        </SubCheck>'

        # --- EC2 EBS 스냅샷 퍼블릭 액세스 점검 ---
        local service="EC2_EBS_Snapshot"
        echo "        <SubCheck service=\"${service}\">"
        ERROR_MSG=$(mktemp)
        SNAPSHOT_IDS_OUTPUT=$(aws ec2 --no-verify-ssl describe-snapshots --owner-ids self --query "Snapshots[].SnapshotId" --output text 2>"$ERROR_MSG")
        CMD_EXIT_CODE=$?
        if [ $CMD_EXIT_CODE -ne 0 ]; then
            local resource_id="EBS Snapshots"; local status="error"
            ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
            if echo "$ERROR_DETAIL" | grep -qi "AccessDenied\|not authorized"; then
                local detail="권한 부족 (AccessDenied) - IAM 정책 확인 필요"
            else
                local detail="목록 조회 오류"
            fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
            rm -f "$ERROR_MSG"
        else
            rm -f "$ERROR_MSG"
            SNAPSHOT_IDS=$(echo "$SNAPSHOT_IDS_OUTPUT")
            if [ -z "$SNAPSHOT_IDS" ]; then
                local resource_id="N/A"; local status="info"; local detail="점검할 EBS 스냅샷 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No EBS snapshots found.]]></Evidence></Item>"
            else
                for SNAPSHOT_ID in $SNAPSHOT_IDS; do
                    ERROR_MSG=$(mktemp)
                    PERM_OUTPUT=$(aws ec2 --no-verify-ssl describe-snapshot-attribute --snapshot-id "$SNAPSHOT_ID" --attribute createVolumePermission 2>"$ERROR_MSG")
                    EXIT_CODE=$?
                    if [ $EXIT_CODE -ne 0 ]; then
                        ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                        if echo "$ERROR_DETAIL" | grep -qi "AccessDenied\|not authorized"; then
                            status="error"; detail="권한 부족 (AccessDenied) - IAM 정책 확인 필요"
                        else
                            status="error"; detail="스냅샷 속성 조회 중 오류 발생"
                        fi
                        summary_string+="${status}|${service}|${SNAPSHOT_ID}\n"
                        echo "          <Item status=\"${status}\"><ResourceID>${SNAPSHOT_ID}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $EXIT_CODE}]]></Evidence></Item>"
                    else
                        if echo "$PERM_OUTPUT" | grep -q '"Group": "all"'; then status="bad"; detail="[보안 위험] 모든 사용자에게 스냅샷 공개 설정 활성화"; else status="good"; detail="스냅샷 퍼블릭 설정 비활성화"; fi
                        summary_string+="${status}|${service}|${SNAPSHOT_ID}\n"
                        echo "          <Item status=\"${status}\"><ResourceID>${SNAPSHOT_ID}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${PERM_OUTPUT}]]></Evidence></Item>"
                    fi
                    rm -f "$ERROR_MSG"
                done
            fi
        fi
        echo '        </SubCheck>'

        # --- RDS DB 인스턴스 퍼블릭 액세스 점검 ---
        local service="RDS_DB_Instance"
        echo "        <SubCheck service=\"${service}\">"
        ERROR_MSG=$(mktemp)
        DB_INSTANCES_RAW=$(aws rds --no-verify-ssl describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,PubliclyAccessible]" --output text 2>"$ERROR_MSG")
        CMD_EXIT_CODE=$?
        if [ $CMD_EXIT_CODE -ne 0 ]; then
            local resource_id="RDS DB Instances"; local status="error"
            ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
            if echo "$ERROR_DETAIL" | grep -qi "AccessDenied\|not authorized"; then
                local detail="권한 부족 (AccessDenied) - IAM 정책 확인 필요"
            else
                local detail="목록 조회 오류"
            fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
            rm -f "$ERROR_MSG"
        else
            rm -f "$ERROR_MSG"
            if [ -z "$DB_INSTANCES_RAW" ]; then
                local resource_id="N/A"; local status="info"; local detail="점검할 DB 인스턴스 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No RDS DB instances found.]]></Evidence></Item>"
            else
                while read -r DB_ID PUBLIC_STATUS; do
                    if [ -z "$DB_ID" ]; then continue; fi
                    if [ "$PUBLIC_STATUS" == "True" ]; then status="bad"; detail="Publicly Accessible이 'True'로 설정됨"; else status="good"; detail="Publicly Accessible이 'False'로 설정됨"; fi
                    summary_string+="${status}|${service}|${DB_ID}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${DB_ID}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[PubliclyAccessible: ${PUBLIC_STATUS}]]></Evidence></Item>"
                done <<< "$DB_INSTANCES_RAW"
            fi
        fi
        echo '        </SubCheck>'

        # --- Aurora DB 클러스터 퍼블릭 액세스 점검 (추가) ---
        local service="Aurora_DB_Cluster"
        echo "        <SubCheck service=\"${service}\">"
        ERROR_MSG=$(mktemp)
        DB_CLUSTERS_RAW=$(aws rds --no-verify-ssl describe-db-clusters --query "DBClusters[*].[DBClusterIdentifier,PubliclyAccessible]" --output text 2>"$ERROR_MSG")
        CMD_EXIT_CODE=$?
        if [ $CMD_EXIT_CODE -ne 0 ]; then
            local resource_id="Aurora DB Clusters"; local status="error"
            ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
            if echo "$ERROR_DETAIL" | grep -qi "AccessDenied\|not authorized"; then
                local detail="권한 부족 (AccessDenied) - IAM 정책 확인 필요"
            else
                local detail="목록 조회 오류"
            fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
            rm -f "$ERROR_MSG"
        else
            rm -f "$ERROR_MSG"
            if [ -z "$DB_CLUSTERS_RAW" ]; then
                local resource_id="N/A"; local status="info"; local detail="점검할 Aurora 클러스터 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No Aurora DB clusters found.]]></Evidence></Item>"
            else
                while read -r CLUSTER_ID PUBLIC_STATUS; do
                    if [ -z "$CLUSTER_ID" ]; then continue; fi
                    if [ "$PUBLIC_STATUS" == "True" ]; then status="bad"; detail="Publicly Accessible이 'True'로 설정됨"; else status="good"; detail="Publicly Accessible이 'False'로 설정됨"; fi
                    summary_string+="${status}|${service}|${CLUSTER_ID}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${CLUSTER_ID}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[PubliclyAccessible: ${PUBLIC_STATUS}]]></Evidence></Item>"
                done <<< "$DB_CLUSTERS_RAW"
            fi
        fi
        echo '        </SubCheck>'

        echo "      </Results>"

        print_summary "$summary_string"

        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_007] 네트워크 접근 제어 설정의 최소 권한 적용
check_pism_007() {
    local check_id="pism_007"
    local check_name="네트워크 접근 제어 설정의 최소 권한 적용"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"

        echo '      <Command><![CDATA[aws ec2 describe-security-groups]]></Command>'

        echo "      <Results>"

        # --- SubCheck: Security Groups ---
        local service="SecurityGroups"
        echo "        <SubCheck service=\"${service}\">"
        SG_INFO=$(aws ec2 --no-verify-ssl describe-security-groups --query "SecurityGroups[*].[GroupId,GroupName,VpcId]" --output text 2>/dev/null)
        
        if [ -z "$SG_INFO" ]; then
            local resource_id="N/A"; local status="info"; local detail="점검할 보안 그룹(Security Group) 미존재"
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence>N/A</Evidence></Item>"
        else
            while IFS=$'\t' read -r SG_ID SG_NAME VPC_ID; do
                if [ -z "$SG_ID" ]; then continue; fi
                
                # Ingress 규칙 조회
                INGRESS_RULES=$(aws ec2 --no-verify-ssl describe-security-groups --group-ids "$SG_ID" \
                    --query "SecurityGroups[0].IpPermissions[*].[IpProtocol,FromPort,ToPort,IpRanges[0].CidrIp,Ipv6Ranges[0].CidrIpv6]" \
                    --output text 2>/dev/null)
                
                if [ $? -ne 0 ]; then
                    local resource_id="$SG_ID"; local status="error"; local detail="보안 그룹 규칙 조회 불가 (권한 확인 필요)"
                    summary_string+="${status}|${service}|${resource_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence>Failed to describe security group.</Evidence></Item>"
                    continue
                fi

                if [ -z "$INGRESS_RULES" ]; then
                    local resource_id="${SG_ID} (${SG_NAME})"; local status="info"; local detail="인바운드 규칙 미존재"
                    summary_string+="${status}|${service}|${resource_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence>No ingress rules defined.</Evidence></Item>"
                else
                    # 인바운드 규칙 점검
                    while IFS=$'\t' read -r PROTOCOL FROM_PORT TO_PORT CIDR_IPV4 CIDR_IPV6; do
                        local detail="일반 규칙"
                        local src_ip="${CIDR_IPV4:-${CIDR_IPV6:-N/A}}"
                        
                        # 0.0.0.0/0 또는 ::/0 (전체 인터넷 개방) 체크
                        if [[ "$src_ip" == "0.0.0.0/0" || "$src_ip" == "::/0" ]]; then
                            
                            # 모든 포트 개방 체크
                            if [[ "$PROTOCOL" == "-1" ]] || [[ ("$FROM_PORT" == "0" || -z "$FROM_PORT") && ("$TO_PORT" == "65535" || -z "$TO_PORT") ]]; then
                                detail="모든 포트 인바운드 허용 규칙"
                            else
                                # 특정 위험 포트 체크
                                case "$FROM_PORT" in
                                    "20"|"21") detail="FTP(20,21) 포트 인바운드 허용 규칙";;
                                    "22") detail="SSH(22) 포트 인바운드 허용 규칙";;
                                    "23") detail="Telnet(23) 포트 인바운드 허용 규칙";;
                                    "25") detail="SMTP(25) 포트 인바운드 허용 규칙";;
                                    "53") detail="DNS(53) 포트 인바운드 허용 규칙";;
                                    "67"|"68") detail="DHCP(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "69") detail="TFTP(69) 포트 인바운드 허용 규칙";;
                                    "80") detail="HTTP(80) 포트 인바운드 허용 규칙";;
                                    "88") detail="Kerberos(88) 포트 인바운드 허용 규칙";;
                                    "123") detail="NTP(123) 포트 인바운드 허용 규칙";;
                                    "161"|"162") detail="SNMP(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "389") detail="LDAP(389) 포트 인바운드 허용 규칙";;
                                    "443") detail="HTTPS(443) 포트 인바운드 허용 규칙";;
                                    "464") detail="Kerberos Password(464) 포트 인바운드 허용 규칙";;
                                    "514") detail="Syslog(514) 포트 인바운드 허용 규칙";;
                                    "636") detail="LDAPS(636) 포트 인바운드 허용 규칙";;
                                    "902") detail="VMware Server(902) 포트 인바운드 허용 규칙";;
                                    "111"|"135") detail="RPC(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "137"|"138"|"139"|"445") detail="SMB/NetBIOS(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "1433") detail="MSSQL DB(1433) 포트 인바운드 허용 규칙";;
                                    "1521") detail="Oracle DB(1521) 포트 인바운드 허용 규칙";;
                                    "1812"|"1813") detail="RADIUS(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "2049") detail="NFS(2049) 포트 인바운드 허용 규칙";;
                                    "2375"|"2376") detail="Docker API(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "3000") detail="Node.js/Grafana(3000) 포트 인바운드 허용 규칙";;
                                    "3306") detail="MySQL/MariaDB(3306) 포트 인바운드 허용 규칙";;
                                    "3389") detail="RDP(3389) 포트 인바운드 허용 규칙";;
                                    "4000") detail="Ruby on Rails(4000) 포트 인바운드 허용 규칙";;
                                    "4848") detail="GlassFish Admin(4848) 포트 인바운드 허용 규칙";;
                                    "5000") detail="Flask/Docker Registry(5000) 포트 인바운드 허용 규칙";;
                                    "5432") detail="PostgreSQL DB(5432) 포트 인바운드 허용 규칙";;
                                    "5985"|"5986") detail="WinRM(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "6379") detail="Redis(6379) 포트 인바운드 허용 규칙";;
                                    "6443") detail="Kubernetes API(6443) 포트 인바운드 허용 규칙";;
                                    "7001"|"7002") detail="WebLogic(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "8000"|"8008"|"8081"|"8088"|"8180") detail="Alternative Web/WAS(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "8009") detail="Tomcat AJP(8009) 포트 인바운드 허용 규칙";;
                                    "8080") detail="WAS/Proxy(8080) 포트 인바운드 허용 규칙";;
                                    "8443") detail="OpenShift/HTTPS Alt(8443) 포트 인바운드 허용 규칙";;
                                    "8629") detail="Tibero DB(8629) 포트 인바운드 허용 규칙";;
                                    "9000") detail="PHP-FPM/Jenkins(9000) 포트 인바운드 허용 규칙";;
                                    "9080"|"9443") detail="WebSphere(${FROM_PORT}) 포트 인바운드 허용 규칙";;
                                    "9090") detail="JBoss Management(9090) 포트 인바운드 허용 규칙";;
                                    "9200") detail="Elasticsearch HTTP(9200) 포트 인바운드 허용 규칙";;
                                    "9300") detail="Elasticsearch Transport(9300) 포트 인바운드 허용 규칙";;
                                    "27017") detail="MongoDB(27017) 포트 인바운드 허용 규칙";;
                                    *) detail="포트 ${FROM_PORT}${TO_PORT:+-${TO_PORT}} 인바운드 허용 규칙";;
                                esac
                            fi
                        fi
                        
                        # Evidence 포맷 생성
                        local port_range="${FROM_PORT:-All}"
                        if [ -n "$TO_PORT" ] && [ "$FROM_PORT" != "$TO_PORT" ]; then
                            port_range="${FROM_PORT}-${TO_PORT}"
                        fi
                        
                        local protocol_name="$PROTOCOL"
                        case "$PROTOCOL" in
                            "-1") protocol_name="All";;
                            "6") protocol_name="TCP";;
                            "17") protocol_name="UDP";;
                            "1") protocol_name="ICMP";;
                        esac
                        
                        local evidence_string
                        printf -v evidence_string "Protocol: %s, Port: %s, Source: %s, VPC: %s" \
                            "$protocol_name" "$port_range" "$src_ip" "${VPC_ID:-N/A}"

                        local resource_id="${SG_ID}/${SG_NAME}"; local status="review"
                        summary_string+="${status}|${service}|${resource_id}\n"
                        echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>[Inbound] ${detail}</Detail><Evidence><![CDATA[${evidence_string}]]></Evidence></Item>"
                    done <<< "$INGRESS_RULES"
                fi
                
                # Egress 규칙 조회
                EGRESS_RULES=$(aws ec2 --no-verify-ssl describe-security-groups --group-ids "$SG_ID" \
                    --query "SecurityGroups[0].IpPermissionsEgress[*].[IpProtocol,FromPort,ToPort,IpRanges[0].CidrIp,Ipv6Ranges[0].CidrIpv6]" \
                    --output text 2>/dev/null)
                
                if [ -n "$EGRESS_RULES" ]; then
                    # 아웃바운드 규칙 점검
                    while IFS=$'\t' read -r PROTOCOL FROM_PORT TO_PORT CIDR_IPV4 CIDR_IPV6; do
                        local detail="일반 규칙"
                        local dest_ip="${CIDR_IPV4:-${CIDR_IPV6:-N/A}}"
                        
                        # 0.0.0.0/0 또는 ::/0 (전체 인터넷 개방) 체크
                        if [[ "$dest_ip" == "0.0.0.0/0" || "$dest_ip" == "::/0" ]]; then
                            
                            # 모든 포트 개방 체크
                            if [[ "$PROTOCOL" == "-1" ]] || [[ ("$FROM_PORT" == "0" || -z "$FROM_PORT") && ("$TO_PORT" == "65535" || -z "$TO_PORT") ]]; then
                                detail="모든 포트 아웃바운드 허용 규칙"
                            else
                                # 특정 위험 포트 체크 (인바운드와 동일)
                                case "$FROM_PORT" in
                                    "20"|"21") detail="FTP(20,21) 포트 아웃바운드 허용 규칙";;
                                    "22") detail="SSH(22) 포트 아웃바운드 허용 규칙";;
                                    "23") detail="Telnet(23) 포트 아웃바운드 허용 규칙";;
                                    "25") detail="SMTP(25) 포트 아웃바운드 허용 규칙";;
                                    "53") detail="DNS(53) 포트 아웃바운드 허용 규칙";;
                                    "67"|"68") detail="DHCP(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "69") detail="TFTP(69) 포트 아웃바운드 허용 규칙";;
                                    "80") detail="HTTP(80) 포트 아웃바운드 허용 규칙";;
                                    "88") detail="Kerberos(88) 포트 아웃바운드 허용 규칙";;
                                    "123") detail="NTP(123) 포트 아웃바운드 허용 규칙";;
                                    "161"|"162") detail="SNMP(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "389") detail="LDAP(389) 포트 아웃바운드 허용 규칙";;
                                    "443") detail="HTTPS(443) 포트 아웃바운드 허용 규칙";;
                                    "464") detail="Kerberos Password(464) 포트 아웃바운드 허용 규칙";;
                                    "514") detail="Syslog(514) 포트 아웃바운드 허용 규칙";;
                                    "636") detail="LDAPS(636) 포트 아웃바운드 허용 규칙";;
                                    "902") detail="VMware Server(902) 포트 아웃바운드 허용 규칙";;
                                    "111"|"135") detail="RPC(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "137"|"138"|"139"|"445") detail="SMB/NetBIOS(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "1433") detail="MSSQL DB(1433) 포트 아웃바운드 허용 규칙";;
                                    "1521") detail="Oracle DB(1521) 포트 아웃바운드 허용 규칙";;
                                    "1812"|"1813") detail="RADIUS(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "2049") detail="NFS(2049) 포트 아웃바운드 허용 규칙";;
                                    "2375"|"2376") detail="Docker API(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "3000") detail="Node.js/Grafana(3000) 포트 아웃바운드 허용 규칙";;
                                    "3306") detail="MySQL/MariaDB(3306) 포트 아웃바운드 허용 규칙";;
                                    "3389") detail="RDP(3389) 포트 아웃바운드 허용 규칙";;
                                    "4000") detail="Ruby on Rails(4000) 포트 아웃바운드 허용 규칙";;
                                    "4848") detail="GlassFish Admin(4848) 포트 아웃바운드 허용 규칙";;
                                    "5000") detail="Flask/Docker Registry(5000) 포트 아웃바운드 허용 규칙";;
                                    "5432") detail="PostgreSQL DB(5432) 포트 아웃바운드 허용 규칙";;
                                    "5985"|"5986") detail="WinRM(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "6379") detail="Redis(6379) 포트 아웃바운드 허용 규칙";;
                                    "6443") detail="Kubernetes API(6443) 포트 아웃바운드 허용 규칙";;
                                    "7001"|"7002") detail="WebLogic(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "8000"|"8008"|"8081"|"8088"|"8180") detail="Alternative Web/WAS(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "8009") detail="Tomcat AJP(8009) 포트 아웃바운드 허용 규칙";;
                                    "8080") detail="WAS/Proxy(8080) 포트 아웃바운드 허용 규칙";;
                                    "8443") detail="OpenShift/HTTPS Alt(8443) 포트 아웃바운드 허용 규칙";;
                                    "8629") detail="Tibero DB(8629) 포트 아웃바운드 허용 규칙";;
                                    "9000") detail="PHP-FPM/Jenkins(9000) 포트 아웃바운드 허용 규칙";;
                                    "9080"|"9443") detail="WebSphere(${FROM_PORT}) 포트 아웃바운드 허용 규칙";;
                                    "9090") detail="JBoss Management(9090) 포트 아웃바운드 허용 규칙";;
                                    "9200") detail="Elasticsearch HTTP(9200) 포트 아웃바운드 허용 규칙";;
                                    "9300") detail="Elasticsearch Transport(9300) 포트 아웃바운드 허용 규칙";;
                                    "27017") detail="MongoDB(27017) 포트 아웃바운드 허용 규칙";;
                                    *) detail="포트 ${FROM_PORT}${TO_PORT:+-${TO_PORT}} 아웃바운드 허용 규칙";;
                                esac
                            fi
                        fi
                        
                        # Evidence 포맷 생성
                        local port_range="${FROM_PORT:-All}"
                        if [ -n "$TO_PORT" ] && [ "$FROM_PORT" != "$TO_PORT" ]; then
                            port_range="${FROM_PORT}-${TO_PORT}"
                        fi
                        
                        local protocol_name="$PROTOCOL"
                        case "$PROTOCOL" in
                            "-1") protocol_name="All";;
                            "6") protocol_name="TCP";;
                            "17") protocol_name="UDP";;
                            "1") protocol_name="ICMP";;
                        esac
                        
                        local evidence_string
                        printf -v evidence_string "Protocol: %s, Port: %s, Destination: %s, VPC: %s" \
                            "$protocol_name" "$port_range" "$dest_ip" "${VPC_ID:-N/A}"

                        local resource_id="${SG_ID}/${SG_NAME}"; local status="review"
                        summary_string+="${status}|${service}|${resource_id}\n"
                        echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>[Outbound] ${detail}</Detail><Evidence><![CDATA[${evidence_string}]]></Evidence></Item>"
                    done <<< "$EGRESS_RULES"
                fi
            done <<< "$SG_INFO"
        fi
        echo '        </SubCheck>'

        echo "      </Results>"

        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_013] 접근 로그 수집 기능 비활성화
check_pism_013() {
    local check_id="pism_013"
    local check_name="접근 로그 수집 기능 비활성화"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws cloudtrail describe-trails, aws cloudtrail get-event-selectors, aws cloudtrail get-trail-status, aws cloudtrail list-trails, aws cloudtrail lookup-events, aws ec2 describe-flow-logs, aws ec2 describe-instances, aws ec2 describe-security-groups, aws iam get-instance-profile, aws iam get-policy, aws iam get-policy-version, aws iam get-role-policy, aws iam list-attached-role-policies, aws iam list-role-policies, aws iam simulate-principal-policy, aws lambda get-function-configuration, aws lambda list-functions, aws lambda list-tags, aws rds describe-db-cluster-parameters, aws rds describe-db-clusters, aws rds describe-db-instances, aws rds describe-db-parameters, aws rds describe-option-groups, aws s3 ls, aws s3api get-bucket-logging]]></Command>"
        echo "      <Results>"

        # --- SubCheck: CloudTrail & IAM Management Events ---
        echo '        <SubCheck service="CloudTrail">'
        local service="CloudTrail"
        TRAILS=$(command aws cloudtrail --no-verify-ssl describe-trails --query 'trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled,IncludeGlobalServiceEvents]' --output text 2>/dev/null)
        if [ -z "$TRAILS" ]; then
            summary_string+="bad|${service}|N/A\n"
            echo '          <Item status="bad"><ResourceID>N/A</ResourceID><Detail>활성화된 CloudTrail 트레일 미존재</Detail><Evidence><![CDATA[No trails found.]]></Evidence></Item>'
        else
            while read -r name is_multi_region has_validation include_global; do
                local evidence=""
                local overall_status="good"
                
                # 2.1 로깅 활성화 여부
                status_output=$(command aws cloudtrail --no-verify-ssl get-trail-status --name "$name" --output json 2>/dev/null)
                if echo "$status_output" | grep -q '"IsLogging": true'; then
                    evidence+=$'\n'"[OK] 로깅 활성화 (IsLogging: true)"$'\n'
                else
                    evidence+=$'\n'"[FAIL] 로깅 비활성화 (IsLogging: false)"$'\n'
                    overall_status="bad"
                fi

                # 2.2 다중 리전 활성화 여부
                if [ "$is_multi_region" == "True" ]; then
                    evidence+="[OK] 다중 리전 추적 활성화 (IsMultiRegionTrail: true)"$'\n'
                else
                    evidence+="[FAIL] 다중 리전 추적 비활성화 (IsMultiRegionTrail: false)"$'\n'
                    overall_status="bad"
                fi

                # 2.3 로그 파일 무결성 검증 활성화 여부
                if [ "$has_validation" == "True" ]; then
                    evidence+="[OK] 로그 파일 검증 활성화 (LogFileValidationEnabled: true)"$'\n'
                else
                    evidence+="[FAIL] 로그 파일 검증 비활성화 (LogFileValidationEnabled: false)"$'\n'
                    overall_status="bad"
                fi

                # (참고) 전역 서비스 이벤트 로깅 여부 - 판정에 미반영
                evidence+=$'\n'"--- 추가 정보 (참고용) ---"$'\n'
                if [ "$include_global" == "True" ]; then
                    evidence+="전역 서비스 이벤트 로깅: 활성화 (IncludeGlobalServiceEvents: true)"$'\n'
                else
                    evidence+="전역 서비스 이벤트 로깅: 비활성화 (IncludeGlobalServiceEvents: false)"$'\n'
                fi

                # (참고) 관리 이벤트 로깅 여부 - 판정에 미반영 (IAM 항목에서 점검)
                event_selectors=$(command aws cloudtrail --no-verify-ssl get-event-selectors --trail-name "$name" --output json 2>/dev/null)
                if echo "$event_selectors" | grep -q '"ReadWriteType": "All"'; then
                    evidence+="관리 이벤트 로깅: 모든 이벤트(읽기/쓰기) 활성화 (ReadWriteType: All)"$'\n'
                elif echo "$event_selectors" | grep -v '"eventCategory": "Data"' | grep -q '"eventCategory": "Management"'; then
                    evidence+="관리 이벤트 로깅: 일부 관리 이벤트만 로깅 중"$'\n'
                else
                    evidence+="관리 이벤트 로깅: 미설정"$'\n'
                fi

                evidence+=$'\n'"--- Raw Data ---"$'\n'
                evidence+="Trail Status: ${status_output}"$'\n'
                evidence+="Event Selectors: ${event_selectors}"$'\n'
                
                local detail="CloudTrail 주요 감사 설정이 양호합니다."
                if [ "$overall_status" == "bad" ]; then
                    detail="CloudTrail 주요 감사 설정 중 일부가 미흡합니다. (상세 내용은 Evidence 확인)"
                fi

                summary_string+="${overall_status}|${service}|${name}\n"
                echo "          <Item status=\"${overall_status}\"><ResourceID>${name}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
            done <<< "$TRAILS"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Security Group (로그 수집) ---
        echo '        <SubCheck service="SecurityGroup_Logging">'
        local service="SecurityGroup_Logging"

        # 공식 기준:
        # 1. CloudTrail: Security Group 규칙 변경 감사 (관리 이벤트)
        # 2. VPC Flow Logs: Security Group 규칙에 히트한 트래픽 로깅 (네트워크 트래픽)

        SG_COUNT=$(aws ec2 --no-verify-ssl describe-security-groups --query "length(SecurityGroups)" 2>/dev/null)
        if [ -z "$SG_COUNT" ] || [ "$SG_COUNT" -eq 0 ]; then
            summary_string+="info|${service}|N/A\n"
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 보안 그룹(Security Group)이 없습니다.</Detail></Item>'
        else
            local cloudtrail_ok=false
            local flowlogs_ok=false
            local evidence_detail=""

            # ===== 1. CloudTrail 변경 이벤트 확인 =====
            evidence_detail+="[1] CloudTrail - Security Group 변경 감사\n"
            evidence_detail+="────────────────────────────────────────\n"

            local start_time=$(date -u -v-90d +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || date -u -d "90 days ago" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null)
            local sg_events=""

            # 6가지 Security Group 관련 API 이벤트 확인
            for event_name in "AuthorizeSecurityGroupIngress" "RevokeSecurityGroupIngress" \
                              "AuthorizeSecurityGroupEgress" "RevokeSecurityGroupEgress" \
                              "CreateSecurityGroup" "DeleteSecurityGroup"; do
                local event_count=$(aws cloudtrail --no-verify-ssl lookup-events \
                    --lookup-attributes AttributeKey=EventName,AttributeValue="$event_name" \
                    --start-time "$start_time" \
                    --query "length(Events)" \
                    --output text 2>/dev/null)

                if [ -n "$event_count" ] && [ "$event_count" -gt 0 ]; then
                    sg_events+="${event_name}: ${event_count}건\n"
                    evidence_detail+="  [${event_name}] ${event_count}건\n"
                fi
            done

            if [ -z "$sg_events" ]; then
                local trail_status=$(aws cloudtrail --no-verify-ssl get-trail-status --name $(aws cloudtrail --no-verify-ssl list-trails --query "Trails[0].Name" --output text 2>/dev/null) --query "IsLogging" --output text 2>/dev/null)
                if [ "$trail_status" == "True" ]; then
                    evidence_detail+="  CloudTrail: 활성화 (최근 90일간 변경 이벤트 없음)\n"
                    cloudtrail_ok=true
                else
                    evidence_detail+="  CloudTrail: 비활성화 - Security Group 변경 감사 불가\n"
                    cloudtrail_ok=false
                fi
            else
                evidence_detail+="  CloudTrail: 활성화 및 이벤트 기록 중\n"
                cloudtrail_ok=true
            fi

            # ===== 2. VPC Flow Logs 확인 =====
            evidence_detail+="\n[2] VPC Flow Logs - Security Group 트래픽 로깅\n"
            evidence_detail+="────────────────────────────────────────\n"

            FLOW_LOGS_JSON=$(aws ec2 --no-verify-ssl describe-flow-logs --query "FlowLogs[?FlowLogStatus=='ACTIVE']" --output json 2>/dev/null)

            if [ -z "$FLOW_LOGS_JSON" ] || [ "$FLOW_LOGS_JSON" == "[]" ]; then
                evidence_detail+="  VPC Flow Logs: 비활성화 - Security Group 트래픽 로깅 불가\n"
                flowlogs_ok=false
            else
                local flow_log_count=$(echo "$FLOW_LOGS_JSON" | grep -c "FlowLogId" 2>/dev/null || echo "0")
                evidence_detail+="  VPC Flow Logs: 활성화 (${flow_log_count}개 Flow Log)\n"

                # Flow Logs 상세 정보
                echo "$FLOW_LOGS_JSON" | grep -E "FlowLogId|ResourceId|LogDestinationType" | while read -r line; do
                    evidence_detail+="    ${line}\n"
                done
                flowlogs_ok=true
            fi

            # ===== 종합 판정 =====
            evidence_detail+="\n[종합 판정]\n"
            evidence_detail+="────────────────────────────────────────\n"

            local overall_status="bad"
            local detail_msg=""

            if [ "$cloudtrail_ok" == true ] && [ "$flowlogs_ok" == true ]; then
                overall_status="good"
                detail_msg="Security Group 로그 수집 정상 (변경 감사 + 트래픽 로깅)"
                evidence_detail+="✓ CloudTrail 변경 감사: 활성화\n"
                evidence_detail+="✓ VPC Flow Logs 트래픽 로깅: 활성화\n"
            elif [ "$cloudtrail_ok" == true ]; then
                overall_status="bad"
                detail_msg="VPC Flow Logs 미활성화 (트래픽 히트 로깅 불가)"
                evidence_detail+="✓ CloudTrail 변경 감사: 활성화\n"
                evidence_detail+="✗ VPC Flow Logs 트래픽 로깅: 비활성화\n"
            elif [ "$flowlogs_ok" == true ]; then
                overall_status="bad"
                detail_msg="CloudTrail 미활성화 (변경 감사 불가)"
                evidence_detail+="✗ CloudTrail 변경 감사: 비활성화\n"
                evidence_detail+="✓ VPC Flow Logs 트래픽 로깅: 활성화\n"
            else
                overall_status="bad"
                detail_msg="CloudTrail 및 VPC Flow Logs 모두 미활성화"
                evidence_detail+="✗ CloudTrail 변경 감사: 비활성화\n"
                evidence_detail+="✗ VPC Flow Logs 트래픽 로깅: 비활성화\n"
            fi

            summary_string+="${overall_status}|${service}|All Security Groups\n"
            echo "          <Item status=\"${overall_status}\"><ResourceID>All Security Groups</ResourceID><Detail>${detail_msg}</Detail><Evidence><![CDATA[${evidence_detail}]]></Evidence></Item>"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: EC2 Instance Logging ---
        echo '        <SubCheck service="EC2_Logging">'
        local service="EC2_Logging"
        EC2_INSTANCES=$(aws ec2 --no-verify-ssl describe-instances --filters "Name=instance-state-name,Values=running" --query "Reservations[*].Instances[*].[InstanceId,IamInstanceProfile.Arn]" --output text 2>/dev/null)
        if [ -z "$EC2_INSTANCES" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>실행 중인 EC2 인스턴스 미존재</Detail></Item>'
        else
            while read -r instance_id profile_arn; do
                if [ "$profile_arn" == "None" ] || [ -z "$profile_arn" ]; then
                    summary_string+="bad|${service}|${instance_id}\n"
                    echo "        <Item status=\"bad\"><ResourceID>${instance_id}</ResourceID><Detail>인스턴스에 IAM 역할이 연결되지 않아 CloudWatch 로그 전송이 불가합니다.</Detail></Item>"
                else
                    profile_name=$(echo "$profile_arn" | awk -F/ '{print $NF}')
                    role_name=$(aws iam --no-verify-ssl get-instance-profile --instance-profile-name "$profile_name" --query "InstanceProfile.Roles[0].RoleName" --output text 2>/dev/null)
                    if [ -n "$role_name" ]; then
                        attached_policies=$(aws iam --no-verify-ssl list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[*].PolicyName' --output text 2>/dev/null)
                        # CloudWatchAgentServerPolicy 정책이 있는지 확인
                        if echo "$attached_policies" | grep -q "CloudWatchAgentServerPolicy"; then
                            summary_string+="good|${service}|${instance_id}\n"
                            echo "        <Item status=\"good\"><ResourceID>${instance_id}</ResourceID><Detail>역할(${role_name})에 CloudWatch 로그 전송 권한(CloudWatchAgentServerPolicy) 부여</Detail><Evidence><![CDATA[Attached Policies: ${attached_policies}]]></Evidence></Item>"
                        else
                            summary_string+="bad|${service}|${instance_id}\n"
                            echo "        <Item status=\"bad\"><ResourceID>${instance_id}</ResourceID><Detail>역할(${role_name})에 CloudWatch 로그 전송을 위한 표준 정책(CloudWatchAgentServerPolicy) 미존재 (수동 권한 부여 여부 확인 필요)</Detail><Evidence><![CDATA[Attached Policies: ${attached_policies}]]></Evidence></Item>"
                        fi
                    fi
                fi
            done <<< "$EC2_INSTANCES"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Lambda Comprehensive Security Check ---
        echo '        <SubCheck service="Lambda_Comprehensive">'
        local service="Lambda_Comprehensive"

        # Lambda 함수 목록 가져오기 (함수명, 역할, 설명, ARN)
        LAMBDA_FUNCTIONS=$(command aws lambda --no-verify-ssl list-functions \
            --query "Functions[*].[FunctionName,Role,Description,FunctionArn]" \
            --output text 2>/dev/null)

        if [ -z "$LAMBDA_FUNCTIONS" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>Lambda 함수 미존재</Detail><Evidence><![CDATA[No Lambda functions found.]]></Evidence></Item>'
        else
            while read -r func_name role_arn description func_arn; do
                # 역할 이름 추출
                role_name=$(echo "$role_arn" | awk -F/ '{print $NF}')

                # 태그 조회
                tags_raw=$(command aws lambda --no-verify-ssl list-tags --resource "$func_arn" \
                    --query "Tags" --output text 2>/dev/null | tr '\n' ' ' | sed 's/\t/: /g; s/ $//; s/Key: //g')

                # 디스플레이용 함수명
                display_name="${func_name}"
                [ -n "$description" ] && [ "$description" != "None" ] && display_name+=" (Desc: ${description})"
                [ -n "$tags_raw" ] && display_name+=" (Tags: ${tags_raw})"

                # -------------------- Evidence 영역 --------------------
                evidence=$'\n'"=== Lambda Function: ${func_name} ==="$'\n'

                # (1) Logging Config Evidence
                config=$(command aws lambda --no-verify-ssl get-function-configuration \
                    --function-name "$func_name" \
                    --query "LoggingConfig" 2>/dev/null)
                evidence+=$'\n'"--- [Logging Configuration] ---"$'\n'"${config}"$'\n'

                # (2) IAM Managed Policies Evidence
                managed_policies=$(command aws iam --no-verify-ssl list-attached-role-policies \
                    --role-name "$role_name" \
                    --query 'AttachedPolicies[*].PolicyArn' \
                    --output text 2>/dev/null)
                if [ -n "$managed_policies" ]; then
                    for policy_arn in $managed_policies; do
                        version_id=$(command aws iam --no-verify-ssl get-policy \
                            --policy-arn "$policy_arn" \
                            --query 'Policy.DefaultVersionId' \
                            --output text 2>/dev/null)
                        policy_json=$(command aws iam --no-verify-ssl get-policy-version \
                            --policy-arn "$policy_arn" \
                            --version-id "$version_id" \
                            --output json 2>/dev/null)
                        evidence+=$'\n'"--- [Managed Policy: ${policy_arn}] ---"$'\n'"${policy_json}"$'\n'
                    done
                else
                    evidence+=$'\n'"--- [Managed Policy] --- None"$'\n'
                fi

                # (3) IAM Inline Policies Evidence
                inline_policies=$(command aws iam --no-verify-ssl list-role-policies \
                    --role-name "$role_name" \
                    --query 'PolicyNames' \
                    --output text 2>/dev/null)
                if [ -n "$inline_policies" ]; then
                    for policy_name in $inline_policies; do
                        policy_json=$(command aws iam --no-verify-ssl get-role-policy \
                            --role-name "$role_name" \
                            --policy-name "$policy_name" \
                            --output json 2>/dev/null)
                        evidence+=$'\n'"--- [Inline Policy: ${policy_name}] ---"$'\n'"${policy_json}"$'\n'
                    done
                else
                    evidence+=$'\n'"--- [Inline Policy] --- None"$'\n'
                fi

                # (4) CloudWatch 로그 권한 검증 Evidence
                sim_result=$(command aws iam --no-verify-ssl simulate-principal-policy \
                    --policy-source-arn "$role_arn" \
                    --action-names "logs:PutLogEvents" \
                    --output json 2>/dev/null)
                if echo "$sim_result" | grep -q '"EvalDecision": "allowed"'; then
                    log_perm_status="CloudWatch 로그 쓰기 권한 있음"
                    has_log_permission=true
                else
                    log_perm_status="CloudWatch 로그 쓰기 권한 없음"
                    has_log_permission=false
                fi
                evidence+=$'\n'"--- [CloudWatch 로그 쓰기 권한] ---"$'\n'"${sim_result}"$'\n'

                # (5) 로그 그룹 설정 여부 확인
                findings=""
                status="good"
                if ! echo "$config" | grep -q "LogGroup"; then
                    findings+="CloudWatch 로그 그룹 미설정. "
                    status="bad"
                fi

                if [ "$has_log_permission" = false ]; then
                    findings+="실행 역할에 logs:PutLogEvents 권한 없음. "
                    status="bad"
                fi

                # -------------------- CloudTrail Lambda 데이터 이벤트 점검 (참고용) --------------------
                # 참고: CloudTrail 데이터 이벤트는 Lambda 호출 API 로그이며, PISM-013(실행 로그 수집)과는 별개입니다.
                # 이 정보는 Evidence에만 기록하며 판정에는 영향을 주지 않습니다.
                lambda_data_event_found="false"
                trail_evidence=""
                ALL_TRAILS=$(command aws cloudtrail --no-verify-ssl describe-trails \
                    --query 'trailList[*].Name' \
                    --output text 2>/dev/null)
                if [ -n "$ALL_TRAILS" ]; then
                    for name in $ALL_TRAILS; do
                        event_selectors=$(command aws cloudtrail --no-verify-ssl get-event-selectors \
                            --trail-name "$name" 2>/dev/null)
                        trail_evidence+="Trail: $name, Selectors: $event_selectors\n"
                        if echo "$event_selectors" | grep -A 2 '"Field": "resources.type"' | grep -q '"AWS::Lambda::Function"'; then
                            lambda_data_event_found="true"
                            break
                        fi
                    done
                fi

                if [ "$lambda_data_event_found" == "true" ]; then
                    evidence+=$'\n'"--- [CloudTrail Data Events (참고)] ---"$'\n'"Lambda 함수 데이터 이벤트 로깅 활성화"$'\n'"${trail_evidence}"$'\n'
                else
                    evidence+=$'\n'"--- [CloudTrail Data Events (참고)] ---"$'\n'"Lambda 함수 데이터 이벤트 로깅 비활성화"$'\n'"${trail_evidence}"$'\n'
                fi

                # -------------------- 결과 출력 --------------------
                if [ "$status" == "good" ]; then
                    echo "          <Item status=\"good\"><ResourceID>${display_name}</ResourceID><Detail>CloudWatch 로그 그룹 설정 및 logs:PutLogEvents 권한 정상</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
                else
                    echo "          <Item status=\"bad\"><ResourceID>${display_name}</ResourceID><Detail>${findings}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
                fi

                summary_string+="${status}|${service}|${func_name}\n"
            done <<< "$LAMBDA_FUNCTIONS"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: S3 Server Access Logging ---
        echo '        <SubCheck service="S3_ServerAccessLogging">'
        local service="S3_ServerAccessLogging"
        
        S3_BUCKETS=$(aws s3 --no-verify-ssl ls 2>/dev/null | awk '{print $3}')
        if [ -z "$S3_BUCKETS" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>S3 버킷 미존재</Detail></Item>'
        else
            for bucket_name in $S3_BUCKETS; do
                if [ -z "$bucket_name" ]; then continue; fi
                
                logging_config=$(aws s3api --no-verify-ssl get-bucket-logging --bucket "$bucket_name" 2>/dev/null)
                local status; local detail; local evidence;
                
                if [ -z "$logging_config" ] || echo "$logging_config" | grep -q '{}'; then
                    status="bad"
                    detail="서버 액세스 로깅 비활성화"
                    evidence="No logging configuration found."
                elif echo "$logging_config" | grep -q '"TargetBucket"'; then
                    target_bucket=$(echo "$logging_config" | grep -o '"TargetBucket": "[^"]*"' | cut -d'"' -f4)
                    target_prefix=$(echo "$logging_config" | grep -o '"TargetPrefix": "[^"]*"' | cut -d'"' -f4)
                    status="good"
                    detail="서버 액세스 로깅 활성화 (대상: ${target_bucket}/${target_prefix})"
                    evidence="$logging_config"
                else
                    status="bad"
                    detail="서버 액세스 로깅 설정 미흡"
                    evidence="$logging_config"
                fi
                
                summary_string+="${status}|${service}|${bucket_name}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${bucket_name}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
            done
        fi
        echo '        </SubCheck>'

        # --- SubCheck: RDS_Aurora ---
        echo '        <SubCheck service="RDS_Aurora">'
        local service="RDS_Aurora"

        # DB Instances
        DB_INSTANCES_DETAILS=$(aws rds --no-verify-ssl describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,Engine,DBParameterGroups[0].DBParameterGroupName,OptionGroupMemberships[0].OptionGroupName,DBClusterIdentifier,join(`,`,EnabledCloudwatchLogsExports || [`None`])]' --output text 2>/dev/null)

        if [ -n "$DB_INSTANCES_DETAILS" ]; then
            echo "$DB_INSTANCES_DETAILS" | while IFS=$'\t' read -r db_id engine param_group opt_group cluster_id logs_export; do
                [ -z "$db_id" ] && continue

                instance_status="good"
                failure_reasons=""

                # 방법별 evidence
                method1_evidence=""
                method2_evidence=""
                method3_evidence=""

                # 엔진별 검증
                case "$engine" in
                    oracle*)
                        # 방법1: CloudWatch Logs (alert, audit)
                        method1_evidence+="[방법1: CloudWatch Logs 내보내기 검증]"$'\n'
                        if [ -n "$logs_export" ] && [ "$logs_export" != "None" ]; then
                            method1_evidence+="  상태: ENABLED"$'\n'
                            method1_evidence+="  활성화된 로그: ${logs_export}"$'\n'

                            if ! echo "$logs_export" | grep -q "alert"; then
                                instance_status="bad"
                                failure_reasons+="알림 로그(alert) 미설정; "
                                method1_evidence+="  ❌ 알림 로그(alert) 미설정"$'\n'
                            fi
                            if ! echo "$logs_export" | grep -q "audit"; then
                                instance_status="bad"
                                failure_reasons+="감사 로그(audit) 미설정; "
                                method1_evidence+="  ❌ 감사 로그(audit) 미설정"$'\n'
                            fi
                        else
                            method1_evidence+="  상태: DISABLED"$'\n'
                            instance_status="bad"
                            failure_reasons+="CloudWatch Logs 미설정; "
                        fi
                        method1_evidence+=$'\n'

                        # 방법2: 해당없음
                        method2_evidence+="[방법2: Option Group 검증]"$'\n'
                        method2_evidence+="  이 엔진은 Option Group 검증 미해당"$'\n\n'

                        # 방법3: 해당없음
                        method3_evidence+="[방법3: Parameter Group 검증]"$'\n'
                        method3_evidence+="  이 엔진은 Parameter Group 검증 미해당"$'\n\n'
                        ;;

                    mysql|mariadb)
                        # 방법1: CloudWatch Logs (audit, error, slowquery, iam-db-auth-error)
                        method1_evidence+="[방법1: CloudWatch Logs 내보내기 검증]"$'\n'
                        if [ -n "$logs_export" ] && [ "$logs_export" != "None" ]; then
                            method1_evidence+="  상태: ENABLED"$'\n'
                            method1_evidence+="  활성화된 로그: ${logs_export}"$'\n'

                            if ! echo "$logs_export" | grep -q "audit"; then
                                instance_status="bad"
                                failure_reasons+="감사 로그(audit) 미설정; "
                                method1_evidence+="  ❌ 감사 로그(audit) 미설정"$'\n'
                            fi
                            if ! echo "$logs_export" | grep -q "error"; then
                                instance_status="bad"
                                failure_reasons+="에러 로그(error) 미설정; "
                                method1_evidence+="  ❌ 에러 로그(error) 미설정"$'\n'
                            fi
                            if ! echo "$logs_export" | grep -q "slowquery"; then
                                instance_status="bad"
                                failure_reasons+="느린 쿼리 로그(slowquery) 미설정; "
                                method1_evidence+="  ❌ 느린 쿼리 로그(slowquery) 미설정"$'\n'
                            fi
                        else
                            method1_evidence+="  상태: DISABLED"$'\n'
                            instance_status="bad"
                            failure_reasons+="CloudWatch Logs 미설정; "
                        fi
                        method1_evidence+=$'\n'

                        # 방법2: MariaDB만 해당
                        if [ "$engine" == "mariadb" ]; then
                            method2_evidence+="[방법2: Option Group 검증 - MARIADB_AUDIT_PLUGIN]"$'\n'

                            # MARIADB_AUDIT_PLUGIN 옵션 확인
                            plugin_enabled=$(aws rds --no-verify-ssl describe-option-groups --option-group-name "$opt_group" --query 'OptionGroupsList[0].Options[?OptionName==`MARIADB_AUDIT_PLUGIN`] | [0].OptionName' --output text 2>/dev/null)

                            if [ -n "$plugin_enabled" ] && [ "$plugin_enabled" != "None" ]; then
                                method2_evidence+="  MARIADB_AUDIT_PLUGIN: ENABLED"$'\n'

                                # 각 파라미터 확인
                                server_audit=$(aws rds --no-verify-ssl describe-option-groups --option-group-name "$opt_group" --query 'OptionGroupsList[0].Options[?OptionName==`MARIADB_AUDIT_PLUGIN`].OptionSettings[?Name==`SERVER_AUDIT`].Value' --output text 2>/dev/null)
                                server_audit_events=$(aws rds --no-verify-ssl describe-option-groups --option-group-name "$opt_group" --query 'OptionGroupsList[0].Options[?OptionName==`MARIADB_AUDIT_PLUGIN`].OptionSettings[?Name==`SERVER_AUDIT_EVENTS`].Value' --output text 2>/dev/null)
                                server_audit_excl=$(aws rds --no-verify-ssl describe-option-groups --option-group-name "$opt_group" --query 'OptionGroupsList[0].Options[?OptionName==`MARIADB_AUDIT_PLUGIN`].OptionSettings[?Name==`SERVER_AUDIT_EXCL_USERS`].Value' --output text 2>/dev/null)
                                server_audit_logging=$(aws rds --no-verify-ssl describe-option-groups --option-group-name "$opt_group" --query 'OptionGroupsList[0].Options[?OptionName==`MARIADB_AUDIT_PLUGIN`].OptionSettings[?Name==`SERVER_AUDIT_LOGGING`].Value' --output text 2>/dev/null)
                                server_audit_incl=$(aws rds --no-verify-ssl describe-option-groups --option-group-name "$opt_group" --query 'OptionGroupsList[0].Options[?OptionName==`MARIADB_AUDIT_PLUGIN`].OptionSettings[?Name==`SERVER_AUDIT_INCL_USERS`].Value' --output text 2>/dev/null)

                                # 기준 검증 및 출력
                                # SERVER_AUDIT
                                if [ "$server_audit" != "FORCE_PLUS_PERMANENT" ]; then
                                    instance_status="bad"
                                    failure_reasons+="SERVER_AUDIT 미설정(FORCE_PLUS_PERMANENT 필요); "
                                    method2_evidence+="  SERVER_AUDIT: ${server_audit:-Not Set} (FORCE_PLUS_PERMANENT으로 미설정)"$'\n'
                                else
                                    method2_evidence+="  SERVER_AUDIT: ${server_audit}"$'\n'
                                fi

                                # SERVER_AUDIT_EVENTS
                                if [[ ! "$server_audit_events" =~ "CONNECT" ]] || [[ ! "$server_audit_events" =~ "QUERY_DDL" ]] || \
                                   [[ ! "$server_audit_events" =~ "QUERY_DML" ]] || [[ ! "$server_audit_events" =~ "QUERY_DCL" ]]; then
                                    instance_status="bad"
                                    failure_reasons+="SERVER_AUDIT_EVENTS 미설정(CONNECT,QUERY_DDL,QUERY_DML,QUERY_DCL 필요); "
                                    method2_evidence+="  SERVER_AUDIT_EVENTS: ${server_audit_events:-Not Set} (CONNECT, QUERY_DDL, QUERY_DML, QUERY_DCL 미포함)"$'\n'
                                else
                                    method2_evidence+="  SERVER_AUDIT_EVENTS: ${server_audit_events}"$'\n'
                                fi

                                # SERVER_AUDIT_EXCL_USERS
                                if [ -n "$server_audit_excl" ] && [ "$server_audit_excl" != "Not Set" ]; then
                                    instance_status="bad"
                                    failure_reasons+="SERVER_AUDIT_EXCL_USERS는 공란이어야 함; "
                                    method2_evidence+="  SERVER_AUDIT_EXCL_USERS: ${server_audit_excl} (공란이어야 함)"$'\n'
                                else
                                    method2_evidence+="  SERVER_AUDIT_EXCL_USERS: ${server_audit_excl:-Not Set}"$'\n'
                                fi

                                # SERVER_AUDIT_LOGGING
                                if [ "$server_audit_logging" != "ON" ]; then
                                    instance_status="bad"
                                    failure_reasons+="SERVER_AUDIT_LOGGING 미활성화; "
                                    method2_evidence+="  SERVER_AUDIT_LOGGING: ${server_audit_logging:-Not Set} (ON으로 미설정)"$'\n'
                                else
                                    method2_evidence+="  SERVER_AUDIT_LOGGING: ${server_audit_logging}"$'\n'
                                fi

                                # SERVER_AUDIT_INCL_USERS
                                if [ -n "$server_audit_incl" ] && [ "$server_audit_incl" != "Not Set" ]; then
                                    instance_status="bad"
                                    failure_reasons+="SERVER_AUDIT_INCL_USERS는 공란이어야 함; "
                                    method2_evidence+="  SERVER_AUDIT_INCL_USERS: ${server_audit_incl} (공란이어야 함)"$'\n'
                                else
                                    method2_evidence+="  SERVER_AUDIT_INCL_USERS: ${server_audit_incl:-Not Set}"$'\n'
                                fi
                            else
                                method2_evidence+="  MARIADB_AUDIT_PLUGIN: DISABLED"$'\n'
                                instance_status="bad"
                                failure_reasons+="MARIADB_AUDIT_PLUGIN 미설정; "
                            fi
                            method2_evidence+=$'\n'
                        else
                            method2_evidence+="[방법2: Option Group 검증]"$'\n'
                            method2_evidence+="  이 엔진은 Option Group 검증 미해당"$'\n\n'
                        fi

                        # 방법3: 해당없음
                        method3_evidence+="[방법3: Parameter Group 검증]"$'\n'
                        method3_evidence+="  이 엔진은 Parameter Group 검증 미해당"$'\n\n'
                        ;;

                    sqlserver*)
                        # 방법1: 해당없음
                        method1_evidence+="[방법1: CloudWatch Logs 내보내기 검증]"$'\n'
                        method1_evidence+="  이 엔진은 CloudWatch Logs 검증 미해당"$'\n\n'

                        # 방법2: SQLSERVER_AUDIT
                        method2_evidence+="[방법2: Option Group 검증 - SQLSERVER_AUDIT]"$'\n'

                        sqlserver_audit=$(aws rds --no-verify-ssl describe-option-groups --option-group-name "$opt_group" --query 'OptionGroupsList[0].Options[?OptionName==`SQLSERVER_AUDIT`] | [0].OptionName' --output text 2>/dev/null)

                        if [ -n "$sqlserver_audit" ] && [ "$sqlserver_audit" != "None" ]; then
                            method2_evidence+="  SQLSERVER_AUDIT: ENABLED"$'\n'

                            iam_role=$(aws rds --no-verify-ssl describe-option-groups --option-group-name "$opt_group" --query 'OptionGroupsList[0].Options[?OptionName==`SQLSERVER_AUDIT`].OptionSettings[?Name==`IAM_ROLE_ARN`].Value' --output text 2>/dev/null)
                            s3_bucket=$(aws rds --no-verify-ssl describe-option-groups --option-group-name "$opt_group" --query 'OptionGroupsList[0].Options[?OptionName==`SQLSERVER_AUDIT`].OptionSettings[?Name==`S3_BUCKET_ARN`].Value' --output text 2>/dev/null)

                            method2_evidence+="  IAM_ROLE_ARN: ${iam_role:-Not Set}"$'\n'
                            method2_evidence+="  S3_BUCKET_ARN: ${s3_bucket:-Not Set}"$'\n'
                        else
                            method2_evidence+="  SQLSERVER_AUDIT: DISABLED"$'\n'
                            instance_status="bad"
                            failure_reasons+="SQLSERVER_AUDIT 미설정; "
                        fi
                        method2_evidence+=$'\n'

                        # 방법3: 해당없음
                        method3_evidence+="[방법3: Parameter Group 검증]"$'\n'
                        method3_evidence+="  이 엔진은 Parameter Group 검증 미해당"$'\n\n'
                        ;;

                    postgres)
                        # 방법1: CloudWatch Logs (postgresql, iam-db-auth-error)
                        method1_evidence+="[방법1: CloudWatch Logs 내보내기 검증]"$'\n'
                        if [ -n "$logs_export" ] && [ "$logs_export" != "None" ]; then
                            method1_evidence+="  상태: ENABLED"$'\n'
                            method1_evidence+="  활성화된 로그: ${logs_export}"$'\n'

                            if ! echo "$logs_export" | grep -q "postgresql"; then
                                instance_status="bad"
                                failure_reasons+="PostgreSQL 로그(postgresql) 미설정; "
                                method1_evidence+="  ❌ PostgreSQL 로그(postgresql) 미설정"$'\n'
                            fi
                        else
                            method1_evidence+="  상태: DISABLED"$'\n'
                            instance_status="bad"
                            failure_reasons+="CloudWatch Logs 미설정; "
                        fi
                        method1_evidence+=$'\n'

                        # 방법2: 해당없음
                        method2_evidence+="[방법2: Option Group 검증]"$'\n'
                        method2_evidence+="  이 엔진은 Option Group 검증 미해당"$'\n\n'

                        # 방법3: Instance Parameter Group (shared_preload_libraries, pgaudit.log, pgaudit.log_parameter, pgaudit.log_rows, pgaudit.role)
                        method3_evidence+="[방법3: Parameter Group 검증]"$'\n'
                        shared_libs=$(aws rds --no-verify-ssl describe-db-parameters --db-parameter-group-name "$param_group" --query "Parameters[?ParameterName=='shared_preload_libraries'].ParameterValue" --output text 2>/dev/null)
                        pgaudit_log=$(aws rds --no-verify-ssl describe-db-parameters --db-parameter-group-name "$param_group" --query "Parameters[?ParameterName=='pgaudit.log'].ParameterValue" --output text 2>/dev/null)
                        pgaudit_log_param=$(aws rds --no-verify-ssl describe-db-parameters --db-parameter-group-name "$param_group" --query "Parameters[?ParameterName=='pgaudit.log_parameter'].ParameterValue" --output text 2>/dev/null)
                        pgaudit_log_rows=$(aws rds --no-verify-ssl describe-db-parameters --db-parameter-group-name "$param_group" --query "Parameters[?ParameterName=='pgaudit.log_rows'].ParameterValue" --output text 2>/dev/null)
                        pgaudit_role=$(aws rds --no-verify-ssl describe-db-parameters --db-parameter-group-name "$param_group" --query "Parameters[?ParameterName=='pgaudit.role'].ParameterValue" --output text 2>/dev/null)

                        # 기준 검증 및 출력
                        # shared_preload_libraries
                        if [[ ! "$shared_libs" =~ "pgaudit" ]]; then
                            instance_status="bad"
                            failure_reasons+="shared_preload_libraries에 pgaudit 미포함; "
                            method3_evidence+="  shared_preload_libraries: ${shared_libs:-Not Set} (pgaudit 미포함)"$'\n'
                        else
                            method3_evidence+="  shared_preload_libraries: ${shared_libs}"$'\n'
                        fi

                        # pgaudit.log
                        if [[ ! "$pgaudit_log" =~ "ddl" ]] || [[ ! "$pgaudit_log" =~ "role" ]] || \
                           [[ ! "$pgaudit_log" =~ "read" ]] || [[ ! "$pgaudit_log" =~ "write" ]]; then
                            instance_status="bad"
                            failure_reasons+="pgaudit.log 미설정(ddl,role,read,write 필요); "
                            method3_evidence+="  pgaudit.log: ${pgaudit_log:-Not Set} (ddl, role, read, write 미포함)"$'\n'
                        else
                            method3_evidence+="  pgaudit.log: ${pgaudit_log}"$'\n'
                        fi

                        # pgaudit.log_parameter
                        if [ "$pgaudit_log_param" != "0" ]; then
                            instance_status="bad"
                            failure_reasons+="pgaudit.log_parameter는 0이어야 함; "
                            method3_evidence+="  pgaudit.log_parameter: ${pgaudit_log_param:-Not Set} (0으로 미설정)"$'\n'
                        else
                            method3_evidence+="  pgaudit.log_parameter: ${pgaudit_log_param}"$'\n'
                        fi

                        # pgaudit.log_rows
                        if [ "$pgaudit_log_rows" != "0" ]; then
                            instance_status="bad"
                            failure_reasons+="pgaudit.log_rows는 0이어야 함; "
                            method3_evidence+="  pgaudit.log_rows: ${pgaudit_log_rows:-Not Set} (0으로 미설정)"$'\n'
                        else
                            method3_evidence+="  pgaudit.log_rows: ${pgaudit_log_rows}"$'\n'
                        fi

                        # pgaudit.role
                        if [ "$pgaudit_role" != "rds_pgaudit" ]; then
                            instance_status="bad"
                            failure_reasons+="pgaudit.role은 rds_pgaudit이어야 함; "
                            method3_evidence+="  pgaudit.role: ${pgaudit_role:-Not Set} (rds_pgaudit으로 미설정)"$'\n'
                        else
                            method3_evidence+="  pgaudit.role: ${pgaudit_role}"$'\n'
                        fi
                        method3_evidence+=$'\n'
                        ;;

                    aurora-mysql)
                        # 방법1: 클러스터 레벨에서 확인
                        method1_evidence+="[방법1: CloudWatch Logs 내보내기 검증]"$'\n'
                        method1_evidence+="  Aurora MySQL 인스턴스는 클러스터 레벨에서 확인"$'\n'
                        method1_evidence+="  클러스터 ID: ${cluster_id}"$'\n\n'

                        # 방법2: 해당없음
                        method2_evidence+="[방법2: Option Group 검증]"$'\n'
                        method2_evidence+="  이 엔진은 Option Group 검증 미해당"$'\n\n'

                        # 방법3: Instance와 Cluster 구분
                        method3_evidence+="[방법3-1: Instance Parameter Group 검증]"$'\n'
                        method3_evidence+="  Aurora MySQL 인스턴스는 Instance 파라미터 그룹 검증 미해당"$'\n\n'

                        # 방법3-2: Cluster Parameter Group - 실제 클러스터 파라미터 조회
                        method3_evidence+="[방법3-2: Cluster Parameter Group 검증]"$'\n'
                        if [ -n "$cluster_id" ] && [ "$cluster_id" != "None" ]; then
                            # 클러스터 파라미터 그룹 이름 조회
                            instance_cluster_param_group=$(aws rds --no-verify-ssl describe-db-clusters --db-cluster-identifier "$cluster_id" --query 'DBClusters[0].DBClusterParameterGroup' --output text 2>/dev/null)

                            if [ -n "$instance_cluster_param_group" ] && [ "$instance_cluster_param_group" != "None" ]; then
                                # 클러스터 파라미터 조회
                                instance_audit_logging=$(aws rds --no-verify-ssl describe-db-cluster-parameters --db-cluster-parameter-group-name "$instance_cluster_param_group" --query "Parameters[?ParameterName=='server_audit_logging'].ParameterValue" --output text 2>/dev/null)
                                instance_audit_upload=$(aws rds --no-verify-ssl describe-db-cluster-parameters --db-cluster-parameter-group-name "$instance_cluster_param_group" --query "Parameters[?ParameterName=='server_audit_logs_upload'].ParameterValue" --output text 2>/dev/null)

                                method3_evidence+="  클러스터 ID: ${cluster_id}"$'\n'
                                method3_evidence+="  클러스터 파라미터 그룹: ${instance_cluster_param_group}"$'\n'

                                # 기준 검증 및 출력
                                # server_audit_logging
                                if [ "$instance_audit_logging" != "1" ]; then
                                    instance_status="bad"
                                    failure_reasons+="server_audit_logging은 1이어야 함; "
                                    method3_evidence+="  server_audit_logging: ${instance_audit_logging:-Not Set} (1로 미설정)"$'\n'
                                else
                                    method3_evidence+="  server_audit_logging: ${instance_audit_logging}"$'\n'
                                fi

                                # server_audit_logs_upload
                                if [ "$instance_audit_upload" != "1" ]; then
                                    instance_status="bad"
                                    failure_reasons+="server_audit_logs_upload는 1이어야 함; "
                                    method3_evidence+="  server_audit_logs_upload: ${instance_audit_upload:-Not Set} (1로 미설정)"$'\n'
                                else
                                    method3_evidence+="  server_audit_logs_upload: ${instance_audit_upload}"$'\n'
                                fi
                            else
                                method3_evidence+="  클러스터 파라미터 그룹 조회 실패"$'\n'
                            fi
                        else
                            method3_evidence+="  클러스터 정보 없음"$'\n'
                        fi
                        method3_evidence+=$'\n'
                        ;;

                    aurora-postgresql)
                        # 방법1: 클러스터 레벨에서 확인
                        method1_evidence+="[방법1: CloudWatch Logs 내보내기 검증]"$'\n'
                        method1_evidence+="  Aurora PostgreSQL 인스턴스는 클러스터 레벨에서 확인"$'\n'
                        method1_evidence+="  클러스터 ID: ${cluster_id}"$'\n\n'

                        # 방법2: 해당없음
                        method2_evidence+="[방법2: Option Group 검증]"$'\n'
                        method2_evidence+="  이 엔진은 Option Group 검증 미해당"$'\n\n'

                        # 방법3-1: Instance Parameter Group (shared_preload_libraries, pgaudit.log_parameter, pgaudit.log_rows)
                        method3_evidence+="[방법3-1: Instance Parameter Group 검증]"$'\n'
                        shared_libs=$(aws rds --no-verify-ssl describe-db-parameters --db-parameter-group-name "$param_group" --query "Parameters[?ParameterName=='shared_preload_libraries'].ParameterValue" --output text 2>/dev/null)
                        pgaudit_log_param=$(aws rds --no-verify-ssl describe-db-parameters --db-parameter-group-name "$param_group" --query "Parameters[?ParameterName=='pgaudit.log_parameter'].ParameterValue" --output text 2>/dev/null)
                        pgaudit_log_rows=$(aws rds --no-verify-ssl describe-db-parameters --db-parameter-group-name "$param_group" --query "Parameters[?ParameterName=='pgaudit.log_rows'].ParameterValue" --output text 2>/dev/null)

                        # 기준 검증 및 출력
                        # shared_preload_libraries
                        if [[ ! "$shared_libs" =~ "pgaudit" ]]; then
                            instance_status="bad"
                            failure_reasons+="shared_preload_libraries에 pgaudit 미포함; "
                            method3_evidence+="  shared_preload_libraries: ${shared_libs:-Not Set} (pgaudit 미포함)"$'\n'
                        else
                            method3_evidence+="  shared_preload_libraries: ${shared_libs}"$'\n'
                        fi

                        # pgaudit.log_parameter
                        if [ "$pgaudit_log_param" != "0" ]; then
                            instance_status="bad"
                            failure_reasons+="pgaudit.log_parameter는 0이어야 함; "
                            method3_evidence+="  pgaudit.log_parameter: ${pgaudit_log_param:-Not Set} (0으로 미설정)"$'\n'
                        else
                            method3_evidence+="  pgaudit.log_parameter: ${pgaudit_log_param}"$'\n'
                        fi

                        # pgaudit.log_rows
                        if [ "$pgaudit_log_rows" != "0" ]; then
                            instance_status="bad"
                            failure_reasons+="pgaudit.log_rows는 0이어야 함; "
                            method3_evidence+="  pgaudit.log_rows: ${pgaudit_log_rows:-Not Set} (0으로 미설정)"$'\n'
                        else
                            method3_evidence+="  pgaudit.log_rows: ${pgaudit_log_rows}"$'\n'
                        fi
                        method3_evidence+=$'\n'

                        # 방법3-2: Cluster Parameter Group - 실제 클러스터 파라미터 조회
                        method3_evidence+="[방법3-2: Cluster Parameter Group 검증]"$'\n'
                        if [ -n "$cluster_id" ] && [ "$cluster_id" != "None" ]; then
                            # 클러스터 파라미터 그룹 이름 조회
                            instance_cluster_param_group=$(aws rds --no-verify-ssl describe-db-clusters --db-cluster-identifier "$cluster_id" --query 'DBClusters[0].DBClusterParameterGroup' --output text 2>/dev/null)

                            if [ -n "$instance_cluster_param_group" ] && [ "$instance_cluster_param_group" != "None" ]; then
                                # 클러스터 파라미터 조회
                                instance_pgaudit_log=$(aws rds --no-verify-ssl describe-db-cluster-parameters --db-cluster-parameter-group-name "$instance_cluster_param_group" --query "Parameters[?ParameterName=='pgaudit.log'].ParameterValue" --output text 2>/dev/null)
                                instance_pgaudit_role=$(aws rds --no-verify-ssl describe-db-cluster-parameters --db-cluster-parameter-group-name "$instance_cluster_param_group" --query "Parameters[?ParameterName=='pgaudit.role'].ParameterValue" --output text 2>/dev/null)

                                method3_evidence+="  클러스터 ID: ${cluster_id}"$'\n'
                                method3_evidence+="  클러스터 파라미터 그룹: ${instance_cluster_param_group}"$'\n'
                                method3_evidence+="  pgaudit.log: ${instance_pgaudit_log:-Not Set}"$'\n'
                                method3_evidence+="  pgaudit.role: ${instance_pgaudit_role:-Not Set}"$'\n'

                                # 기준 검증 - Aurora PostgreSQL 인스턴스는 Instance 파라미터만 검증 (클러스터 파라미터는 참고)
                            else
                                method3_evidence+="  클러스터 파라미터 그룹 조회 실패"$'\n'
                            fi
                        else
                            method3_evidence+="  클러스터 정보 없음"$'\n'
                        fi
                        method3_evidence+=$'\n'
                        ;;

                    *)
                        # 기타 엔진
                        method1_evidence+="[방법1: CloudWatch Logs 내보내기 검증]"$'\n'
                        if [ -n "$logs_export" ] && [ "$logs_export" != "None" ]; then
                            method1_evidence+="  상태: ENABLED"$'\n'
                            method1_evidence+="  활성화된 로그: ${logs_export}"$'\n'
                        else
                            method1_evidence+="  상태: DISABLED"$'\n'
                        fi
                        method1_evidence+=$'\n'

                        method2_evidence+="[방법2: Option Group 검증]"$'\n'
                        method2_evidence+="  검증 기준 없음"$'\n\n'

                        method3_evidence+="[방법3: Parameter Group 검증]"$'\n'
                        method3_evidence+="  검증 기준 없음"$'\n\n'
                        ;;
                esac

                # Evidence 생성
                evidence=""
                evidence+="════════════════════════════════════════════════════════"$'\n'
                evidence+="  DB Instance: ${db_id}"$'\n'
                evidence+="════════════════════════════════════════════════════════"$'\n\n'
                evidence+="[기본 정보]"$'\n'
                evidence+="  Engine: ${engine}"$'\n'
                evidence+="  Parameter Group: ${param_group}"$'\n'
                evidence+="  Option Group: ${opt_group}"$'\n'
                if [ -n "$cluster_id" ] && [ "$cluster_id" != "None" ]; then
                    evidence+="  Cluster ID: ${cluster_id}"$'\n'
                fi
                evidence+=$'\n'
                evidence+="${method1_evidence}"
                evidence+="${method2_evidence}"
                evidence+="${method3_evidence}"

                # 판정 결과
                evidence+="[판정 결과]"$'\n'
                if [ "$instance_status" == "good" ]; then
                    evidence+="  Status: good"$'\n'
                    evidence+="  Result: 감사 로그 설정 정상"$'\n'
                    detail="[${engine}] 감사 로그 설정 정상"
                else
                    evidence+="  Status: bad"$'\n'
                    evidence+="  Issues: ${failure_reasons}"$'\n'
                    detail="[${engine}] ${failure_reasons}"
                fi

                # Summary 및 XML 출력
                summary_string+="${instance_status}|${service}|${db_id}\n"
                echo "          <Item status=\"${instance_status}\">"
                echo "            <ResourceID>${db_id}</ResourceID>"
                echo "            <Detail>${detail}</Detail>"
                echo "            <Evidence><![CDATA[${evidence}]]></Evidence>"
                echo "          </Item>"
            done
        fi

        # DB Clusters
        DB_CLUSTERS_DETAILS=$(aws rds --no-verify-ssl describe-db-clusters --query 'DBClusters[*].[DBClusterIdentifier,Engine,DBClusterParameterGroup,join(`,`,EnabledCloudwatchLogsExports || [`None`])]' --output text 2>/dev/null)

        if [ -n "$DB_CLUSTERS_DETAILS" ]; then
            echo "$DB_CLUSTERS_DETAILS" | while IFS=$'\t' read -r cluster_id engine cluster_param_group logs_export; do
                [ -z "$cluster_id" ] && continue

                cluster_status="good"
                failure_reasons=""

                # 방법별 evidence
                method1_evidence=""
                method2_evidence=""
                method3_evidence=""

                case "$engine" in
                    aurora-mysql)
                        # 방법1: CloudWatch Logs (audit, error, slowquery, iam-db-auth-error)
                        method1_evidence+="[방법1: CloudWatch Logs 내보내기 검증]"$'\n'

                        if [ -n "$logs_export" ] && [ "$logs_export" != "None" ]; then
                            method1_evidence+="  상태: ENABLED"$'\n'
                            method1_evidence+="  활성화된 로그: ${logs_export}"$'\n'

                            if ! echo "$logs_export" | grep -q "audit"; then
                                cluster_status="bad"
                                failure_reasons+="감사 로그(audit) 미설정; "
                                method1_evidence+="  ❌ 감사 로그(audit) 미설정"$'\n'
                            fi
                            if ! echo "$logs_export" | grep -q "error"; then
                                cluster_status="bad"
                                failure_reasons+="에러 로그(error) 미설정; "
                                method1_evidence+="  ❌ 에러 로그(error) 미설정"$'\n'
                            fi
                            if ! echo "$logs_export" | grep -q "slowquery"; then
                                cluster_status="bad"
                                failure_reasons+="느린 쿼리 로그(slowquery) 미설정; "
                                method1_evidence+="  ❌ 느린 쿼리 로그(slowquery) 미설정"$'\n'
                            fi
                        else
                            method1_evidence+="  상태: DISABLED"$'\n'
                            cluster_status="bad"
                            failure_reasons+="CloudWatch Logs 미설정; "
                        fi
                        method1_evidence+=$'\n'

                        # 방법2: 해당없음
                        method2_evidence+="[방법2: Option Group 검증]"$'\n'
                        method2_evidence+="  클러스터는 Option Group 검증 미해당"$'\n\n'

                        # 방법3-1: Instance Parameter Group (Aurora MySQL 클러스터는 미해당)
                        method3_evidence+="[방법3-1: Instance Parameter Group 검증]"$'\n'
                        method3_evidence+="  Aurora MySQL 클러스터는 Instance 파라미터 그룹 검증 미해당"$'\n\n'

                        # 방법3-2: Cluster Parameter Group (server_audit_logging, server_audit_logs_upload)
                        method3_evidence+="[방법3-2: Cluster Parameter Group 검증]"$'\n'
                        audit_logging=$(aws rds --no-verify-ssl describe-db-cluster-parameters --db-cluster-parameter-group-name "$cluster_param_group" --query "Parameters[?ParameterName=='server_audit_logging'].ParameterValue" --output text 2>/dev/null)
                        audit_upload=$(aws rds --no-verify-ssl describe-db-cluster-parameters --db-cluster-parameter-group-name "$cluster_param_group" --query "Parameters[?ParameterName=='server_audit_logs_upload'].ParameterValue" --output text 2>/dev/null)

                        # 기준 검증 및 출력
                        # server_audit_logging
                        if [ "$audit_logging" != "1" ]; then
                            cluster_status="bad"
                            failure_reasons+="server_audit_logging은 1이어야 함; "
                            method3_evidence+="  server_audit_logging: ${audit_logging:-Not Set} (1로 미설정)"$'\n'
                        else
                            method3_evidence+="  server_audit_logging: ${audit_logging}"$'\n'
                        fi

                        # server_audit_logs_upload
                        if [ "$audit_upload" != "1" ]; then
                            cluster_status="bad"
                            failure_reasons+="server_audit_logs_upload는 1이어야 함; "
                            method3_evidence+="  server_audit_logs_upload: ${audit_upload:-Not Set} (1로 미설정)"$'\n'
                        else
                            method3_evidence+="  server_audit_logs_upload: ${audit_upload}"$'\n'
                        fi
                        method3_evidence+=$'\n'
                        ;;

                    aurora-postgresql)
                        # 방법1: CloudWatch Logs (postgresql, iam-db-auth-error)
                        method1_evidence+="[방법1: CloudWatch Logs 내보내기 검증]"$'\n'

                        if [ -n "$logs_export" ] && [ "$logs_export" != "None" ]; then
                            method1_evidence+="  상태: ENABLED"$'\n'
                            method1_evidence+="  활성화된 로그: ${logs_export}"$'\n'

                            if ! echo "$logs_export" | grep -q "postgresql"; then
                                cluster_status="bad"
                                failure_reasons+="PostgreSQL 로그(postgresql) 미설정; "
                                method1_evidence+="  ❌ PostgreSQL 로그(postgresql) 미설정"$'\n'
                            fi
                        else
                            method1_evidence+="  상태: DISABLED"$'\n'
                            cluster_status="bad"
                            failure_reasons+="CloudWatch Logs 미설정; "
                        fi
                        method1_evidence+=$'\n'

                        # 방법2: 해당없음
                        method2_evidence+="[방법2: Option Group 검증]"$'\n'
                        method2_evidence+="  클러스터는 Option Group 검증 미해당"$'\n\n'

                        # 방법3-1: Instance Parameter Group (인스턴스에서 확인)
                        method3_evidence+="[방법3-1: Instance Parameter Group 검증]"$'\n'
                        method3_evidence+="  Aurora PostgreSQL Instance 파라미터는 각 인스턴스에서 확인"$'\n'
                        method3_evidence+="  (shared_preload_libraries, pgaudit.log_parameter, pgaudit.log_rows)"$'\n\n'

                        # 방법3-2: Cluster Parameter Group (pgaudit.log, pgaudit.role)
                        method3_evidence+="[방법3-2: Cluster Parameter Group 검증]"$'\n'
                        pgaudit_log=$(aws rds --no-verify-ssl describe-db-cluster-parameters --db-cluster-parameter-group-name "$cluster_param_group" --query "Parameters[?ParameterName=='pgaudit.log'].ParameterValue" --output text 2>/dev/null)
                        pgaudit_role=$(aws rds --no-verify-ssl describe-db-cluster-parameters --db-cluster-parameter-group-name "$cluster_param_group" --query "Parameters[?ParameterName=='pgaudit.role'].ParameterValue" --output text 2>/dev/null)

                        # 기준 검증 및 출력
                        # pgaudit.log
                        if [[ ! "$pgaudit_log" =~ "ddl" ]] || [[ ! "$pgaudit_log" =~ "role" ]] || \
                           [[ ! "$pgaudit_log" =~ "read" ]] || [[ ! "$pgaudit_log" =~ "write" ]]; then
                            cluster_status="bad"
                            failure_reasons+="pgaudit.log는 ddl,role,read,write를 포함해야 함; "
                            method3_evidence+="  pgaudit.log: ${pgaudit_log:-Not Set} (ddl, role, read, write 미포함)"$'\n'
                        else
                            method3_evidence+="  pgaudit.log: ${pgaudit_log}"$'\n'
                        fi

                        # pgaudit.role - 참고 정보로만 표시 (검증 기준 없음)
                        method3_evidence+="  pgaudit.role: ${pgaudit_role:-Not Set}"$'\n'
                        method3_evidence+=$'\n'
                        ;;
                esac

                # Evidence 생성
                evidence=""
                evidence+="════════════════════════════════════════════════════════"$'\n'
                evidence+="  DB Cluster: ${cluster_id}"$'\n'
                evidence+="════════════════════════════════════════════════════════"$'\n\n'
                evidence+="[기본 정보]"$'\n'
                evidence+="  Engine: ${engine}"$'\n'
                evidence+="  Cluster Parameter Group: ${cluster_param_group}"$'\n'
                evidence+=$'\n'
                evidence+="${method1_evidence}"
                evidence+="${method2_evidence}"
                evidence+="${method3_evidence}"

                # 판정 결과
                evidence+="[판정 결과]"$'\n'
                if [ "$cluster_status" == "good" ]; then
                    evidence+="  Status: good"$'\n'
                    evidence+="  Result: 감사 로그 설정 정상"$'\n'
                    detail="[${engine}] 감사 로그 설정 정상"
                else
                    evidence+="  Status: bad"$'\n'
                    evidence+="  Issues: ${failure_reasons}"$'\n'
                    detail="[${engine}] ${failure_reasons}"
                fi

                # Summary 및 XML 출력
                summary_string+="${cluster_status}|${service}|${cluster_id}\n"
                echo "          <Item status=\"${cluster_status}\">"
                echo "            <ResourceID>${cluster_id}</ResourceID>"
                echo "            <Detail>${detail}</Detail>"
                echo "            <Evidence><![CDATA[${evidence}]]></Evidence>"
                echo "          </Item>"
            done
        fi

        # DB 인스턴스와 클러스터가 모두 없는 경우
        if [ -z "$DB_INSTANCES_DETAILS" ] && [ -z "$DB_CLUSTERS_DETAILS" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>DB 인스턴스나 클러스터 미존재</Detail></Item>'
        fi

        echo '        </SubCheck>'

        echo "      </Results>"
        
        print_summary "$summary_string"
        
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_017] 삭제된 저장소 복원 기능 비활성화
check_pism_017() {
    local check_id="pism_017"
    local check_name="삭제된 저장소 복원 기능 비활성화"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws s3 ls, aws s3api get-bucket-versioning]]></Command>"
        echo "      <Results>"
        S3_BUCKETS=$(aws s3 --no-verify-ssl ls 2>/dev/null | awk '{print $3}')
        local service="S3"
        if [ -z "$S3_BUCKETS" ]; then
            local resource_id="N/A";status="info"
            echo "        <Item status=\"${status}\"><ResourceID>N/A</ResourceID><Detail>점검할 S3 버킷이 없습니다.</Detail><Evidence><![CDATA[No S3 buckets found.]]></Evidence></Item>"
            summary_string+="${status}|${service}|${resource_id}\n"
        else
            for BUCKET_NAME in $S3_BUCKETS; do
                VERSIONING_OUTPUT=$(aws s3api --no-verify-ssl get-bucket-versioning --bucket "$BUCKET_NAME" 2>/dev/null)
                if echo "$VERSIONING_OUTPUT" | grep -q '"Status": "Enabled"'; then status="good"; detail="버전 관리 활성화";
                elif echo "$VERSIONING_OUTPUT" | grep -q 'AccessDenied'; then status="error"; detail="권한이 부족하여 버전 관리 상태를 확인할 수 없습니다.";
                elif echo "$VERSIONING_OUTPUT" | grep -q '"Status": "Suspended"'; then status="bad"; detail="버전 관리 비활성화";
                else status="bad"; detail="버전 관리 설정 부재(기본값:비활성화)"; fi
                summary_string+="${status}|${service}|${BUCKET_NAME}\n"
                echo "        <Item status=\"${status}\"><ResourceID>${BUCKET_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${VERSIONING_OUTPUT}]]></Evidence></Item>"
            done
        fi
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_023] 업무상 불필요한 가상자원 존재
check_pism_023() {
    local check_id="pism_023"
    local check_name="업무상 불필요한 가상자원 존재"
    {
        start_timer
        local summary_string=""

        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws ec2 describe-addresses, aws ec2 describe-images, aws ec2 describe-instances, aws ec2 describe-network-interfaces, aws ec2 describe-security-groups, aws ec2 describe-snapshots, aws ec2 describe-volumes, aws lambda list-functions, aws rds describe-db-cluster-snapshots, aws rds describe-db-clusters, aws rds describe-db-instances, aws rds describe-db-snapshots, aws s3 ls]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Lambda 함수 목록 ---
        local service="Lambda"
        echo "        <SubCheck service=\"${service}\">"
        ERROR_MSG=$(mktemp)
        FUNCTIONS_OUTPUT=$(aws lambda --no-verify-ssl list-functions --query "Functions[*].FunctionName" --output text 2>"$ERROR_MSG")
        CMD_EXIT_CODE=$?
        if [ $CMD_EXIT_CODE -ne 0 ]; then
            local resource_id="Lambda Functions"; local status="error"
            ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
            if echo "$ERROR_DETAIL" | grep -qi "AccessDenied\|not authorized"; then
                local detail="권한 부족 (AccessDenied) - IAM 정책 확인 필요"
            else
                local detail="목록 조회 오류"
            fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
            rm -f "$ERROR_MSG"
        else
            rm -f "$ERROR_MSG"
            if [ -z "$FUNCTIONS_OUTPUT" ]; then
                local resource_id="N/A"; local status="info"; local detail="Lambda 함수 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No Lambda functions found.]]></Evidence></Item>"
            else
                for func_name in $FUNCTIONS_OUTPUT; do
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인"
                    summary_string+="${status}|${service}|${func_name}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${func_name}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Function: ${func_name}]]></Evidence></Item>"
                done
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: S3 버킷 목록 ---
        local service="S3"
        echo "        <SubCheck service=\"${service}\">"
        ERROR_MSG=$(mktemp)
        S3_BUCKETS_OUTPUT=$(aws s3 --no-verify-ssl ls 2>"$ERROR_MSG")
        CMD_EXIT_CODE=$?
        if [ $CMD_EXIT_CODE -ne 0 ]; then
            local resource_id="S3 Buckets"; local status="error"
            ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
            if echo "$ERROR_DETAIL" | grep -qi "AccessDenied\|not authorized"; then
                local detail="권한 부족 (AccessDenied) - IAM 정책 확인 필요"
            else
                local detail="목록 조회 오류"
            fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
            rm -f "$ERROR_MSG"
        else
            rm -f "$ERROR_MSG"
            if [ -z "$S3_BUCKETS_OUTPUT" ]; then
                local resource_id="N/A"; local status="info"; local detail="S3 버킷 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No S3 buckets found.]]></Evidence></Item>"
            else
                S3_BUCKETS=$(echo "$S3_BUCKETS_OUTPUT" | awk '{print $3}')
                for bucket_name in $S3_BUCKETS; do
                    [ -z "$bucket_name" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인"
                    summary_string+="${status}|${service}|${bucket_name}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${bucket_name}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Bucket: ${bucket_name}]]></Evidence></Item>"
                done
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: EC2 인스턴스 목록 ---
        local service="EC2_Instance"
        echo "        <SubCheck service=\"${service}\">"
        EC2_INSTANCES=$(aws ec2 --no-verify-ssl describe-instances --query "Reservations[*].Instances[*].[InstanceId,State.Name]" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="EC2 Instances"; local status="error"; local detail="권한 부족"
            if ! echo "$EC2_INSTANCES" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${EC2_INSTANCES}]]></Evidence></Item>"
        else
            if [ -z "$EC2_INSTANCES" ]; then
                local resource_id="N/A"; local status="info"; local detail="EC2 인스턴스 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No EC2 instances found.]]></Evidence></Item>"
            else
                while read -r instance_id state; do
                    [ -z "$instance_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인 (State: ${state})"
                    summary_string+="${status}|${service}|${instance_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${instance_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[InstanceId: ${instance_id}, State: ${state}]]></Evidence></Item>"
                done <<< "$EC2_INSTANCES"
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: 네트워크 인터페이스 목록 ---
        local service="EC2_NetworkInterface"
        echo "        <SubCheck service=\"${service}\">"
        ENI_OUTPUT=$(aws ec2 --no-verify-ssl describe-network-interfaces --query "NetworkInterfaces[*].[NetworkInterfaceId,Status]" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="Network Interfaces"; local status="error"; local detail="권한 부족"
            if ! echo "$ENI_OUTPUT" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${ENI_OUTPUT}]]></Evidence></Item>"
        else
            if [ -z "$ENI_OUTPUT" ]; then
                local resource_id="N/A"; local status="info"; local detail="네트워크 인터페이스 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No network interfaces found.]]></Evidence></Item>"
            else
                while read -r eni_id eni_status; do
                    [ -z "$eni_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인 (Status: ${eni_status})"
                    summary_string+="${status}|${service}|${eni_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${eni_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[ENI: ${eni_id}, Status: ${eni_status}]]></Evidence></Item>"
                done <<< "$ENI_OUTPUT"
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: EBS 스냅샷 목록 ---
        local service="EBS_Snapshot"
        echo "        <SubCheck service=\"${service}\">"
        SNAPSHOTS=$(aws ec2 --no-verify-ssl describe-snapshots --owner-ids self --query "Snapshots[*].[SnapshotId,StartTime]" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="EBS Snapshots"; local status="error"; local detail="권한 부족"
            if ! echo "$SNAPSHOTS" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${SNAPSHOTS}]]></Evidence></Item>"
        else
            if [ -z "$SNAPSHOTS" ]; then
                local resource_id="N/A"; local status="info"; local detail="EBS 스냅샷 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No snapshots found.]]></Evidence></Item>"
            else
                while read -r snapshot_id start_time; do
                    [ -z "$snapshot_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인"
                    summary_string+="${status}|${service}|${snapshot_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${snapshot_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[SnapshotId: ${snapshot_id}, StartTime: ${start_time}]]></Evidence></Item>"
                done <<< "$SNAPSHOTS"
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: EBS 볼륨 목록 ---
        local service="EBS_Volume"
        echo "        <SubCheck service=\"${service}\">"
        VOLUMES=$(aws ec2 --no-verify-ssl describe-volumes --query "Volumes[*].[VolumeId,State]" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="EBS Volumes"; local status="error"; local detail="권한 부족"
            if ! echo "$VOLUMES" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${VOLUMES}]]></Evidence></Item>"
        else
            if [ -z "$VOLUMES" ]; then
                local resource_id="N/A"; local status="info"; local detail="EBS 볼륨 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No volumes found.]]></Evidence></Item>"
            else
                while read -r volume_id vol_state; do
                    [ -z "$volume_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인 (State: ${vol_state})"
                    summary_string+="${status}|${service}|${volume_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${volume_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[VolumeId: ${volume_id}, State: ${vol_state}]]></Evidence></Item>"
                done <<< "$VOLUMES"
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: AMI 목록 ---
        local service="AMI"
        echo "        <SubCheck service=\"${service}\">"
        AMIS=$(aws ec2 --no-verify-ssl describe-images --owners self --query "Images[*].[ImageId,Name,CreationDate]" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="AMIs"; local status="error"; local detail="권한 부족"
            if ! echo "$AMIS" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${AMIS}]]></Evidence></Item>"
        else
            if [ -z "$AMIS" ]; then
                local resource_id="N/A"; local status="info"; local detail="AMI 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No AMIs found.]]></Evidence></Item>"
            else
                while read -r ami_id ami_name creation_date; do
                    [ -z "$ami_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인"
                    summary_string+="${status}|${service}|${ami_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${ami_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[ImageId: ${ami_id}, Name: ${ami_name}, Created: ${creation_date}]]></Evidence></Item>"
                done <<< "$AMIS"
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: 탄력적 IP 목록 ---
        local service="ElasticIP"
        echo "        <SubCheck service=\"${service}\">"
        EIPS=$(aws ec2 --no-verify-ssl describe-addresses --query "Addresses[*].[PublicIp,AllocationId,InstanceId]" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="Elastic IPs"; local status="error"; local detail="권한 부족"
            if ! echo "$EIPS" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${EIPS}]]></Evidence></Item>"
        else
            if [ -z "$EIPS" ]; then
                local resource_id="N/A"; local status="info"; local detail="탄력적 IP 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No elastic IPs found.]]></Evidence></Item>"
            else
                while read -r public_ip allocation_id instance_id; do
                    [ -z "$public_ip" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인 (InstanceId: ${instance_id:-N/A})"
                    summary_string+="${status}|${service}|${public_ip}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${public_ip}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[PublicIp: ${public_ip}, AllocationId: ${allocation_id}]]></Evidence></Item>"
                done <<< "$EIPS"
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: 보안 그룹 목록 ---
        local service="SecurityGroup"
        echo "        <SubCheck service=\"${service}\">"
        SGS=$(aws ec2 --no-verify-ssl describe-security-groups --query "SecurityGroups[*].[GroupId,GroupName,Description]" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="Security Groups"; local status="error"; local detail="권한 부족"
            if ! echo "$SGS" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${SGS}]]></Evidence></Item>"
        else
            if [ -z "$SGS" ]; then
                local resource_id="N/A"; local status="info"; local detail="보안 그룹 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No security groups found.]]></Evidence></Item>"
            else
                while IFS=$'\t' read -r group_id group_name description; do
                    [ -z "$group_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인 (Name: ${group_name})"
                    summary_string+="${status}|${service}|${group_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${group_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[GroupId: ${group_id}, GroupName: ${group_name}, Description: ${description}]]></Evidence></Item>"
                done <<< "$SGS"
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: RDS 인스턴스 목록 ---
        local service="RDS_Instance"
        echo "        <SubCheck service=\"${service}\">"
        RDS_INSTANCES=$(aws rds --no-verify-ssl describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,DBInstanceStatus]" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="RDS Instances"; local status="error"; local detail="권한 부족"
            if ! echo "$RDS_INSTANCES" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${RDS_INSTANCES}]]></Evidence></Item>"
        else
            if [ -z "$RDS_INSTANCES" ]; then
                local resource_id="N/A"; local status="info"; local detail="RDS 인스턴스 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No RDS instances found.]]></Evidence></Item>"
            else
                while read -r db_id db_status; do
                    [ -z "$db_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인 (Status: ${db_status})"
                    summary_string+="${status}|${service}|${db_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${db_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[DBInstanceIdentifier: ${db_id}, Status: ${db_status}]]></Evidence></Item>"
                done <<< "$RDS_INSTANCES"
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: RDS 클러스터 (Aurora) 목록 ---
        local service="Aurora_Cluster"
        echo "        <SubCheck service=\"${service}\">"
        AURORA_CLUSTERS=$(aws rds --no-verify-ssl describe-db-clusters --query "DBClusters[*].[DBClusterIdentifier,Status]" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="Aurora Clusters"; local status="error"; local detail="권한 부족"
            if ! echo "$AURORA_CLUSTERS" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${AURORA_CLUSTERS}]]></Evidence></Item>"
        else
            if [ -z "$AURORA_CLUSTERS" ]; then
                local resource_id="N/A"; local status="info"; local detail="Aurora 클러스터 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No Aurora clusters found.]]></Evidence></Item>"
            else
                while read -r cluster_id cluster_status; do
                    [ -z "$cluster_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인 (Status: ${cluster_status})"
                    summary_string+="${status}|${service}|${cluster_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${cluster_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[DBClusterIdentifier: ${cluster_id}, Status: ${cluster_status}]]></Evidence></Item>"
                done <<< "$AURORA_CLUSTERS"
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: RDS 스냅샷 목록 ---
        local service="RDS_Snapshot"
        echo "        <SubCheck service=\"${service}\">"
        RDS_SNAPSHOTS=$(aws rds --no-verify-ssl describe-db-snapshots --snapshot-type manual --query "DBSnapshots[*].DBSnapshotIdentifier" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="RDS Snapshots"; local status="error"; local detail="권한 부족"
            if ! echo "$RDS_SNAPSHOTS" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${RDS_SNAPSHOTS}]]></Evidence></Item>"
        else
            if [ -z "$RDS_SNAPSHOTS" ]; then
                local resource_id="N/A"; local status="info"; local detail="RDS 스냅샷 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No RDS snapshots found.]]></Evidence></Item>"
            else
                for snapshot_id in $RDS_SNAPSHOTS; do
                    [ -z "$snapshot_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인"
                    summary_string+="${status}|${service}|${snapshot_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${snapshot_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[DBSnapshotIdentifier: ${snapshot_id}]]></Evidence></Item>"
                done
            fi
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Aurora 스냅샷 목록 ---
        local service="Aurora_Snapshot"
        echo "        <SubCheck service=\"${service}\">"
        AURORA_SNAPSHOTS=$(aws rds --no-verify-ssl describe-db-cluster-snapshots --snapshot-type manual --query "DBClusterSnapshots[*].DBClusterSnapshotIdentifier" --output text 2>/dev/null)
        if [ $? -ne 0 ]; then
            local resource_id="Aurora Snapshots"; local status="error"; local detail="권한 부족"
            if ! echo "$AURORA_SNAPSHOTS" | grep -q "AccessDenied"; then status="Error"; detail="목록 조회 오류"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${AURORA_SNAPSHOTS}]]></Evidence></Item>"
        else
            if [ -z "$AURORA_SNAPSHOTS" ]; then
                local resource_id="N/A"; local status="info"; local detail="Aurora 스냅샷 미존재"
                summary_string+="${status}|${service}|${resource_id}\n"
                echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[No Aurora snapshots found.]]></Evidence></Item>"
            else
                for snapshot_id in $AURORA_SNAPSHOTS; do
                    [ -z "$snapshot_id" ] && continue
                    local status="info"; local detail="담당자와 인터뷰하여 업무상 필요 여부 확인"
                    summary_string+="${status}|${service}|${snapshot_id}\n"
                    echo "          <Item status=\"${status}\"><ResourceID>${snapshot_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[DBClusterSnapshotIdentifier: ${snapshot_id}]]></Evidence></Item>"
                done
            fi
        fi
        echo '        </SubCheck>'

        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_025] 지원이 중단(EOS)된 런타임 사용
check_pism_025() {
    local check_id="pism_025"
    local check_name="지원이 중단(EOS)된 런타임 사용"

    {
        start_timer
        local summary_string=""
        local service="Lambda"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws lambda list-functions]]></Command>"
        echo "      <Results>"

        LAMBDA_FUNCTIONS=$(aws lambda --no-verify-ssl list-functions --query "Functions[*].[FunctionName,Runtime]" --output text 2>/dev/null)
        if [ -z "$LAMBDA_FUNCTIONS" ]; then
            local resource_id="N/A"
            local status="info"
            summary_string+="${status}|${service}|${resource_id}\n"
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>Lambda 함수 미존재</Detail><Evidence><![CDATA[No Lambda functions found.]]></Evidence></Item>'
        else
            while read -r func_name runtime; do
                local status="info"
                local detail="지원 중인 런타임(${runtime}) 사용"
                local detail="런타임(${runtime}) 사용 중. 공식 문서를 참고하여 지원 중단(EOS) 여부 확인 필요"

                # Custom Runtime(provided)은 별도 확인 필요
                if [[ "$runtime" == "provided"* ]]; then
                    detail="Custom Runtime(${runtime}) 사용. Amazon Linux 2 지원 종료일(2025-06-30)을 참고하여 기반 OS의 지원 중단 여부를 직접 확인 필요"
                fi

                summary_string+="${status}|${service}|${func_name}\n"

                echo "        <Item status=\"${status}\"><ResourceID>${func_name}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Runtime: ${runtime}]]></Evidence></Item>"

            done <<< "$LAMBDA_FUNCTIONS"
        fi

        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_030] 디스크 볼륨 생성 시 암호화 설정 비활성화
check_pism_030() {
    local check_id="pism_030"
    local check_name="디스크 볼륨 생성 시 암호화 설정 비활성화"
    {
        start_timer
        local summary_string=""
        local service="EBS"
        local region=$(aws ec2 --no-verify-ssl describe-availability-zones --query "AvailabilityZones[0].RegionName" --output text 2>/dev/null)
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws ec2 describe-availability-zones, aws ec2 get-ebs-encryption-by-default]]></Command>"
        echo "      <Results>"
        ENCRYPTION_STATUS_OUTPUT=$(aws ec2 --no-verify-ssl get-ebs-encryption-by-default 2>/dev/null)
        if echo "$ENCRYPTION_STATUS_OUTPUT" | grep -q '"EbsEncryptionByDefault": true'; then
            status="good"
            detail="리전에 EBS 기본 암호화 설정 활성화"
        else
            status="bad"
            detail="리전에 EBS 기본 암호화 설정 비활성화"
        fi
        
        summary_string+="${status}|${service}|${region}\n"
        
        echo "        <Item status=\"${status}\"><Region>${region}</Region><Detail>${detail}</Detail><Evidence><![CDATA[${ENCRYPTION_STATUS_OUTPUT}]]></Evidence></Item>"
        
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_031] 디스크 볼륨 암호화 미적용
check_pism_031() {
    local check_id="pism_031"
    local check_name="디스크 볼륨 암호화 미적용"
    {
        start_timer
        local summary_string=""
        local service="EBS"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws ec2 describe-volumes]]></Command>"
        echo "      <Results>"
        
        local query="Volumes[*].[VolumeId, Encrypted, State, Attachments[0].InstanceId, Tags[?Key=='Name'].Value | [0]]"
        EBS_VOLUMES_INFO=$(aws ec2 --no-verify-ssl describe-volumes --query "$query" --output text 2>/dev/null)
        
        if [ -z "$EBS_VOLUMES_INFO" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>EBS 볼륨 미존재</Detail><Evidence><![CDATA[No EBS volumes found.]]></Evidence></Item>'
        else
            while IFS=$'\t' read -r volume_id encrypted_status state instance_id name_tag; do
                local status
                local detail
                
                # AWS CLI 출력에서 'None' 또는 빈 값을 'N/A'로 변경
                [ "$instance_id" == "None" ] && instance_id="N/A (Detached)"
                [ "$name_tag" == "None" ] || [ -z "$name_tag" ] && name_tag="N/A"

                if [ "$encrypted_status" == "True" ]; then
                    status="good"
                    detail="볼륨 암호화 적용"
                else
                    status="bad"
                    detail="볼륨 암호화 미적용"
                fi
                
                summary_string+="${status}|${service}|${volume_id}\n"
                
                # 상세 정보를 별도의 XML 태그로 출력하도록 변경
                echo "        <Item status=\"${status}\">"
                echo "          <ResourceID>${volume_id}</ResourceID>"
                echo "          <Detail>${detail}</Detail>"
                echo "          <State>${state}</State>"
                echo "          <AttachedInstance>${instance_id}</AttachedInstance>"
                echo "          <NameTag>${name_tag}</NameTag>"
                echo "          <Evidence><![CDATA[Encrypted: ${encrypted_status}]]></Evidence>"
                echo "        </Item>"
            done <<< "$EBS_VOLUMES_INFO"
        fi
        
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_032] 스냅샷 암호화 미적용
check_pism_032() {
    local check_id="pism_032"
    local check_name="스냅샷 암호화 미적용"
    {
        start_timer
        local summary_string=""
        local service="EBS_Snapshot"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws ec2 describe-snapshots]]></Command>"
        echo "      <Results>"

        # 스냅샷 목록 조회 (Encrypted 속성 포함)
        local query="Snapshots[*].[SnapshotId,Encrypted,VolumeSize,StartTime,Tags[?Key=='Name'].Value|[0]]"
        EBS_SNAPSHOTS_INFO=$(aws ec2 --no-verify-ssl describe-snapshots --owner-ids self --query "$query" --output text 2>/dev/null)

        if [ -z "$EBS_SNAPSHOTS_INFO" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>EBS 스냅샷이 없습니다.</Detail><Evidence><![CDATA[No EBS snapshots found.]]></Evidence></Item>'
        else
            while IFS=$'\t' read -r snapshot_id encrypted_status volume_size start_time name_tag; do
                local status
                local detail

                # AWS CLI 출력에서 'None' 또는 빈 값을 'N/A'로 변경
                [ "$name_tag" == "None" ] || [ -z "$name_tag" ] && name_tag="N/A"

                # Encrypted 속성 확인하여 판단
                if [ "$encrypted_status" == "True" ]; then
                    status="good"
                    detail="스냅샷 암호화 적용 (${volume_size}GB)"
                else
                    status="bad"
                    detail="스냅샷 암호화 미적용 (${volume_size}GB)"
                fi

                summary_string+="${status}|${service}|${snapshot_id}\n"

                # 상세 정보를 별도의 XML 태그로 출력
                echo "        <Item status=\"${status}\">"
                echo "          <ResourceID>${snapshot_id}</ResourceID>"
                echo "          <Detail>${detail}</Detail>"
                echo "          <NameTag>${name_tag}</NameTag>"
                echo "          <VolumeSize>${volume_size}GB</VolumeSize>"
                echo "          <CreateTime>${start_time}</CreateTime>"
                echo "          <Evidence><![CDATA[Encrypted: ${encrypted_status}]]></Evidence>"
                echo "        </Item>"
            done <<< "$EBS_SNAPSHOTS_INFO"
        fi

        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_033] 이미지 암호화 미적용
check_pism_033() {
    local check_id="pism_033"
    local check_name="이미지 암호화 미적용"
    {
        start_timer
        local summary_string=""
        local service="AMI"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws ec2 describe-images, aws ec2 describe-snapshots]]></Command>"
        echo "      <Results>"

        # AMI ID와 Name 목록을 조회
        AMI_LIST=$(aws ec2 --no-verify-ssl describe-images --owners self --query "Images[*].[ImageId,Name]" --output text 2>/dev/null)

        if [ -z "$AMI_LIST" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>사용자 정의 AMI 미존재</Detail><Evidence><![CDATA[No custom AMIs found.]]></Evidence></Item>'
        else
            while IFS=$'\t' read -r ami_id name_tag; do
                # Name이 없는 경우 'N/A'로 처리
                [ "$name_tag" == "None" ] || [ -z "$name_tag" ] && name_tag="N/A"

                local ami_encrypted="true"
                local unencrypted_snapshots=""
                local all_snapshots=""
                local evidence_text=""

                # 현재 AMI의 BlockDeviceMappings에서 스냅샷 ID 목록을 조회
                SNAPSHOT_IDS=$(aws ec2 --no-verify-ssl describe-images --image-ids "$ami_id" --query "Images[0].BlockDeviceMappings[?Ebs].Ebs.SnapshotId" --output text 2>/dev/null)

                if [ -z "$SNAPSHOT_IDS" ]; then
                    status="info"
                    detail="AMI에 연결된 EBS 스냅샷이 없어 암호화 여부 판단 불가"
                    evidence_text="Instance-store backed AMI or no EBS mappings."
                else
                    # 각 스냅샷의 암호화 상태를 개별적으로 확인
                    for snapshot_id in $SNAPSHOT_IDS; do
                        ENCRYPTED=$(aws ec2 --no-verify-ssl describe-snapshots --snapshot-ids "$snapshot_id" --query "Snapshots[0].Encrypted" --output text 2>/dev/null)

                        all_snapshots+="${snapshot_id},"
                        evidence_text+="${snapshot_id}: Encrypted=${ENCRYPTED}"$'\n'

                        if [ "$ENCRYPTED" == "False" ] || [ "$ENCRYPTED" == "false" ]; then
                            ami_encrypted="false"
                            unencrypted_snapshots+="${snapshot_id},"
                        fi
                    done

                    # 마지막 쉼표 제거
                    all_snapshots=${all_snapshots%,}
                    unencrypted_snapshots=${unencrypted_snapshots%,}

                    # 판단
                    if [ "$ami_encrypted" == "true" ]; then
                        status="good"
                        detail="AMI의 모든 스냅샷 암호화 적용 (스냅샷: ${all_snapshots})"
                    else
                        status="bad"
                        detail="AMI 스냅샷 중 일부 암호화 미적용 (미암호화: ${unencrypted_snapshots})"
                    fi
                fi

                summary_string+="${status}|${service}|${ami_id}\n"

                echo "        <Item status=\"${status}\">"
                echo "          <ResourceID>${ami_id}</ResourceID>"
                echo "          <Detail>${detail}</Detail>"
                echo "          <ImageName>${name_tag}</ImageName>"
                if [ -n "$unencrypted_snapshots" ]; then
                    echo "          <UnencryptedSnapshots>${unencrypted_snapshots}</UnencryptedSnapshots>"
                fi
                echo "          <Evidence><![CDATA[${evidence_text}]]></Evidence>"
                echo "        </Item>"
            done <<< "$AMI_LIST"
        fi

        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_034] DB 인스턴스 암호화 미적용
check_pism_034() {
    local check_id="pism_034"
    local check_name="DB 인스턴스 암호화 미적용"
    {
        start_timer
        local summary_string=""
        local service="RDS"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws rds describe-db-instances]]></Command>"
        echo "      <Results>"
        
        # DB인스턴스ID, 스토리지암호화여부, 엔진 정보를 조회
        local query="DBInstances[*].[DBInstanceIdentifier, StorageEncrypted, Engine]"
        DB_INSTANCES_INFO=$(aws rds --no-verify-ssl describe-db-instances --query "$query" --output text 2>/dev/null)
        
        if [ -z "$DB_INSTANCES_INFO" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>DB 인스턴스 미존재</Detail><Evidence><![CDATA[No RDS DB instances found.]]></Evidence></Item>'
        else
            while IFS=$'\t' read -r db_id encrypted_status engine; do
                local status
                local detail

                if [ "$encrypted_status" == "True" ]; then
                    status="good"
                    detail="스토리지 암호화 적용"
                else
                    status="bad"
                    detail="스토리지 암호화 미적용"
                fi
                
                summary_string+="${status}|${service}|${db_id}\n"
                
                # 상세 정보를 별도의 XML 태그로 출력
                echo "        <Item status=\"${status}\">"
                echo "          <ResourceID>${db_id}</ResourceID>"
                echo "          <Detail>${detail}</Detail>"
                echo "          <Engine>${engine}</Engine>"
                echo "          <Evidence><![CDATA[StorageEncrypted: ${encrypted_status}]]></Evidence>"
                echo "        </Item>"
            done <<< "$DB_INSTANCES_INFO"
        fi
        
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_036] 환경변수 내 중요정보 암호화 미적용
check_pism_036() {
    local check_id="pism_036"
    local check_name="환경변수 내 중요정보 암호화 미적용"
    {
        start_timer
        local summary_string=""
        local service="Lambda_Env"
        declare -a SENSITIVE_PATTERNS=(
            "password" "passwd" "pwd" "secret" "credential" "token" "auth" "key"
            "api_key" "client_id" "client_secret" "bearer" "session" "jwt"
            "aws_access_key" "aws_secret_key" "ldap_password" "ad_password"
            "db_user" "db_pass" "db_password" "db_host" "conn_string" "database_url"
            "redis_password" "ssn" "jumin" "resident_registration_number"
            "credit_card" "card_number" "cvv" "cvc" "account_number" "bank_account"
            "pin_number" "private_key" "public_key" "certificate" "passphrase"
            "keystore" "truststore" "pgp_key" "stripe_key" "trade_key" "trading_secret"
        )
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws lambda get-function-configuration, aws lambda list-functions]]></Command>"
        echo "      <Results>"
        LAMBDA_FUNCTIONS=$(aws lambda --no-verify-ssl list-functions --query "Functions[*].FunctionName" --output text 2>/dev/null)
        if [ -z "$LAMBDA_FUNCTIONS" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>Lambda 함수 미존재</Detail></Item>'
        else
            for function_name in $LAMBDA_FUNCTIONS; do
                ENV_VARS_JSON=$(aws lambda --no-verify-ssl get-function-configuration --function-name "$function_name" --query "Environment.Variables" --output json 2>/dev/null)
                
                local status
                local detail
                local all_keys="N/A"
                local evidence_text=""

                if [ -z "$ENV_VARS_JSON" ] || [ "$ENV_VARS_JSON" == "{}" ] || [ "$ENV_VARS_JSON" == "null" ]; then
                    status="good"
                    detail="환경변수 미존재"
                    evidence_text="No environment variables found."
                else
                    local found_keys=""
                    local all_keys_list=$(echo "$ENV_VARS_JSON" | tr -d '{"}' | sed 's/,/\n/g' | sed 's/:.*//' | xargs -n1)
                    
                    all_keys=$(echo "$all_keys_list" | paste -s -d, -)
                    if [ -z "$all_keys" ]; then all_keys="N/A"; fi

                    # 서브쉘 문제를 해결하기 위해 for 반복문으로 변경
                    for key in $all_keys_list; do
                        if [ -z "$key" ]; then continue; fi
                        for pattern in "${SENSITIVE_PATTERNS[@]}"; do
                            if echo "$key" | grep -iq "$pattern"; then
                                if ! echo "$found_keys" | tr ',' '\n' | grep -q "^${key}$"; then
                                    if [ -z "$found_keys" ]; then found_keys="$key"; else found_keys="${found_keys},${key}"; fi
                                fi
                                break 
                            fi
                        done
                    done

                    if [ -z "$found_keys" ]; then
                        status="review"
                        detail="민감 정보 포함 여부 검토 필요 (민감 정보 패턴 미발견)"
                    else
                        status="bad"
                        detail="민감 정보 패턴이 포함된 환경변수 발견: [${found_keys}]"
                    fi
                    evidence_text=$ENV_VARS_JSON
                fi
                
                summary_string+="${status}|${service}|${function_name}\n"

                echo "        <Item status=\"${status}\">"
                echo "          <ResourceID>${function_name}</ResourceID>"
                echo "          <Detail>${detail}</Detail>"
                echo "          <KeyNames>${all_keys}</KeyNames>"
                echo "          <Evidence><![CDATA[${evidence_text}]]></Evidence>"
                echo "        </Item>"
            done
        fi
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_037_1] 비밀번호 정책 수립 및 로그인 제한 설정(비밀번호 복잡도 설정 확인)
check_pism_037_1() {
    local check_id="pism_037_1"
    local check_name="비밀번호 정책 수립 및 로그인 제한 설정(비밀번호 복잡도 설정 확인)"
    {
        start_timer
        local summary_string=""
        local service="IAM_Password_Policy"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws iam get-account-password-policy]]></Command>"
        echo "      <Results>"
        POLICY_OUTPUT=$(aws iam --no-verify-ssl get-account-password-policy 2>/dev/null)
        if [ $? -ne 0 ]; then
            local status="bad"
            local resource_id="IAM Password Policy"
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>계정에 암호 정책 미설정</Detail><Evidence><![CDATA[${POLICY_OUTPUT}]]></Evidence></Item>"
        else
            get_policy_value() { echo "$POLICY_OUTPUT" | grep "\"$1\"" | sed -e 's/.*: //' -e 's/[",]//g'; }
            
            # 최소 길이 점검
            local resource_id="MinimumPasswordLength"
            local MIN_LENGTH=$(get_policy_value "MinimumPasswordLength"); MIN_LENGTH=${MIN_LENGTH:-0}
            if [ "$MIN_LENGTH" -ge 8 ]; then local status="good"; else local status="bad"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>설정값: ${MIN_LENGTH}</Detail><Evidence><![CDATA[MinimumPasswordLength: ${MIN_LENGTH}]]></Evidence></Item>"

            # 소문자 포함 여부 점검
            local resource_id="RequireLowercaseCharacters"
            local REQ_LOWER=$(get_policy_value "RequireLowercaseCharacters")
            if [ "$REQ_LOWER" == "true" ]; then local status="good"; else local status="bad"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>설정값: ${REQ_LOWER:-false}</Detail><Evidence><![CDATA[RequireLowercaseCharacters: ${REQ_LOWER:-false}]]></Evidence></Item>"

            # 숫자 포함 여부 점검
            local resource_id="RequireNumbers"
            local REQ_NUMBERS=$(get_policy_value "RequireNumbers")
            if [ "$REQ_NUMBERS" == "true" ]; then local status="good"; else local status="bad"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>설정값: ${REQ_NUMBERS:-false}</Detail><Evidence><![CDATA[RequireNumbers: ${REQ_NUMBERS:-false}]]></Evidence></Item>"

            # 특수문자 포함 여부 점검
            local resource_id="RequireSymbols"
            local REQ_SYMBOLS=$(get_policy_value "RequireSymbols")
            if [ "$REQ_SYMBOLS" == "true" ]; then local status="good"; else local status="bad"; fi
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>설정값: ${REQ_SYMBOLS:-false}</Detail><Evidence><![CDATA[RequireSymbols: ${REQ_SYMBOLS:-false}]]></Evidence></Item>"
        fi
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}


# [pism_037_2] 비밀번호 정책 수립 및 로그인 제한 설정 (비밀번호 재사용 방지 확인)
check_pism_037_2() {
    local check_id="pism_037_2"
    local check_name="비밀번호 정책 수립 및 로그인 제한 설정 (비밀번호 재사용 방지 확인)"
    {
        start_timer
        local summary_string=""
        local service="IAM_Password_Policy"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws iam get-account-password-policy]]></Command>"
        echo "      <Results>"
        POLICY_OUTPUT=$(aws iam --no-verify-ssl get-account-password-policy 2>/dev/null)
        if [ $? -ne 0 ]; then
            local status="bad"
            local resource_id="IAM Password Policy"
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>계정에 암호 정책 미설정</Detail><Evidence><![CDATA[${POLICY_OUTPUT}]]></Evidence></Item>"
        else
            get_policy_value() { echo "$POLICY_OUTPUT" | grep "\"$1\"" | sed -e 's/.*: //' -e 's/[",]//g'; }
            
            local resource_id="PasswordReusePrevention"
            local REUSE_PREVENTION=$(get_policy_value "PasswordReusePrevention")
            REUSE_PREVENTION=${REUSE_PREVENTION:-0}
            
            if [ "$REUSE_PREVENTION" -ge 1 ]; then local status="good"; else local status="bad"; fi
            
            summary_string+="${status}|${service}|${resource_id}\n"
            echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>설정값: ${REUSE_PREVENTION}</Detail><Evidence><![CDATA[PasswordReusePrevention: ${REUSE_PREVENTION}]]></Evidence></Item>"
        fi
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_039] 클라우드 자원에 접근 가능한 계정에 추가인증수단 미적용
check_pism_039() {
    local check_id="pism_039"
    local check_name="클라우드 자원에 접근 가능한 계정에 추가인증수단 미적용"
    {
        start_timer
        local summary_string=""
        local service="IAM_User"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws iam get-credential-report]]></Command>"
        echo "      <Results>"

        if [ -z "$G_CREDENTIAL_REPORT" ]; then
            summary_string+="error|${service}|N/A\n"
            echo '        <Item status="error"><ResourceID>IAM Credential Report</ResourceID><Detail>자격증명 보고서 생성 에러</Detail><Evidence><![CDATA[Credential report not available.]]></Evidence></Item>'
        else
            # CSV의 첫 줄(헤더)을 제외하고 한 줄씩 읽어 처리
            echo "$G_CREDENTIAL_REPORT" | tail -n +2 | while IFS=, read -r user arn user_creation_time password_enabled password_last_used password_last_rotated password_next_rotation mfa_active access_key_1_active access_key_1_last_rotated access_key_1_last_used_date access_key_1_last_used_region access_key_1_last_used_service access_key_2_active access_key_2_last_rotated access_key_2_last_used_date access_key_2_last_used_region access_key_2_last_used_service cert_1_active cert_1_last_rotated cert_2_active cert_2_last_rotated; do
                
                # 콘솔 접속 비밀번호가 활성화되어 있거나, 액세스 키가 하나라도 활성화된 사용자를 점검 대상으로 함
                if [ "$password_enabled" == "true" ] || [ "$access_key_1_active" == "true" ] || [ "$access_key_2_active" == "true" ] || [ "$user" == "<root_account>" ]; then
                    local status
                    local detail

                    if [ "$mfa_active" == "true" ]; then
                        status="good"
                        detail="MFA 활성화"
                    else
                        status="bad"
                        detail="MFA 비활성화"
                    fi
                    
                    # 예외 조건: 콘솔 비밀번호 없이 Access Key만 사용하는 경우 MFA가 없어도 '양호'로 처리
                    if [ "$password_enabled" == "false" ] && ( [ "$access_key_1_active" == "true" ] || [ "$access_key_2_active" == "true" ] ); then
                        status="good"
                        detail="프로그래밍 방식 액세스 전용 사용자 (MFA 비필수)"
                    fi
                    
                    # 루트 계정 이름에 포함된 <, > 문자가 XML을 깨트리지 않도록 처리
                    local user_display=$(echo "$user" | sed 's/</\&lt;/g; s/>/\&gt;/g')
                    
                    summary_string+="${status}|${service}|${user}\n"
                    echo "        <Item status=\"${status}\"><ResourceID>${user_display}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[user: ${user}, mfa_active: ${mfa_active}, password_enabled: ${password_enabled}, access_key_1_active: ${access_key_1_active}, access_key_2_active: ${access_key_2_active}]]></Evidence></Item>"
                fi
            done
        fi
        
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_040] 자격 증명 관리 설정 미흡
# [pism_041] 관리자 계정의 액세스 키 미삭제
check_pism_041() {
    local check_id="pism_041"
    local check_name="관리자 계정의 액세스 키 미삭제"
    {
        start_timer
        local summary_string=""
        local service="IAM_Root_Access_Key"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws iam get-credential-report]]></Command>"
        echo "      <Results>"
        if [ -z "$G_CREDENTIAL_REPORT" ]; then
            summary_string+="error|${service}|N/A\n"
            echo '        <Item status="error"><ResourceID>&lt;root_account&gt;</ResourceID><Detail>자격증명 보고서 생성 에러</Detail><Evidence><![CDATA[Credential report not available.]]></Evidence></Item>'
        else
            local ROOT_info=$(echo "$G_CREDENTIAL_REPORT" | grep "^<root_account>,")
            local KEY1_ACTIVE=$(echo "$ROOT_info" | cut -d, -f9)
            local KEY2_ACTIVE=$(echo "$ROOT_info" | cut -d, -f14)
            local status
            local detail
            
            if [ "$KEY1_ACTIVE" == "true" ] || [ "$KEY2_ACTIVE" == "true" ]; then
                status="bad"
                detail="관리자 계정에 활성화된 액세스 키 존재"
            else
                status="good"
                detail="관리자 계정에 활성화된 액세스 키 미존재"
            fi
            
            summary_string+="${status}|${service}|<root_account>\n"
            echo "        <Item status=\"${status}\"><ResourceID>&lt;root_account&gt;</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[access_key_1_active: ${KEY1_ACTIVE}, access_key_2_active: ${KEY2_ACTIVE}]]></Evidence></Item>"
        fi
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_042] 단일 계정 내 액세스 키 다중 발급
check_pism_042() {
    local check_id="pism_042"
    local check_name="단일 계정 내 액세스 키 다중 발급"
    {
        start_timer
        local summary_string=""
        local service="IAM_User_Access_Key"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws iam list-access-keys, aws iam list-users]]></Command>"
        echo "      <Results>"
        IAM_USERS=$(aws iam --no-verify-ssl list-users --query "Users[*].UserName" --output text 2>/dev/null)
        if [ -z "$IAM_USERS" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>IAM 사용자 미존재</Detail><Evidence><![CDATA[No IAM users found.]]></Evidence></Item>'
        else
            for user_name in $IAM_USERS; do
                # 사용자의 '전체(활성/비활성)' 액세스 키의 수를 직접 카운트
                TOTAL_KEY_COUNT=$(aws iam --no-verify-ssl list-access-keys --user-name "$user_name" --query "length(AccessKeyMetadata)" --output text 2>/dev/null)
                
                local status
                local detail

                if [ "$TOTAL_KEY_COUNT" -gt 1 ]; then
                    status="bad"
                    detail="하나의 IAM 사용자에 다중 액세스 키(활성/비활성 포함) 발급 확인"
                else
                    status="good"
                    detail="하나의 IAM 사용자에 단일 액세스 키 발급 확인"
                fi
                
                summary_string+="${status}|${service}|${user_name}\n"
                
                echo "        <Item status=\"${status}\">"
                echo "          <ResourceID>${user_name}</ResourceID>"
                echo "          <Detail>${detail}</Detail>"
                echo "          <TotalKeyCount>${TOTAL_KEY_COUNT}</TotalKeyCount>"
                echo "          <Evidence><![CDATA[User ${user_name} has ${TOTAL_KEY_COUNT} total access key(s).]]></Evidence>"
                echo "        </Item>"
            done
        fi
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_043] 액세스 키의 정기적 갱신 미이행
check_pism_043() {
    local check_id="pism_043"
    local check_name="액세스 키의 정기적 갱신 미이행"
    {
        start_timer
        local summary_string=""
        local service="IAM_AccessKey_Rotation"
        local ROTATION_THRESHOLD_DAYS=90
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws iam generate-credential-report, aws iam get-policy, aws iam get-policy-version]]></Command>"
        
        # Credential Report 상태 정보 추가
        echo "      <CredentialReportInfo>"
        if [ -z "$G_CREDENTIAL_REPORT" ]; then
            echo "        <Status>NotAvailable</Status>"
            echo "        <Detail>IAM Credential Report가 생성되지 않았습니다. 'aws iam generate-credential-report' 명령을 실행한 후 재점검하세요.</Detail>"
            echo "      </CredentialReportInfo>"
        else
            # Report 생성 시각 및 사용자 수 계산
            local USER_COUNT=$(echo "$G_CREDENTIAL_REPORT" | tail -n +2 | wc -l | tr -d ' ')
            echo "        <Status>Success</Status>"
            echo "        <Detail>Credential Report를 성공적으로 로드했습니다.</Detail>"
            echo "        <UserCount>${USER_COUNT}</UserCount>"
            echo "      </CredentialReportInfo>"
        fi
        
        echo "      <Results>"
        if [ -z "$G_CREDENTIAL_REPORT" ]; then
            summary_string+="error|${service}|N/A\n" 
            echo '        <Item status="error"><ResourceID>IAM Credential Report</ResourceID><Detail>자격증명 보고서 생성 에러 - 보고서가 없어 액세스 키 갱신 점검 불가</Detail><Evidence><![CDATA[Credential Report is not available. Run "aws iam generate-credential-report" first.]]></Evidence></Item>'
        else
            local NOW_EPOCH=$(date +%s); local ROTATION_SECONDS=$((ROTATION_THRESHOLD_DAYS * 86400))
            # 날짜를 epoch 초로 변환하는 함수 (macOS/Linux 호환)
            to_epoch() {
                local input_date=$1
                # Z를 +0000으로 바꿔 macOS date가 인식하게 함
                local sanitized_date=$(echo "$input_date" | sed 's/\(....-..-..T..:..:..\)Z/\1+0000/')
                if [[ "$OSTYPE" == "darwin"* ]]; then
                    date -j -f "%Y-%m-%dT%H:%M:%S%z" "$sanitized_date" "+%s" 2>/dev/null
                else
                    date -d "$input_date" "+%s" 2>/dev/null
                fi
            }
            while IFS=, read -r user arn uct pe plu plc pnr mfa ak1a ak1lr ak1lud ak1lur ak1lus ak2a ak2lr ak2lud ak2lur ak2lus cert1a cert1lr cert2a cert2lr; do
                if [ "$user" == "<root_account>" ]; then user_display="&lt;root_account&gt;"; else user_display=$user; fi
                
                if [ "$ak1a" == "true" ]; then
                    local resource_id="${user}-AccessKey1"
                    last_rotated_epoch=$(to_epoch "$ak1lr")
                    if [ -n "$last_rotated_epoch" ]; then
                        diff=$((NOW_EPOCH - last_rotated_epoch)); days_ago=$((diff / 86400))
                        if [ $diff -gt $ROTATION_SECONDS ]; then status="bad"; detail="액세스 키 1 마지막 갱신 후 ${days_ago}일 경과 (기준: ${ROTATION_THRESHOLD_DAYS}일 초과)";
                        else status="good"; detail="액세스 키 1 마지막 갱신 후 ${days_ago}일 경과 (기준: ${ROTATION_THRESHOLD_DAYS}일 이내)"; fi
                    else status="error"; detail="날짜 형식 변환 실패";
                    fi
                    summary_string+="${status}|${service}|${resource_id}\n" 
                    echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><User>${user_display}</User><Detail>${detail}</Detail><Evidence><![CDATA[access_key_1_last_rotated: ${ak1lr}]]></Evidence></Item>"
                fi
                if [ "$ak2a" == "true" ]; then
                    local resource_id="${user}-AccessKey2"
                    last_rotated_epoch=$(to_epoch "$ak2lr")
                    if [ -n "$last_rotated_epoch" ]; then
                        diff=$((NOW_EPOCH - last_rotated_epoch)); days_ago=$((diff / 86400))
                        if [ $diff -gt $ROTATION_SECONDS ]; then status="bad"; detail="액세스 키 2 마지막 갱신 후 ${days_ago}일 경과 (기준: ${ROTATION_THRESHOLD_DAYS}일 초과)";
                        else status="good"; detail="액세스 키 2 마지막 갱신 후 ${days_ago}일 경과 (기준: ${ROTATION_THRESHOLD_DAYS}일 이내)"; fi
                    else status="error"; detail="날짜 형식 변환 실패";
                    fi
                    summary_string+="${status}|${service}|${resource_id}\n" 
                    echo "        <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><User>${user_display}</User><Detail>${detail}</Detail><Evidence><![CDATA[access_key_2_last_rotated: ${ak2lr}]]></Evidence></Item>"
                fi
            done < <(echo "$G_CREDENTIAL_REPORT" | tail -n +2)
        fi
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

get_managed_policy_info() {
    local policy_name=$1
    local policy_arn=$2
    local indent=${3:-""}

    if [[ "$policy_arn" == arn:aws:iam::aws:policy/* ]]; then
        echo "${indent}PolicyName: ${policy_name}"
    else
        echo "${indent}PolicyName: ${policy_name}"
        version_id=$(aws iam --no-verify-ssl get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null)
        if [ -n "$version_id" ]; then
            policy_doc=$(aws iam --no-verify-ssl get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' 2>/dev/null)
            echo "${indent}PolicyDocument: ${policy_doc}"
        fi
    fi
}

# [pism_045_1] 그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용 (업무상 불필요한 권한 과다 부여)
check_pism_045_1() {
    local check_id="pism_045_1"
    local check_name="그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용 (업무상 불필요한 권한 과다 부여)"
    {
        start_timer
        local summary_string=""
        local service="IAM_Permissions"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws iam get-group-policy, aws iam get-user-policy, aws iam list-attached-group-policies, aws iam list-attached-user-policies, aws iam list-group-policies, aws iam list-groups-for-user, aws iam list-user-policies, aws iam list-users]]></Command>"
        echo "      <Results>"

        IAM_USERS=$(aws iam --no-verify-ssl list-users --query 'Users[*].UserName' --output text 2>/dev/null)
        if [ -z "$IAM_USERS" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>IAM 사용자 미존재</Detail><Evidence><![CDATA[No IAM users found.]]></Evidence></Item>'
        else
            for user_name in $IAM_USERS; do
                local evidence=""
                local status="review"

                local user_managed_policies_evidence
                user_managed_policies_evidence=$(
                    aws iam --no-verify-ssl list-attached-user-policies --user-name "$user_name" --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' --output text 2>/dev/null | while IFS=$'\t' read -r policy_name policy_arn; do
                        get_managed_policy_info "$policy_name" "$policy_arn" ""
                    done
                )

                local user_inline_policies_evidence
                user_inline_policies_evidence=$(
                    aws iam --no-verify-ssl list-user-policies --user-name "$user_name" --query 'PolicyNames' --output text 2>/dev/null | tr '\t' '\n' | while read -r policy_name; do
                        echo "PolicyName: ${policy_name} (Inline)"
                        policy_doc=$(aws iam --no-verify-ssl get-user-policy --user-name "$user_name" --policy-name "$policy_name" --query 'PolicyDocument' 2>/dev/null)
                        echo "PolicyDocument: ${policy_doc}"
                    done
                )

                local groups_evidence=""
                local user_groups=$(aws iam --no-verify-ssl list-groups-for-user --user-name "$user_name" --query 'Groups[*].GroupName' --output text 2>/dev/null | tr '\t' '\n')
                if [ -n "$user_groups" ]; then
                    groups_evidence=$'\n'"--- Policies from Group Memberships ---"$'\n'
                    groups_evidence+=$(
                        echo "$user_groups" | while read -r group_name; do
                            echo $'\n'"  -- Group [${group_name}] --"$'\n'
                            # 그룹 관리형 정책 (최적화 적용)
                            aws iam --no-verify-ssl list-attached-group-policies --group-name "$group_name" --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' --output text 2>/dev/null | while IFS=$'\t' read -r policy_name policy_arn; do
                                get_managed_policy_info "$policy_name" "$policy_arn" "  "
                            done
                            # 그룹 인라인 정책
                            aws iam --no-verify-ssl list-group-policies --group-name "$group_name" --query 'PolicyNames' --output text 2>/dev/null | tr '\t' '\n' | while read -r policy_name; do
                                echo "  Inline PolicyName: ${policy_name}"
                                policy_doc=$(aws iam --no-verify-ssl get-group-policy --group-name "$group_name" --policy-name "$policy_name" --query 'PolicyDocument' 2>/dev/null)
                                echo "  PolicyDocument: ${policy_doc}"
                            done
                        done
                    )
                fi

                evidence+=$'\n'"--- Directly Attached Managed Policies for [${user_name}] ---"$'\n'
                evidence+="${user_managed_policies_evidence:-"None"}"$'\n'
                evidence+=$'\n'"--- Directly Attached Inline Policies for [${user_name}] ---"$'\n'
                evidence+="${user_inline_policies_evidence:-"None"}"$'\n'
                evidence+="$groups_evidence"

                summary_string+="${status}|${service}|${user_name}\n"
                echo "        <Item status=\"${status}\">"
                echo "          <ResourceID>${user_name}</ResourceID>"
                echo "          <Detail>아래 증적(Evidence)을 확인하여 사용자에게 업무상 필요한 권한을 최소한으로 부여하고 있는지 점검</Detail>"
                printf '          <Evidence><![CDATA[%s]]></Evidence>\n' "$evidence"
                echo "        </Item>"
            done
        fi

        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_045_2] 그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용 (가상자원에 실행 역할 과다 부여)
check_pism_045_2() {
    local check_id="pism_045_2"
    local check_name="그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용 (가상자원에 실행 역할 과다 부여)"

    get_role_policies_evidence_detailed() {
        local role_name=$1
        local evidence=""

        evidence+=$'\n'"--- Attached Managed Policies for Role [${role_name}] ---"$'\n'
        local managed_policies_evidence
        managed_policies_evidence=$(
            aws iam --no-verify-ssl list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' --output text 2>/dev/null | while IFS=$'\t' read -r policy_name policy_arn; do
                if [[ "$policy_arn" == arn:aws:iam::aws:policy/* ]]; then
                    echo "Policy Name: ${policy_name}"
                else
                    echo "Policy Name: ${policy_name}"
                    local default_version_id=$(aws iam --no-verify-ssl get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null)
                    if [ -n "$default_version_id" ]; then
                        local policy_doc=$(aws iam --no-verify-ssl get-policy-version --policy-arn "$policy_arn" --version-id "$default_version_id" --query 'PolicyVersion.Document' --output json 2>/dev/null)
                        echo "Content:"
                        echo "${policy_doc}"
                    fi
                fi
                echo "--------------------"
            done
        )
        evidence+="${managed_policies_evidence:-"None"}"

        evidence+=$'\n\n'"--- Inline Policies for Role [${role_name}] ---"$'\n'
        local inline_policies_evidence
        inline_policies_evidence=$(
            aws iam --no-verify-ssl list-role-policies --role-name "$role_name" --query 'PolicyNames' --output text 2>/dev/null | tr '\t' '\n' | while read -r policy_name; do
                echo "Policy Name: ${policy_name}"
                local policy_doc=$(aws iam --no-verify-ssl get-role-policy --role-name "$role_name" --policy-name "$policy_name" --query 'PolicyDocument' --output json 2>/dev/null)
                echo "Content:"
                echo "${policy_doc}"
                echo "--------------------"
            done
        )
        evidence+="${inline_policies_evidence:-"None"}"

        echo -e "$evidence"
    }

    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws ec2 describe-instances, aws iam get-instance-profile, aws iam get-policy, aws iam get-policy-version, aws iam get-role-policy, aws iam list-attached-role-policies, aws iam list-role-policies, aws lambda list-functions]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Lambda ---
        echo '        <SubCheck service="Lambda_Role_Permissions">'
        local service="Lambda_Role_Permissions"
        LAMBDA_FUNCTIONS=$(aws lambda --no-verify-ssl list-functions --query "Functions[*].[FunctionName,Role]" --output text 2>/dev/null)
        if [ -z "$LAMBDA_FUNCTIONS" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 Lambda 함수가 없습니다.</Detail></Item>'
        else
            while read -r func_name role_arn; do
                local role_name=$(echo "$role_arn" | awk -F/ '{print $NF}')
                local policies_evidence=$(get_role_policies_evidence_detailed "$role_name")
                local status="review"

                summary_string+="${status}|${service}|${func_name}\n"
                echo "        <Item status=\"${status}\">"
                echo "          <ResourceID>${func_name}</ResourceID>"
                echo "          <Detail>Lambda 함수에 연결된 실행 역할(${role_name})의 권한 상세 내용. 기능 수행에 필요한 최소한의 권한 부여 여부를 점검</Detail>"
                printf '          <Evidence><![CDATA[%s]]></Evidence>\n' "$policies_evidence"
                echo "        </Item>"
            done <<< "$LAMBDA_FUNCTIONS"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: EC2 ---
        echo '        <SubCheck service="EC2_Role_Permissions">'
        local service="EC2_Role_Permissions"
        EC2_INSTANCES=$(aws ec2 --no-verify-ssl describe-instances --filters "Name=instance-state-name,Values=running,pending,stopped,stopping" --query "Reservations[*].Instances[*].[InstanceId,IamInstanceProfile.Arn]" --output text 2>/dev/null)
        if [ -z "$EC2_INSTANCES" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>EC2 인스턴스 미존재</Detail></Item>'
        else
            while read -r instance_id profile_arn; do
                if [ "$profile_arn" == "None" ] || [ -z "$profile_arn" ]; then
                    summary_string+="good|${service}|${instance_id}\n"
                    echo "        <Item status=\"good\"><ResourceID>${instance_id}</ResourceID><Detail>EC2 인스턴스에 연결된 IAM 역할 미존재</Detail><Evidence></Evidence></Item>"
                else
                    local profile_name=$(echo "$profile_arn" | awk -F/ '{print $NF}')
                    local role_name=$(aws iam --no-verify-ssl get-instance-profile --instance-profile-name "$profile_name" --query "InstanceProfile.Roles[0].RoleName" --output text 2>/dev/null)
                    
                    if [ -n "$role_name" ]; then
                        local policies_evidence=$(get_role_policies_evidence_detailed "$role_name")
                        local status="review"
                        summary_string+="${status}|${service}|${instance_id}\n"
                        echo "        <Item status=\"${status}\">"
                        echo "          <ResourceID>${instance_id}</ResourceID>"
                        echo "          <Detail>EC2 인스턴스에 연결된 실행 역할(${role_name})의 권한 상세 내용. 기능 수행에 필요한 최소한의 권한 부여 여부를 점검</Detail>"
                        printf '          <Evidence><![CDATA[%s]]></Evidence>\n' "$policies_evidence"
                        echo "        </Item>"
                    else
                        local status="info"
                        summary_string+="${status}|${service}|${instance_id}\n"
                        echo "        <Item status=\"${status}\"><ResourceID>${instance_id}</ResourceID><Detail>인스턴스 프로파일(${profile_name})에 연결된 역할 미존재</Detail><Evidence></Evidence></Item>"
                    fi
                fi
            done <<< "$EC2_INSTANCES"
        fi
        echo '        </SubCheck>'

        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_045_3] 그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용 (가상자원 호출 권한 과다 부여)
check_pism_045_3() {
    local check_id="pism_045_3"
    local check_name="그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용 (가상자원 호출 권한 과다 부여)"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws lambda get-policy, aws lambda list-functions, aws s3api get-bucket-policy, aws s3api list-buckets]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Lambda ---
        echo '        <SubCheck service="Lambda_Resource_Policy">'
        local service="Lambda_Resource_Policy"
        LAMBDA_FUNCTIONS=$(aws lambda --no-verify-ssl list-functions --query "Functions[*].FunctionName" --output text 2>/dev/null)
        if [ -z "$LAMBDA_FUNCTIONS" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>Lambda 함수 미존재</Detail></Item>'
        else
            while read -r func_name; do
                if [ -z "$func_name" ]; then continue; fi
                
                local status; local detail; local evidence
                policy_json=$(aws lambda --no-verify-ssl get-policy --function-name "$func_name" --output json 2>/dev/null)
                local policy_doc=$(echo "$policy_json" | tr -d '\n\r' | sed -e 's/.*"Policy":"//' -e 's/"}$//' | sed -e 's/\\n/\n/g' -e 's/\\"/"/g')

                if [ -z "$policy_doc" ]; then
                    status="good"
                    detail="리소스 기반 정책이 없어 호출 권한이 계정 내 IAM Principal로 제한"
                    evidence="No resource-based policy found."
                else
                    evidence=$(echo "$policy_doc" | sed -e 's/{/{\n  /g' -e 's/}/ \n}/g' -e 's/,/,\n  /g')
                    if echo "$policy_doc" | tr -d ' \n' | grep -q -e '"Principal":"\*"' -e '"Principal":{"AWS":"\*"'; then
                        status="bad"
                        detail="리소스 기반 정책의 Principal이 와일드카드('*')로 설정되어, 불특정 다수에게 호출 권한 부여"
                    else
                        status="review"
                        detail="리소스 기반 정책이 존재. 업무상 필요한 권한인지 Principal 및 Condition 항목 검토"
                    fi
                fi
                summary_string+="${status}|${service}|${func_name}\n"
                echo "        <Item status=\"${status}\"><ResourceID>${func_name}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
            done < <(echo "$LAMBDA_FUNCTIONS" | tr '\t' '\n')
        fi
        echo '        </SubCheck>'

        # --- SubCheck: S3 ---
        echo '        <SubCheck service="S3_Resource_Policy">'
        local service="S3_Resource_Policy"
        S3_BUCKETS=$(aws s3api --no-verify-ssl list-buckets --query "Buckets[*].Name" --output text 2>/dev/null)
        if [ -z "$S3_BUCKETS" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>S3 버킷 미존재</Detail></Item>'
        else
            while read -r bucket_name; do
                if [ -z "$bucket_name" ]; then continue; fi
                
                local status; local detail; local evidence
                policy_json=$(aws s3api --no-verify-ssl get-bucket-policy --bucket "$bucket_name" --output json 2>/dev/null)
                local policy_doc=$(echo "$policy_json" | tr -d '\n\r' | sed -e 's/.*"Policy":"//' -e 's/"}$//' | sed -e 's/\\n/\n/g' -e 's/\\"/"/g')

                if [ -z "$policy_doc" ]; then
                    status="good"
                    detail="버킷 정책이 없어 Public Access Block 설정 및 ACL에 따라 접근 제어"
                    evidence="No bucket policy found."
                else
                    evidence=$(format_json "$policy_doc") 
                    statements=$(echo "$policy_doc" | tr -d ' \n\t' | sed 's/},{/}\n{/g')
                    if echo "$statements" | grep '"Effect":"Allow"' | grep -q -e '"Principal":"\*"' -e '"Principal":{"AWS":"\*"'; then
                        status="bad"
                        detail="버킷 정책에 'Allow'와 'Principal:*'가 함께 사용되어 퍼블릭 액세스 허용"
                    else
                        if echo "$policy_doc" | tr -d ' \n' | grep -q '"Effect":"Deny"' && echo "$policy_doc" | tr -d ' \n' | grep -q '"aws:SecureTransport":"false"'; then
                            status="good"
                            detail="버킷 정책이 존재하나, HTTPS 강제 적용을 위한 보안 정책으로 확인됨."
                        else
                            status="review"
                            detail="버킷 정책 존재. 'Principal'이 '*'인 Public 'Allow' 정책은 없음. 세부 권한 검토 필요."
                        fi
                    fi
                fi
                summary_string+="${status}|${service}|${bucket_name}\n"
                echo "        <Item status=\"${status}\"><ResourceID>${bucket_name}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
            done < <(echo "$S3_BUCKETS" | tr '\t' '\n')
        fi
        echo '        </SubCheck>'

        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_046] 웹 기반 쉘 환경에 권한 과다 부여
check_pism_046() {
    local check_id="pism_046"
    local check_name="웹 기반 쉘 환경에 권한 과다 부여"
    {
        start_timer
        local summary_string=""
        local service="IAM_CloudShell_Access"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws iam list-roles, aws iam list-users, aws iam simulate-principal-policy]]></Command>"
        echo "      <Results>"
        
        # 계정의 모든 사용자 및 역할의 ARN을 수집
        local user_arns=$(aws iam --no-verify-ssl list-users --query 'Users[*].Arn' --output text 2>/dev/null)
        local role_arns=$(aws iam --no-verify-ssl list-roles --query 'Roles[*].Arn' --output text 2>/dev/null)
        local principals="$user_arns $role_arns"

        if [ -z "$principals" ]; then
            summary_string+="info|${service}|N/A\n"
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>IAM 사용자나 역할 미존재</Detail><Evidence><![CDATA[No IAM users or roles found.]]></Evidence></Item>'
        else
            local found_count=0
            for principal_arn in $principals; do
                if [ -z "$principal_arn" ]; then continue; fi
                
                # 각 principal이 CloudShell 세션을 생성할 수 있는지 시뮬레이션
                sim_result=$(aws iam --no-verify-ssl simulate-principal-policy --policy-source-arn "$principal_arn" --action-names "cloudshell:CreateSession" 2>/dev/null)
                
                # 시뮬레이션 결과가 'allowed'인 경우에만 결과에 포함
                if echo "$sim_result" | grep -q '"EvalDecision": "allowed"'; then
                    found_count=$((found_count + 1))
                    principal_name=$(echo "$principal_arn" | awk -F'/' '{print $NF}')
                    local status="review"
                    
                    summary_string+="${status}|${service}|${principal_name}\n"
                    
                    echo "        <Item status=\"${status}\">"
                    echo "          <ResourceID>${principal_name}</ResourceID>"
                    echo "          <PrincipalARN>${principal_arn}</PrincipalARN>"
                    echo "          <Detail>이 principal은 CloudShell 사용 권한(세션 연결 권한)을 보유하고 있으므로 적절성 검토 필요</Detail>"
                    printf '          <Evidence><![CDATA[Simulation for "cloudshell:CreateSession" was "allowed". Full simulation result:\n%s]]></Evidence>\n' "$sim_result"
                    echo "        </Item>"
                fi
            done

            if [ "$found_count" -eq 0 ]; then
                summary_string+="good|${service}|All Principals\n"
                echo '        <Item status="good"><ResourceID>All Users and Roles</ResourceID><Detail>CloudShell 사용 권한을 가진 사용자와 역할 미탐지</Detail><Evidence><![CDATA[No principals found with cloudshell:CreateSession permission.]]></Evidence></Item>'
            fi
        fi
        
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_060] 실행 코드 무결성 검증 절차 미흡
check_pism_060() {
    local check_id="pism_060"
    local check_name="실행 코드 무결성 검증 절차 미흡"
    {
        start_timer
        local summary_string=""
        local service="Lambda_CodeSigning"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws lambda get-code-signing-config, aws lambda get-function-code-signing-config, aws lambda list-functions]]></Command>"
        echo "      <Results>"
        
        LAMBDA_FUNCTIONS=$(aws lambda --no-verify-ssl list-functions --query "Functions[*].FunctionName" --output text 2>/dev/null)
        if [ -z "$LAMBDA_FUNCTIONS" ]; then
            summary_string+="info|${service}|N/A\n" 
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 Lambda 함수가 없습니다.</Detail></Item>'
        else
            while read -r func_name; do
                if [ -z "$func_name" ]; then continue; fi
                
                local status; local detail; local evidence;
                csc_arn=$(aws lambda --no-verify-ssl get-function-code-signing-config --function-name "$func_name" --query "CodeSigningConfigArn" --output text 2>/dev/null)
                
                if [ -z "$csc_arn" ] || [ "$csc_arn" == "None" ]; then
                    status="bad"
                    detail="코드 서명 기능 비활성화"
                    evidence="No Code Signing Config found for this function."
                else
                    policy=$(aws lambda --no-verify-ssl get-code-signing-config --code-signing-config-arn "$csc_arn" --query "CodeSigningConfig.CodeSigningPolicies.UntrustedArtifactOnDeployment" --output text 2>/dev/null)
                    evidence="CodeSigningConfigArn: ${csc_arn}\nUntrustedArtifactOnDeployment: ${policy}"
                    
                    if [ "$policy" == "Enforce" ]; then
                        status="good"
                        detail="코드 서명 정책이 'Enforce'로 설정되어 무결성을 검증"
                    else
                        status="bad"
                        detail="코드 서명 정책이 '${policy:-Warn}'으로 설정되어, 서명되지 않은 코드 배포 허용"
                    fi
                fi
                summary_string+="${status}|${service}|${func_name}\n" 
                echo "        <Item status=\"${status}\"><ResourceID>${func_name}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
            done < <(echo "$LAMBDA_FUNCTIONS" | tr '\t' '\n')
        fi
        
        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism_064] 컴퓨팅 인스턴스에서 IMDSv1 비활성화
check_pism_064() {
    local check_id="pism_064"
    local check_name="컴퓨팅 인스턴스에서 IMDSv1 비활성화"
    {
        start_timer
        local summary_string=""
        local service="EC2_IMDSv1"
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[aws ec2 describe-instances]]></Command>"
        echo "      <Results>"
        
        INSTANCES=$(aws ec2 --no-verify-ssl describe-instances --query "Reservations[*].Instances[*].[InstanceId,State.Name,MetadataOptions.HttpTokens]" --output text 2>/dev/null)
        
        if [ -z "$INSTANCES" ]; then
            summary_string+="info|${service}|N/A\n" 
            echo '        <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 EC2 인스턴스 미존재</Detail></Item>'
        else
            while read -r instance_id instance_state http_tokens; do
                if [ -z "$instance_id" ]; then continue; fi
                
                local status; local detail;
                if [ "$http_tokens" == "required" ]; then
                    status="good"
                    detail="IMDSv2 사용이 강제(required)되어 IMDSv1 사용 불가"
                else # 'optional' 이거나, 설정값이 없어 'None'으로 나오는 경우 모두 포함
                    status="bad"
                    detail="IMDSv1 사용 허용(${http_tokens:-기본값})"
                fi
                summary_string+="${status}|${service}|${instance_id}\n" 
                echo "        <Item status=\"${status}\"><ResourceID>${instance_id}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[State: ${instance_state}, HttpTokens: ${http_tokens:-optional (default)}]]></Evidence></Item>"
            done <<< "$INSTANCES"
        fi
        
        echo "      </Results>"
        print_summary "$summary_string" 
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# --- [3] 메인 실행부 ---
targets=(
    "check_pism_001" # 통신구간 암호화 미적용
    "check_pism_005" # 가상자원에 대한 퍼블릭 액세스 허용
    "check_pism_007" # 네트워크 접근 제어 설정의 최소 권한 적용
    "check_pism_013" # 접근 로그 수집 기능 비활성화
    "check_pism_017" # 삭제된 저장소 복원 기능 비활성화
    "check_pism_023" # 업무상 불필요한 가상자원 존재
    "check_pism_025" # 지원이 중단(EOS)된 런타임 사용
    "check_pism_030" # 디스크 볼륨 생성 시 암호화 설정 비활성화
    "check_pism_031" # 디스크 볼륨 암호화 미적용
    "check_pism_032" # 스냅샷 암호화 미적용
    "check_pism_033" # 이미지 암호화 미적용
    "check_pism_034" # DB 인스턴스 암호화 미적용
    "check_pism_036" # 환경변수 내 중요정보 암호화 미적용
    "check_pism_037_1" # 비밀번호 정책 수립 및 로그인 제한 설정 (비밀번호 복잡도 설정 확인)
    "check_pism_037_2" # 비밀번호 정책 수립 및 로그인 제한 설정 (비밀번호 재사용 방지 확인)
    "check_pism_039" # 클라우드 자원에 접근 가능한 계정에 추가인증수단 미적용
    "check_pism_041" # 관리자 계정의 액세스 키 삭제 여부
    "check_pism_042" # 단일 계정 내 액세스 키 다중 발급
    "check_pism_043" # 액세스 키의 정기적 갱신 미이행
    "check_pism_045_1" # 그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용 (업무상 불필요한 권한 과다 부여)
    "check_pism_045_2" # 그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용 (가상자원에 실행 역할 과다 부여)
    "check_pism_045_3" # 그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용 (가상자원 호출 권한 과다 부여)
    "check_pism_046" # 웹 기반 쉘 환경에 권한 과다 부여
    "check_pism_060" # 실행 코드 무결성 검증 절차 미흡
    "check_pism_064" # 컴퓨팅 인스턴스에서 IMDSv1 비활성화
)

echo "[INFO] 점검을 시작합니다. 총 ${#targets[@]}개 항목."
echo "[INFO] 결과는 ${OUTFILE} 파일에 저장됩니다."

for check_function in "${targets[@]}"; do
    echo "[RUNNING] -> ${check_function}"
    "$check_function"
done


# --- [4] 최종 마무리 ---

# 총 소요 시간 계산
TOTAL_END_TIME=$(date +%s)
TOTAL_END_TIME_STR=$(date '+%Y-%m-%d %H:%M:%S')
TOTAL_DURATION=$((TOTAL_END_TIME - TOTAL_START_TIME))

echo '  </CheckList>' >> "$OUTFILE"
# 총 소요 시간 출력 추가
echo "  <TotalExecutionTime>" >> "$OUTFILE"
echo "    <StartTime>${TOTAL_START_TIME_STR}</StartTime>" >> "$OUTFILE"
echo "    <EndTime>${TOTAL_END_TIME_STR}</EndTime>" >> "$OUTFILE"
echo "    <TotalDurationSecs>${TOTAL_DURATION}</TotalDurationSecs>" >> "$OUTFILE"
echo "  </TotalExecutionTime>" >> "$OUTFILE"
echo '</AuditReport>' >> "$OUTFILE"


echo ""
echo "##############################"
echo "# 점검 완료."
echo "# 점검 시작 시간: ${TOTAL_START_TIME_STR}"
echo "# 점검 종료 시간: ${TOTAL_END_TIME_STR}"
echo "# 소요 시간(초): ${TOTAL_DURATION}"
echo "# 결과 확인: ${OUTFILE}"
echo "##############################"

exit 0