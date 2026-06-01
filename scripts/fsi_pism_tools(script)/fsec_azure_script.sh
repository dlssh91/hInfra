#!/bin/bash

#################################################################
# 금융보안원 퍼블릭 클라우드(Azure) 취약점 분석 스크립트
# 최종 수정: 2025-12-30
#################################################################

# SSL 인증서 검증 비활성화 (인터넷이 제한된 환경에서 사용)
# 필요 시 아래 주석을 해제하여 활성화
# export AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=1

# --- [0] Azure 자격 증명(Service Principal) 입력 ---
echo "Azure Service Principal 자격 증명을 입력하세요."
read -p "Application (client) ID: " AZURE_CLIENT_ID
read -sp "Client Secret: " AZURE_CLIENT_SECRET
echo "" # 비밀번호 입력 후 줄바꿈
read -p "Directory (tenant) ID: " AZURE_TENANT_ID
read -p "Subscription ID: " AZURE_SUBSCRIPTION_ID

# 필수 값이 비어있는지 확인
if [ -z "$AZURE_CLIENT_ID" ] || [ -z "$AZURE_CLIENT_SECRET" ] || [ -z "$AZURE_TENANT_ID" ] || [ -z "$AZURE_SUBSCRIPTION_ID" ]; then
    echo "[ERROR] Client ID, Client Secret, Tenant ID, Subscription ID는 필수 입력값입니다. 스크립트를 종료합니다."
    exit 1
fi

# 입력받은 정보로 Azure에 로그인
echo "[INFO] 입력된 자격 증명으로 Azure에 로그인합니다."
az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "[ERROR] Azure 로그인이 실패했습니다. 자격 증명을 확인하세요."
    exit 1
fi

# 지정된 구독으로 컨텍스트 변경
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
if [ $? -ne 0 ]; then
    echo "[ERROR] 구독(Subscription)을 찾을 수 없거나 접근 권한이 없습니다."
    exit 1
fi

# -o tsv 옵션을 사용하여 탭으로 구분된 값으로 받음
ACCOUNT_INFO=$(az account show --query "[name, user.name]" -o tsv)
SUB_NAME=$(echo "$ACCOUNT_INFO" | head -n 1)
SP_CLIENT_ID=$(echo "$ACCOUNT_INFO" | tail -n 1)

# Service Principal의 실제 이름 조회 (이메일 형식이 포함될 수 있음)
SP_NAME=$(az ad sp show --id "$SP_CLIENT_ID" --query "displayName" -o tsv 2>/dev/null)
if [ -z "$SP_NAME" ]; then
    # displayName이 없으면 appDisplayName 시도
    SP_NAME=$(az ad sp show --id "$SP_CLIENT_ID" --query "appDisplayName" -o tsv 2>/dev/null)
fi
if [ -z "$SP_NAME" ]; then
    # 그래도 없으면 client ID 사용
    SP_NAME="$SP_CLIENT_ID"
fi

echo "[INFO] 로그인 성공. 점검을 시작합니다."
echo "       - Subscription: ${SUB_NAME}"
echo "       - Service Principal: ${SP_NAME}"
echo "--------------------------------------------------------"


# --- [1] 설정 및 초기화 ---
DATE=$(date +%Y%m%d_%H%M%S)
OUTFILE="azure_report_${DATE}_${SP_NAME}.xml"

# 전체 시작 시간 기록
TOTAL_START_TIME=$(date +%s)
TOTAL_START_TIME_STR=$(date '+%Y-%m-%d %H:%M:%S')

# 스크립트 실행 시 XML 파일의 최상단 루트 요소를 생성합니다.
echo '<?xml version="1.0" encoding="UTF-8"?>' > "$OUTFILE"
echo '<AuditReport>' >> "$OUTFILE"
echo "  <Timestamp>$(date -u +"%Y-%m-%dT%H:%M:%SZ")</Timestamp>" >> "$OUTFILE"
echo '  <CheckList>' >> "$OUTFILE"


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

# Summary 섹션 생성 (AWS 스타일)
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

# JSON 포맷팅 함수 (가독성 향상)
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

# [pism-001] 통신구간 암호화 미적용
check_pism_001() {
    local check_id="pism-001"
    local check_name="통신구간 암호화 미적용"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az functionapp list, az functionapp show, az mysql flexible-server list, az mysql flexible-server parameter show, az postgres flexible-server list, az postgres flexible-server parameter show, az storage account list, az storage account show]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Functions ---
        echo '        <SubCheck service="Functions">'
        FUNCTION_APPS_INFO=$(az functionapp list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$FUNCTION_APPS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 함수 앱 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r APP_NAME RESOURCE_GROUP; do
                if [ -z "$APP_NAME" ]; then continue; fi
                ERROR_MSG=$(mktemp)
                HTTPS_ONLY_STATUS=$(az functionapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "properties.httpsOnly" --output tsv 2>"$ERROR_MSG" | tr '[:upper:]' '[:lower:]')
                CMD_EXIT_CODE=$?
                if [ $CMD_EXIT_CODE -ne 0 ]; then
                    status="error"; detail="함수 앱 설정 확인 불가 (권한 부족 또는 리소스 상태 확인 필요)"
                    ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                    summary_string+="error|Functions|${APP_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
                elif [ "$HTTPS_ONLY_STATUS" == "true" ]; then
                    status="good"; detail="HTTPS만 사용 설정 활성화"
                    summary_string+="good|Functions|${APP_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[httpsOnly: ${HTTPS_ONLY_STATUS}]]></Evidence></Item>"
                else
                    status="bad"; detail="HTTPS만 사용 설정 비활성화"
                    summary_string+="bad|Functions|${APP_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[httpsOnly: ${HTTPS_ONLY_STATUS}]]></Evidence></Item>"
                fi
                rm -f "$ERROR_MSG"
            done <<< "$FUNCTION_APPS_INFO"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Blob Storage ---
        echo '        <SubCheck service="BlobStorage">'
        STORAGE_ACCOUNTS_INFO=$(az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$STORAGE_ACCOUNTS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 스토리지 계정 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r ACCOUNT_NAME RESOURCE_GROUP; do
                if [ -z "$ACCOUNT_NAME" ]; then continue; fi
                ERROR_MSG=$(mktemp)
                HTTPS_TRAFFIC_ONLY_STATUS=$(az storage account show --name "$ACCOUNT_NAME" --resource-group "$RESOURCE_GROUP" --query "enableHttpsTrafficOnly" --output tsv 2>"$ERROR_MSG" | tr '[:upper:]' '[:lower:]')
                CMD_EXIT_CODE=$?
                if [ $CMD_EXIT_CODE -ne 0 ]; then
                    status="error"; detail="스토리지 계정 설정 확인 불가 (권한 부족 또는 리소스 상태 확인 필요)"
                    ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                    summary_string+="error|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
                elif [ "$HTTPS_TRAFFIC_ONLY_STATUS" == "true" ]; then
                    status="good"; detail="보안 전송 설정 활성화"
                    summary_string+="good|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[enableHttpsTrafficOnly: ${HTTPS_TRAFFIC_ONLY_STATUS}]]></Evidence></Item>"
                else
                    status="bad"; detail="보안 전송 설정 비활성화"
                    summary_string+="bad|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[enableHttpsTrafficOnly: ${HTTPS_TRAFFIC_ONLY_STATUS}]]></Evidence></Item>"
                fi
                rm -f "$ERROR_MSG"
            done <<< "$STORAGE_ACCOUNTS_INFO"
        fi
        echo '        </SubCheck>'
        
        # --- SubCheck: Database (MySQL Flexible Server) ---
        echo '        <SubCheck service="MySQLFlexibleServer">'
        MYSQL_SERVERS_INFO=$(az mysql flexible-server list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$MYSQL_SERVERS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 MySQL Flexible Server 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r SERVER_NAME RESOURCE_GROUP; do
                if [ -z "$SERVER_NAME" ]; then continue; fi
                ERROR_MSG=$(mktemp)
                SECURE_TRANSPORT_STATUS=$(az mysql flexible-server parameter show --resource-group "$RESOURCE_GROUP" --server-name "$SERVER_NAME" --name require_secure_transport --query "value" --output tsv 2>"$ERROR_MSG")
                CMD_EXIT_CODE=$?
                if [ $CMD_EXIT_CODE -ne 0 ]; then
                    status="error"; detail="서버 파라미터 확인 불가 (권한 부족 또는 서버 상태 확인 필요)"
                    ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                    summary_string+="error|MySQLFlexibleServer|${SERVER_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${SERVER_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
                elif [ "$SECURE_TRANSPORT_STATUS" == "ON" ]; then
                    status="good"; detail="보안 전송 설정 활성화"
                    summary_string+="good|MySQLFlexibleServer|${SERVER_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${SERVER_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[require_secure_transport: ${SECURE_TRANSPORT_STATUS}]]></Evidence></Item>"
                else
                    status="bad"; detail="보안 전송 필요 설정 비활성화"
                    summary_string+="bad|MySQLFlexibleServer|${SERVER_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${SERVER_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[require_secure_transport: ${SECURE_TRANSPORT_STATUS}]]></Evidence></Item>"
                fi
                rm -f "$ERROR_MSG"
            done <<< "$MYSQL_SERVERS_INFO"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Database (PostgreSQL Flexible Server) ---
        echo '        <SubCheck service="PostgreSQLFlexibleServer">'
        POSTGRES_SERVERS_INFO=$(az postgres flexible-server list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$POSTGRES_SERVERS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 PostgreSQL Flexible Server 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r SERVER_NAME RESOURCE_GROUP; do
                if [ -z "$SERVER_NAME" ]; then continue; fi
                ERROR_MSG=$(mktemp)
                SECURE_TRANSPORT_STATUS=$(az postgres flexible-server parameter show --resource-group "$RESOURCE_GROUP" --server-name "$SERVER_NAME" --name require_secure_transport --query "value" --output tsv 2>"$ERROR_MSG" | tr '[:upper:]' '[:lower:]')
                CMD_EXIT_CODE=$?
                if [ $CMD_EXIT_CODE -ne 0 ]; then
                    status="error"; detail="서버 파라미터 확인 불가 (권한 부족 또는 서버 상태 확인 필요)"
                    ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                    summary_string+="error|PostgreSQLFlexibleServer|${SERVER_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${SERVER_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
                elif [ "$SECURE_TRANSPORT_STATUS" == "on" ]; then
                    status="good"; detail="보안 전송 설정 활성화"
                    summary_string+="good|PostgreSQLFlexibleServer|${SERVER_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${SERVER_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[require_secure_transport: ${SECURE_TRANSPORT_STATUS}]]></Evidence></Item>"
                else
                    status="bad"; detail="보안 전송 설정 비활성화"
                    summary_string+="bad|PostgreSQLFlexibleServer|${SERVER_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${SERVER_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[require_secure_transport: ${SECURE_TRANSPORT_STATUS}]]></Evidence></Item>"
                fi
                rm -f "$ERROR_MSG"
            done <<< "$POSTGRES_SERVERS_INFO"
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-002] 취약한 HTTPS 프로토콜 허용
check_pism_002() {
    local check_id="pism-002"
    local check_name="취약한 HTTPS 프로토콜 허용"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az functionapp config show, az functionapp list, az storage account list, az storage account show]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Functions ---
        echo '        <SubCheck service="Functions">'
        FUNCTION_APPS_INFO=$(az functionapp list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$FUNCTION_APPS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 함수 앱 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r APP_NAME RESOURCE_GROUP; do
                if [ -z "$APP_NAME" ]; then continue; fi
                ERROR_MSG=$(mktemp)
                MIN_TLS_VERSION=$(az functionapp config show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "minTlsVersion" --output tsv 2>"$ERROR_MSG")
                CMD_EXIT_CODE=$?
                if [ $CMD_EXIT_CODE -ne 0 ]; then
                    status="error"; detail="함수 앱 설정 확인 불가 (권한 부족 또는 리소스 상태 확인 필요)"
                    ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                    summary_string+="error|Functions|${APP_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
                elif [ "$MIN_TLS_VERSION" == "1.2" ]; then
                    status="good"; detail="최소 TLS 버전 1.2로 설정"
                    summary_string+="good|Functions|${APP_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[minTlsVersion: ${MIN_TLS_VERSION}]]></Evidence></Item>"
                else
                    status="bad"; detail="최소 TLS 버전 1.2 미만(${MIN_TLS_VERSION})으로 설정"
                    summary_string+="bad|Functions|${APP_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[minTlsVersion: ${MIN_TLS_VERSION}]]></Evidence></Item>"
                fi
                rm -f "$ERROR_MSG"
            done <<< "$FUNCTION_APPS_INFO"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Blob Storage ---
        echo '        <SubCheck service="BlobStorage">'
        STORAGE_ACCOUNTS_INFO=$(az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$STORAGE_ACCOUNTS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 스토리지 계정 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r ACCOUNT_NAME RESOURCE_GROUP; do
                if [ -z "$ACCOUNT_NAME" ]; then continue; fi
                ERROR_MSG=$(mktemp)
                MIN_TLS_VERSION=$(az storage account show --name "$ACCOUNT_NAME" --resource-group "$RESOURCE_GROUP" --query "minimumTlsVersion" --output tsv 2>"$ERROR_MSG")
                CMD_EXIT_CODE=$?
                if [ $CMD_EXIT_CODE -ne 0 ]; then
                    status="error"; detail="스토리지 계정 설정 확인 불가 (권한 부족 또는 리소스 상태 확인 필요)"
                    ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                    summary_string+="error|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
                elif [ "$MIN_TLS_VERSION" == "TLS1_2" ]; then
                    status="good"; detail="최소 TLS 버전 1.2로 설정"
                    summary_string+="good|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[minimumTlsVersion: ${MIN_TLS_VERSION}]]></Evidence></Item>"
                else
                    status="bad"; detail="최소 TLS 버전 1.2 미만(${MIN_TLS_VERSION})으로 설정"
                    summary_string+="bad|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[minimumTlsVersion: ${MIN_TLS_VERSION}]]></Evidence></Item>"
                fi
                rm -f "$ERROR_MSG"
            done <<< "$STORAGE_ACCOUNTS_INFO"
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-003] 앱 배포 시 취약한 프로토콜 허용
check_pism_003() {
    local check_id="pism-003"
    local check_name="앱 배포 시 취약한 프로토콜 허용"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az functionapp config show, az functionapp list]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Functions ---
        echo '        <SubCheck service="Functions">'
        FUNCTION_APPS_INFO=$(az functionapp list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$FUNCTION_APPS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 함수 앱 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r APP_NAME RESOURCE_GROUP; do
                if [ -z "$APP_NAME" ]; then continue; fi
                ERROR_MSG=$(mktemp)
                FTPS_STATE=$(az functionapp config show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "ftpsState" --output tsv 2>"$ERROR_MSG")
                CMD_EXIT_CODE=$?

                if [ $CMD_EXIT_CODE -ne 0 ]; then
                    status="error"; detail="함수 앱 설정 확인 불가 (권한 부족 또는 리소스 상태 확인 필요)"
                    ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                    summary_string+="error|Functions|${APP_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}]]></Evidence></Item>"
                elif [ "$FTPS_STATE" == "AllAllowed" ]; then
                    status="bad"; detail="FTP/FTPS 배포 모두 허용"
                    summary_string+="bad|Functions|${APP_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[ftpsState: ${FTPS_STATE}]]></Evidence></Item>"
                else
                    status="good"; detail="FTP 배포 비활성화 (${FTPS_STATE})"
                    summary_string+="good|Functions|${APP_NAME}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[ftpsState: ${FTPS_STATE}]]></Evidence></Item>"
                fi
                rm -f "$ERROR_MSG"
            done <<< "$FUNCTION_APPS_INFO"
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-005] 가상자원에 대한 퍼블릭 액세스 허용
check_pism_005() {
    local check_id="pism-005"
    local check_name="가상자원에 대한 퍼블릭 액세스 허용"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az functionapp config access-restriction show, az functionapp list, az functionapp show, az storage account list, az storage account show, az storage container list, az vm list]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Functions ---
        echo '        <SubCheck service="Functions">'
        FUNCTION_APPS_INFO=$(az functionapp list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$FUNCTION_APPS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 함수 앱 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r APP_NAME RESOURCE_GROUP; do
                if [ -z "$APP_NAME" ]; then continue; fi
                local status=""; local detail=""; local evidence=""
                ERROR_MSG=$(mktemp)
                PUBLIC_ACCESS=$(az functionapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "properties.publicNetworkAccess" --output tsv 2>"$ERROR_MSG")
                CMD_EXIT_CODE=$?

                if [ $CMD_EXIT_CODE -ne 0 ] || [ -z "$PUBLIC_ACCESS" ]; then
                    status="error"; detail="공용 액세스 설정 확인 불가 (권한 부족 또는 리소스 상태 확인 필요)"
                    ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                    summary_string+="error|Functions|${APP_NAME}"$'\n'
                    evidence="Error: ${ERROR_DETAIL:-Command failed with exit code $CMD_EXIT_CODE}"
                elif [ "$PUBLIC_ACCESS" == "Disabled" ]; then
                    status="good"; detail="공용 네트워크 액세스 차단"
                    summary_string+="good|Functions|${APP_NAME}"$'\n'
                    evidence="publicNetworkAccess: ${PUBLIC_ACCESS}"
                elif [ "$PUBLIC_ACCESS" == "Enabled" ]; then
                    evidence="publicNetworkAccess: ${PUBLIC_ACCESS}"$'\n'
                    RESTRICTIONS=$(az functionapp config access-restriction show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "mainSite.ipSecurityRestrictions" --output tsv 2>/dev/null)
                    evidence+="ipSecurityRestrictions: ${RESTRICTIONS}"
                    if [ -n "$RESTRICTIONS" ] && [ "$RESTRICTIONS" != "[]" ]; then
                        status="review"; detail="공용 액세스는 허용되었으나, 접근 제한 규칙 존재 (세부 규칙 검토 필요)"
                        summary_string+="review|Functions|${APP_NAME}"$'\n'
                    else
                        status="bad"; detail="공용 액세스가 허용되었고, 접근 제한 규칙 미존재"
                        summary_string+="bad|Functions|${APP_NAME}"$'\n'
                    fi
                fi
                echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
                rm -f "$ERROR_MSG"
            done <<< "$FUNCTION_APPS_INFO"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Blob Storage ---
        echo '        <SubCheck service="BlobStorage">'
        STORAGE_ACCOUNTS_INFO=$(az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$STORAGE_ACCOUNTS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 스토리지 계정 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r ACCOUNT_NAME RESOURCE_GROUP; do
                if [ -z "$ACCOUNT_NAME" ]; then continue; fi

                ERROR_MSG=$(mktemp)
                PUBLIC_ACCESS=$(az storage account show --name "$ACCOUNT_NAME" --resource-group "$RESOURCE_GROUP" --query "publicNetworkAccess" --output tsv 2>"$ERROR_MSG")
                AZ_EXIT_CODE=$?

                if [ $AZ_EXIT_CODE -ne 0 ]; then
                    status="error"; detail="스토리지 계정 설정 확인 불가 (권한 부족 또는 리소스 상태 확인 필요)"
                    ERROR_DETAIL=$(cat "$ERROR_MSG" 2>/dev/null | head -3)
                    summary_string+="error|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    evidence="Error: ${ERROR_DETAIL:-Command failed with exit code $AZ_EXIT_CODE}"
                    echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
                    rm -f "$ERROR_MSG"
                
                elif [ "$PUBLIC_ACCESS" == "Disabled" ]; then
                    status="good"; detail="계정 수준에서 공용 네트워크 액세스 차단"
                    summary_string+="good|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    evidence="publicNetworkAccess: ${PUBLIC_ACCESS}"
                    echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
                    rm -f "$ERROR_MSG"

                else # Enabled 또는 null(기본값)인 경우
                    status="bad"; detail="계정 수준에서 공용 네트워크 액세스 허용"
                    summary_string+="bad|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    evidence="publicNetworkAccess: ${PUBLIC_ACCESS:-null}"
                    echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
                    rm -f "$ERROR_MSG"

                    CONTAINERS_INFO=$(az storage container list --account-name "$ACCOUNT_NAME" --auth-mode login --query "[].{Name:name, AccessLevel:properties.publicAccess}" --output tsv 2>/dev/null)

                    if [ $? -ne 0 ]; then
                        # 계정 수준은 통과했으나 컨테이너 조회 권한(e.g. Storage Blob Data Reader)이 없는 경우
                        echo "          <Item status=\"review\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>계정은 공용 액세스 허용 상태이나, 컨테이너 목록 조회 불가 (권한 확인 필요)</Detail><Evidence>Could not list containers. Check RBAC roles like 'Storage Blob Data Reader'.</Evidence></Item>"
                    elif [ -z "$CONTAINERS_INFO" ]; then
                        echo "          <Item status=\"info\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>계정은 공용 액세스 허용 상태이나, 내부에 컨테이너 미존재</Detail><Evidence>N/A</Evidence></Item>"
                    else
                         while IFS=$'\t' read -r CONTAINER_NAME ACCESS_LEVEL; do
                            if [ -z "$CONTAINER_NAME" ]; then continue; fi

                            if [ "$ACCESS_LEVEL" == "blob" ] || [ "$ACCESS_LEVEL" == "container" ]; then
                                c_status="bad"; c_detail="컨테이너 퍼블릭 액세스 허용 (${ACCESS_LEVEL})"
                            else
                                c_status="good"; c_detail="컨테이너 비공개 액세스 설정"
                            fi
                            echo "          <Item status=\"${c_status}\"><ResourceID>${ACCOUNT_NAME}/${CONTAINER_NAME}</ResourceID><Detail>${c_detail}</Detail><Evidence><![CDATA[publicAccess: ${ACCESS_LEVEL:-private}]]></Evidence></Item>"
                        done <<< "$CONTAINERS_INFO"
                    fi
                fi
            done <<< "$STORAGE_ACCOUNTS_INFO"
        fi
        echo '        </SubCheck>'
        
        # --- SubCheck: Virtual Machines ---
        echo '        <SubCheck service="VirtualMachines">'
        VMS_INFO=$(az vm list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$VMS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 가상 머신 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            while IFS=$'\t' read -r VM_NAME RESOURCE_GROUP; do
                if [ -z "$VM_NAME" ]; then continue; fi
                PUBLIC_IP=$(az vm list-ip-addresses --name "$VM_NAME" --resource-group "$RESOURCE_GROUP" --query "[].virtualMachine.network.publicIpAddresses[0].ipAddress" --output tsv 2>/dev/null)
                if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" == "null" ]; then
                    status="good"; detail="공용 IP 주소 미존재"
                    summary_string+="good|VirtualMachines|${VM_NAME}"$'\n'
                else
                    status="bad"; detail="공용 IP 주소(${PUBLIC_IP}) 할당됨"
                    summary_string+="bad|VirtualMachines|${VM_NAME}"$'\n'
                fi
                echo "          <Item status=\"${status}\"><ResourceID>${VM_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[PublicIP: ${PUBLIC_IP:-None}]]></Evidence></Item>"
            done <<< "$VMS_INFO"
        fi
        echo '        </SubCheck>'
        
        # --- SubCheck: Databases (MySQL & PostgreSQL) ---
        DB_TYPES=("mysql" "postgres")
        for DB_TYPE in "${DB_TYPES[@]}"; do
            echo "        <SubCheck service=\"Database-${DB_TYPE}\">"
            DB_SERVERS_INFO=$(az $DB_TYPE flexible-server list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
            if [ -z "$DB_SERVERS_INFO" ]; then
                echo "          <Item status=\"info\"><ResourceID>N/A</ResourceID><Detail>점검할 ${DB_TYPE} 서버 미존재</Detail><Evidence>N/A</Evidence></Item>"
            else
                while IFS=$'\t' read -r SERVER_NAME RESOURCE_GROUP; do
                    if [ -z "$SERVER_NAME" ]; then continue; fi
                    PUBLIC_ACCESS=$(az $DB_TYPE flexible-server show --resource-group "$RESOURCE_GROUP" --name "$SERVER_NAME" --query "network.publicNetworkAccess" --output tsv 2>/dev/null)
                    if [ "$PUBLIC_ACCESS" == "Disabled" ]; then
                        status="good"; detail="공용 네트워크 액세스 차단"
                        summary_string+="good|Unknown|${DB_TYPE}"$'\n'
                    else
                        status="bad"; detail="공용 네트워크 액세스 허용"
                        summary_string+="bad|Unknown|${SERVER_NAME}"$'\n'
                    fi
                    echo "          <Item status=\"${status}\"><ResourceID>${SERVER_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[publicNetworkAccess: ${PUBLIC_ACCESS}]]></Evidence></Item>"
                done <<< "$DB_SERVERS_INFO"
            fi
            echo "        </SubCheck>"
        done

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}


# [pism-007] 네트워크 접근 제어 설정의 최소 권한 적용
check_pism_007() {
    local check_id="pism-007"
    local check_name="네트워크 접근 제어 설정의 최소 권한 적용"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"

        echo '      <Command><![CDATA[az network nsg list, az network nsg rule list]]></Command>'

        echo "      <Results>"

        # --- SubCheck: Network Security Groups ---
        local service="NetworkSecurityGroups"
        echo "        <SubCheck service=\"${service}\">"
        NSG_INFO=$(az network nsg list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$NSG_INFO" ]; then
            local resource_id="N/A"; local status="info"; local detail="점검할 네트워크 보안 그룹(NSG) 미존재"
            summary_string+="${status}|${service}|${resource_id}"$'\n'
            echo "          <Item status=\"${status}\"><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail><Evidence>NA</Evidence></Item>"
        else
            while IFS=$'\t' read -r NSG_NAME RESOURCE_GROUP; do
                if [ -z "$NSG_NAME" ]; then continue; fi
                
                echo "          <Asset resource_id=\"${NSG_NAME}\" resource_group=\"${RESOURCE_GROUP}\">"

                # 스크립트가 실제 사용하는 쿼리 (sourceAddressPrefix와 destinationAddressPrefix 모두 조회)
                RULES_INFO=$(az network nsg rule list --resource-group "$RESOURCE_GROUP" --nsg-name "$NSG_NAME" --query "sort_by(@, &priority)[*].{Name:name, Direction:direction, Access:access, Priority:priority, Source:sourceAddressPrefix, Destination:destinationAddressPrefix, DstPort:destinationPortRange, Protocol:protocol}" --output tsv 2>/dev/null)

                if [ $? -ne 0 ]; then
                    local resource_id="$NSG_NAME"; local status="error"; local detail="NSG 규칙 조회 불가 (권한 확인 필요)"
                    summary_string+="${status}|${service}|${resource_id}"$'\n'
                    echo "            <Item status=\"${status}\"><Evidence>Failed to list rules.</Evidence><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail></Item>"
                    echo "          </Asset>"
                    continue
                fi

                if [ -z "$RULES_INFO" ]; then
                    local resource_id="$NSG_NAME"; local status="info"; local detail="NSG에 정의된 규칙 미존재"
                    summary_string+="${status}|${service}|${resource_id}"$'\n'
                    echo "            <Item status=\"${status}\"><Evidence>No rules defined.</Evidence><ResourceID>${resource_id}</ResourceID><Detail>${detail}</Detail></Item>"
                else
                    while IFS=$'\t' read -r RULE_NAME DIRECTION ACCESS PRIORITY SRC_IP DST_IP DST_PORT PROTOCOL; do
                        local detail="일반 규칙"

                        # Inbound 규칙 점검 (Source가 인터넷인 경우)
                        if [ "$DIRECTION" == "Inbound" ] && [ "$ACCESS" == "Allow" ] && [[ "$SRC_IP" == "*" || "$SRC_IP" == "Internet" || "$SRC_IP" == "Any" || "$SRC_IP" == "0.0.0.0/0" ]]; then

                            if [[ "$DST_PORT" == "*" || "$DST_PORT" == "Any" ]]; then
                                detail="모든 포트 허용 규칙"
                            fi

                            case "$DST_PORT" in
                                "20"|"21") detail="FTP(20,21) 포트 허용 규칙";;
                                "22") detail="SSH(22) 포트 허용 규칙";;
                                "23") detail="Telnet(23) 포트 허용 규칙";;
                                "25") detail="SMTP(25) 포트 허용 규칙";;
                                "53") detail="DNS(53) 포트 허용 규칙";;
                                "67"|"68") detail="DHCP(${DST_PORT}) 포트 허용 규칙";;
                                "69") detail="TFTP(69) 포트 허용 규칙";;
                                "80") detail="HTTP(80) 포트 허용 규칙";;
                                "88") detail="Kerberos(88) 포트 허용 규칙";;
                                "123") detail="NTP(123) 포트 허용 규칙";;
                                "161"|"162") detail="SNMP(${DST_PORT}) 포트 허용 규칙";;
                                "389") detail="LDAP(389) 포트 허용 규칙";;
                                "443") detail="HTTPS(443) 포트 허용 규칙";;
                                "464") detail="Kerberos Password(464) 포트 허용 규칙";;
                                "514") detail="Syslog(514) 포트 허용 규칙";;
                                "636") detail="LDAPS(636) 포트 허용 규칙";;
                                "902") detail="VMware Server(902) 포트 허용 규칙";;
                                "111"|"135") detail="RPC(${DST_PORT}) 포트 허용 규칙";;
                                "137"|"138"|"139"|"445") detail="SMB/NetBIOS(${DST_PORT}) 포트 허용 규칙";;
                                "1433") detail="MSSQL DB(1433) 포트 허용 규칙";;
                                "1521") detail="Oracle DB(1521) 포트 허용 규칙";;
                                "1812"|"1813") detail="RADIUS(${DST_PORT}) 포트 허용 규칙";;
                                "2049") detail="NFS(2049) 포트 허용 규칙";;
                                "2375"|"2376") detail="Docker API(${DST_PORT}) 포트 허용 규칙";;
                                "3000") detail="Node.js/Grafana(3000) 포트 허용 규칙";;
                                "3306") detail="MySQL/MariaDB(3306) 포트 허용 규칙";;
                                "3389") detail="RDP(3389) 포트 허용 규칙";;
                                "4000") detail="Ruby on Rails(4000) 포트 허용 규칙";;
                                "4848") detail="GlassFish Admin(4848) 포트 허용 규칙";;
                                "5000") detail="Flask/Docker Registry(5000) 포트 허용 규칙";;
                                "5432") detail="PostgreSQL DB(5432) 포트 허용 규칙";;
                                "5985"|"5986") detail="WinRM(${DST_PORT}) 포트 허용 규칙";;
                                "6379") detail="Redis(6379) 포트 허용 규칙";;
                                "6443") detail="Kubernetes API(6443) 포트 허용 규칙";;
                                "7001"|"7002") detail="WebLogic(${DST_PORT}) 포트 허용 규칙";;
                                "8000"|"8008"|"8081"|"8088"|"8180") detail="Alternative Web/WAS(${DST_PORT}) 포트 허용 규칙";;
                                "8009") detail="Tomcat AJP(8009) 포트 허용 규칙";;
                                "8080") detail="WAS/Proxy(8080) 포트 허용 규칙";;
                                "8443") detail="OpenShift/HTTPS Alt(8443) 포트 허용 규칙";;
                                "8629") detail="Tibero DB(8629) 포트 허용 규칙";;
                                "9000") detail="PHP-FPM/Jenkins(9000) 포트 허용 규칙";;
                                "9080"|"9443") detail="WebSphere(${DST_PORT}) 포트 허용 규칙";;
                                "9090") detail="JBoss Management(9090) 포트 허용 규칙";;
                                "9200") detail="Elasticsearch HTTP(9200) 포트 허용 규칙";;
                                "9300") detail="Elasticsearch Transport(9300) 포트 허용 규칙";;
                                "27017") detail="MongoDB(27017) 포트 허용 규칙";;
                            esac
                        fi

                        # Outbound 규칙 점검 (Destination이 인터넷인 경우)
                        if [ "$DIRECTION" == "Outbound" ] && [ "$ACCESS" == "Allow" ] && [[ "$DST_IP" == "*" || "$DST_IP" == "Internet" || "$DST_IP" == "Any" || "$DST_IP" == "0.0.0.0/0" ]]; then

                            if [[ "$DST_PORT" == "*" || "$DST_PORT" == "Any" ]]; then
                                detail="모든 포트 허용 규칙"
                            else
                                case "$DST_PORT" in
                                    "20"|"21") detail="FTP(20,21) 포트 허용 규칙";;
                                    "22") detail="SSH(22) 포트 허용 규칙";;
                                    "23") detail="Telnet(23) 포트 허용 규칙";;
                                    "25") detail="SMTP(25) 포트 허용 규칙";;
                                    "53") detail="DNS(53) 포트 허용 규칙";;
                                    "67"|"68") detail="DHCP(${DST_PORT}) 포트 허용 규칙";;
                                    "69") detail="TFTP(69) 포트 허용 규칙";;
                                    "80") detail="HTTP(80) 포트 허용 규칙";;
                                    "88") detail="Kerberos(88) 포트 허용 규칙";;
                                    "123") detail="NTP(123) 포트 허용 규칙";;
                                    "161"|"162") detail="SNMP(${DST_PORT}) 포트 허용 규칙";;
                                    "389") detail="LDAP(389) 포트 허용 규칙";;
                                    "443") detail="HTTPS(443) 포트 허용 규칙";;
                                    "464") detail="Kerberos Password(464) 포트 허용 규칙";;
                                    "514") detail="Syslog(514) 포트 허용 규칙";;
                                    "636") detail="LDAPS(636) 포트 허용 규칙";;
                                    "902") detail="VMware Server(902) 포트 허용 규칙";;
                                    "111"|"135") detail="RPC(${DST_PORT}) 포트 허용 규칙";;
                                    "137"|"138"|"139"|"445") detail="SMB/NetBIOS(${DST_PORT}) 포트 허용 규칙";;
                                    "1433") detail="MSSQL DB(1433) 포트 허용 규칙";;
                                    "1521") detail="Oracle DB(1521) 포트 허용 규칙";;
                                    "1812"|"1813") detail="RADIUS(${DST_PORT}) 포트 허용 규칙";;
                                    "2049") detail="NFS(2049) 포트 허용 규칙";;
                                    "2375"|"2376") detail="Docker API(${DST_PORT}) 포트 허용 규칙";;
                                    "3000") detail="Node.js/Grafana(3000) 포트 허용 규칙";;
                                    "3306") detail="MySQL/MariaDB(3306) 포트 허용 규칙";;
                                    "3389") detail="RDP(3389) 포트 허용 규칙";;
                                    "4000") detail="Ruby on Rails(4000) 포트 허용 규칙";;
                                    "4848") detail="GlassFish Admin(4848) 포트 허용 규칙";;
                                    "5000") detail="Flask/Docker Registry(5000) 포트 허용 규칙";;
                                    "5432") detail="PostgreSQL DB(5432) 포트 허용 규칙";;
                                    "5985"|"5986") detail="WinRM(${DST_PORT}) 포트 허용 규칙";;
                                    "6379") detail="Redis(6379) 포트 허용 규칙";;
                                    "6443") detail="Kubernetes API(6443) 포트 허용 규칙";;
                                    "7001"|"7002") detail="WebLogic(${DST_PORT}) 포트 허용 규칙";;
                                    "8000"|"8008"|"8081"|"8088"|"8180") detail="Alternative Web/WAS(${DST_PORT}) 포트 허용 규칙";;
                                    "8009") detail="Tomcat AJP(8009) 포트 허용 규칙";;
                                    "8080") detail="WAS/Proxy(8080) 포트 허용 규칙";;
                                    "8443") detail="OpenShift/HTTPS Alt(8443) 포트 허용 규칙";;
                                    "8629") detail="Tibero DB(8629) 포트 허용 규칙";;
                                    "9000") detail="PHP-FPM/Jenkins(9000) 포트 허용 규칙";;
                                    "9080"|"9443") detail="WebSphere(${DST_PORT}) 포트 허용 규칙";;
                                    "9090") detail="JBoss Management(9090) 포트 허용 규칙";;
                                    "9200") detail="Elasticsearch HTTP(9200) 포트 허용 규칙";;
                                    "9300") detail="Elasticsearch Transport(9300) 포트 허용 규칙";;
                                    "27017") detail="MongoDB(27017) 포트 허용 규칙";;
                                esac
                            fi
                        fi

                        local evidence_string
                        printf -v evidence_string "Priority: %s, Direction: %s, Access: %s, Source: %s, Destination: %s, Port: %s, Protocol: %s" \
                            "$PRIORITY" "$DIRECTION" "$ACCESS" "$SRC_IP" "$DST_IP" "$DST_PORT" "$PROTOCOL"

                        local resource_id="$RULE_NAME"; local status="review"
                        summary_string+="${status}|${service}|${resource_id}"$'\n'
                        echo "            <Item status=\"${status}\" check_id=\"${check_id}\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>${resource_id}</ResourceID><Detail>[${DIRECTION}] ${detail}</Detail></Item>"
                    done <<< "$RULES_INFO"
                fi

                echo "          </Asset>"

            done <<< "$NSG_INFO"
        fi
        echo '        </SubCheck>'
        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-013] 접근 로그 수집 기능 활성화 여부
check_pism_013() {
    local check_id="pism-013"
    local check_name="접근 로그 수집 기능 활성화 여부"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az account show, az extension add, az extension show, az functionapp list, az monitor data-collection rule association list, az monitor data-collection rule show, az monitor diagnostic-settings list, az monitor diagnostic-settings subscription list, az mysql flexible-server parameter show, az network bastion list, az network nsg list, az postgres flexible-server parameter show, az rest --method get, az storage account list, az vm extension list, az vm list]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Functions ---
        echo '        <SubCheck service="Functions">'
        FUNCTION_APPS_INFO=$(az functionapp list --query "[].{Id:id, Name:name}" --output tsv 2>/dev/null)
        if [ -z "$FUNCTION_APPS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 함수 앱 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r RES_ID RES_NAME; do
                DIAG_SETTINGS=$(az monitor diagnostic-settings list --resource "$RES_ID" -o json 2>/dev/null)
                if [ -z "$DIAG_SETTINGS" ] || [ "$DIAG_SETTINGS" == "[]" ]; then
                    status="bad"; detail="진단 설정 미존재"
                    summary_string+="bad|Functions|${RES_ID}"$'\n'
                else
                    log1_ok=$(echo "$DIAG_SETTINGS" | grep -A 1 '"category": "FunctionAppLogs"' | grep -c '"enabled": true')
                    log2_ok=$(echo "$DIAG_SETTINGS" | grep -A 1 '"category": "AppServiceAuthenticationLogs"' | grep -c '"enabled": true')

                    if [ "$log1_ok" -gt 0 ] && [ "$log2_ok" -gt 0 ]; then
                        status="good"; detail="주요 로그(FunctionAppLogs, AppServiceAuthenticationLogs) 수집 설정됨"
                        summary_string+="good|Functions|${RES_ID}"$'\n'
                    else
                        status="bad"; detail="주요 로그 일부 또는 전체 미설정"
                        summary_string+="bad|Functions|N/A"$'\n'
                    fi
                fi
                echo "          <Item status=\"${status}\"><ResourceID>${RES_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${DIAG_SETTINGS}]]></Evidence></Item>"
            done <<< "$FUNCTION_APPS_INFO"
        fi
        echo '        </SubCheck>'
        
        # --- SubCheck: Entra ID ---
        echo '        <SubCheck service="EntraID">'
        DIAG_SETTINGS=$(az rest --method get --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" -o json 2>/dev/null)
        if [ -z "$DIAG_SETTINGS" ] || echo "$DIAG_SETTINGS" | grep -q '"value":\[\]'; then
            status="bad"; detail="Entra ID에 대한 진단 설정 미존재"
            summary_string+="bad|EntraID|N/A"$'\n'
        else
            # 공식 기준: 10개 로그 카테고리 모두 확인
            log1_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "AuditLogs"' | grep -c '"enabled": true')
            log2_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "SignInLogs"' | grep -c '"enabled": true')
            log3_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "NonInteractiveUserSignInLogs"' | grep -c '"enabled": true')
            log4_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "ServicePrincipalSignInLogs"' | grep -c '"enabled": true')
            log5_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "ManagedIdentitySignInLogs"' | grep -c '"enabled": true')
            log6_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "ProvisioningLogs"' | grep -c '"enabled": true')
            log7_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "RiskyUsers"' | grep -c '"enabled": true')
            log8_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "UserRiskEvents"' | grep -c '"enabled": true')
            log9_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "RiskyServicePrincipals"' | grep -c '"enabled": true')
            log10_ok=$(echo "$DIAG_SETTINGS" | grep -A 2 '"category": "ServicePrincipalRiskEvents"' | grep -c '"enabled": true')

            # 10개 로그 모두 활성화되어야 양호
            if [ "$log1_ok" -gt 0 ] && [ "$log2_ok" -gt 0 ] && [ "$log3_ok" -gt 0 ] && \
               [ "$log4_ok" -gt 0 ] && [ "$log5_ok" -gt 0 ] && [ "$log6_ok" -gt 0 ] && \
               [ "$log7_ok" -gt 0 ] && [ "$log8_ok" -gt 0 ] && [ "$log9_ok" -gt 0 ] && \
               [ "$log10_ok" -gt 0 ]; then
                status="good"
                detail="주요 로그 10개 카테고리 모두 수집 설정됨 (AuditLogs, SignInLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs, ManagedIdentitySignInLogs, ProvisioningLogs, RiskyUsers, UserRiskEvents, RiskyServicePrincipals, ServicePrincipalRiskEvents)"
                summary_string+="good|EntraID|N/A"$'\n'
            else
                status="bad"
                # 어떤 로그가 누락되었는지 상세히 표시
                missing_logs=""
                [ "$log1_ok" -eq 0 ] && missing_logs+="AuditLogs, "
                [ "$log2_ok" -eq 0 ] && missing_logs+="SignInLogs, "
                [ "$log3_ok" -eq 0 ] && missing_logs+="NonInteractiveUserSignInLogs, "
                [ "$log4_ok" -eq 0 ] && missing_logs+="ServicePrincipalSignInLogs, "
                [ "$log5_ok" -eq 0 ] && missing_logs+="ManagedIdentitySignInLogs, "
                [ "$log6_ok" -eq 0 ] && missing_logs+="ProvisioningLogs, "
                [ "$log7_ok" -eq 0 ] && missing_logs+="RiskyUsers, "
                [ "$log8_ok" -eq 0 ] && missing_logs+="UserRiskEvents, "
                [ "$log9_ok" -eq 0 ] && missing_logs+="RiskyServicePrincipals, "
                [ "$log10_ok" -eq 0 ] && missing_logs+="ServicePrincipalRiskEvents, "
                missing_logs=${missing_logs%, }  # 마지막 쉼표 제거

                detail="주요 로그 미설정: ${missing_logs}"
                summary_string+="bad|EntraID|N/A"$'\n'
            fi
        fi
        echo "          <Item status=\"${status}\"><ResourceID>Entra ID Tenant</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${DIAG_SETTINGS}]]></Evidence></Item>"
        echo '        </SubCheck>'

        # --- SubCheck: Blob Storage  ---
        echo '        <SubCheck service="BlobStorage">'
        STORAGE_ACCOUNTS_INFO=$(az storage account list --query "[].{Id:id, Name:name}" --output tsv 2>/dev/null)
         if [ -z "$STORAGE_ACCOUNTS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 스토리지 계정 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r RES_ID RES_NAME; do
                # Blob Storage의 진단 설정은 계정 ID 뒤에 /blobServices/default를 추가해야 합니다.
                BLOB_RESOURCE_URI="${RES_ID}/blobServices/default"
                DIAG_SETTINGS=$(az monitor diagnostic-settings list --resource "$BLOB_RESOURCE_URI" -o json 2>/dev/null)
                
                if [ -z "$DIAG_SETTINGS" ] || [ "$DIAG_SETTINGS" == "[]" ]; then
                    status="bad"; detail="진단 설정 미존재"
                    summary_string+="bad|BlobStorage|${RES_ID}"$'\n'
                else
                    log1_ok=$(echo "$DIAG_SETTINGS" | grep -A 1 '"category": "StorageRead"' | grep -c '"enabled": true')
                    log2_ok=$(echo "$DIAG_SETTINGS" | grep -A 1 '"category": "StorageWrite"' | grep -c '"enabled": true')
                    log3_ok=$(echo "$DIAG_SETTINGS" | grep -A 1 '"category": "StorageDelete"' | grep -c '"enabled": true')

                    if [ "$log1_ok" -gt 0 ] && [ "$log2_ok" -gt 0 ] && [ "$log3_ok" -gt 0 ]; then
                        status="good"; detail="주요 로그(Read, Write, Delete) 수집 설정됨"
                        summary_string+="good|BlobStorage|N/A"$'\n'
                    else
                        status="bad"; detail="주요 로그 일부 또는 전체 미설정"
                        summary_string+="bad|BlobStorage|N/A"$'\n'
                    fi
                fi
                echo "          <Item status=\"${status}\"><ResourceID>${RES_NAME} (blob)</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${DIAG_SETTINGS}]]></Evidence></Item>"
            done <<< "$STORAGE_ACCOUNTS_INFO"
        fi
        echo '        </SubCheck>'
        
        # --- SubCheck: Virtual Machines ---
        echo '        <SubCheck service="VirtualMachines">'
        VMS_INFO=$(az vm list --query "[].{Name:name, ResourceGroup:resourceGroup, Id:id}" --output tsv 2>/dev/null)
        if [ -z "$VMS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 가상 머신 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r VM_NAME RESOURCE_GROUP VM_ID; do
                # 1단계: Azure Monitor 에이전트 설치 여부 확인
                EXTENSIONS=$(az vm extension list --vm-name "$VM_NAME" -g "$RESOURCE_GROUP" --query "[].name" -o tsv 2>/dev/null)

                if echo "$EXTENSIONS" | grep -q "AzureMonitor"; then
                    # 2단계: 데이터 수집 규칙(DCR) 연결 여부 확인
                    DCR_ASSOCIATIONS=$(az monitor data-collection rule association list \
                        --resource "$VM_ID" \
                        --query "[].{RuleId:dataCollectionRuleId}" \
                        -o tsv 2>/dev/null)

                    if [ -n "$DCR_ASSOCIATIONS" ] && [ "$DCR_ASSOCIATIONS" != "[]" ]; then
                        # DCR이 연결되어 있으면 규칙 상세 확인
                        DCR_COUNT=$(echo "$DCR_ASSOCIATIONS" | wc -l | tr -d ' ')

                        # 로그 수집 여부 확인 (Syslog, Performance 등)
                        has_logging=false
                        for dcr_id in $DCR_ASSOCIATIONS; do
                            dcr_details=$(az monitor data-collection rule show --ids "$dcr_id" -o json 2>/dev/null)
                            if echo "$dcr_details" | grep -q '"syslog"' || echo "$dcr_details" | grep -q '"performanceCounters"' || echo "$dcr_details" | grep -q '"windowsEventLogs"'; then
                                has_logging=true
                                break
                            fi
                        done

                        if [ "$has_logging" = true ]; then
                            status="good"
                            detail="Azure Monitor 에이전트 설치됨 + 데이터 수집 규칙 활성화 (${DCR_COUNT}개 DCR 연결, 로그 수집 중)"
                            summary_string+="good|VirtualMachines|${VM_NAME}"$'\n'
                        else
                            status="review"
                            detail="Azure Monitor 에이전트 설치됨 + DCR 연결됨 (${DCR_COUNT}개, 로그 수집 설정 검토 필요)"
                            summary_string+="review|VirtualMachines|${VM_NAME}"$'\n'
                        fi
                        evidence="Extensions: ${EXTENSIONS}\nDCR Count: ${DCR_COUNT}\nDCR Associations: ${DCR_ASSOCIATIONS}"
                    else
                        # 에이전트는 있으나 DCR 없음
                        status="bad"
                        detail="Azure Monitor 에이전트 설치됨 (데이터 수집 규칙 미연결)"
                        summary_string+="bad|VirtualMachines|${VM_NAME}"$'\n'
                        evidence="Extensions: ${EXTENSIONS}\nDCR: None"
                    fi
                else
                    # 에이전트 미설치
                    status="bad"
                    detail="Azure Monitor 에이전트 미설치"
                    summary_string+="bad|VirtualMachines|${VM_NAME}"$'\n'
                    evidence="Extensions: ${EXTENSIONS}"
                fi

                echo "          <Item status=\"${status}\"><ResourceID>${VM_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
            done <<< "$VMS_INFO"
        fi
        echo '        </SubCheck>'
        
        # --- SubCheck: Databases (MySQL & PostgreSQL) ---
        DB_TYPES=("mysql" "postgres")
        for DB_TYPE in "${DB_TYPES[@]}"; do
            echo "        <SubCheck service=\"Database-${DB_TYPE}\">"
            DB_SERVERS_INFO=$(az $DB_TYPE flexible-server list --query "[].{Id:id, Name:name, RG:resourceGroup}" --output tsv 2>/dev/null)
            if [ -z "$DB_SERVERS_INFO" ]; then
                echo "          <Item status=\"info\"><ResourceID>N/A</ResourceID><Detail>점검할 ${DB_TYPE} 서버 미존재</Detail></Item>"
            else
                while IFS=$'\t' read -r RES_ID SERVER_NAME RESOURCE_GROUP; do
                    local all_checks_ok=true
                    local evidence=""
                    
                    # 1. 진단 설정 'audit' 그룹 활성화 여부 확인
                    DIAG_SETTINGS=$(az monitor diagnostic-settings list --resource "$RES_ID" -o json 2>/dev/null)
                    AUDIT_LOG_ENABLED=$(echo "$DIAG_SETTINGS" | grep -A 1 '"categoryGroup": "audit"' | grep -c '"enabled": true')
                    evidence+="Diagnostic Setting 'audit' enabled: "
                    if [ $AUDIT_LOG_ENABLED -gt 0 ]; then
                        evidence+="Yes"$'\n'
                    else
                        evidence+="No"$'\n'; all_checks_ok=false
                    fi

                    # 2. 각 DB 타입별 상세 서버 매개 변수 확인
                    if [ "$DB_TYPE" == "mysql" ]; then
                        params_to_check=("audit_log_enabled" "audit_log_events" "audit_log_exclude_users" "audit_log_include_users")
                        criteria=("ON" "ADMIN,CONNECTION,DCL,DDL,DML" "" "") # audit_log_exclude/include_users는 비어있어야 '양호'
                        for i in "${!params_to_check[@]}"; do
                            param_name=${params_to_check[$i]}
                            param_value=$(az mysql flexible-server parameter show -g "$RESOURCE_GROUP" -s "$SERVER_NAME" -n "$param_name" --query "value" -o tsv 2>/dev/null)
                            evidence+="- ${param_name}: ${param_value}"$'\n'
                            if [ "${param_value}" != "${criteria[$i]}" ]; then
                                all_checks_ok=false
                            fi
                        done
                    elif [ "$DB_TYPE" == "postgres" ]; then
                        # 공식 기준: 4가지 파라미터 확인
                        # 1. azure.extensions (PGAUDIT 포함)
                        azure_extensions=$(az postgres flexible-server parameter show -g "$RESOURCE_GROUP" -s "$SERVER_NAME" -n "azure.extensions" --query "value" -o tsv 2>/dev/null)
                        evidence+="- azure.extensions: ${azure_extensions}"$'\n'
                        if ! echo "$azure_extensions" | grep -q "PGAUDIT"; then
                            all_checks_ok=false
                        fi

                        # 2. pgaudit.log (DDL, READ, ROLE, WRITE 포함)
                        pgaudit_log=$(az postgres flexible-server parameter show -g "$RESOURCE_GROUP" -s "$SERVER_NAME" -n "pgaudit.log" --query "value" -o tsv 2>/dev/null)
                        evidence+="- pgaudit.log: ${pgaudit_log}"$'\n'
                        if ! (echo "$pgaudit_log" | grep -q "DDL" && echo "$pgaudit_log" | grep -q "READ" && echo "$pgaudit_log" | grep -q "ROLE" && echo "$pgaudit_log" | grep -q "WRITE"); then
                            all_checks_ok=false
                        fi

                        # 3. pgaudit.log_parameter (OFF 권장)
                        pgaudit_log_parameter=$(az postgres flexible-server parameter show -g "$RESOURCE_GROUP" -s "$SERVER_NAME" -n "pgaudit.log_parameter" --query "value" -o tsv 2>/dev/null)
                        evidence+="- pgaudit.log_parameter: ${pgaudit_log_parameter}"$'\n'
                        if [ "$pgaudit_log_parameter" != "OFF" ] && [ "$pgaudit_log_parameter" != "off" ]; then
                            all_checks_ok=false
                        fi

                        # 4. pgaudit.role (별도 계정 설정 권장)
                        pgaudit_role=$(az postgres flexible-server parameter show -g "$RESOURCE_GROUP" -s "$SERVER_NAME" -n "pgaudit.role" --query "value" -o tsv 2>/dev/null)
                        evidence+="- pgaudit.role: ${pgaudit_role}"$'\n'
                        # role은 설정되어 있으면 양호, 비어있어도 일단 pass (기준에 "별도 계정 설정"이라고만 명시)
                        # 엄격하게 하려면 비어있으면 false 처리
                    fi
                    
                    # 최종 판단
                    if [ "$all_checks_ok" = true ]; then
                        status="good"; detail="진단 설정 및 모든 주요 감사 파라미터가 기준에 맞게 설정됨"
                        summary_string+="good|Unknown|${SERVER_NAME}"$'\n'
                    else
                        status="bad"; detail="진단 설정 또는 일부 주요 감사 파라미터가 기준 미달"
                        summary_string+="bad|Unknown|${SERVER_NAME}"$'\n'
                    fi
                    echo "          <Item status=\"${status}\"><ResourceID>${SERVER_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"

                done <<< "$DB_SERVERS_INFO"
            fi
            echo "        </SubCheck>"
        done

        # --- SubCheck: Network Security Groups ---
        echo '        <SubCheck service="NetworkSecurityGroups">'
        NSG_INFO=$(az network nsg list --query "[].{Id:id, Name:name}" --output tsv 2>/dev/null)
        if [ -z "$NSG_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 NSG 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r RES_ID RES_NAME; do
                DIAG_SETTINGS=$(az monitor diagnostic-settings list --resource "$RES_ID" -o json 2>/dev/null)
                if [ -z "$DIAG_SETTINGS" ] || [ "$DIAG_SETTINGS" == "[]" ]; then
                    status="bad"; detail="진단 설정 미존재"
                    summary_string+="bad|NetworkSecurityGroups|${RES_ID}"$'\n'
                else
                    # 조건 1: 개별 카테고리가 모두 켜져 있는지 확인
                    log1_ok=$(echo "$DIAG_SETTINGS" | grep -A 1 '"category": "NetworkSecurityGroupEvent"' | grep -c '"enabled": true')
                    log2_ok=$(echo "$DIAG_SETTINGS" | grep -A 1 '"category": "NetworkSecurityGroupRuleCounter"' | grep -c '"enabled": true')

                    # 조건 2: 'allLogs' 카테고리 그룹이 켜져 있는지 확인
                    all_logs_ok=$(echo "$DIAG_SETTINGS" | grep -A 1 '"categoryGroup": "allLogs"' | grep -c '"enabled": true')

                    if ( [ "$log1_ok" -gt 0 ] && [ "$log2_ok" -gt 0 ] ) || [ "$all_logs_ok" -gt 0 ]; then
                        status="good"; detail="주요 로그(Event, RuleCounter) 또는 전체 로그(allLogs) 수집 설정됨"
                        summary_string+="good|NetworkSecurityGroups|N/A"$'\n'
                    else
                        status="bad"; detail="주요 로그 일부 또는 전체 미설정"
                        summary_string+="bad|NetworkSecurityGroups|N/A"$'\n'
                    fi
                fi
                echo "          <Item status=\"${status}\"><ResourceID>${RES_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${DIAG_SETTINGS}]]></Evidence></Item>"
            done <<< "$NSG_INFO"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Azure Monitor (Activity Log) ---
        echo '        <SubCheck service="AzureMonitor">'
        local service="AzureMonitor"

        # 공식 기준: Azure Activity Log의 진단 설정을 통한 로그 수집 여부 확인
        # Activity Log는 구독 수준에서 설정됨

        # 현재 구독 ID 가져오기
        SUBSCRIPTION_ID=$(az account show --query "id" -o tsv 2>/dev/null)

        if [ -z "$SUBSCRIPTION_ID" ]; then
            status="error"
            detail="구독 정보를 가져올 수 없습니다."
            summary_string+="error|${service}|N/A"$'\n'
            echo "          <Item status=\"${status}\"><ResourceID>N/A</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[Failed to retrieve subscription ID]]></Evidence></Item>"
        else
            # Activity Log 진단 설정 조회 (구독 수준)
            ACTIVITY_LOG_DIAG=$(az monitor diagnostic-settings subscription list -o json 2>/dev/null)

            if [ -z "$ACTIVITY_LOG_DIAG" ] || [ "$ACTIVITY_LOG_DIAG" == "[]" ]; then
                status="bad"
                detail="Activity Log 진단 설정 미존재 (Azure Monitor 로그 수집 미설정)"
                summary_string+="bad|${service}|Subscription:${SUBSCRIPTION_ID}"$'\n'
                evidence="No diagnostic settings found for Activity Log at subscription level."
            else
                # Activity Log 진단 설정이 있는 경우, 주요 카테고리 확인
                # 주요 카테고리: Administrative, Security, ServiceHealth, Alert, Recommendation, Policy, Autoscale, ResourceHealth

                admin_ok=$(echo "$ACTIVITY_LOG_DIAG" | grep -A 1 '"category": "Administrative"' | grep -c '"enabled": true')
                security_ok=$(echo "$ACTIVITY_LOG_DIAG" | grep -A 1 '"category": "Security"' | grep -c '"enabled": true')
                service_health_ok=$(echo "$ACTIVITY_LOG_DIAG" | grep -A 1 '"category": "ServiceHealth"' | grep -c '"enabled": true')
                alert_ok=$(echo "$ACTIVITY_LOG_DIAG" | grep -A 1 '"category": "Alert"' | grep -c '"enabled": true')
                recommendation_ok=$(echo "$ACTIVITY_LOG_DIAG" | grep -A 1 '"category": "Recommendation"' | grep -c '"enabled": true')
                policy_ok=$(echo "$ACTIVITY_LOG_DIAG" | grep -A 1 '"category": "Policy"' | grep -c '"enabled": true')
                autoscale_ok=$(echo "$ACTIVITY_LOG_DIAG" | grep -A 1 '"category": "Autoscale"' | grep -c '"enabled": true')
                resource_health_ok=$(echo "$ACTIVITY_LOG_DIAG" | grep -A 1 '"category": "ResourceHealth"' | grep -c '"enabled": true')

                # Administrative, Security는 필수, 나머지는 권장
                if [ "$admin_ok" -gt 0 ] && [ "$security_ok" -gt 0 ]; then
                    # 필수 카테고리가 모두 활성화된 경우
                    local enabled_count=0
                    [ "$admin_ok" -gt 0 ] && enabled_count=$((enabled_count + 1))
                    [ "$security_ok" -gt 0 ] && enabled_count=$((enabled_count + 1))
                    [ "$service_health_ok" -gt 0 ] && enabled_count=$((enabled_count + 1))
                    [ "$alert_ok" -gt 0 ] && enabled_count=$((enabled_count + 1))
                    [ "$recommendation_ok" -gt 0 ] && enabled_count=$((enabled_count + 1))
                    [ "$policy_ok" -gt 0 ] && enabled_count=$((enabled_count + 1))
                    [ "$autoscale_ok" -gt 0 ] && enabled_count=$((enabled_count + 1))
                    [ "$resource_health_ok" -gt 0 ] && enabled_count=$((enabled_count + 1))

                    if [ "$enabled_count" -eq 8 ]; then
                        status="good"
                        detail="Activity Log 진단 설정됨 (8개 주요 카테고리 모두 활성화)"
                    else
                        status="good"
                        detail="Activity Log 진단 설정됨 (필수 카테고리 활성화, ${enabled_count}/8개 카테고리 활성화)"
                    fi
                    summary_string+="good|${service}|Subscription:${SUBSCRIPTION_ID}"$'\n'
                else
                    # 필수 카테고리가 누락된 경우
                    status="bad"
                    missing_required=""
                    [ "$admin_ok" -eq 0 ] && missing_required+="Administrative, "
                    [ "$security_ok" -eq 0 ] && missing_required+="Security, "
                    missing_required=${missing_required%, }

                    detail="Activity Log 진단 설정 부족 (필수 카테고리 미활성화: ${missing_required})"
                    summary_string+="bad|${service}|Subscription:${SUBSCRIPTION_ID}"$'\n'
                fi

                evidence="Activity Log Diagnostic Settings:\n${ACTIVITY_LOG_DIAG}"$'\n'$'\n'
                evidence+="Category Status:"$'\n'
                evidence+="- Administrative: $( [ "$admin_ok" -gt 0 ] && echo "Enabled" || echo "Disabled" )"$'\n'
                evidence+="- Security: $( [ "$security_ok" -gt 0 ] && echo "Enabled" || echo "Disabled" )"$'\n'
                evidence+="- ServiceHealth: $( [ "$service_health_ok" -gt 0 ] && echo "Enabled" || echo "Disabled" )"$'\n'
                evidence+="- Alert: $( [ "$alert_ok" -gt 0 ] && echo "Enabled" || echo "Disabled" )"$'\n'
                evidence+="- Recommendation: $( [ "$recommendation_ok" -gt 0 ] && echo "Enabled" || echo "Disabled" )"$'\n'
                evidence+="- Policy: $( [ "$policy_ok" -gt 0 ] && echo "Enabled" || echo "Disabled" )"$'\n'
                evidence+="- Autoscale: $( [ "$autoscale_ok" -gt 0 ] && echo "Enabled" || echo "Disabled" )"$'\n'
                evidence+="- ResourceHealth: $( [ "$resource_health_ok" -gt 0 ] && echo "Enabled" || echo "Disabled" )"
            fi

            echo "          <Item status=\"${status}\"><ResourceID>Subscription: ${SUBSCRIPTION_ID}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Bastions (진단 설정 - BastionAuditLogs) ---
        echo '        <SubCheck service="Bastions">'
        local service="Bastions"

        # 공식 기준: Bastion의 진단 설정에서 "Bastion Audit Logs" 로그 수집 설정 여부 확인
        # 참고: PISM-046의 Bastion RBAC 점검과는 별개로, PISM-013에서는 감사 로그 수집만 점검

        # Bastion 확장 설치 여부 확인
        if ! az extension show -n bastion > /dev/null 2>&1; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>Bastion 점검 건너뜀 (Azure CLI bastion 확장 미설치. 오프라인 설치: 1) 인터넷 연결된 별도 환경에서 az extension add -n bastion --upgrade 실행, 2) ~/.azure/cliextensions/bastion 디렉터리를 검토 후 대상 시스템의 동일 경로에 반영)</Detail></Item>'
        else
            BASTIONS_INFO=$(az network bastion list --query "[].{Name:name, Id:id}" --output tsv 2>/dev/null)
            if [ -z "$BASTIONS_INFO" ]; then
                echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 Bastion 호스트 미존재</Detail></Item>'
            else
                while IFS=$'\t' read -r BASTION_NAME RES_ID; do
                    if [ -z "$BASTION_NAME" ]; then continue; fi

                    # Bastion 리소스에 대한 진단 설정 확인
                    DIAG_SETTINGS=$(az monitor diagnostic-settings list --resource "$RES_ID" -o json 2>/dev/null)

                    if [ -z "$DIAG_SETTINGS" ] || [ "$DIAG_SETTINGS" == "[]" ]; then
                        status="bad"
                        detail="진단 설정 미존재 (BastionAuditLogs 수집 안 됨)"
                        summary_string+="bad|${service}|${BASTION_NAME}"$'\n'
                        evidence="No diagnostic settings found for Bastion resource: ${BASTION_NAME}"
                    else
                        # BastionAuditLogs 카테고리 활성화 여부 확인
                        bastion_audit_ok=$(echo "$DIAG_SETTINGS" | grep -A 1 '"category": "BastionAuditLogs"' | grep -c '"enabled": true')

                        if [ "$bastion_audit_ok" -gt 0 ]; then
                            status="good"
                            detail="Bastion Audit Logs 수집 설정됨"
                            summary_string+="good|${service}|${BASTION_NAME}"$'\n'
                        else
                            status="bad"
                            detail="진단 설정은 존재하나 BastionAuditLogs 카테고리 미활성화"
                            summary_string+="bad|${service}|${BASTION_NAME}"$'\n'
                        fi

                        evidence="${DIAG_SETTINGS}"
                    fi

                    echo "          <Item status=\"${status}\"><ResourceID>${BASTION_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
                done <<< "$BASTIONS_INFO"
            fi
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-016] 저장소 임의 삭제 방지 대책 적용 여부
check_pism_016() {
    local check_id="pism-016"
    local check_name="저장소 임의 삭제 방지 대책 적용 여부"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az lock list, az storage account list]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Blob Storage Locks ---
        echo '        <SubCheck service="BlobStorage">'
        STORAGE_ACCOUNTS_INFO=$(az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$STORAGE_ACCOUNTS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 스토리지 계정 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r ACCOUNT_NAME RESOURCE_GROUP; do
                if [ -z "$ACCOUNT_NAME" ]; then continue; fi
                
                # 스토리지 계정에 설정된 잠금 목록 확인
                LOCK_INFO=$(az lock list --resource-group "$RESOURCE_GROUP" --resource-name "$ACCOUNT_NAME" --resource-type "Microsoft.Storage/storageAccounts" --query "[].level" -o tsv 2>/dev/null)
                
                if [ $? -ne 0 ]; then
                    status="error"; detail="잠금 정보 조회 불가 (권한 확인 필요)"
                    summary_string+="error|BlobStorage|${ACCOUNT_NAME}"$'\n'
                elif echo "$LOCK_INFO" | grep -q "CanNotDelete"; then
                    status="good"; detail="삭제 잠금(CanNotDelete) 설정됨"
                    summary_string+="good|BlobStorage|${ACCOUNT_NAME}"$'\n'
                else
                    status="bad"; detail="삭제 잠금(CanNotDelete) 미설정"
                    summary_string+="bad|BlobStorage|${ACCOUNT_NAME}"$'\n'
                fi
                echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${LOCK_INFO}]]></Evidence></Item>"
            done <<< "$STORAGE_ACCOUNTS_INFO"
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-017] 삭제된 저장소 내 데이터 복원 기능 활성화 여부
check_pism_017() {
    local check_id="pism-017"
    local check_name="삭제된 저장소 내 데이터 복원 기능 활성화 여부"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az storage account blob-service-properties show, az storage account list]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Blob Storage Soft Delete ---
        echo '        <SubCheck service="BlobStorage">'
        STORAGE_ACCOUNTS_INFO=$(az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$STORAGE_ACCOUNTS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 스토리지 계정 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r ACCOUNT_NAME RESOURCE_GROUP; do
                if [ -z "$ACCOUNT_NAME" ]; then continue; fi

                # Blob 및 컨테이너의 일시 삭제 설정 상태를 가져옴
                DELETE_POLICY_INFO=$(az storage account blob-service-properties show --account-name "$ACCOUNT_NAME" --resource-group "$RESOURCE_GROUP" --query "{blobEnabled:deleteRetentionPolicy.enabled, containerEnabled:containerDeleteRetentionPolicy.enabled}" --output json 2>/dev/null)

                if [ $? -ne 0 ]; then
                    status="error"; detail="일시 삭제 정책 조회 불가 (권한 확인 필요)"
                    summary_string+="error|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    evidence="${DELETE_POLICY_INFO}"
                else
                    blob_enabled=$(echo "$DELETE_POLICY_INFO" | grep -o '"blobEnabled": [^,]*' | awk '{print $2}' | tr -d ',')
                    container_enabled=$(echo "$DELETE_POLICY_INFO" | grep -o '"containerEnabled": [^,]*' | awk '{print $2}' | tr -d ',')

                    if [ "$blob_enabled" == "true" ] && [ "$container_enabled" == "true" ]; then
                        status="good"; detail="Blob 및 컨테이너 일시 삭제 기능 모두 활성화"
                        summary_string+="good|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    else
                        status="bad"; detail="Blob 또는 컨테이너 일시 삭제 기능 비활성화"
                        summary_string+="bad|BlobStorage|${ACCOUNT_NAME}"$'\n'
                    fi
                    evidence="Blob Soft Delete: ${blob_enabled:-false}, Container Soft Delete: ${container_enabled:-false}"
                fi
                echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
            done <<< "$STORAGE_ACCOUNTS_INFO"
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-023] 업무상 불필요한 가상자원 존재
check_pism_023() {
    local check_id="pism-023"
    local check_name="업무상 불필요한 가상자원 존재"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az disk list, az functionapp list, az mysql flexible-server list, az network nic list, az network public-ip list, az postgres flexible-server list, az storage account list, az vm list]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Functions ---
        echo '        <SubCheck service="Functions">'
        local func_evidence=$(az functionapp list --query "[].{Name:name, State:state, ResourceGroup:resourceGroup}" --output table 2>/dev/null)
        if [ -z "$func_evidence" ]; then func_evidence="점검할 함수 앱 미존재"; fi
        echo "          <Item status=\"review\"><ResourceID>All Functions</ResourceID><Detail>아래 목록을 기반으로 불필요한 함수 앱 존재 여부 검토</Detail><Evidence><![CDATA[${func_evidence}]]></Evidence></Item>"
        echo '        </SubCheck>'

        # --- SubCheck: Storage ---
        echo '        <SubCheck service="Storage">'
        local storage_evidence=$(az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup, CreationTime:creationTime}" --output table 2>/dev/null)
        if [ -z "$storage_evidence" ]; then storage_evidence="점검할 스토리지 계정 미존재"; fi
        echo "          <Item status=\"review\"><ResourceID>All Storage Accounts</ResourceID><Detail>아래 목록을 기반으로 불필요한 스토리지 계정 존재 여부 검토</Detail><Evidence><![CDATA[${storage_evidence}]]></Evidence></Item>"
        echo '        </SubCheck>'

        # --- SubCheck: Virtual Machine & Related Resources ---
        echo '        <SubCheck service="VirtualMachineResources">'
        # 각 목록을 별도 변수에 저장
        local vm_list=$(az vm list --query "[].{Name:name, PowerState:powerState, ResourceGroup:resourceGroup}" --output table 2>/dev/null || echo "Error listing VMs")

        # NIC: 연결 가능한 모든 자원 정보 수집 (VM, Private Endpoint, App Gateway, Load Balancer 등)
        local nic_json=$(az network nic list --output json 2>/dev/null)

        # Disk: ManagedBy 필드로 연결된 전체 리소스 표시
        local disk_list=$(az disk list --query "[].{Name:name, SizeGB:diskSizeGb, DiskState:diskState, ManagedBy:managedBy, ResourceGroup:resourceGroup}" --output table 2>/dev/null || echo "Error listing Disks")

        # Public IP: 연결 가능한 모든 자원 정보 수집
        local ip_json=$(az network public-ip list --output json 2>/dev/null)

        echo "          <Item status=\"review\"><ResourceID>All VM Resources</ResourceID><Detail>아래 목록을 기반으로 불필요한 VM 관련 자원(NIC, Disk, Public IP 등) 존재 여부 검토</Detail><Evidence><![CDATA["
        # Evidence 내부에서 각 목록을 제목과 함께 별도로 echo
        echo "--- Virtual Machines ---"
        echo "${vm_list}"
        echo ""
        echo "--- Network Interfaces (연결된 자원 유형 표시) ---"
        printf "%-25s %-20s %-20s %-50s %-15s\n" "Name" "ResourceGroup" "ConnectedType" "ConnectedResource" "State"
        echo "$nic_json" | jq -r '.[] |
            {
                Name: .name,
                RG: .resourceGroup,
                VM: (.virtualMachine.id // ""),
                PE: (.privateEndpoint.id // ""),
                State: .provisioningState
            } |
            if .VM != "" then
                "\(.Name)\t\(.RG)\tVM\t" + (.VM | split("/") | .[-1]) + "\t\(.State)"
            elif .PE != "" then
                "\(.Name)\t\(.RG)\tPrivateEndpoint\t" + (.PE | split("/") | .[-1]) + "\t\(.State)"
            else
                "\(.Name)\t\(.RG)\t미연결\t-\t\(.State)"
            end
        ' 2>/dev/null | while IFS=$'\t' read -r name rg type resource state; do
            printf "%-25s %-20s %-20s %-50s %-15s\n" "$name" "$rg" "$type" "$resource" "$state"
        done
        echo ""
        echo "--- Disks (ManagedBy 필드로 연결 자원 식별) ---"
        echo "${disk_list}"
        echo ""
        echo "설명: ManagedBy 경로에서 자원 유형 확인 가능"
        echo "  - /virtualMachines/ 포함 → VM 연결"
        echo "  - /virtualMachineScaleSets/ 포함 → VMSS 연결"
        echo "  - 비어있음 → 미연결 (불필요 자원 의심)"
        echo ""
        echo "--- Public IP Addresses (연결된 자원 유형 표시) ---"
        printf "%-25s %-20s %-20s %-25s %-50s\n" "Name" "IP" "ResourceGroup" "ConnectedType" "ConnectedResource"
        echo "$ip_json" | jq -r '.[] |
            {
                Name: .name,
                IP: .ipAddress,
                RG: .resourceGroup,
                IpConfig: (.ipConfiguration.id // ""),
                NatGW: (.natGateway.id // "")
            } |
            if .IpConfig != "" then
                if (.IpConfig | contains("/networkInterfaces/")) then
                    "\(.Name)\t\(.IP)\t\(.RG)\tNIC\t" + (.IpConfig | split("/networkInterfaces/")[1] | split("/")[0])
                elif (.IpConfig | contains("/loadBalancers/")) then
                    "\(.Name)\t\(.IP)\t\(.RG)\tLoadBalancer\t" + (.IpConfig | split("/loadBalancers/")[1] | split("/")[0])
                elif (.IpConfig | contains("/applicationGateways/")) then
                    "\(.Name)\t\(.IP)\t\(.RG)\tAppGateway\t" + (.IpConfig | split("/applicationGateways/")[1] | split("/")[0])
                elif (.IpConfig | contains("/virtualNetworkGateways/")) then
                    "\(.Name)\t\(.IP)\t\(.RG)\tVPNGateway\t" + (.IpConfig | split("/virtualNetworkGateways/")[1] | split("/")[0])
                elif (.IpConfig | contains("/bastionHosts/")) then
                    "\(.Name)\t\(.IP)\t\(.RG)\tBastion\t" + (.IpConfig | split("/bastionHosts/")[1] | split("/")[0])
                elif (.IpConfig | contains("/azureFirewalls/")) then
                    "\(.Name)\t\(.IP)\t\(.RG)\tFirewall\t" + (.IpConfig | split("/azureFirewalls/")[1] | split("/")[0])
                else
                    "\(.Name)\t\(.IP)\t\(.RG)\tOther\t" + (.IpConfig | split("/") | .[-3] + "/" + .[-1])
                end
            elif .NatGW != "" then
                "\(.Name)\t\(.IP)\t\(.RG)\tNATGateway\t" + (.NatGW | split("/") | .[-1])
            else
                "\(.Name)\t\(.IP)\t\(.RG)\t미할당\t"
            end
        ' 2>/dev/null | while IFS=$'\t' read -r name ip rg type resource; do
            printf "%-25s %-20s %-20s %-25s %-50s\n" "$name" "$ip" "$rg" "$type" "$resource"
        done
        echo "]]></Evidence></Item>"
        echo '        </SubCheck>'
        
        # --- SubCheck: Databases ---
        echo '        <SubCheck service="Databases">'
        local mysql_list=$(az mysql flexible-server list --query "[].{Name:name, State:state, ResourceGroup:resourceGroup}" --output table 2>/dev/null || echo "Error listing MySQL servers")
        local postgres_list=$(az postgres flexible-server list --query "[].{Name:name, State:state, ResourceGroup:resourceGroup}" --output table 2>/dev/null || echo "Error listing PostgreSQL servers")

        echo "          <Item status=\"review\"><ResourceID>All Databases</ResourceID><Detail>아래 목록을 기반으로 불필요한 데이터베이스 존재 여부 검토</Detail><Evidence><![CDATA["
        echo "--- MySQL Flexible Servers ---"
        echo "${mysql_list}"
        echo ""
        echo "--- PostgreSQL Flexible Servers ---"
        echo "${postgres_list}"
        echo "]]></Evidence></Item>"
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-025] 서비스 지원이 종료된(EoS) 런타임 교체 여부
check_pism_025() {
    local check_id="pism-025"
    local check_name="서비스 지원이 종료된(EoS) 런타임 교체 여부"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az functionapp config appsettings list, az functionapp list, az functionapp show]]></Command>"
        echo "      <Results>"

        echo '        <SubCheck service="Functions">'
        FUNCTION_APPS_INFO=$(az functionapp list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$FUNCTION_APPS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 함수 앱 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r APP_NAME RESOURCE_GROUP; do
                if [ -z "$APP_NAME" ]; then continue; fi
                
                local status="info" 
                local detail=""
                local evidence=""

                # 1. linuxFxVersion 또는 windowsFxVersion으로 최신 런타임 정보 조회
                RUNTIME_INFO=$(az functionapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "siteConfig.linuxFxVersion || siteConfig.windowsFxVersion" -o tsv 2>/dev/null)
                
                # 2. FxVersion 정보가 없는 경우, FUNCTIONS_EXTENSION_VERSION 확인
                EXT_VERSION=$(az functionapp config appsettings list --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "[?name=='FUNCTIONS_EXTENSION_VERSION'].value" -o tsv 2>/dev/null)

                if [ -n "$RUNTIME_INFO" ] && [ "$RUNTIME_INFO" != "null" ]; then
                    detail="런타임(${RUNTIME_INFO}) 사용 중. 공식 문서를 참고하여 지원 중단(EOS) 여부 직접 확인 필요"
                    evidence="RuntimeFxVersion: ${RUNTIME_INFO}"
                elif [ -n "$EXT_VERSION" ]; then
                    detail="런타임 버전(${EXT_VERSION}) 사용 중. 공식 문서를 참고하여 지원 중단(EOS) 여부 직접 확인 필요"
                    evidence="FUNCTIONS_EXTENSION_VERSION: ${EXT_VERSION}"
                else
                    detail="런타임 버전을 확인할 수 없음 (수동 확인 필요)"
                    evidence="N/A"
                fi
                
                echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
            done <<< "$FUNCTION_APPS_INFO"
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-036] 환경변수 내 중요정보 암호화 적용 여부
check_pism_036() {
    local check_id="pism-036"
    local check_name="환경변수 내 중요정보 암호화 적용 여부"
    
    declare -a SENSITIVE_PATTERNS=(
        "password" "passwd" "pwd" "secret" "credential" "token" "auth" "key"
        "api_key" "client_id" "client_secret" "bearer" "session" "jwt"
        "azure_client_id" "azure_client_secret" "azure_tenant_id" "ldap_password" "ad_password"
        "db_user" "db_pass" "db_password" "db_host" "conn_string" "database_url"
        "redis_password" "ssn" "jumin" "resident_registration_number"
        "credit_card" "card_number" "cvv" "cvc" "account_number" "bank_account"
        "pin_number" "private_key" "public_key" "certificate" "passphrase"
        "keystore" "truststore" "pgp_key" "stripe_key" "trade_key" "trading_secret"
    )

    {
        start_timer
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az functionapp config appsettings list, az functionapp list]]></Command>"
        echo "      <Results>"

        echo '        <SubCheck service="Functions">'
        FUNCTION_APPS_INFO=$(az functionapp list --query "[].{Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$FUNCTION_APPS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 함수 앱 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r APP_NAME RESOURCE_GROUP; do
                if [ -z "$APP_NAME" ]; then continue; fi
                
                # 키 이름과 값을 모두 가져와서 Evidence에 포함
                SETTINGS_TABLE=$(az functionapp config appsettings list --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "[].{Name:name, Value:value}" -o tsv 2>/dev/null)
                
                local found_keys=""
                if [ -n "$SETTINGS_TABLE" ]; then
                    while IFS=$'\t' read -r key value; do
                        local lower_key=$(echo "$key" | tr '[:upper:]' '[:lower:]')
                        local is_sensitive=false

                        # 1. 키 이름 패턴 검사
                        for pattern in "${SENSITIVE_PATTERNS[@]}"; do
                            if [[ "$lower_key" == *"$pattern"* ]]; then
                                is_sensitive=true
                                break
                            fi
                        done

                        # 2. 값 패턴 검사: 32자 이상의 영숫자+특수문자 조합 (평문 의심)
                        if [ "$is_sensitive" = false ] && [ -n "$value" ]; then
                            # Key Vault 참조나 URL이 아닌 경우에만 검사
                            if [[ "$value" != "@Microsoft.KeyVault("* ]] && [[ "$value" != "http"* ]] && [[ "$value" != "https"* ]]; then
                                # 32자 이상이고 영숫자+특수문자가 섞여있으면 의심
                                if [ ${#value} -ge 32 ] && [[ "$value" =~ [a-zA-Z] ]] && [[ "$value" =~ [0-9] ]]; then
                                    is_sensitive=true
                                fi
                            fi
                        fi

                        # 의심 키로 추가 (Key Vault 참조가 아닌 경우만)
                        if [ "$is_sensitive" = true ] && [[ "$value" != "@Microsoft.KeyVault("* ]]; then
                            if [ -z "$found_keys" ]; then found_keys="$key"; else found_keys+=", $key"; fi
                        fi
                    done <<< "$SETTINGS_TABLE"
                fi

                # 사용자 요청에 따른 출력 로직
                if [ -n "$found_keys" ]; then
                    status="review"
                    summary_string+="review|Unknown|N/A"$'\n'
                    detail="의심되는 환경변수 키 [${found_keys}] 발견. 환경 변수 내 중요정보의 암호화 미적용 여부 검토 필요"
                else
                    status="review"
                    summary_string+="review|Unknown|N/A"$'\n'
                    detail="자동화된 패턴 검사에서 의심되는 환경변수 미발견. 환경 변수 내 중요정보의 암호화 미적용 여부 검토 필요"
                fi
                
                echo "          <Item status=\"${status}\"><ResourceID>${APP_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${SETTINGS_TABLE}]]></Evidence></Item>"
            done <<< "$FUNCTION_APPS_INFO"
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-037] 비밀번호 정책 수립 및 로그인 제한 설정 (로그인 실패 횟수 제한 설정)
check_pism_037() {
    local check_id="pism-037"
    local check_name="비밀번호 정책 수립 및 로그인 제한 설정 (로그인 실패 횟수 제한 설정)"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[Manual Check Required in Azure Portal]]></Command>"
        echo "      <Results>"

        echo '        <SubCheck service="EntraID">'
        echo "          <Item status=\"review\">"
        echo "            <ResourceID>Entra ID Tenant Policy</ResourceID>"
        echo "            <Detail>Entra ID의 '스마트 잠금' 임계값 설정은 API를 통한 자동 점검을 지원하지 않으므로, 내규에 맞게 설정되어 있는지 평가자가 직접 Azure Portal에서 확인 필요</Detail>"
        echo "            <Evidence><![CDATA["
        echo "확인 경로:"
        echo "1. Azure Portal (https://portal.azure.com) 접속"
        echo "2. Microsoft Entra ID 진입"
        echo "3. 좌측 메뉴: '관리' 하위 '보안 (Security)' 클릭"
        echo "4. 좌측 메뉴: '관리' 하위 '인증 방법 (Authentication methods)' 클릭"
        echo "5. 좌측 메뉴: '관리' 하위 '암호 보호 (Password protection)' 클릭"
        echo "6. '사용자 지정 스마트 잠금' 섹션에서 '잠금 임계값' 및 '잠금 기간(초)' 확인"
        echo ""
        echo "]]></Evidence>"
        echo "          </Item>"
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-039] 클라우드 자원에 접근 가능한 계정에 추가인증수단 미적용
check_pism_039() {
    local check_id="pism-039"
    local check_name="클라우드 자원에 접근 가능한 계정에 추가인증수단 미적용"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[Manual Check Required in Azure Portal]]></Command>"
        echo "      <Results>"

        echo '        <SubCheck service="EntraID">'
        echo "          <Item status=\"review\">"
        echo "            <ResourceID>All Entra ID Users</ResourceID>"
        echo "            <Detail>'사용자별 MFA' 상태는 API를 통한 자동 점검을 지원하지 않으므로, 평가자가 직접 Azure Portal에서 확인 필요. 특히 Owner/Contributor 역할을 가진 관리자 계정의 MFA 설정을 우선 확인 필요</Detail>"
        echo "            <Evidence><![CDATA["
        echo "확인 경로:"
        echo "1. Azure Portal (https://portal.azure.com) 접속"
        echo "2. Microsoft Entra ID 진입"
        echo "3. 좌측 메뉴: '관리' 하위 '사용자 (Users)' 클릭"
        echo "4. 좌측 메뉴: '모든 사용자 (All users)' 클릭"
        echo "5. 상단 메뉴: '사용자별 MFA (Per-user MFA)' 클릭"
        echo "6. 사용자별 다단계 인증 상태 확인"
        echo "   - 사용 (Enabled): MFA 등록 필요"
        echo "   - 적용 (Enforced): MFA 적용됨"
        echo "   - 사용 안 함 (Disabled): MFA 미적용"
        echo ""
        echo "]]></Evidence>"
        echo "          </Item>"
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-042] API 자격 증명 관리 설정 및 갱신 여부
check_pism_042() {
    local check_id="pism-042"
    local check_name="API 자격 증명 다중 발급 방지 여부"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az ad app list, az ad app show]]></Command>"
        echo "      <Results>"

        # --- SubCheck: App Registrations ---
        echo '        <SubCheck service="AppRegistration">'

        # 모든 앱 등록 조회
        APPS_OUTPUT=$(az ad app list --query '[].{appId:appId,displayName:displayName}' -o json 2>&1)
        APPS_EXIT_CODE=$?

        if [ $APPS_EXIT_CODE -ne 0 ]; then
            # 권한 부족 에러 확인
            if echo "$APPS_OUTPUT" | grep -qi "Insufficient privileges\|Authorization_RequestDenied\|Forbidden"; then
                echo '          <Item status="error"><ResourceID>N/A</ResourceID><Detail>권한 부족: Service Principal에 Microsoft Graph API 권한(Application.Read.All 또는 Directory.Read.All) 필요</Detail><Evidence><![CDATA['"$APPS_OUTPUT"']]></Evidence></Item>'
                summary_string+="error|AppRegistration|N/A"$'\n'
            else
                echo '          <Item status="error"><ResourceID>N/A</ResourceID><Detail>앱 등록 목록 조회 실패</Detail><Evidence><![CDATA['"$APPS_OUTPUT"']]></Evidence></Item>'
                summary_string+="error|AppRegistration|N/A"$'\n'
            fi
        elif [ -z "$APPS_OUTPUT" ] || [ "$APPS_OUTPUT" == "[]" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>앱 등록 없음</Detail><Evidence>No app registrations found.</Evidence></Item>'
            summary_string+="info|AppRegistration|N/A"$'\n'
        else
            # 각 앱 등록의 자격 증명 개수 확인
            echo "$APPS_OUTPUT" | jq -c '.[]' | while read -r app; do
                app_id=$(echo "$app" | jq -r '.appId')
                display_name=$(echo "$app" | jq -r '.displayName')

                # 상세 정보 조회 (자격 증명 포함)
                APP_DETAIL=$(az ad app show --id "$app_id" --query '{passwordCredentials:passwordCredentials,keyCredentials:keyCredentials}' -o json 2>/dev/null)

                if [ -n "$APP_DETAIL" ] && [ "$APP_DETAIL" != "null" ]; then
                    # passwordCredentials 개수
                    PASSWORD_COUNT=$(echo "$APP_DETAIL" | jq -r '.passwordCredentials | length')
                    # keyCredentials 개수
                    KEY_COUNT=$(echo "$APP_DETAIL" | jq -r '.keyCredentials | length')

                    # 총 자격 증명 개수
                    TOTAL_CRED_COUNT=$((PASSWORD_COUNT + KEY_COUNT))

                    local status
                    local detail

                    # 판단: 2개 이상이면 취약
                    if [ "$TOTAL_CRED_COUNT" -ge 2 ]; then
                        status="bad"
                        detail="자격증명 ${TOTAL_CRED_COUNT}개 (password: ${PASSWORD_COUNT}, key: ${KEY_COUNT}) - 다중 발급됨"
                        summary_string+="bad|AppRegistration|${app_id}"$'\n'
                    elif [ "$TOTAL_CRED_COUNT" -eq 1 ]; then
                        status="good"
                        detail="자격증명 1개 (password: ${PASSWORD_COUNT}, key: ${KEY_COUNT}) - 단일 자격증명 사용"
                        summary_string+="good|AppRegistration|${app_id}"$'\n'
                    else
                        status="info"
                        detail="자격증명 없음 (Managed Identity 또는 인증서 기반)"
                        summary_string+="info|AppRegistration|${app_id}"$'\n'
                    fi

                    echo "          <Item status=\"${status}\">"
                    echo "            <ResourceID>${display_name} (${app_id})</ResourceID>"
                    echo "            <Detail>${detail}</Detail>"
                    echo "            <Evidence><![CDATA[passwordCredentials: ${PASSWORD_COUNT}, keyCredentials: ${KEY_COUNT}, Total: ${TOTAL_CRED_COUNT}]]></Evidence>"
                    echo "          </Item>"
                else
                    status="error"
                    detail="앱 상세 정보 조회 실패"
                    summary_string+="error|AppRegistration|${app_id}"$'\n'
                    echo "          <Item status=\"${status}\"><ResourceID>${display_name} (${app_id})</ResourceID><Detail>${detail}</Detail><Evidence>Failed to retrieve app details</Evidence></Item>"
                fi
            done
        fi

        echo '        </SubCheck>'

        echo "      </Results>"
        print_summary "$summary_string"
        end_timer_and_print
        echo "    </CheckResult>"
    } >> "$OUTFILE"
}

# [pism-043] API 자격 증명의 정기적 갱신 미흡 여부
check_pism_043() {
    local check_id="pism-043"
    local check_name="API 자격 증명의 정기적 갱신 미흡 여부"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az ad app show, az ad sp list, az keyvault list, az keyvault secret list, az keyvault secret show]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Service Principal 갱신 주기 ---
        echo '        <SubCheck service="ServicePrincipal">'

        SP_LIST=$(az ad sp list --all --query "[?appOwnerOrganizationId=='$AZURE_TENANT_ID'].{DisplayName:displayName, AppId:appId}" -o json 2>&1)
        SP_EXIT_CODE=$?

        if [ $SP_EXIT_CODE -ne 0 ]; then
            # 권한 부족 에러 확인
            if echo "$SP_LIST" | grep -qi "Insufficient privileges\|Authorization_RequestDenied\|Forbidden"; then
                echo '          <Item status="error"><ResourceID>N/A</ResourceID><Detail>권한 부족: Service Principal에 Microsoft Graph API 권한(Application.Read.All 또는 Directory.Read.All) 필요</Detail><Evidence><![CDATA['"$SP_LIST"']]></Evidence></Item>'
                summary_string+="error|ServicePrincipal|N/A"$'\n'
            else
                echo '          <Item status="error"><ResourceID>N/A</ResourceID><Detail>Service Principal 목록 조회 실패</Detail><Evidence><![CDATA['"$SP_LIST"']]></Evidence></Item>'
                summary_string+="error|ServicePrincipal|N/A"$'\n'
            fi
        elif [ -z "$SP_LIST" ] || [ "$SP_LIST" == "[]" ]; then
            echo '          <Item status="review"><ResourceID>N/A</ResourceID><Detail>Service Principal 조회 결과 없음 (권한 제한으로 일부만 조회될 수 있음. 정확한 점검을 위해 Microsoft Graph API 권한 필요)</Detail><Evidence>빈 리스트 반환. Reader 역할은 제한된 SP만 조회 가능</Evidence></Item>'
            summary_string+="review|ServicePrincipal|N/A"$'\n'
        else
            echo "$SP_LIST" | jq -c '.[]' | while read -r sp; do
                display_name=$(echo "$sp" | jq -r '.DisplayName')
                app_id=$(echo "$sp" | jq -r '.AppId')

                credentials=$(az ad app show --id "$app_id" --query "passwordCredentials" -o json 2>/dev/null)

                local status="good"
                local detail="자격 증명 갱신 주기 확인 완료"
                local evidence=""

                if [ -z "$credentials" ] || [ "$credentials" == "null" ] || [ "$credentials" == "[]" ]; then
                    status="info"
                    summary_string+="info|ServicePrincipal|N/A"$'\n'
                    detail="Client Secret 미등록"
                    evidence="passwordCredentials: []"
                else
                    local current_time=$(date -u +%s)
                    local has_old_cred=false
                    local cred_details=""

                    echo "$credentials" | jq -c '.[]' | while read -r cred; do
                        start_date=$(echo "$cred" | jq -r '.startDateTime')
                        end_date=$(echo "$cred" | jq -r '.endDateTime')
                        hint=$(echo "$cred" | jq -r '.hint // "N/A"')

                        if [ "$start_date" != "null" ]; then
                            # 생성일을 Unix timestamp로 변환
                            if date --version 2>&1 | grep -q GNU; then
                                start_time=$(date -d "$start_date" +%s 2>/dev/null)
                            else
                                start_time=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "${start_date%.*}Z" +%s 2>/dev/null)
                            fi

                            if [ -n "$start_time" ]; then
                                days_since_create=$(( (current_time - start_time) / 86400 ))

                                cred_details+="Hint: ${hint}, 생성일: ${start_date}, 만료일: ${end_date}"

                                if [ $days_since_create -gt 90 ]; then
                                    cred_details+=" [90일 이상 미갱신]"
                                    has_old_cred=true
                                else
                                    cred_details+=" [최근 생성/갱신]"
                                fi
                                cred_details+=""$'\n'
                            fi
                        fi
                    done

                    if [ "$has_old_cred" = true ]; then
                        status="review"
                        summary_string+="review|Unknown|N/A"$'\n'
                        detail="90일 이상 갱신되지 않은 Client Secret 존재. 정기적 갱신 정책 검토 필요"
                    else
                        status="good"
                        summary_string+="good|Unknown|N/A"$'\n'
                        detail="모든 Client Secret이 최근(90일 이내) 생성/갱신됨"
                    fi

                    evidence="$cred_details"
                fi

                echo "          <Item status=\"${status}\"><ResourceID>${display_name} (${app_id})</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[${evidence}]]></Evidence></Item>"
            done
        fi

        echo '        </SubCheck>'

        # --- SubCheck: Key Vault Secret 갱신 주기 ---
        echo '        <SubCheck service="KeyVault">'

        KEY_VAULTS=$(az keyvault list --query "[].name" -o tsv 2>/dev/null)

        if [ -z "$KEY_VAULTS" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 Key Vault 미존재</Detail><Evidence>N/A</Evidence></Item>'
        else
            for vault_name in $KEY_VAULTS; do
                secrets=$(az keyvault secret list --vault-name "$vault_name" --query "[].{Name:name, Id:id}" -o json 2>/dev/null)

                if [ -z "$secrets" ] || [ "$secrets" == "[]" ]; then
                    echo "          <Item status=\"info\"><ResourceID>${vault_name}</ResourceID><Detail>저장된 Secret 미존재</Detail><Evidence>N/A</Evidence></Item>"
                else
                    local vault_status="good"
                    local vault_detail=""
                    local secret_details=""
                    local old_secret_count=0

                    echo "$secrets" | jq -c '.[]' | while read -r secret; do
                        secret_name=$(echo "$secret" | jq -r '.Name')

                        # Secret 상세 정보 조회
                        secret_info=$(az keyvault secret show --vault-name "$vault_name" --name "$secret_name" -o json 2>/dev/null)

                        if [ -n "$secret_info" ]; then
                            created=$(echo "$secret_info" | jq -r '.attributes.created // "N/A"')
                            updated=$(echo "$secret_info" | jq -r '.attributes.updated // "N/A"')

                            if [ "$created" != "N/A" ] && [ "$created" != "null" ]; then
                                # Unix timestamp를 날짜로 변환
                                if date --version 2>&1 | grep -q GNU; then
                                    created_date=$(date -d "@$created" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
                                else
                                    created_date=$(date -r "$created" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
                                fi

                                # 최종 업데이트 시점 기준으로 갱신 주기 판단
                                update_time=$updated
                                if [ "$update_time" == "null" ] || [ -z "$update_time" ]; then
                                    update_time=$created
                                fi

                                current_time=$(date -u +%s)
                                days_since_update=$(( (current_time - update_time) / 86400 ))

                                secret_details+="- ${secret_name}: 생성 ${created_date}"

                                if [ $days_since_update -gt 90 ]; then
                                    secret_details+=" [90일 이상 미갱신]"
                                    old_secret_count=$((old_secret_count + 1))
                                else
                                    secret_details+=" [최근 갱신]"
                                fi
                                secret_details+=""$'\n'
                            fi
                        fi
                    done

                    if [ $old_secret_count -gt 0 ]; then
                        vault_status="review"
                        vault_detail="${old_secret_count}개의 Secret이 90일 이상 갱신되지 않음. 정기적 갱신 정책 검토 필요"
                    else
                        vault_status="good"
                        vault_detail="모든 Secret이 최근(90일 이내) 생성/갱신됨"
                    fi

                    echo "          <Item status=\"${vault_status}\"><ResourceID>${vault_name}</ResourceID><Detail>${vault_detail}</Detail><Evidence><![CDATA[${secret_details}]]></Evidence></Item>"
                fi
            done
        fi

        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}


# [pism-045] 그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용
check_pism_045() {
    local check_id="pism-045"
    local check_name="그룹 및 속성 기반 권한 부여 및 최소 권한 정책 적용"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo '      <Command><![CDATA[az extension add, az extension show, az functionapp identity show, az functionapp list, az identity show, az network bastion list, az role assignment list, az role definition list, az storage account list, az storage account network-rule list, az storage container-rm list, az storage container-rm show, az vm identity show, az vm list, az webapp auth show]]></Command>'
        echo "      <Results>"

        # --- SubCheck: Entra ID ---
        echo '        <SubCheck service="EntraID">'

        ROLE_ASSIGNMENTS=$(az role assignment list --all --include-inherited --query "[?principalType=='User' || principalType=='Group'].{Role:roleDefinitionName, Principal:principalName, PrincipalId:principalId, Type:principalType, Scope:scope}" --output tsv 2>/dev/null)

        if [ -z "$ROLE_ASSIGNMENTS" ]; then
            echo '          <Item status="info"><Evidence>No role assignments found for users/groups</Evidence><ResourceID>N/A</ResourceID><Detail>사용자 또는 그룹에 할당된 역할이 없습니다.</Detail></Item>'
        else
            echo "$ROLE_ASSIGNMENTS" | while IFS=$'\t' read -r role_name principal_name principal_id principal_type scope; do
                if [ -z "$role_name" ]; then continue; fi

                evidence="Principal: ${principal_name:-$principal_id}"$'\n'
                evidence+="Type: ${principal_type}"$'\n'
                evidence+=$'\n'"Role: ${role_name}"$'\n'
                evidence+="Scope: ${scope}"$'\n'

                is_custom=$(az role definition list --name "$role_name" --query "[0].roleType" -o tsv 2>/dev/null)

                if [[ "$is_custom" == "CustomRole" ]]; then
                    role_permissions=$(az role definition list --name "$role_name" --query "[0].permissions[].actions[]" -o tsv 2>/dev/null | tr '\n' ', ')
                    evidence+="Role Type: Custom"$'\n'
                    evidence+="Permissions: ${role_permissions:-No specific actions}"$'\n'
                else
                    evidence+="Role Type: Built-in"$'\n'
                fi

                echo "          <Item status=\"review\">"
                echo "            <ResourceID>${principal_name:-$principal_id}</ResourceID>"
                echo "            <Detail>Entra ID 역할 할당 확인. 그룹 기반 관리 원칙 및 최소 권한 부여 여부 검토 필요</Detail>"
                printf '            <Evidence><![CDATA[%s]]></Evidence>\n' "$evidence"
                echo "          </Item>"
            done
        fi

        echo '        </SubCheck>'

        # --- SubCheck: Functions ---
        echo '        <SubCheck service="Functions">'
        FUNCTION_APPS_INFO=$(az functionapp list --query "[].{Name:name, ResourceGroup:resourceGroup, Id:id}" --output tsv 2>/dev/null)
        if [ -z "$FUNCTION_APPS_INFO" ]; then
            echo '          <Item status="info"><Evidence>NA</Evidence><ResourceID>N/A</ResourceID><Detail>점검할 함수 앱 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r APP_NAME RESOURCE_GROUP RES_ID; do
                if [ -z "$APP_NAME" ]; then continue; fi
                echo "          <Asset resource_id=\"${APP_NAME}\" resource_group=\"${RESOURCE_GROUP}\">"

                # Check: [Functions] 함수 앱의 호출 권한 제한 설정 확인 (인증 - 익명 호출 차단)
                AUTH_SETTINGS_RAW=$(az webapp auth show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "{Enabled:enabled, Action:unauthenticatedClientAction}" -o json 2>/dev/null)
                auth_enabled=$(echo "$AUTH_SETTINGS_RAW" | grep '"enabled":' | awk '{print $2}' | tr -d '," ')
                unauth_action=$(echo "$AUTH_SETTINGS_RAW" | grep '"unauthenticatedClientAction":' | awk -F'"' '{print $4}')
                local auth_status="bad"; local auth_detail=""
                if [[ "$auth_enabled" == "true" ]] && [[ "$unauth_action" == "AllowAnonymous" || "$unauth_action" == "null" || -z "$unauth_action" ]]; then
                     auth_detail="[호출-인증] App Service 인증 활성화, 그러나 익명 접근 허용"
                elif [[ "$auth_enabled" != "true" ]]; then
                    auth_detail="[호출-인증] App Service 인증 비활성화, 익명 접근 허용"
                else
                    auth_status="good"; auth_detail="[호출-인증] App Service 인증으로 익명 접근 차단"
                fi
                echo "            <Item status=\"${auth_status}\"><Evidence><![CDATA[${AUTH_SETTINGS_RAW}]]></Evidence><ResourceID>Authentication</ResourceID><Detail>${auth_detail}</Detail></Item>"

                # Check: [Functions] 함수 앱의 호출 권한 제한 설정 확인 (인가 - 리소스 RBAC)
                RESOURCE_ROLES=$(az role assignment list --scope "$RES_ID" --include-inherited --query "[].{Role:roleDefinitionName, PrincipalName:principalName, PrincipalId:principalId, Type:principalType}" --output tsv 2>/dev/null)
                if [ -z "$RESOURCE_ROLES" ]; then
                    echo "            <Item status=\"good\"><Evidence>No role assignments found on this resource scope (incl. inherited)</Evidence><ResourceID>ResourceRBAC</ResourceID><Detail>[호출-인가] 함수 앱 리소스 범위에 할당된 역할 없음 (상속 포함)</Detail></Item>"
                else
                     while IFS=$'\t' read -r role_name principal_name principal_id principal_type; do
                        principal_display_name="${principal_name:-$principal_id}"
                        local evidence_string="Role: ${role_name}, Principal: ${principal_display_name} (ID: ${principal_id}), Type: ${principal_type}"
                        echo "            <Item status=\"review\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>ResourceRBAC</ResourceID><Detail>[호출-인가] 함수 앱 범위에 할당된 역할. 인가된 주체인지 검토 필요.</Detail></Item>"
                    done <<< "$RESOURCE_ROLES"
                fi

                # Check: [Functions] 함수 앱의 실행 권한 확인 (관리 ID)
                SYSTEM_ID=$(az functionapp identity show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "principalId" -o tsv 2>/dev/null)
                USER_ID_URIS=$(az functionapp identity show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "keys(userAssignedIdentities)" -o tsv 2>/dev/null)

                if [[ "$SYSTEM_ID" == "null" || -z "$SYSTEM_ID" ]] && [ -z "$USER_ID_URIS" ]; then
                    echo "            <Item status=\"good\"><Evidence>Managed Identity not enabled</Evidence><ResourceID>ManagedIdentity</ResourceID><Detail>[실행 역할] 관리 ID가 할당되지 않음</Detail></Item>"
                else
                    # 시스템 할당 ID 역할 점검
                    if [ -n "$SYSTEM_ID" ] && [ "$SYSTEM_ID" != "null" ]; then
                        ASSIGNED_ROLES=$(az role assignment list --assignee "$SYSTEM_ID" --query "[].{Role:roleDefinitionName, Scope:scope, PrincipalName:principalName, PrincipalId:principalId, Type:principalType}" -o tsv 2>/dev/null)
                        if [ -z "$ASSIGNED_ROLES" ]; then
                             echo "            <Item status=\"good\"><Evidence>Principal ID: ${SYSTEM_ID}</Evidence><ResourceID>SystemIdentity</ResourceID><Detail>[실행 역할] 시스템 할당 ID는 있으나, 할당된 역할 미존재</Detail></Item>"
                        else
                            while IFS=$'\t' read -r role_name scope principal_name principal_id principal_type; do
                                is_custom_role=$(az role definition list --name "$role_name" --query "[0].isCustom" -o tsv 2>/dev/null)
                                role_type=$([ "$is_custom_role" == "true" ] && echo "Custom" || echo "Built-in")
                                principal_display_name="${principal_name:-$principal_id}"
                                local evidence_string="IdentityType: System, Principal: ${principal_display_name} (ID: ${principal_id}), Role: ${role_name}, Type: ${role_type}, Scope: ${scope}"
                                local role_detail="[실행 역할] 시스템 할당 ID 역할. 최소 권한인지 검토 필요."
                                local item_status="review"

                                # 과도한 권한 탐지
                                if [[ "$role_name" == "Owner" || "$role_name" == "Contributor" || "$role_name" =~ "Administrator" ]]; then
                                    item_status="bad"
                                    role_detail="[실행 역할 - 고위험] 과도한 권한('${role_name}') 부여. 최소 권한 원칙 위배 가능성 높음"
                                fi

                                if [ "$is_custom_role" == "true" ]; then
                                    role_permissions=$(az role definition list --name "$role_name" --query "[0].permissions[].actions[]" -o tsv 2>/dev/null | tr '\n' ' ')
                                    evidence_string+=", Permissions: ${role_permissions:-No specific actions}"
                                    role_detail+=" (사용자 지정 역할 상세 권한 확인)"

                                    # Custom Role에 와일드카드(*) 권한이 있는지 확인
                                    if [[ "$role_permissions" == *"*"* ]]; then
                                        item_status="bad"
                                        role_detail+=" [경고: 와일드카드(*) 권한 포함 - 과도한 권한]"
                                    fi
                                fi
                                echo "            <Item status=\"${item_status}\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>SystemIdentityRole</ResourceID><Detail>${role_detail}</Detail></Item>"
                            done <<< "$ASSIGNED_ROLES"
                        fi
                    fi
                    # 사용자 할당 ID 역할 점검
                    if [ -n "$USER_ID_URIS" ]; then
                        for user_assigned_id_uri in $USER_ID_URIS; do
                            USER_PRINCIPAL_ID=$(az identity show --ids "$user_assigned_id_uri" --query "principalId" -o tsv 2>/dev/null)
                            USER_ID_NAME=$(az identity show --ids "$user_assigned_id_uri" --query "name" -o tsv 2>/dev/null)
                            if [ -n "$USER_PRINCIPAL_ID" ]; then
                                ASSIGNED_ROLES=$(az role assignment list --assignee "$USER_PRINCIPAL_ID" --query "[].{Role:roleDefinitionName, Scope:scope, PrincipalName:principalName, PrincipalId:principalId, Type:principalType}" -o tsv 2>/dev/null)
                                if [ -z "$ASSIGNED_ROLES" ]; then
                                    echo "            <Item status=\"good\"><Evidence>Identity: ${USER_ID_NAME}, Principal ID: ${USER_PRINCIPAL_ID}</Evidence><ResourceID>UserIdentity_${USER_ID_NAME}</ResourceID><Detail>[실행 역할] 사용자 할당 ID(${USER_ID_NAME})는 있으나, 할당된 역할 미존재</Detail></Item>"
                                else
                                    while IFS=$'\t' read -r role_name scope principal_name principal_id principal_type; do
                                        is_custom_role=$(az role definition list --name "$role_name" --query "[0].isCustom" -o tsv 2>/dev/null)
                                        role_type=$([ "$is_custom_role" == "true" ] && echo "Custom" || echo "Built-in")
                                        principal_display_name="${principal_name:-$principal_id}"
                                        local evidence_string="IdentityType: User (${USER_ID_NAME}), Principal: ${principal_display_name} (ID: ${principal_id}), Role: ${role_name}, Type: ${role_type}, Scope: ${scope}"
                                        local role_detail="[실행 역할] 사용자 할당 ID(${USER_ID_NAME}) 역할. 최소 권한인지 검토 필요."
                                        local item_status="review"

                                        # 과도한 권한 탐지
                                        if [[ "$role_name" == "Owner" || "$role_name" == "Contributor" || "$role_name" =~ "Administrator" ]]; then
                                            item_status="bad"
                                            role_detail="[실행 역할 - 고위험] 과도한 권한('${role_name}') 부여. 최소 권한 원칙 위배 가능성 높음"
                                        fi

                                         if [ "$is_custom_role" == "true" ]; then
                                            role_permissions=$(az role definition list --name "$role_name" --query "[0].permissions[].actions[]" -o tsv 2>/dev/null | tr '\n' ' ')
                                            evidence_string+=", Permissions: ${role_permissions:-No specific actions}"
                                            role_detail+=" (사용자 지정 역할 상세 권한 확인)"

                                            # Custom Role에 와일드카드(*) 권한이 있는지 확인
                                            if [[ "$role_permissions" == *"*"* ]]; then
                                                item_status="bad"
                                                role_detail+=" [경고: 와일드카드(*) 권한 포함 - 과도한 권한]"
                                            fi
                                        fi
                                        echo "            <Item status=\"${item_status}\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>UserIdentityRole_${USER_ID_NAME}</ResourceID><Detail>${role_detail}</Detail></Item>"
                                    done <<< "$ASSIGNED_ROLES"
                                fi
                            fi
                        done
                    fi
                fi
                echo "          </Asset>"
            done <<< "$FUNCTION_APPS_INFO"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Virtual Machines ---
        echo '        <SubCheck service="VirtualMachines">'
        VMS_INFO=$(az vm list --query "[].{Name:name, ResourceGroup:resourceGroup, Id:id}" --output tsv 2>/dev/null)
        if [ -z "$VMS_INFO" ]; then
            echo '          <Item status="info"><Evidence>NA</Evidence><ResourceID>N/A</ResourceID><Detail>점검할 가상 머신 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r VM_NAME RESOURCE_GROUP RES_ID; do
                if [ -z "$VM_NAME" ]; then continue; fi
                echo "          <Asset resource_id=\"${VM_NAME}\" resource_group=\"${RESOURCE_GROUP}\">"

                # Check: [Virtual Machine] 컴퓨팅 인스턴스의 실행 권한 확인 (관리 ID)
                SYSTEM_ID=$(az vm identity show --name "$VM_NAME" --resource-group "$RESOURCE_GROUP" --query "principalId" -o tsv 2>/dev/null)
                USER_ID_URIS=$(az vm identity show --name "$VM_NAME" --resource-group "$RESOURCE_GROUP" --query "keys(userAssignedIdentities)" -o tsv 2>/dev/null)

                if [[ "$SYSTEM_ID" == "null" || -z "$SYSTEM_ID" ]] && [ -z "$USER_ID_URIS" ]; then
                    echo "            <Item status=\"good\"><Evidence>Managed Identity not enabled</Evidence><ResourceID>ManagedIdentity</ResourceID><Detail>[실행 역할] 관리 ID가 할당되지 않음</Detail></Item>"
                else
                     # 시스템 할당 ID 역할 점검
                    if [ -n "$SYSTEM_ID" ] && [ "$SYSTEM_ID" != "null" ]; then
                        ASSIGNED_ROLES=$(az role assignment list --assignee "$SYSTEM_ID" --query "[].{Role:roleDefinitionName, Scope:scope, PrincipalName:principalName, PrincipalId:principalId, Type:principalType}" -o tsv 2>/dev/null)
                        if [ -z "$ASSIGNED_ROLES" ]; then
                             echo "            <Item status=\"good\"><Evidence>Principal ID: ${SYSTEM_ID}</Evidence><ResourceID>SystemIdentity</ResourceID><Detail>[실행 역할] 시스템 할당 ID는 있으나, 할당된 역할 미존재</Detail></Item>"
                        else
                            while IFS=$'\t' read -r role_name scope principal_name principal_id principal_type; do
                                is_custom_role=$(az role definition list --name "$role_name" --query "[0].isCustom" -o tsv 2>/dev/null)
                                role_type=$([ "$is_custom_role" == "true" ] && echo "Custom" || echo "Built-in")
                                principal_display_name="${principal_name:-$principal_id}"
                                local evidence_string="IdentityType: System, Principal: ${principal_display_name} (ID: ${principal_id}), Role: ${role_name}, Type: ${role_type}, Scope: ${scope}"
                                local role_detail="[실행 역할] 시스템 할당 ID 역할. 최소 권한인지 검토 필요."
                                local item_status="review"

                                # 과도한 권한 탐지
                                if [[ "$role_name" == "Owner" || "$role_name" == "Contributor" || "$role_name" =~ "Administrator" ]]; then
                                    item_status="bad"
                                    role_detail="[실행 역할 - 고위험] 과도한 권한('${role_name}') 부여. 최소 권한 원칙 위배 가능성 높음"
                                fi

                                if [ "$is_custom_role" == "true" ]; then
                                    role_permissions=$(az role definition list --name "$role_name" --query "[0].permissions[].actions[]" -o tsv 2>/dev/null | tr '\n' ' ')
                                    evidence_string+=", Permissions: ${role_permissions:-No specific actions}"
                                    role_detail+=" (사용자 지정 역할 상세 권한 확인)"

                                    # Custom Role에 와일드카드(*) 권한이 있는지 확인
                                    if [[ "$role_permissions" == *"*"* ]]; then
                                        item_status="bad"
                                        role_detail+=" [경고: 와일드카드(*) 권한 포함 - 과도한 권한]"
                                    fi
                                fi
                                echo "            <Item status=\"${item_status}\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>SystemIdentityRole</ResourceID><Detail>${role_detail}</Detail></Item>"
                            done <<< "$ASSIGNED_ROLES"
                        fi
                    fi
                    # 사용자 할당 ID 역할 점검
                    if [ -n "$USER_ID_URIS" ]; then
                        for user_assigned_id_uri in $USER_ID_URIS; do
                             USER_PRINCIPAL_ID=$(az identity show --ids "$user_assigned_id_uri" --query "principalId" -o tsv 2>/dev/null)
                             USER_ID_NAME=$(az identity show --ids "$user_assigned_id_uri" --query "name" -o tsv 2>/dev/null)
                            if [ -n "$USER_PRINCIPAL_ID" ]; then
                                ASSIGNED_ROLES=$(az role assignment list --assignee "$USER_PRINCIPAL_ID" --query "[].{Role:roleDefinitionName, Scope:scope, PrincipalName:principalName, PrincipalId:principalId, Type:principalType}" -o tsv 2>/dev/null)
                                if [ -z "$ASSIGNED_ROLES" ]; then
                                    echo "            <Item status=\"good\"><Evidence>Identity: ${USER_ID_NAME}, Principal ID: ${USER_PRINCIPAL_ID}</Evidence><ResourceID>UserIdentity_${USER_ID_NAME}</ResourceID><Detail>[실행 역할] 사용자 할당 ID(${USER_ID_NAME})는 있으나, 할당된 역할 미존재</Detail></Item>"
                                else
                                    while IFS=$'\t' read -r role_name scope principal_name principal_id principal_type; do
                                        is_custom_role=$(az role definition list --name "$role_name" --query "[0].isCustom" -o tsv 2>/dev/null)
                                        role_type=$([ "$is_custom_role" == "true" ] && echo "Custom" || echo "Built-in")
                                        principal_display_name="${principal_name:-$principal_id}"
                                        local evidence_string="IdentityType: User (${USER_ID_NAME}), Principal: ${principal_display_name} (ID: ${principal_id}), Role: ${role_name}, Type: ${role_type}, Scope: ${scope}"
                                        local role_detail="[실행 역할] 사용자 할당 ID(${USER_ID_NAME}) 역할. 최소 권한인지 검토 필요."
                                        local item_status="review"

                                        # 과도한 권한 탐지
                                        if [[ "$role_name" == "Owner" || "$role_name" == "Contributor" || "$role_name" =~ "Administrator" ]]; then
                                            item_status="bad"
                                            role_detail="[실행 역할 - 고위험] 과도한 권한('${role_name}') 부여. 최소 권한 원칙 위배 가능성 높음"
                                        fi

                                         if [ "$is_custom_role" == "true" ]; then
                                            role_permissions=$(az role definition list --name "$role_name" --query "[0].permissions[].actions[]" -o tsv 2>/dev/null | tr '\n' ' ')
                                            evidence_string+=", Permissions: ${role_permissions:-No specific actions}"
                                            role_detail+=" (사용자 지정 역할 상세 권한 확인)"

                                            # Custom Role에 와일드카드(*) 권한이 있는지 확인
                                            if [[ "$role_permissions" == *"*"* ]]; then
                                                item_status="bad"
                                                role_detail+=" [경고: 와일드카드(*) 권한 포함 - 과도한 권한]"
                                            fi
                                        fi
                                        echo "            <Item status=\"${item_status}\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>UserIdentityRole_${USER_ID_NAME}</ResourceID><Detail>${role_detail}</Detail></Item>"
                                    done <<< "$ASSIGNED_ROLES"
                                fi
                            fi
                        done
                    fi
                fi

                # Check: [Bastions] VM 접근 권한 최소화 (Bastion 경유 사용자 역할)
                # VM 리소스 범위에 할당된 역할 중 사용자/그룹에게 할당된 'VM 로그인' 관련 역할 확인
                VM_LOGIN_ROLES=$(az role assignment list --scope "$RES_ID" --include-inherited --query "[?principalType=='User' || principalType=='Group'].{Role:roleDefinitionName, PrincipalName:principalName, PrincipalId:principalId, Type:principalType}" --output tsv 2>/dev/null | grep -E "Virtual Machine Administrator Login|Virtual Machine User Login")
                if [ -z "$VM_LOGIN_ROLES" ]; then
                    echo "            <Item status=\"info\"><Evidence>No 'VM Login' roles found assigned to users/groups on this VM scope</Evidence><ResourceID>VMLoginRBAC</ResourceID><Detail>[Bastion VM 접근] 이 VM에 사용자/그룹 대상 'VM 관리자/사용자 로그인' 역할 할당 없음</Detail></Item>"
                else
                     while IFS=$'\t' read -r role_name principal_name principal_id principal_type; do
                        principal_display_name="${principal_name:-$principal_id}"
                        local evidence_string="Role: ${role_name}, Principal: ${principal_display_name} (ID: ${principal_id}), Type: ${principal_type}"
                        # 'VM 관리자 로그인'은 광범위하므로 review, 'VM 사용자 로그인'은 비교적 제한적이므로 info 또는 review (상황 따라)
                        local login_status="review"; local login_detail="[Bastion VM 접근] VM 로그인 역할 할당됨. 필요한 사용자/그룹에게 최소한의 역할('VM 사용자 로그인')이 부여되었는지 검토 필요."
                        if [[ "$role_name" == "Virtual Machine User Login" ]]; then
                             login_status="review" # 또는 info, 정책에 따라
                        elif [[ "$role_name" == "Virtual Machine Administrator Login" ]]; then
                             login_status="review" # 관리자 로그인은 항상 검토 필요
                        fi
                        echo "            <Item status=\"${login_status}\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>VMLoginRBAC</ResourceID><Detail>${login_detail}</Detail></Item>"
                    done <<< "$VM_LOGIN_ROLES"
                fi
                echo "          </Asset>"
            done <<< "$VMS_INFO"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Blob Storage ---
        echo '        <SubCheck service="BlobStorage">'
        STORAGE_ACCOUNTS_INFO=$(az storage account list --query "[].{Id:id, Name:name, ResourceGroup:resourceGroup}" --output tsv 2>/dev/null)
        if [ -z "$STORAGE_ACCOUNTS_INFO" ]; then
            echo '          <Item status="info"><Evidence>NA</Evidence><ResourceID>N/A</ResourceID><Detail>점검할 스토리지 계정 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r RES_ID ACCOUNT_NAME RESOURCE_GROUP; do
                if [ -z "$ACCOUNT_NAME" ]; then continue; fi
                 echo "          <Asset resource_id=\"${ACCOUNT_NAME}\" resource_group=\"${RESOURCE_GROUP}\">"

                # Check: [Blob Storage] 저장소 호출 권한 제한 설정 확인 (인가 - 리소스 RBAC)
                ROLE_ASSIGNMENTS=$(az role assignment list --scope "$RES_ID" --include-inherited --query "[].{Role:roleDefinitionName, PrincipalName:principalName, PrincipalId:principalId, Type:principalType}" --output tsv 2>/dev/null)
                if [ -z "$ROLE_ASSIGNMENTS" ]; then
                     echo "            <Item status=\"good\"><Evidence>No role assignments found for this resource scope (incl. inherited)</Evidence><ResourceID>ResourceRBAC</ResourceID><Detail>[접근 권한] 스토리지 계정 범위에 할당된 역할 없음 (상속 포함)</Detail></Item>"
                else
                     while IFS=$'\t' read -r role_name principal_name principal_id principal_type; do
                        principal_display_name="${principal_name:-$principal_id}"
                        local evidence_string="Role: ${role_name}, Principal: ${principal_display_name} (ID: ${principal_id}), Type: ${principal_type}"
                        echo "            <Item status=\"review\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>ResourceRBAC</ResourceID><Detail>[접근 권한] 스토리지 계정 범위에 할당된 역할. 인가된 주체인지 검토 필요.</Detail></Item>"
                    done <<< "$ROLE_ASSIGNMENTS"
                fi

                # Check: [Blob Storage] 저장소 호출 권한 제한 설정 확인 (네트워크 접근 제한)
                DEFAULT_ACTION=$(az storage account network-rule list --account-name "$ACCOUNT_NAME" --resource-group "$RESOURCE_GROUP" --query "defaultAction" -o tsv 2>/dev/null)
                HAS_IP_RULES=$(az storage account network-rule list --account-name "$ACCOUNT_NAME" --resource-group "$RESOURCE_GROUP" --query "length(ipRules)>0" -o tsv 2>/dev/null)
                HAS_VNET_RULES=$(az storage account network-rule list --account-name "$ACCOUNT_NAME" --resource-group "$RESOURCE_GROUP" --query "length(virtualNetworkRules)>0" -o tsv 2>/dev/null)
                local net_status="bad"; local net_detail=""; local net_evidence=""
                printf -v net_evidence "Default Action: %s, Has IP Rules: %s, Has VNet Rules: %s" "$DEFAULT_ACTION" "$HAS_IP_RULES" "$HAS_VNET_RULES"

                if [ "$DEFAULT_ACTION" == "Allow" ]; then
                     net_detail="[네트워크 접근] 기본 작업이 'Allow'로 설정됨. IP/VNet 예외 규칙 검토 필요."
                     if [[ "$HAS_IP_RULES" != "true" ]] && [[ "$HAS_VNET_RULES" != "true" ]]; then
                        net_detail="[네트워크 접근] 기본 작업 'Allow', 예외 규칙 없음. 모든 네트워크 접근 허용."
                     else
                         net_status="review"
                     fi
                else # Deny
                     net_status="good"; net_detail="[네트워크 접근] 기본 작업이 'Deny'로 설정되어 기본 차단됨."
                     if [[ "$HAS_IP_RULES" == "true" ]] || [[ "$HAS_VNET_RULES" == "true" ]]; then
                        net_status="review"; net_detail+=" 단, 허용된 예외 IP/VNet 규칙 검토 필요."
                     fi
                fi
                echo "            <Item status=\"${net_status}\"><Evidence><![CDATA[${net_evidence}]]></Evidence><ResourceID>NetworkRules</ResourceID><Detail>${net_detail}</Detail></Item>"

                # Check: [Blob Storage] 저장소 호출 권한 제한 설정 확인 (컨테이너 공용 접근 차단)
                CONTAINERS=$(az storage container-rm list --storage-account "$ACCOUNT_NAME" --query "[].name" -o tsv 2>/dev/null)
                if [ -z "$CONTAINERS" ]; then
                    echo "            <Item status=\"info\"><Evidence>No containers found</Evidence><ResourceID>PublicAccess</ResourceID><Detail>[공용 접근] 점검할 컨테이너 미존재</Detail></Item>"
                else
                    local found_public_container=0
                    while IFS= read -r container_name; do
                        PUBLIC_ACCESS=$(az storage container-rm show --storage-account "$ACCOUNT_NAME" --name "$container_name" --query "properties.publicAccess || 'None'" -o tsv 2>/dev/null)
                        if [[ "$PUBLIC_ACCESS" == "Blob" || "$PUBLIC_ACCESS" == "Container" ]]; then
                            found_public_container=1
                            local evidence_string="Container: ${container_name}, Public Access Level: ${PUBLIC_ACCESS}"
                            echo "            <Item status=\"bad\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>PublicAccess</ResourceID><Detail>[공용 접근] 컨테이너 '${container_name}'가 익명 접근('${PUBLIC_ACCESS}') 허용</Detail></Item>"
                        fi
                    done <<< "$CONTAINERS"
                    if [ "$found_public_container" -eq 0 ]; then
                        echo "            <Item status=\"good\"><Evidence>Public access set to 'None' for all containers</Evidence><ResourceID>PublicAccess</ResourceID><Detail>[공용 접근] 모든 컨테이너가 'Private(액세스 없음)'으로 설정됨</Detail></Item>"
                    fi
                fi

                echo "          </Asset>"
            done <<< "$STORAGE_ACCOUNTS_INFO"
        fi
        echo '        </SubCheck>'

        # --- SubCheck: Bastions ---
        echo '        <SubCheck service="Bastions">'
        # Bastion 확장 설치 여부 확인
        if ! az extension show -n bastion > /dev/null 2>&1; then
            echo '          <Item status="info"><Evidence>NA</Evidence><ResourceID>N/A</ResourceID><Detail>Bastion 점검 건너뜀 (Azure CLI bastion 확장 미설치. 오프라인 설치: 1) 인터넷 연결된 별도 환경에서 az extension add -n bastion --upgrade 실행, 2) ~/.azure/cliextensions/bastion 디렉터리를 검토 후 대상 시스템의 동일 경로에 반영)</Detail></Item>'
        else
            BASTIONS_INFO=$(az network bastion list --query "[].{Name:name, ResourceGroup:resourceGroup, Id:id}" --output tsv 2>/dev/null)
            if [ -z "$BASTIONS_INFO" ]; then
                echo '          <Item status="info"><Evidence>NA</Evidence><ResourceID>N/A</ResourceID><Detail>점검할 Bastion 호스트 미존재</Detail></Item>'
            else
                while IFS=$'\t' read -r BASTION_NAME RESOURCE_GROUP RES_ID; do
                    if [ -z "$BASTION_NAME" ]; then continue; fi
                    echo "          <Asset resource_id=\"${BASTION_NAME}\" resource_group=\"${RESOURCE_GROUP}\">"

                    # Check: [Bastions] 베스천 호출 권한 제한 설정 확인 (Bastion 리소스 RBAC)
                    ROLE_ASSIGNMENTS=$(az role assignment list --scope "$RES_ID" --include-inherited --query "[].{Role:roleDefinitionName, PrincipalName:principalName, PrincipalId:principalId, Type:principalType}" --output tsv 2>/dev/null)
                    if [ -z "$ROLE_ASSIGNMENTS" ]; then
                        echo "            <Item status=\"good\"><Evidence>No role assignments found for this Bastion resource scope (incl. inherited)</Evidence><ResourceID>BastionRBAC</ResourceID><Detail>[접근 권한] Bastion 리소스 범위에 할당된 역할 없음 (상속 포함)</Detail></Item>"
                    else
                        local found_excessive_role_on_bastion=0
                        while IFS=$'\t' read -r role_name principal_name principal_id principal_type; do
                            principal_display_name="${principal_name:-$principal_id}"
                            local evidence_string="Role: ${role_name}, Principal: ${principal_display_name} (ID: ${principal_id}), Type: ${principal_type}"
                            local item_status="review"; local item_detail="[접근 권한] Bastion 리소스 범위에 할당된 역할. 최소 권한(예: Reader)인지 검토 필요."
                            if [[ "$role_name" == "Owner" || "$role_name" == "Contributor" ]]; then
                                item_status="bad"; item_detail="[접근 권한] Bastion 리소스 범위에 과도한 역할('${role_name}') 할당됨. 최소 권한(Reader 등)으로 제한 필요."
                                found_excessive_role_on_bastion=1
                            fi
                            echo "            <Item status=\"${item_status}\"><Evidence><![CDATA[${evidence_string}]]></Evidence><ResourceID>BastionRBAC</ResourceID><Detail>${item_detail}</Detail></Item>"
                        done <<< "$ROLE_ASSIGNMENTS"
                    fi
                    echo "          </Asset>"
                done <<< "$BASTIONS_INFO"
            fi
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}


# [pism-046] 웹 기반 쉘 환경 권한 통제 여부 
check_pism_046() {
    local check_id="pism-046"
    local check_name="웹 기반 쉘 환경 권한 통제 여부"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az role assignment list, az role definition list]]></Command>"
        echo "      <Results>"

        echo '        <SubCheck service="CloudShell">'

        # User 및 Group principal만 필터링 (ServicePrincipal 제외)
        ROLE_ASSIGNMENTS=$(az role assignment list --all --include-inherited \
            --query "[?principalType=='User' || principalType=='Group'].{Principal:principalName, PrincipalId:principalId, Role:roleDefinitionName, Scope:scope, Type:principalType}" \
            --output tsv 2>/dev/null)

        if [ -z "$ROLE_ASSIGNMENTS" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 역할 할당(User/Group)이 미존재</Detail></Item>'
        else
            local found_cloudshell_access=0
            while IFS=$'\t' read -r PRINCIPAL_NAME PRINCIPAL_ID ROLE_NAME SCOPE PRINCIPAL_TYPE; do
                [ -z "$ROLE_NAME" ] && continue

                # Cloud Shell 사용 가능 여부 판단
                local has_cloudshell_access=0
                STATUS="review"
                DETAIL=""
                EVIDENCE=""

                # 역할이 Built-in인지 확인
                is_custom_role=$(az role definition list --name "$ROLE_NAME" --query "[0].isCustom" -o tsv 2>/dev/null)

                if [ "$is_custom_role" == "true" ]; then
                    # Custom Role의 권한 상세 조회
                    ROLE_DEFINITION_DETAILS=$(az role definition list --name "$ROLE_NAME" \
                        --query "[0].permissions[0].actions" -o json 2>/dev/null)

                    # Cloud Shell 관련 권한 체크: Microsoft.Portal/consoles/write 또는 */write 또는 *
                    if echo "$ROLE_DEFINITION_DETAILS" | grep -qE '("Microsoft\.Portal/consoles/write"|"Microsoft\.Portal/\*"|"\*/\*"|"\*")'; then
                        has_cloudshell_access=1
                        STATUS="bad"
                        DETAIL="[고위험] Custom Role에 Cloud Shell 사용 권한 포함 - 과도한 권한. 상세 권한 엄격히 검토 필요"
                        EVIDENCE="Role: $ROLE_NAME (Custom)\nScope: $SCOPE\nType: $PRINCIPAL_TYPE\n권한: $ROLE_DEFINITION_DETAILS"
                    fi
                else
                    # Built-in 역할에서 Cloud Shell 사용 가능한 역할만 필터링
                    case "$ROLE_NAME" in
                        "Owner"|"Contributor")
                            has_cloudshell_access=1
                            STATUS="bad"
                            DETAIL="[고위험] ${ROLE_NAME} 역할 - Cloud Shell 사용 가능. 구독 관리 권한 과다. 접근 필요성 엄격히 검토 필요"
                            EVIDENCE="Role: $ROLE_NAME, Scope: $SCOPE, Type: $PRINCIPAL_TYPE"
                            ;;
                        *"Administrator"*)
                            has_cloudshell_access=1
                            STATUS="bad"
                            DETAIL="[고위험] ${ROLE_NAME} 역할 - Cloud Shell 사용 가능. 관리 권한 과다. 접근 필요성 엄격히 검토 필요"
                            EVIDENCE="Role: $ROLE_NAME, Scope: $SCOPE, Type: $PRINCIPAL_TYPE"
                            ;;
                        "Storage Blob Data Contributor"|"Storage Blob Data Owner"|"Storage Account Contributor")
                            has_cloudshell_access=1
                            STATUS="review"
                            DETAIL="[주의] ${ROLE_NAME} 역할 - Cloud Shell 스토리지 관리 가능. 권한 보유 필요성 검토"
                            EVIDENCE="Role: $ROLE_NAME, Scope: $SCOPE, Type: $PRINCIPAL_TYPE"
                            ;;
                    esac
                fi

                # Cloud Shell 사용 가능한 권한만 출력
                if [ "$has_cloudshell_access" -eq 1 ]; then
                    found_cloudshell_access=1
                    echo "          <Item status=\"$STATUS\">"
                    echo "            <ResourceID>${PRINCIPAL_NAME:-$PRINCIPAL_ID}</ResourceID>"
                    echo "            <Detail>${DETAIL}</Detail>"
                    echo "            <Evidence><![CDATA[$EVIDENCE]]></Evidence>"
                    echo "          </Item>"
                fi

            done <<< "$ROLE_ASSIGNMENTS"

            if [ "$found_cloudshell_access" -eq 0 ]; then
                echo '          <Item status="good"><ResourceID>All Users/Groups</ResourceID><Detail>Cloud Shell 사용 가능한 역할 할당 미탐지</Detail><Evidence><![CDATA[No high-risk roles for Cloud Shell access found.]]></Evidence></Item>'
            fi
        fi
        echo '        </SubCheck>'
        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}

# [pism-049] 테넌트 간 개체 복제 허용 방지
check_pism_049() {
    local check_id="pism-049"
    local check_name="테넌트 간 개체 복제 허용 방지"
    {
        start_timer
        local summary_string=""
        echo "    <CheckResult>"
        echo "      <CheckID>${check_id}</CheckID>"
        echo "      <CheckName>${check_name}</CheckName>"
        echo "      <Command><![CDATA[az storage account list]]></Command>"
        echo "      <Results>"

        # --- SubCheck: Blob Storage ---
        echo '        <SubCheck service="BlobStorage">'
        STORAGE_ACCOUNTS_INFO=$(az storage account list --query "[].{Name:name, AllowCrossTenantReplication:allowCrossTenantReplication}" --output tsv 2>/dev/null)
        
        if [ -z "$STORAGE_ACCOUNTS_INFO" ]; then
            echo '          <Item status="info"><ResourceID>N/A</ResourceID><Detail>점검할 스토리지 계정 미존재</Detail></Item>'
        else
            while IFS=$'\t' read -r ACCOUNT_NAME ALLOW_REPLICATION; do
                if [ -z "$ACCOUNT_NAME" ]; then continue; fi
                
                if [ "$ALLOW_REPLICATION" == "False" ]; then
                    status="good"; detail="테넌트 간 개체 복제 허용 설정 비활성화"
                    summary_string+="good|BlobStorage|${ACCOUNT_NAME}"$'\n'
                else
                    status="bad"; detail="테넌트 간 개체 복제 허용 설정 활성화"
                    summary_string+="bad|BlobStorage|${ACCOUNT_NAME}"$'\n'
                fi
                
                echo "          <Item status=\"${status}\"><ResourceID>${ACCOUNT_NAME}</ResourceID><Detail>${detail}</Detail><Evidence><![CDATA[allowCrossTenantReplication: ${ALLOW_REPLICATION}]]></Evidence></Item>"
            done <<< "$STORAGE_ACCOUNTS_INFO"
        fi
        echo '        </SubCheck>'

        print_summary "$summary_string"
        echo "      </Results>"
        echo "    </CheckResult>"
        end_timer_and_print
    } >> "$OUTFILE"
}


# --- [3] 메인 실행부 ---
targets=(
    "check_pism_001"
    "check_pism_002"
    "check_pism_003"
    "check_pism_005"
    "check_pism_007"
    "check_pism_013"
    "check_pism_016"
    "check_pism_017"
    "check_pism_023"
    "check_pism_025"
    "check_pism_036"
    "check_pism_037"
    "check_pism_039"
    "check_pism_042"
    "check_pism_043"
    "check_pism_045"
    "check_pism_046"
    "check_pism_049"
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


# Azure 로그아웃
az logout --username "$AZURE_CLIENT_ID" > /dev/null 2>&1

exit 0