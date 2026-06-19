# VENDOR-EDIT(a): import 경로 수정 (벤더 내부 wslib 사용).
import re, json
from judge_tool.vendor.common.webwas.wslib import get_remove_line

# 스크립트 결과
# WST-34(기존 SRV-043)은 서버 스크립트 결과로 나오는 xml 항목을 참조하여 점검
# 기존 자동 점검 루틴도 실행 여부만 확인 후에 수동점검하는 식으로 안내됨
def check_WST_033(outputData):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    reason_str = ""

    separator = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    output_arr = outputData.split(separator)
    apache_version = ""

    # Check if Apache service is running
    service_pattern = "http\\|https\\|http-alt\\|www\\|www-http\\|apache\\|apache2"
    if not re.search(service_pattern, output_arr[0], re.IGNORECASE):
        auto_result_reason = "(+) Apache 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + output_arr[0]
        return result, auto_result_reason, vulnerability_condition_result_model_list

    # Check first Apache version pattern
    httpd_pattern = r"httpd-(.*?)-.*"
    m = re.search(httpd_pattern, output_arr[1], re.IGNORECASE)
    if m:
        apache_version = m.group()
        version_str = m.group(1).rsplit('.', 1)[0]
        try:
            version = float(version_str)
            if version < 2.1:
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": "취약한 Apache 버전: " + m.group(1),
                    "vulnerabilityConditionReasonCode": "WST-003"
                }
                reason_str += m.group() + "\n"
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        except ValueError:
            pass

    # Check second Apache version pattern
    apache_pattern = r"apache[0-9\s]\s(.*?)-"
    m_ = re.search(apache_pattern, output_arr[2], re.IGNORECASE)
    if m_:
        apache_version = m_.group()
        version_str = m_.group(1).rsplit('.', 1)[0]
        try:
            version2 = float(version_str)
            if version2 < 2.1:
                vulnerability_condition_result_model2 = {
                    "vulnerabilityConditionOutput": "취약한 Apache 버전: " + m_.group(1),
                    "vulnerabilityConditionReasonCode": "WST-033"
                }
                reason_str += m_.group() + "\n"
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model2)
        except ValueError:
            pass

    if not vulnerability_condition_result_model_list:
        auto_result_reason = "(+) Apache 버전이 2.1 이상인 것으로 탐지되어 양호로 판단\n" + apache_version + "\n"
    else:
        result = 'Y'
        auto_result_reason = "(-) Directory Traversal 취약점이 발견된 Apache 버전(<2.1)을 사용 중인 것으로 탐지되어 취약으로 판단\n" + reason_str

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_034(outputData):
    result = 'N'
    auto_result_reason = "(*) 수동 분석 필요, 웹 서비스 경로 내 불필요한 파일 존재 여부 확인"
    vulnerability_condition_result_model_list = []
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_044(outputData):
    # 수동 점검 할 수 있도록 데이터만 올린다.
    result = 'N'
    auto_result_reason = '(*) 수동 점검 필요, tomcat, JEUS 가동 여부 확인 및 기본 계정 미변경 여부 확인'
    vulnerability_condition_result_model_list = []
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

# apache config
def check_WST_031(configData):
    result = "N"
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Remove lines starting with '#'
    configData = get_remove_line(configData, "#")

    # Compile the regex pattern to find <Directory> blocks with problematic Options
    # VENDOR-EDIT(bug): BUG-WST031-apache — [^-]Indexes가 '-Indexes' 앞의 공백(' Indexes')도 매치하여
    # Options -Indexes(양호)를 거짓취약 판정. 음수 룩비하인드로 '-' 직전 Indexes를 제외하고,
    # '+Indexes' 또는 단독 'Indexes'(비활성 제외)만 매치하도록 수정.
    # 취약 조건: Indexes 또는 +Indexes 또는 all (단, -Indexes는 제외)
    vuln_pattern = re.compile(
        r"<Directory((?!<\/Directory>)[\s\S])*?Options[^\n]*(?:(?<!\-)\bIndexes\b|\ball\b)[^\n]*.*?<\/Directory>",
        re.DOTALL | re.IGNORECASE
    )

    reason_str = ""

    # Find all vulnerable <Directory> blocks
    for match in vuln_pattern.finditer(configData):
        output = match.group().strip()
        reason_str += output + "\n\n"

        vulnerability_condition_result = {
            "vulnerabilityConditionOutput": output,
            "vulnerabilityConditionReasonCode": "WST-031"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result)

    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found
        reason_str2 = "(+) Options 구문에 +Indexes, Indexes 또는 all 값이 없는 것으로 탐지되어 양호로 판단\n\n"

        # Compile the regex pattern to find all <Directory> blocks without problematic Options
        norm_pattern = re.compile(
            r"<Directory((?!<\/Directory>)[\s\S])*?(Options.*)[\s\S]*?<\/Directory>",
            re.DOTALL | re.IGNORECASE
        )

        # Append all <Directory> blocks to the reason string
        for match in norm_pattern.finditer(configData):
            reason_str2 += match.group(0).strip() + "\n\n"

        auto_result_reason = reason_str2
    else:
        # Vulnerabilities found
        result = "Y"
        auto_result_reason = "(-) Options 구문에 +Indexes, Indexes 또는 all 값이 존재하는 것으로 탐지되어 취약으로 판단\n" + reason_str

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_035(configData):
    result = "N"  # Default to "Not vulnerable"
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    configData2 = get_remove_line(configData, "#")

    reason_str = ""
    pattern_found = False

    # Compile the regex pattern to find LimitRequestBody settings
    limit_request_body_pattern = re.compile(r"LimitRequestBody\s+(.*)", re.IGNORECASE)

    # Iterate over all matches of the pattern
    for m in limit_request_body_pattern.finditer(configData2):
        pattern_found = True
        value = m.group(1).strip()
        
        if value == "0":
            # Vulnerable configuration found
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": m.group().strip(),
                "vulnerabilityConditionReasonCode": "WST-035"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            reason_str += f"{m.group().strip()}\n"
        else:
            # Non-vulnerable configuration, just add to reason_str
            reason_str += f"{m.group().strip()}\n"

    if not pattern_found:
        # No LimitRequestBody configuration found, which is considered vulnerable
        vulnerability_condition_result_model = {
            "vulnerabilityConditionOutput": "LimitRequestBody 구문 없음",
            "vulnerabilityConditionReasonCode": "WST-035"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        reason_str += "설정 파일에 LimitRequestBody 구문 없음\n"

    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found
        auto_result_reason = (
            "(+) LimitRequestBody 설정을 통해 다운로드 용량 제한이 적용된 것으로 탐지되어 양호로 판단\n" 
            + reason_str
        )
    else:
        # Vulnerabilities found
        result = "Y"
        auto_result_reason = (
            "(-) LimitRequestBody 설정이 존재하지 않거나, 값이 0(제한없음)으로 탐지되어 취약으로 판단\n" 
            + reason_str
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_036(configData):
    result = "N"  # Default to "Not vulnerable"
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Remove lines starting with '#'
    configData = get_remove_line(configData, "#")

    reason_str = ""

    # Compile regex patterns for User and Group
    user_pattern = re.compile(r"User\s+(.*)", re.IGNORECASE)
    group_pattern = re.compile(r"Group\s+(.*)", re.IGNORECASE)

    # Check for User configurations
    for m in user_pattern.finditer(configData):
        user_value = m.group(1).strip()
        
        if "$" in user_value:
            # Manual review needed
            reason_str2 = f"(*) 수동 판단 필요: 프로세스 권한 설정이 환경변수로 설정되어 있어 확인 불가\n{m.group().strip()}"
            return "N", reason_str2, vulnerability_condition_result_model_list
        
        if user_value.lower() == "root":
            # Vulnerable configuration found
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": m.group().strip(),
                "vulnerabilityConditionReasonCode": "WST-036"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"{m.group().strip()}\n"
        else:
            # Non-vulnerable configuration
            reason_str += f"{m.group().strip()}\n"

    # Check for Group configurations
    for m_ in group_pattern.finditer(configData):
        group_value = m_.group(1).strip()
        
        if "$" in group_value:
            # Manual review needed
            reason_str2 = f"(*) 수동 판단 필요: 프로세스 권한 설정이 환경변수로 설정되어 있어 확인 불가\n{m_.group().strip()}"
            return "N", reason_str2, vulnerability_condition_result_model_list
        
        if group_value.lower() == "root":
            # Vulnerable configuration found
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": m_.group().strip(),
                "vulnerabilityConditionReasonCode": "WST-036"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"{m_.group().strip()}\n"
        else:
            # Non-vulnerable configuration
            reason_str += f"{m_.group().strip()}\n"

    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found
        auto_result_reason = (
            "(+) Apache 요청 처리 사용자와 그룹이 root가 아닌 것으로 탐지되어 양호로 판단\n" 
            + reason_str
        )
    else:
        # Vulnerabilities found
        result = "Y"
        auto_result_reason = (
            "(-) Apache 요청 처리 사용자 또는 그룹 중에 root가 탐지되어 취약으로 판단\n" 
            + reason_str
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_037(configData):
    result = 'N'  # Default to "Not vulnerable"
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []
    reason_str = ""

    # Remove lines starting with '#'
    configData2 = get_remove_line(configData, "#")

    # Compile regex pattern for DocumentRoot with case-insensitive flag
    document_root_pattern = re.compile(r'DocumentRoot\s+(.*)', re.IGNORECASE)

    # Iterate over all matches of the DocumentRoot pattern
    for m in document_root_pattern.finditer(configData2):
        document_root_value = m.group(1).strip()
        
        if document_root_value == "\"/\"":
            # Vulnerable configuration found
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": m.group().strip(),
                "vulnerabilityConditionReasonCode": "WST-037"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"{m.group().strip()}\n"
        else:
            # Non-vulnerable configuration
            reason_str += f"{m.group().strip()}\n"

    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found
        auto_result_reason = (
            "(+) DocumentRoot 중 경로가 루트('/')가 탐지되지 않아 양호로 판단('/' 외에 타업무와 분리 되지 않은 경로는 확인 필요)\n"
            + reason_str
        )
    else:
        # Vulnerabilities found
        result = 'Y'
        auto_result_reason = (
            "(-) DocumentRoot 중 경로가 루트('/')인 설정이 탐지되어 취약으로 판단\n"
            + reason_str
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_038(configData):
    result = 'N'  # Default to "Not vulnerable"
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []
    reason_str = ""

    # Remove lines starting with '#'
    configData2 = get_remove_line(configData, "#")

    # Compile regex pattern to find <Directory> blocks with problematic Options
    # VENDOR-EDIT(c): WST-038-apache-dotall — 멀티라인 Directory 블록 미매치 거짓양호 수정(KNOWN_BUGS 참조)
    # re.DOTALL 추가로 외부 <Directory>…</Directory> 경계 매치. [^\n]*로 Options 줄만 검색(over-match 방지).
    vuln_pattern = re.compile(  # noqa: WST-038-apache-dotall
        r"<Directory((?!<\/Directory>)[\s\S])*?Options[^\n]*\b(?:\+FollowSymLinks|FollowSymLinks|all)\b[^\n]*.*?<\/Directory>",
        re.DOTALL | re.IGNORECASE
    )

    # Find all vulnerable <Directory> blocks
    for m in vuln_pattern.finditer(configData2):
        output = m.group().strip()
        reason_str += f"{output}\n"

        vulnerability_condition_result = {
            "vulnerabilityConditionOutput": output,
            "vulnerabilityConditionReasonCode": "WST-038"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result)

    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found
        reason_str2 = "(+) Options 구문에 +FollowSymLinks 또는 all 값이 없는 것으로 탐지되어 양호로 판단\n"

        # Compile regex pattern to find all <Directory> blocks with Options
        norm_pattern = re.compile(
            r"<Directory((?!<\/Directory>)[\s\S])*?Options.*?<\/Directory>",
            re.DOTALL | re.IGNORECASE
        )

        # Append all <Directory> blocks to the reason string
        for match in norm_pattern.finditer(configData2):
            reason_str2 += f"{match.group(0).strip()}\n\n"

        auto_result_reason = reason_str2
    else:
        # Vulnerabilities found
        result = 'Y'
        auto_result_reason = (
            "(-) Options 구문에 +FollowSymLinks, all 값이 존재하는 것으로 탐지되어 취약으로 판단\n" 
            + reason_str
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_039(configData):
    # 수동 점검 할 수 있도록 데이터만 올린다.
    result = 'N'
    auto_result_reason = '(*) 수동 점검 필요, 업무와 관계 없이 불필요하게 활성화되어 있는지 여부 확인'
    vulnerability_condition_result_model_list = []
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_102(configData):
    result = 'N'  # Default to "Not vulnerable"
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []
    reason_str = ""
    
    # Remove lines starting with '#'
    configData2 = get_remove_line(configData, "#")

    # Compile regex pattern for ServerTokens with case-insensitive flag
    server_tokens_pattern = re.compile(r"ServerTokens\s+(.*)", re.IGNORECASE)

    # Search for ServerTokens configuration
    m = server_tokens_pattern.search(configData2)
    if m:
        server_tokens_value = m.group(1).strip().lower()
        if server_tokens_value == "prod":
            reason_str = f"{m.group().strip()}\n"
        else:
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": m.group().strip(),
                "vulnerabilityConditionReasonCode": "WST-102"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str = f"{m.group().strip()}\n"
    else:
        vulnerability_condition_result = {
            "vulnerabilityConditionOutput": "ServerTokens 구문 없음",
            "vulnerabilityConditionReasonCode": "WST-102"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result)
        reason_str = "설정 파일에 ServerTokens 구문 없음\n"
        
    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found
        auto_result_reason = (
            "(+) ServerTokens 옵션의 값이 Prod로 탐지되어 양호로 판단\n" 
            + reason_str
        )
    else:
        # Vulnerabilities found
        result = 'Y'
        auto_result_reason = (
            "(-) ServerTokens 옵션의 값이 Prod가 아니거나 구문이 없는 것으로 탐지되어 취약으로 판단\n" 
            + reason_str
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def main(xml_result_dict):
    json_output = json.dumps(xml_result_dict, indent=4, ensure_ascii=False)
    data_dict = json.loads(json_output)
    results_dict = {}
    
    function_dispatcher = {
        "WST-033": check_WST_033, # 기존 SRV-042
        "WST-034": check_WST_034, # 기존 SRV-043
        "WST-044": check_WST_044, # 기존 SRV-060
    }
    
    config_function_dispatcher = {
        "WST-031": check_WST_031, # 기존 SRV-040
        "WST-035": check_WST_035, # 기존 SRV-044
        "WST-036": check_WST_036, # 기존 SRV-045
        "WST-037": check_WST_037, # 기존 SRV-046
        "WST-038": check_WST_038, # 기존 SRV-047
        "WST-039": check_WST_039, # 기존 SRV-048
        "WST-102": check_WST_102, # 기존 SRV-148
    }
    
    for key, output in data_dict.items():
        result = 'N'
        auto_result_reason = ""
        vul_result_model = []
        
        if key in function_dispatcher:
            returned_value = function_dispatcher[key](output)  # Call the appropriate function based on the key
        
            if isinstance(returned_value, tuple):
                result, auto_result_reason, vul_result_model = returned_value
                
        results_dict[key] = {
            'output': output, 
            'result': result, 
            'auto_result_reason': auto_result_reason, 
            'vul_result_model': vul_result_model
        }
    
    apache_config = data_dict['apache']
    
    for key, func in config_function_dispatcher.items():
        returned_value = func(apache_config)  # 각 함수에 apache_config 전달
        
        if isinstance(returned_value, tuple) and len(returned_value) == 3:
            result, auto_result_reason, vul_result_model = returned_value
        else:
            result = 'N'
            auto_result_reason = ''
            vul_result_model = []
        
        # 결과를 results_dict에 저장
        results_dict[key] = {
            'output': apache_config,
            'result': result,
            'auto_result_reason': auto_result_reason,
            'vul_result_model': vul_result_model
        }
    
    return results_dict