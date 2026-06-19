# VENDOR-EDIT(a): import 경로 수정 (벤더 내부 wslib 사용).
import re, json
from judge_tool.vendor.common.webwas.wslib import get_remove_line

# 스크립트 결과
def check_WST_033(outputData):
    result = 'NA'
    auto_result_reason = "(*) webtob에 해당하지 않는 점검 항목"
    vulnerability_condition_result_model_list = []
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_034(outputData):
    result = 'N'
    auto_result_reason = "(*) 수동 분석 필요, 웹 서비스 경로 내 불필요한 파일 존재 여부 확인"
    vulnerability_condition_result_model_list = []
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_038(outputData):
    result = 'NA'
    auto_result_reason = "(*) webtob에 해당하지 않는 점검 항목"
    vulnerability_condition_result_model_list = []
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_044(outputData):
    result = 'N'
    auto_result_reason = "(*) 수동 분석 필요, tomcat, JEUS 가동 여부 확인 및 기본 계정 미변경 여부 확인"
    vulnerability_condition_result_model_list = []
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

# webtob config
def check_WST_031(configData):
    # Initialize result and reason strings
    result = "N"
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []

    # Remove lines starting with '#' using the assumed get_remove_line function
    configData2 = get_remove_line(configData, "#")
    allData = str(configData)  # Equivalent to String.valueOf(configData) in Java

    # Compile regex pattern to find Options directives containing 'INDEX' (case-insensitive)
    # VENDOR-EDIT(bug): BUG-WST031-webtob — Options.*?INDEX가 'NOINDEX'의 INDEX 서브스트링도
    # 매치하여 Options=NOINDEX(양호)를 거짓취약 판정. 음수 룩비하인드로 'NO' 접두 제외.
    # 취약 조건: INDEX 또는 LIST (단, NOINDEX/NOLIST 제외)
    vuln_pattern = re.compile(r"(.*)?Options.*?(?<!NO)\bINDEX\b.*", re.IGNORECASE)

    # Find all vulnerable Options directives
    for m in vuln_pattern.finditer(configData2):
        vulnerabilityConditionOutput = m.group().strip()
        vulnerability_condition_result = {
            "vulnerabilityConditionOutput": vulnerabilityConditionOutput,
            "vulnerabilityConditionReasonCode": "WST-031"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result)
        reason_str += f"{vulnerabilityConditionOutput}\n\n"

    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found
        reason_str2 = "(+) Options 구문에 INDEX 값이 없는 것으로 탐지되어 양호로 판단(주석처리된 경우도 Default 값 양호)\n\n"
        
        # Compile regex pattern to find all Options directives
        norm_pattern = re.compile(r"(.*)?Options.*", re.IGNORECASE)
        
        # Append all Options directives to reason_str2 for detailed reporting
        for match in norm_pattern.finditer(allData):
            norm_output = match.group(0).strip()
            reason_str2 += f"{norm_output}\n"
        
        auto_result_reason = reason_str2.strip()
    else:
        # Vulnerabilities found
        result = "Y"
        auto_result_reason = (
            "(-) Options 구문에 INDEX 값이 존재하는 것으로 탐지되어 취약으로 판단\n\n" 
            + reason_str.strip()
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_035(configData):
    # Initialize result and reason strings
    result = "N"  # Assume not vulnerable by default
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []

    # Remove lines starting with '#' using the assumed get_remove_line function
    configData2 = get_remove_line(configData, "#")

    #print("configData2 : ", configData2)

    # Compile regex pattern to find LimitRequestBody directives (case-insensitive)
    limit_request_body_pattern = re.compile(r"LimitRequestBody\s*=\s*(.*)", re.IGNORECASE)

    pattern_found = False

    # Iterate over all matches of the LimitRequestBody pattern
    for m in limit_request_body_pattern.finditer(configData2):
        pattern_found = True
        value = m.group(1).strip()

        if value == "0":
            # Vulnerable configuration found (LimitRequestBody is set to 0)
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": m.group().strip(),
                "vulnerabilityConditionReasonCode": "WST-035"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"{m.group().strip()}\n"
        else:
            # Non-vulnerable configuration; add to reason_str for logging
            reason_str += f"{m.group().strip()}\n"

    if not pattern_found:
        # No LimitRequestBody directive found; consider it vulnerable by default
        vulnerability_condition_result = {
            "vulnerabilityConditionOutput": "LimitRequestBody 구문 없음",
            "vulnerabilityConditionReasonCode": "WST-035"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result)
        reason_str += "설정 파일에 LimitRequestBody 구문 없음(Default 값은 0으로 용량 무제한을 의미함)\n"

    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found; LimitRequestBody is set appropriately
        auto_result_reason = (
            "(+) LimitRequestBody 설정을 통해 다운로드 용량 제한이 적용된 것으로 탐지되어 양호로 판단\n\n" 
            + reason_str.strip()
        )
    else:
        # Vulnerabilities found; LimitRequestBody is either missing or set to 0
        result = "Y"
        auto_result_reason = (
            "(-) LimitRequestBody 설정이 존재하지 않거나, 값이 0(제한없음)으로 탐지되어 취약으로 판단\n\n" 
            + reason_str.strip()
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list
    
def check_WST_036(configData):
    # Initialize result and reason strings
    result = "N"  # Assume secure by default
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []

    # Remove lines starting with '#' using the assumed get_remove_line function
    configData2 = get_remove_line(configData, "#")

    # Compile regex patterns for User and Group with case-insensitive flag
    user_pattern = re.compile(r'User\s*=\s*"(.*)"', re.IGNORECASE)
    group_pattern = re.compile(r'Group\s*=\s*"(.*)"', re.IGNORECASE)

    # Search for User configurations
    for m in user_pattern.finditer(configData2):
        user_value = m.group(1).strip().lower()
        
        if user_value == "root":
            # Vulnerable configuration found
            vulnerabilityConditionOutput = m.group().strip()
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": vulnerabilityConditionOutput,
                "vulnerabilityConditionReasonCode": "WST-036"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"{vulnerabilityConditionOutput}\n"
        else:
            # Non-vulnerable configuration; add to reason_str for logging
            reason_str += f"{m.group().strip()}\n"

    # Search for Group configurations
    for m_ in group_pattern.finditer(configData2):
        group_value = m_.group(1).strip().lower()
        
        if group_value == "root":
            # Vulnerable configuration found
            vulnerabilityConditionOutput = m_.group().strip()
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": vulnerabilityConditionOutput,
                "vulnerabilityConditionReasonCode": "WST-036"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"{vulnerabilityConditionOutput}\n"
        else:
            # Non-vulnerable configuration; add to reason_str for logging
            reason_str += f"{m_.group().strip()}\n"

    if not vulnerability_condition_result_model_list:
        if not reason_str:
            reason_str = "User Group 설정이 주석처리 됐거나 없음(즉 Webtob 데몬을 관리자 계정이 아닌 계정으로 구동했으면 양호)\n"
        auto_result_reason = (
            "(+) Webtob 요청 처리 사용자와 그룹이 root가 아닌 것으로 탐지되어 양호로 판단\n\n" 
            + reason_str.strip()
        )
    else:
        # Vulnerabilities found
        result = "Y"
        auto_result_reason = (
            "(-) Webtob 요청 처리 사용자 또는 그룹 중에 root가 탐지되어 취약으로 판단\n\n" 
            + reason_str.strip()
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_037(configData):
    # Initialize result and reason strings
    result = "N"  # Assume secure by default
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []

    # Remove lines starting with '#' using the assumed get_remove_line function
    configData2 = get_remove_line(configData, "#")

    # Compile regex pattern to find DOCROOT directives (case-insensitive)
    docroot_pattern = re.compile(r'DOCROOT\s*=\s*"(.*)"', re.IGNORECASE)

    # Iterate over all matches of the DOCROOT pattern
    for m in docroot_pattern.finditer(configData2):
        docroot_value = m.group(1).strip()

        if docroot_value == "/":
            # Vulnerable configuration found (DOCROOT is set to "/")
            vulnerabilityConditionOutput = m.group().strip()
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": vulnerabilityConditionOutput,
                "vulnerabilityConditionReasonCode": "WST-037"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"{vulnerabilityConditionOutput}\n"
        else:
            # Non-vulnerable configuration; add to reason_str for logging
            reason_str += f"{m.group().strip()}\n"

    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found
        if not reason_str:
            reason_str = "User Group 설정이 주석처리 됐거나 없음(즉 Webtob 데몬을 관리자 계정이 아닌 계정으로 구동했으면 양호)\n"
        auto_result_reason = (
            "(+) DOCROOT 중 경로가 루트('/')가 탐지되지 않아 양호로 판단('/' 외에 타업무와 분리 되지 않은 경로는 확인 필요)\n\n" 
            + reason_str.strip()
        )
    else:
        # Vulnerabilities found
        result = "Y"
        auto_result_reason = (
            "(-) DOCROOT 중 경로가 루트('/')인 설정이 탐지되어 취약으로 판단\n\n" 
            + reason_str.strip()
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_039(configData):
    # 수동 점검 할 수 있도록 데이터만 올린다.
    result = 'N'
    auto_result_reason = '(*) 수동 점검 필요, 업무와 관계 없이 불필요하게 활성화되어 있는지 여부 확인'
    vulnerability_condition_result_model_list = []
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_102(configData):
    # Initialize result and reason strings
    result = "N"  # Assume secure by default
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []

    # Remove lines starting with '#' using the assumed get_remove_line function
    configData2 = get_remove_line(configData, "#")

    # Compile regex pattern to find ServerTokens directives (case-insensitive)
    server_tokens_pattern = re.compile(r'ServerTokens\s*=\s*"(.*)"', re.IGNORECASE)

    # Search for ServerTokens configuration
    m = server_tokens_pattern.search(configData2)
    if not m:
        # ServerTokens directive not found
        reason_str = "설정 파일에 ServerTokens 구문 없음(Default 값이 Off로 양호)\n"
    else:
        tokens_val = m.group(1).strip().lower()
        # VENDOR-EDIT(bug): BUG-WST102-webtob — 구 조건 `"min" not in val and val not in ["os","full","prod"]`에서
        # "full"이 리스트에 포함되어 False → 취약 미탐지(거짓양호). 수정: 버전/OS 노출값(os,full)→취약,
        # 최소 노출값(prod,min 포함)→양호. prod=product name only(버전 미포함)→양호.
        if tokens_val in ("os", "full"):
            # ServerTokens value exposes version/OS info — vulnerable
            vulnerabilityConditionOutput = m.group().strip()
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": vulnerabilityConditionOutput,
                "vulnerabilityConditionReasonCode": "WST-102"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"{vulnerabilityConditionOutput}\n"
        elif tokens_val == "prod":
            # ServerTokens 안전값은 Prod(ProductOnly)뿐. Min/Minimal/Minor는
            # 전체 버전(Apache/2.4.x)을 노출하므로 취약(Apache WST-102와 동일, 함수 메시지와 정합).
            reason_str += f"{m.group().strip()}\n"
        else:
            # Unknown value — treat as vulnerable (버전 정보 노출 여부 불명확)
            vulnerabilityConditionOutput = m.group().strip()
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": vulnerabilityConditionOutput,
                "vulnerabilityConditionReasonCode": "WST-102"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"{vulnerabilityConditionOutput}\n"

    if not vulnerability_condition_result_model_list:
        # No vulnerabilities found
        auto_result_reason = (
            "(+) ServerTokens 옵션의 값이 없거나 버전이 출력되지 않는 값으로 탐지되어 양호로 판단\n\n" 
            + reason_str.strip()
        )
    else:
        # Vulnerabilities found
        result = "Y"
        auto_result_reason = (
            "(-) ServerTokens 옵션의 값이 버전이 출력되는 값(Min, OS, Full)으로 탐지되어 취약으로 판단\n\n" 
            + reason_str.strip()
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def main(xml_result_dict):
    json_output = json.dumps(xml_result_dict, indent=4, ensure_ascii=False)
    data_dict = json.loads(json_output)
    results_dict = {}
    
    function_dispatcher = {
        "WST-033": check_WST_033, # 기존 SRV-042 (NA 처리)
        "WST-034": check_WST_034, # 기존 SRV-043
        "WST-038": check_WST_038, # 기존 SRV-047 (NA 처리)
        "WST-044": check_WST_044, # 기존 SRV-060
    }
    
    config_function_dispatcher = {
        "WST-031": check_WST_031, # 기존 SRV-040
        "WST-035": check_WST_035, # 기존 SRV-044
        "WST-036": check_WST_036, # 기존 SRV-045
        "WST-037": check_WST_037, # 기존 SRV-046
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
        
    webtob_config = data_dict['webtob']
    
    for key, func in config_function_dispatcher.items():
        returned_value = func(webtob_config)  # 각 함수에 webtob_config 전달
        
        if isinstance(returned_value, tuple) and len(returned_value) == 3:
            result, auto_result_reason, vul_result_model = returned_value
        else:
            result = 'N'
            auto_result_reason = ''
            vul_result_model = []
        
        # 결과를 results_dict에 저장
        results_dict[key] = {
            'output': webtob_config,
            'result': result,
            'auto_result_reason': auto_result_reason,
            'vul_result_model': vul_result_model
        }
    
    return results_dict