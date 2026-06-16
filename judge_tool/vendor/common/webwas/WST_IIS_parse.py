import re, json

# 자체 항목
def check_WST_032(outputData):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []
    vul_flag = False

    # 구분자를 기준으로 출력 분할
    delimiter = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    output_arr = outputData.split(delimiter)

    reasonStr = ""

    # 실행은 되고 있다는 가정하에 점검이 수행된다.
    # outputArr 전체를 순회하며 "Everyone" 그룹에 불필요한 권한이 부여되었는지 확인
    for element in output_arr:
        everyone_pattern = re.compile(r"Everyone.*[FMW]", re.DOTALL)
        m = everyone_pattern.search(element)
        if m:
            vul_flag = True
            # 첫 번째 줄을 추출하고 "cmd# cacls"를 제거한 후, 매칭된 문자열을 추가
            first_line = element.strip().split('\n')[0].replace("cmd# cacls", "").strip()
            resultStr = first_line + "\n\t" + m.group(0)
            reasonStr += resultStr + "\n"
            # 취약점 정보를 리스트에 추가
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": resultStr,
                "vulnerabilityConditionReasonCode": "WST-032"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

    # 취약점 여부에 따른 결과 설정
    if vul_flag:
        result = 'Y'
        auto_result_reason = "(-) 스크립트 경로로 추정되는 경로 중 Everyone 그룹에 불필요하게 권한이 부여된 것이 탐지되어 취약으로 판단\n" + reasonStr
    else:
        auto_result_reason = "(+) 일반적인 스크립트 경로에 Everyone 그룹에 부여된 권한이 탐지되지 않아서 양호로 판단(취약 스크립트 존재 여부는 수동 점검 필요)\n" + outputData

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_034(outputData):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []
    vul_flag = False

    # 구분자를 기준으로 출력 분할
    delimiter = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    output_arr = outputData.split(delimiter)

    reasonStr = ""

    # Everyone 그룹 권한 검사
    for element in output_arr:
        # 첫 번째 줄에서 "cmd# dir" 제거 및 경로 추출
        lines = element.strip().split('\n')
        if not lines:
            continue
        path = lines[0].replace("cmd# dir", "").strip()

        if len(path) == 0:
            continue

        # "physicalPath:" 제거
        if "physicalPath:" in path:
            path = path.replace("physicalPath:", "")

        # 경로가 ')'로 끝나면 제거
        if path.endswith(')'):
            path = path[:-1]

        # "%SystemDrive%" 처리
        if "%SystemDrive%" in path:
            path = path.replace("%SystemDrive%", "")
            split_lines = element.strip().split('\n')
            for split_line in split_lines:
                m_drive = re.compile(r".*?\s(.):\\", re.DOTALL).search(split_line)
                if m_drive:
                    drive_letter = m_drive.group(1)
                    path = f"{drive_letter}:{path}"
                    break

        for line in element.split('\n'):
            line_lower = line.lower()
            if "iissamples" in line_lower or "iishelp" in line_lower or "test" in line_lower or "sample" in line_lower:
                vul_flag = True
                reasonStr += f"{path}\\{line}\n"
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": f"{path}\n{line}",
                    "vulnerabilityConditionReasonCode": "WST-034"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

    # 취약점 여부에 따른 결과 설정
    if vul_flag:
        result = 'Y'
        auto_result_reason = (
            "(-) 기본으로 설치된 불필요한 파일 또는 경로가 존재하는 것으로 탐지되어 취약으로 판단(sample, help, test 등)\n" 
            + reasonStr
        )
    else:
        auto_result_reason = (
            "(+) 기본으로 설치된 불필요한 파일 또는 경로(sample, help, test 등)가 탐지되지 않아서 양호로 판단\n" 
            + outputData
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_038(outputData):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []
    vul_flag = False

    reasonStr = ""

    # 전체 출력에서 각 라인을 순회하며 ".lnk" 파일 확인
    lines = outputData.split('\n')
    for line in lines:
        if ".lnk" in line.lower():
            vul_flag = True
            reasonStr += line.strip() + "\n"
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": line.strip(),
                "vulnerabilityConditionReasonCode": "WST-038"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

    # 취약점 여부에 따른 결과 설정
    if vul_flag:
        result = 'Y'
        auto_result_reason = (
            "(-) 웹 서비스 경로에 링크(.lnk) 파일이 탐지되어 취약으로 판단(업무상 필요 여부 확인 필요)\n" 
            + reasonStr
        )
    else:
        auto_result_reason = "(+) 웹 서비스 경로에 attrib 명령을 실행했을 때, 링크 파일(.lnk)이 탐지되지 않아 양호로 판단\n"

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_039(outputData):
    # 수동 점검 할 수 있도록 데이터만 올린다.
    result = 'N'
    auto_result_reason = '(*) 수동 점검 필요, 업무와 관계 없이 불필요하게 활성화되어 있는지 여부 확인'
    vulnerability_condition_result_model_list = []
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_041(outputData):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []
    vul_flag = False

    # 구분자를 기준으로 출력 분할
    delimiter = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    output_arr = outputData.split(delimiter)

    reasonStr = ""

    # outputArr를 순회하며 Everyone 그룹에 권한이 부여된 실행 파일 검사
    for element in output_arr:
        # 첫 번째 줄에서 "cmd# cacls" 제거 및 경로 추출
        lines = element.strip().split('\n')
        if not lines:
            continue
        path = lines[0].replace("cmd# cacls", "").strip()

        if len(path) == 0:
            continue

        # "physicalPath:" 제거
        if "physicalPath:" in path:
            path = path.replace("physicalPath:", "")

        # 경로가 ')'로 끝나면 제거
        if path.endswith(')'):
            path = path[:-1]

        # "%SystemDrive%" 처리
        if "%SystemDrive%" in path:
            path = path.replace("%SystemDrive%", "")
            split_lines = element.strip().split('\n')
            for split_line in split_lines:
                m_drive = re.compile(r".*?\s(.):\\", re.DOTALL | re.IGNORECASE).search(split_line)
                if m_drive:
                    drive_letter = m_drive.group(1)
                    path = f"{drive_letter}:{path}"
                    break

        # 각 라인에서 Everyone 그룹 권한 확인 및 파일 확장자 검사
        for line in element.split('\n'):
            # "Everyone"과 특정 권한 패턴 확인
            m2 = re.compile(r"Everyone.*[FMRXRWD]", re.DOTALL | re.IGNORECASE).search(line)
            if m2:
                # 파일 경로 추출
                parts = line.strip().split()
                if len(parts) > 0:
                    file_part = parts[0]
                    vulFilePath = f"{path}\\{file_part}"
                    # 특정 파일 확장자 확인
                    if any(vul_file in vulFilePath.lower() for vul_file in [".exe", ".dll", ".cmd", ".pl", ".asp", ".aspx", ".inc", ".shtm", ".shtml"]):
                        vul_flag = True
                        reasonStr += f"{vulFilePath}\n\t{m2.group(0)}\n"
                        vulnerability_condition_result_model = {
                            "vulnerabilityConditionOutput": f"Everyone 쓰기 권한이 있는 파일 존재(정적파일일 경우 양호)\n{vulFilePath}\n\t{m2.group(0)}",
                            "vulnerabilityConditionReasonCode": "WST-041"
                        }
                        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

    # 취약점 여부에 따른 결과 설정
    if vul_flag:
        result = 'Y'
        auto_result_reason = (
            "(-) Everyone 그룹에 권한이 부여된 실행 파일이 존재하는 것으로 탐지되어 취약으로 판단\n" 
            + reasonStr
        )
    else:
        auto_result_reason = "(+) cacls *.* [Web root 경로] 명령 결과에 Everyone 그룹에 부여된 권한이 탐지되지 않아 양호로 판단\n"

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_043(outputData):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []

    reasonStr = ""
    vulFlag = False

    # 구분자를 기준으로 출력 분할
    delimiter = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    output_arr = outputData.split(delimiter)

    # VersionString 검사 (outputArr[1])
    if len(output_arr) > 1:
        version_pattern = re.compile(r"VersionString.*([\d]\.[\d])$", re.DOTALL | re.IGNORECASE)
        m_version = version_pattern.search(output_arr[1])
        if m_version:
            try:
                version = float(m_version.group(1).strip())
                if version >= 7.0:
                    reasonStr3 = "(+) IIS 버전이 7.0 이상으로 탐지되어 양호로 판단\n\t" + m_version.group(0)
                    auto_result_reason = reasonStr3
                    return result, auto_result_reason, vulnerability_condition_result_model_list
                else:
                    reasonStr = m_version.group(0)
            except ValueError:
                pass  # 버전 파싱 실패 시 무시
    # SSIEnableCmdDirective 검사 (outputArr[0])
    if len(output_arr) > 0:
        ssi_pattern = re.compile(r"SSIEnableCmdDirective.*0x([\d])$", re.DOTALL | re.IGNORECASE)
        m_ssi = ssi_pattern.search(output_arr[0])
        if m_ssi:
            if m_ssi.group(1) != "0":
                vulFlag = True
                reasonStr = (
                    "(-) IIS 버전 7.0 미만이고, SSIEnableCmdDirective 값이 0x0이 아닌 것으로 탐지되어 취약으로 판단\n"
                    + reasonStr + "\n====\n" + m_ssi.group(0)
                )
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": m_ssi.group(0),
                    "vulnerabilityConditionReasonCode": "WST-043"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            else:
                reasonStr = (
                    "(+) IIS 버전 7.0 미만이지만, SSIEnableCmdDirective 값이 0x0으로 비활성화로 탐지되어 양호로 판단\n"
                    + reasonStr + "\n====\n" + m_ssi.group(0)
                )

    # 취약점 여부에 따른 결과 설정
    if vulFlag:
        result = 'Y'
        auto_result_reason = (
            "(-) IIS 버전 7.0 미만이고, SSIEnableCmdDirective 값이 0x0이 아닌 것으로 탐지되어 취약으로 판단\n"
            + reasonStr
        )
    else:
        auto_result_reason = "(+) SSIEnableCmdDirective 값이 0x0이므로 양호로 판단\n"

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_044(outputData):
    # 수동 점검 할 수 있도록 데이터만 올린다.
    result = 'N'
    auto_result_reason = '(*) 수동 분석 필요, tomcat, JEUS 가동 여부 확인 및 기본 계정 미변경 여부 확인'
    vulnerability_condition_result_model_list = []
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

# appliactionHost.config
def check_WST_031(configData):
    # Initialize result and reason strings
    result = "N"  # 기본값을 양호(Normal)으로 설정
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []

    # 정규 표현식 패턴 컴파일
    # <directoryBrowse enabled="true" /> 또는 <directoryBrowse enabled='false' />
    pattern = re.compile(r'<\s*directoryBrowse\s+enabled\s*=\s*["\'](.*?)["\']\s*/>', re.IGNORECASE)

    # 모든 매칭 찾기
    matches = pattern.finditer(configData)
    count = 0          # directoryBrowse 태그의 총 개수
    vul_count = 0      # 취약으로 판단되는 태그의 개수

    for match in matches:
        count += 1
        enabled_value = match.group(1).strip().lower()
        tag = match.group(0).strip()
        reason_str += f"{tag}\n"

        if "true" in enabled_value:
            vul_count += 1
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": tag,
                "vulnerabilityConditionReasonCode": "WST-031"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)


    # directoryBrowse 태그가 없는 경우
    if count == 0:
        reason_str += "directoryBrowse 구문 없음\n"

    # 취약 여부 판단
    if vul_count > 0:
        # 취약한 설정이 하나 이상 존재
        result = "Y"  # Vulnerable
        auto_result_reason = "(-) directoryBrowse 필드값이 enabled=true가 탐지되어 취약으로 판단\n" + reason_str
    else:
        # 취약한 설정이 없거나, directoryBrowse 태그가 없거나 enabled=false로 설정됨
        result = "N"  # Normal
        if count > 0:
            auto_result_reason = "(+) directoryBrowse 필드가 없거나, 값이 enabled=false로 탐지되어 양호로 판단\n" + reason_str
        else:
            auto_result_reason = "(+) directoryBrowse 필드가 없거나, 값이 enabled=false로 탐지되어 양호로 판단\n" + reason_str

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_033(configData):
    # Initialize result and reason strings
    result = "N"  # 기본값을 양호(Normal)으로 설정
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []
    
    # 정규 표현식 패턴 컴파일
    # <asp enableParentPaths="true" /> 또는 <asp enableParentPaths='false' />
    pattern = re.compile(r'<\s*asp\s+enableParentPaths\s*=\s*["\'](.*?)["\']\s*/>', re.IGNORECASE)
    
    # 모든 매칭 찾기
    matches = pattern.finditer(configData)
    count = 0          # asp 태그의 총 개수
    vuln_found = False  # 취약 설정 발견 여부
    
    for match in matches:
        count += 1
        enabled_value = match.group(1).strip().lower()
        tag = match.group(0).strip()
        reason_str += f"{tag}\n"
        
        if "true" in enabled_value:
            vuln_found = True
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": match.group().strip(),
                "vulnerabilityConditionReasonCode": "WST-033"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)

    
    # asp 태그가 없는 경우
    if count == 0:
        reason_str += "<asp enableParentPaths=.../> 구문 없음\n"
    
    # 취약 여부 판단
    if vuln_found:
        # 취약한 설정이 존재
        result = "Y"  # Vulnerable
        auto_result_reason = "(-) enableParentPaths 필드의 값이 true인 설정이 탐지되어 취약으로 판단\n" + reason_str
    else:
        # 취약한 설정이 없거나, asp 태그가 없거나 enabledParentPaths=false로 설정됨
        result = "N"  # Normal
        if count > 0:
            auto_result_reason = "(+) enableParentPaths 필드가 없거나, 값이 enabled=false로 탐지되어 양호로 판단\n" + reason_str
        else:
            auto_result_reason = "(+) enableParentPaths 필드가 없거나, 값이 enabled=false로 탐지되어 양호로 판단\n" + reason_str
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_035(configData):
    # Initialize result and reason strings
    result = "N"  # 기본값을 양호(Normal)으로 설정
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []

    # 정규 표현식 패턴 컴파일 (대소문자 무시)
    pattern = re.compile(r"<\s*limits\s+maxRequestEntityAllowed\s*=\s*['\"]?(.*?)['\"]?\s*/>", re.IGNORECASE)
    count = 0

    # configData에서 패턴에 매칭되는 모든 항목 찾기
    for match in pattern.finditer(configData):
        count += 1
        # 그룹에서 따옴표 제거 및 공백 제거 후 숫자로 변환
        limit_size_str = match.group(1).replace('"', "").replace("'", "").strip()
        limit_size = int(limit_size_str)

        matched_str = match.group().strip()
        reason_str += matched_str + "\n"

        if limit_size > 100000000:
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": matched_str,
                "vulnerabilityConditionReasonCode": "WST-035"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
        # No else needed since reason_str is already updated

    # 매칭된 항목이 없을 경우 메시지 추가
    if count == 0:
        reason_str += "maxRequestEntityAllowed 구문 없음\n"

    # 취약성 여부 판단 및 결과 문자열 설정
    if not vulnerability_condition_result_model_list:
        result = "N"  # 양호 (Normal)
        auto_result_reason = "(+) maxRequestEntityAllowed 값이 없거나(없을 경우 디폴트값으로 200000 byte로 설정됨) 100000000 이하로 탐지되어 양호로 판단\n" + reason_str
    else:
        result = "Y"  # 취약 (Vulnerable)
        auto_result_reason = "(-) maxRequestEntityAllowed값이 100000000 이상의 값으로 설정된 것으로 탐지되어 취약으로 판단\n" + reason_str

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_036(configData):
    # Initialize result and reason strings
    result = "N"  # 기본값을 양호(Normal)으로 설정
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []
    
    # 정규 표현식 패턴 컴파일
    # <processModel identityType="LocalSystem" /> 또는 <processModel identityType='ApplicationPoolIdentity' />
    pattern = re.compile(r'<\s*processModel\s+identityType\s*=\s*[\'"](.*?)[\'"]\s*/>', re.IGNORECASE)
    
    # 모든 매칭 찾기
    matches = pattern.finditer(configData)
    count = 0          # processModel 태그의 총 개수
    vul_found = False  # 취약 설정 발견 여부
    
    for match in matches:
        count += 1
        tag = match.group(0).strip()
        identity_type = match.group(1).strip().lower()
        reason_str += f"{tag}\n"
        
        if "localsystem" in identity_type:
            vul_found = True
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": match.group().strip(),
                "vulnerabilityConditionReasonCode": "WST-036"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)

    
    # processModel 태그가 없는 경우
    if count == 0:
        auto_result_reason = "(*) 수동 판단 필요: processModel identityType 구문이 탐지되지 않아 수동 판단 필요\n"
    elif vul_found:
        # 취약한 설정이 존재
        auto_result_reason = "(-) processModel 필드의 identityType 값이 localsystem인 값이 탐지되어 취약으로 판단\n" + reason_str
        result = "Y"  # Vulnerable
    else:
        # 취약한 설정이 없거나, processModel 태그가 없거나 identityType이 LocalSystem이 아님
        auto_result_reason = "(+) processModel 필드의 identityType 값이 모두 localsystem이 아닌 것으로 탐지되어 양호로 판단\n" + reason_str
        result = "N"  # Normal
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_037(configData):
    # Initialize result and reason strings
    result = "N"  # 기본값을 양호(Normal)으로 설정
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []
    
    # 정규 표현식 패턴 컴파일
    # <virtualDirectory ... /> 태그 찾기
    pattern = re.compile(r'<\s*virtualDirectory[^>]*\/>', re.IGNORECASE)
    
    # 모든 매칭 찾기
    matches = pattern.finditer(configData)
    vuln_found = False  # 취약 설정 발견 여부
    
    for match in matches:
        tag = match.group(0).strip()
        tag_lower = tag.lower()
        reason_str += f"{tag}\n"
        
        # 'iisadmin' 또는 'iisadmpwd'가 포함되어 있는지 확인
        if "iisadmin" in tag_lower or "iisadmpwd" in tag_lower:
            vuln_found = True
            vulnerability_condition_result = {
                "vulnerabilityConditionOutput": match.group().strip(),
                "vulnerabilityConditionReasonCode": "WST-037"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)

    # 취약 여부 판단
    if vuln_found:
        # 취약한 설정이 존재
        result = "Y"  # Vulnerable
        auto_result_reason = "(-) virtualDirectory의 path에 iisadmin, iisadmpwd 등이 탐지되어 취약으로 판단\n" + reason_str
    else:
        # 취약한 설정이 없거나, virtualDirectory 태그가 없음
        # virtualDirectory 태그가 없는 경우도 양호로 판단
        auto_result_reason = "(+) virtualDirectory의 path에 iisadmin, iisadmpwd 등이 탐지되지 않아 양호로 판단\n" + reason_str
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

# VENDOR-EDIT(bug): WST-040-polarity — xlsx 판단기준 역전 의심(코드만으로 수정 불가).
# 결정론 비활성: webwas 어댑터가 WST-040을 DET_SOURCE MANUAL로 처리하므로 이 함수는
# 호출되지 않아야 함. 사용자 xlsx 확인 후 KNOWN_BUGS.md §3 대기. (Phase 3)
def check_WST_040(configData):
    # Initialize result and reason strings
    result = "N"  # 기본값을 양호(Normal)으로 설정
    auto_result_reason = ""
    reason_str = ""
    vulnerability_condition_result_model_list = []
    
    # 정규 표현식 패턴 컴파일
    # <requestFiltering>...</requestFiltering>
    pattern = re.compile(r'<\s*requestFiltering\s*>([\s\S]*?)<\s*/\s*requestFiltering\s*>', re.IGNORECASE)
    
    # 모든 매칭 찾기
    matches = pattern.finditer(configData)
    count = 0          # .asa 또는 .asax 매핑의 총 개수
    allStr = ""
    has_match = False  # requestFiltering 섹션 존재 여부
    
    for match in matches:
        has_match = True
        allStr += match.group(0).strip() + "\n\n"
        inner_content = match.group(1)
        
        # 각 라인별로 검사
        lines = inner_content.splitlines()
        for line in lines:
            line_lower = line.lower()
            if ((".asa" in line_lower or ".asax" in line_lower) and "true" in line_lower):
                count += 1
                reason_str += line.strip() + "\n"
                vulnerability_condition_result = {
                    "vulnerabilityConditionOutput": line.strip(),
                    "vulnerabilityConditionReasonCode": "WST-040"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result)
    
    # 매핑이 하나도 없는 경우
    if has_match and count == 0:
        reason_str = ".asa, .asax mapping 설정이 탐지되지 않음\n" + allStr
        vulnerability_condition_result2 = {
            "vulnerabilityConditionOutput": ".asa, .asax 노출 방지를 위한 Mapping 설정 없음",
            "vulnerabilityConditionReasonCode": "WST-040"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result2)
        
    # 취약 여부 판단
    if not has_match:
        # requestFiltering 섹션이 없는 경우
        auto_result_reason = "(+) requestFiltering 섹션에서 .asa 와 .asax가 허용 거부된 것으로 탐지되어 양호로 판단\n" + reason_str
    elif count > 0:
        # .asa 또는 .asax 매핑이 존재하는 경우 (취약)
        auto_result_reason = "(-) requestFiltering 섹션에서 .asa 와 .asax가 허용된 것으로 탐지되어 취약으로 판단\n" + reason_str
        result = "Y"  # Vulnerable
    else:
        # requestFiltering 섹션은 존재하지만 .asa 또는 .asax 매핑이 없는 경우 (양호)
        auto_result_reason = "(+) requestFiltering 섹션에서 .asa 와 .asax가 허용 거부된 것으로 탐지되어 양호로 판단\n" + reason_str
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_042(configData):
    # Initialize result and reason strings
    result = "N"  # 기본값을 양호(Normal)으로 설정
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    reason_str = ""
    vul_str = ""
    
    # 정규 표현식 패턴 컴파일
    # <handlers accessPolicy>...</handlers>
    pattern = re.compile(r'<\s*handlers\s*accessPolicy[^>]*>([\s\S]*?)<\s*/\s*handlers\s*>', re.IGNORECASE)
    
    # 모든 매칭 찾기
    matches = pattern.finditer(configData)
    
    for match in matches:
        inner_content = match.group(1)
        # 각 라인별로 검사
        lines = inner_content.splitlines()
        for line in lines:
            line_lower = line.lower()
            if (".htr" in line_lower or ".idc" in line_lower or ".shtm" in line_lower or 
                ".shtml" in line_lower or ".stm" in line_lower or ".printer" in line_lower or 
                ".htw" in line_lower or ".ida" in line_lower or ".idq" in line_lower):
                vul_str += line.strip() + "\n"
                vulnerability_condition_result = {
                    "vulnerabilityConditionOutput": line.strip(),
                    "vulnerabilityConditionReasonCode": "WST-042"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result)

            else:
                reason_str += line.strip() + "\n"
    
    # 매칭된 handlers 섹션이 없는 경우
    if not re.search(pattern, configData):
        auto_result_reason = "(+) handlers 섹션에 .htr, .idc, .shtm, .shtml, .stm, .printer, .htw, ida, idq 매핑이 없는 것으로 탐지되어 양호로 판단\n" + reason_str
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    # 취약한 매핑이 존재하는지 확인
    if vul_str:
        # 취약한 설정이 존재
        result = "Y"  # Vulnerable
        auto_result_reason = "(-) handlers 섹션에 .htr, .idc, .shtm, .shtml, .stm, .printer, .htw, ida, idq 매핑이 존재하는 것으로 탐지되어 취약으로 판단\n" + vul_str
    else:
        # 취약한 설정이 없으므로 양호
        auto_result_reason = "(+) handlers 섹션에 .htr, .idc, .shtm, .shtml, .stm, .printer, .htw, ida, idq 매핑이 없는 것으로 탐지되어 양호로 판단\n" + reason_str
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_WST_102(configData):
    # Initialize result and reason strings
    result = "N"  # 기본값을 양호(Normal)으로 설정
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    reasonStr = ""
    reasonStr2 = ""
    reasonStr3 = ""
    headerVul = True

    #print("ConfigData : ", configData)

    # Pattern to match <requestFiltering removeServerHeader="value" />
    pattern = re.compile(r"<\s*requestFiltering\s+removeServerHeader\s*=\s*['\"]?(.*?)['\"]?\s*/\s*>", re.IGNORECASE)

    # Find all matches for removeServerHeader
    for m in pattern.finditer(configData):
        if "true" in m.group(1).lower():
            reasonStr3 += m.group().strip() + "\n"
            headerVul = False
        else:
            reasonStr3 += "True 설정 없음: " + m.group().strip() + "\n"

    # Check for response_server in each line
    for line in configData.split('\n'):
        if "response_server" in line.lower():
            headerVul = False
            reasonStr3 += line.strip() + "\n"

    # If neither removeServerHeader=true nor response_server is set, mark as vulnerable
    if headerVul:
        vulnerability_condition_result = {
            "vulnerabilityConditionOutput": "removeServerHeader 또는 response_server rewrite rule 적용을 통한 서버 정보 노출 방지 설정 없음",
            "vulnerabilityConditionReasonCode": "WST-102"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result)

    # Pattern to match <httpErrors errorMode="value" ...>
    pattern2 = re.compile(r"<\s*httpErrors\s+errorMode\s*=\s*\"(.*?)\".*>", re.IGNORECASE)
    m2 = pattern2.search(configData)

    if not m2:
        reasonStr2 = "(+) httpErrors errorMode 구문이 탐지되지 않아 양호로 판단 (default는 DetailedLocalOnly 이므로 양호)\n"
    else:
        errorVal = m2.group(1).strip().lower()
        if errorVal == "detailed":
            reasonStr2 = "(-) httpErrors errorMode 설정이 detailed 값으로 탐지되어 취약으로 판단\n" + m2.group(0) + "\n"
            vulnerability_condition_result_model2 = {
                "vulnerabilityConditionOutput": "서버의 에러 메시지가 상세하게 출력되도록 설정됨\n" + m2.group(0),
                "vulnerabilityConditionReasonCode": "WST-102"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model2)
        else:
            reasonStr2 = "(+) httpErrors errorMode 설정이 detailed 값이 아닌 것으로 탐지되어 양호로 판단\n" + m2.group(0) + "\n"

    # VENDOR-EDIT(bug): WST-102-iis-polarity — 위반0건인데 result='Y'(취약) 역전 수정.
    # 원본: `if not vul_list: result = "Y"` (양호 케이스에 취약 코드 → 역전 버그).
    # 수정: 위반 0건 → result='N'(양호), 위반 있음 → result='Y'(취약). (KNOWN_BUGS.md §2)
    if not vulnerability_condition_result_model_list:
        result = "N"  # 위반 0건 → 양호 (버그수정: 원본은 "Y" 였음)
        auto_result_reason = (
            "(+) requestFiltering removeServerHeader값이 true 거나, RESPONSE_SERVER 헤더가 rewrite 설정된 것으로 탐지되어 양호로 판단\n"
            + reasonStr3 + "\n\n" + reasonStr2
        )
    else:
        result = "Y"  # 위반 있음 → 취약 (버그수정: 원본은 이 줄 없어 result='N'이었음)
        if headerVul:
            reasonStr = (
                "(-) requestFiltering removeServerHeader값이 false 또는 존재하지 않거나, RESPONSE_SERVER 헤더가 rewrite 설정이 없는 것으로 탐지되어 취약으로 판단\n"
                + reasonStr3 + "\n" +
                "설정 파일에 removeServerHeader 설정 또는 Response_Server 헤더 rewrite 설정 모두 미존재\n\n"
            )
        else:
            reasonStr = (
                "(+) requestFiltering removeServerHeader값이 true 거나, RESPONSE_SERVER 헤더가 rewrite 설정된 것으로 탐지되어 양호로 판단\n"
                + reasonStr3 + "\n\n"
            )
        auto_result_reason = reasonStr + reasonStr2

    return result, auto_result_reason, vulnerability_condition_result_model_list

def main(xml_result_dict):
    json_output = json.dumps(xml_result_dict, indent=4, ensure_ascii=False)
    data_dict = json.loads(json_output)
    results_dict = {}
    
    function_dispatcher = {
        "WST-032": check_WST_032, # 기존 SRV-041
        "WST-034": check_WST_034, # 기존 SRV-043
        "WST-038": check_WST_038, # 기존 SRV-047
        "WST-039": check_WST_039, # 기존 SRV-048
        "WST-041": check_WST_041, # 기존 SRV-057
        "WST-043": check_WST_043, # 기존 SRV-059
        "WST-044": check_WST_044, # 기존 SRV-060
    }
    
    # 설정 파일 'applicationHost.config'과 관련된 자동분석
    config_function_dispatcher = {
        "WST-031": check_WST_031, # 기존 SRV-040
        "WST-033": check_WST_033, # 기존 SRV-042
        "WST-035": check_WST_035, # 기존 SRV-044
        "WST-036": check_WST_036, # 기존 SRV-045
        "WST-037": check_WST_037, # 기존 SRV-046
        "WST-040": check_WST_040, # 기존 SRV-055
        "WST-042": check_WST_042, # 기존 SRV-058
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

    iis_config = data_dict['IIS_CONFIG']

    for key, func in config_function_dispatcher.items():
        returned_value = func(iis_config)  # 각 함수에 iis_config 전달
        
        if isinstance(returned_value, tuple) and len(returned_value) == 3:
            result, auto_result_reason, vul_result_model = returned_value
        else:
            result = 'N'
            auto_result_reason = ''
            vul_result_model = []
        
        # 결과를 results_dict에 저장
        results_dict[key] = {
            'output': iis_config,
            'result': result,
            'auto_result_reason': auto_result_reason,
            'vul_result_model': vul_result_model
        }
        
    return results_dict