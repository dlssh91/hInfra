# coding=utf-8
# VENDOR-EDIT(a): import 경로 변경
#   원본: from common.ServerConfigLoader.sclib import ...
#   변경: from judge_tool.vendor.common.server.sclib import ...
import re, json
from datetime import datetime, timezone
from judge_tool.vendor.common.server.sclib import get_check_service, split_output

def check_SRV_026(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    telnetOn = False
    sshOn = False
    
    telnetVul = False
    sshVul = False
    infoFlag = False
    
    telnetStr = ""
    sshStr = ""

    # 출력물을 분할  
    outputArr = split_output(output, 3)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    service_check_telnet = get_check_service(outputArr[0], 'telnet')
    service_check_ssh = get_check_service(outputArr[1], 'ssh\\|ssh-server')
    
    if service_check_telnet:
        telnetOn = True
    if service_check_ssh:
        sshOn = True
    
    # Both services are inactive, return positive result
    if not telnetOn and not sshOn:
        result = 'N'
        auto_result_reason = "(+) SSH, telnet 서비스 모두 비활성화로 탐지되어 양호로 판단\n" + outputArr[0] + "\n" + outputArr[1]
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    # Check Telnet configuration for vulnerabilities
    if not telnetOn:
        telnetVul = False
        telnetStr = "(+) telnet 서비스가 비활성화로 탐지되어 양호로 판단\n" + outputArr[0] + "\n"
    else:
        secureFile = re.search(r"(\$?\s*cat\s*/etc/securetty.*?$([\s\S]*?))------------", outputArr[2], re.MULTILINE)
        if secureFile:
            targetStr = secureFile.group(2)
            
            noFile = re.search(r"^cat:.*", targetStr, re.MULTILINE)
            if noFile:
                telnetVul = True
                telnetStr = "(-) /etc/securetty 파일이 존재하지 않는 것으로 탐지되어 취약으로 판단\n" + noFile.group(0) + "\n"
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": "/etc/securetty 파일 없음",
                    "vulnerabilityConditionReasonCode": "SRV-026"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
    
            else:
                consoleStr = re.findall(r"(ptyp1|^pts.*)", targetStr, re.MULTILINE)
                if consoleStr:
                    telnetVul = True
                    telnetStr = "(-) /etc/securetty 파일 내에 ptyp1, pts 등의 가상터미널의 허용이 탐지되어 취약으로 판단\n" + "\n".join(consoleStr) + "\n"
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput": "# /etc/securetty\n" + "\n".join(consoleStr),
                        "vulnerabilityConditionReasonCode": "SRV-026"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    telnetVul = False
                    telnetStr = "(+) /etc/securetty 파일 내에 ptyp1, pts 등의 가상터미널의 허용이 탐지되지 않아 양호로 판단\n" + secureFile.group(1) + "\n"
        else:
            infoFlag = True
            telnetVul = True
            telnetStr = "(-) telnet 서비스가 실행 중이고, /etc/securetty 파일이 탐지되지 않아 취약으로 판단\n"
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": "/etc/securetty 파일 탐지 실패",
                "vulnerabilityConditionReasonCode": "SRV-026"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
    
    # Check SSH configuration for vulnerabilities
    if not sshOn:
        sshVul = False
        sshStr = "(+) SSH 서비스가 비활성화로 탐지되어 양호로 판단\n" + outputArr[1] + "\n"
    else:
        root_login_pattern = re.compile(r'^([#\s]*)PermitRootLogin\s*(.*)', re.MULTILINE | re.IGNORECASE)
        root_login_matches = root_login_pattern.finditer(outputArr[2])
        searchFlag = False
        ssh_Content = ""
        
        for root_login_match in root_login_matches:
            searchFlag = True
            comment_or_setting = root_login_match.group(1)
            permit_root_login = root_login_match.group(2).lower()
            
            if "#" not in comment_or_setting:
                if "yes" not in permit_root_login:
                    sshVul = False
                    sshStr = (
                        "(+) SSH 서비스가 실행 중이나, PermitRootLogin yes로 설정되지 않음이 탐지되어 양호로 판단\n"
                        + root_login_match.group(0) + "\n"
                    )
                else:
                    sshVul = True
                    sshStr = (
                        "(-) SSH 서비스가 실행 중이고, PermitRootLogin yes로 설정된 것이 탐지되어 취약으로 판단\n"
                        + root_login_match.group(0) + "\n"
                    )
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput": root_login_match.group(0),
                        "vulnerabilityConditionReasonCode": "SRV-026"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
                break # 첫 번째로 발견한 설정이 유효 설정이 됨
            
            else:
                ssh_Content += root_login_match.group(0) + "\n"
        
        if not searchFlag:
            sshVul = True
            infoFlag = True
            sshStr = "(-) SSH 서비스가 실행 중이고, PermitRootLogin 구문이 탐지되지 않아 취약으로 판단\n"
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": "PermitRootLogin no 설정 없음",
                "vulnerabilityConditionReasonCode": "SRV-026"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
        elif not sshStr:
            sshVul = True
            sshStr = "(-) SSH 서비스가 실행 중이고, PermitRootLogin 구문이 주석 처리되어 취약으로 판단\n" + ssh_Content
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": ssh_Content,
                "vulnerabilityConditionReasonCode": "SRV-026"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
    
    if sshVul or telnetVul:
        result = 'Y'
    else:
        result = 'N'
    
    auto_result_reason = telnetStr + '\n' + sshStr
    if infoFlag:
        auto_result_reason += '\n' + outputArr[2]
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_069(output):
    result = 'N'
    reason_maxStr = ""
    reason_passwdStr = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Split the output into sections
    outputArr = split_output(output, 4)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    ###### 최대 변경 기간이 90일 초과로 설정된 계정을 탐색 ######
    
    # Initialize variables
    max_vul = False
    vul_str = ""
    result_str = ""
    vul_flag = False
    no_max = False

    # Compile regex patterns
    user_pattern = re.compile(r"^\$ chage -l (\S+)[\r\n]*[\s\S]*?------------", re.MULTILINE | re.IGNORECASE)
    max_pattern = re.compile(r"Maximum.*?(\d{1,})", re.MULTILINE | re.IGNORECASE)
    max_ko_pattern = re.compile(r".*?최대.*?(\d{1,})", re.MULTILINE | re.IGNORECASE)
     
    # Find all user matches in the fourth section
    for m in user_pattern.finditer(outputArr[3]):
        user = m.group(1).strip()
        user_info = m.group(0)

        max_match = max_pattern.search(user_info)
        if max_match:
            max_days = int(max_match.group(1))
            if max_days > 90:
                max_vul = True
                vul_flag = True
                vul_str += f"{user}\n\t{max_match.group(0)}\n\n"
                
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": f"{user}\n\t{max_match.group(0)}",
                    "vulnerabilityConditionReasonCode": "SRV-069"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            result_str += f"{user}\n\t{max_match.group(0)}\n\n"
        
        else:
            max_ko_match = max_ko_pattern.search(user_info)
            if max_ko_match:
                max_days = int(max_ko_match.group(1))
                if max_days > 90:
                    max_vul = True
                    vul_flag = True
                    vul_str += f"{user}\n\t{max_ko_match.group(0)}\n\n"
                    
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput": f"{user}\n\t{max_ko_match.group(0)}",
                        "vulnerabilityConditionReasonCode": "SRV-069"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
                result_str += f"{user}\n\t{max_ko_match.group(0)}\n\n"
            
            else:
                no_max = True

    # Determine reason string based on max_vul
    if max_vul:
        reason_maxStr = "(-) 패스워드 변경 기간이 90일이 초과된 계정이 탐지되어 취약으로 판단\n" + vul_str
    else:
        if not no_max:
            reason_maxStr = "(+) 모든 활성 계정의 패스워드 변경 기간이 90일미만으로 탐지되어 양호로 판단\n" + result_str
        else:
            reason_maxStr = "(*) 하나 이상의 계정에서 패스워드 최대 변경 기간 탐지 실패, 수동 점검 필요\n" + outputArr[3]
    
    ###### 비밀번호 복잡도 및 길이 설정 검사 ######

    # Debian/Ubuntu 계열
    # /etc/pam.d/common-password에 있는 pam_pwquality.so 옵션이 1순위 (outputArr[0])
    # 옵션에 없는 항목은 /etc/security/pwquality.conf 값이 2순위로 적용 (outputArr[1])

    # RHEL/CentOS/Fedora 계열
    # /etc/pam.d/system-auth의 pam_pwquality.so 옵션이 1순위 (outputArr[2])
    # 옵션에 없는 항목은 /etc/security/pwquality.conf 값이 2순위로 적용 (outputArr[1])

    # Initialize complexity count
    complex_cnt = 0

    # Compile regex patterns for complexity
    password_requisite_pattern = re.compile(r"^password\s+requisite\s+.*", re.MULTILINE | re.IGNORECASE)
    credit_types = ['d', 'o', 'u', 'l']
    credit_patterns = [re.compile(rf"{credit_type}credit\s*=\s*-\d*", re.MULTILINE | re.IGNORECASE) for credit_type in credit_types]
    credit_conf_patterns = [re.compile(rf"^[\s]*{credit_type}credit\s*=\s*-\d*", re.MULTILINE | re.IGNORECASE) for credit_type in credit_types]

    credit_set = [False, False, False, False]

    # 우선 outputArr[0] 및 outputArr[2]을 검사
    complex_line = password_requisite_pattern.search(outputArr[0])
    if complex_line:
        complex_str = complex_line.group(0)
        for idx, credit_pattern in enumerate(credit_patterns):
            if credit_pattern.search(complex_str):
                credit_set[idx] = True
    else:
        complex_line2 = password_requisite_pattern.search(outputArr[2])
        if complex_line2:
            complex_str2 = complex_line2.group(0)
            for idx, credit_pattern in enumerate(credit_patterns):
                if credit_pattern.search(complex_str2):
                    credit_set[idx] = True
    
    # 이후 빈 설정들에 대해서 outputArr[1]에서 설정 검사
    for idx, credit_conf_pattern in enumerate(credit_conf_patterns):
        if credit_set[idx]:
            continue
        if credit_conf_pattern.search(outputArr[1]):
            credit_set[idx] = True
    
    # 최종 비밀번호 복잡도 산출
    complex_cnt = sum(credit_set)

    # minlen 산출시에도 비슷한 로직으로 순서대로 살펴본다.
    # Initialize minimum length variables
    min_found = False
    min_val = 0
    minlen_str = ""

    # Compile regex patterns for minimum length
    minlen_common_password_pattern = re.compile(r"^password.*?minlen\s*=\s*(\d{1,})", re.MULTILINE | re.IGNORECASE)
    minlen_pwquality_conf_pattern = re.compile(r"^[\s]*minlen\s*=\s*(\d{1,})", re.MULTILINE | re.IGNORECASE)
    minlen_system_auth_pattern = re.compile(r"^password\s+requisite\s+.*?minlen\s*=\s*(\d{1,})", re.MULTILINE | re.IGNORECASE)

    # Check first section for minlen
    min_match = minlen_common_password_pattern.search(outputArr[0])
    if min_match:
        min_found = True
        min_val = int(min_match.group(1))
        minlen_str = f"# /etc/pam.d/common-password\n{min_match.group(0)}\n"
    else:
        min_match = minlen_system_auth_pattern.search(outputArr[2])
        if min_match:
            min_found = True
            min_val = int(min_match.group(1))
            minlen_str = f"# /etc/pam.d/system-auth\n{min_match.group(0)}\n"

    if not min_found:
        # Check second section for minlen
        min_match = minlen_pwquality_conf_pattern.search(outputArr[1])
        if min_match:
            min_found = True
            min_val = int(min_match.group(1))
            minlen_str = f"# /etc/security/pwquality.conf\n{min_match.group(0)}\n"

    # 여전히 min_found == False라면 최소 길이 설정이 되지 않은 것, 취약
    if not min_found:
        vul_flag = True
        reason_passwdStr = f"(-) 패스워드 최소길이 minlen 구문이 탐지되지 않아 취약으로 판단\n{output}"
        vulnerability_condition_result_model = {
            "vulnerabilityConditionOutput": "minlen 설정 없음",
            "vulnerabilityConditionReasonCode": "SRV-069"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
    else:
        if complex_cnt < 2:
            vul_flag = True
            reason_passwdStr = f"(-) 복잡도 설정이 2조합 미만(lcredit, ucredit, dcredit, ocredit 설정 참조)으로 탐지되어 취약으로 판단\n"
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": f"패스워드 복잡도: {complex_cnt}\n",
                "vulnerabilityConditionReasonCode": "SRV-069"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
        elif complex_cnt == 2:
            if min_val >= 10:
                reason_passwdStr = f"(+) 복잡도 설정이 3조합 미만(lcredit, ucredit, dcredit, ocredit 설정 참조)이지만, 길이 10자리 이상 설정이 탐지되어 양호로 판단\n{minlen_str}"
            else:
                vul_flag = True
                reason_passwdStr = (
                    f"(-) 복잡도 설정이 3조합 미만(lcredit, ucredit, dcredit, ocredit 설정 참조)으로 탐지됐고, "
                    f"길이가 10자리 미만으로 설정되어 취약으로 판단\n"
                    f"{minlen_str}"
                )
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": f"패스워드 복잡도: {complex_cnt}\n{minlen_str}",
                    "vulnerabilityConditionReasonCode": "SRV-069"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
        else: # 복잡도 설정 3이상
            if min_val >= 8:
                reason_passwdStr = (
                    f"(+) 복잡도 설정이 3조합 이상(lcredit, ucredit, dcredit, ocredit 설정 참조)으로 탐지됐고, "
                    f"길이 8자리 이상 설정이 탐지되어 양호로 판단\n"
                    f"{minlen_str}"
                )
            else:
                vul_flag = True
                reason_passwdStr = (
                    f"(-) 복잡도 설정이 3조합 이상(lcredit, ucredit, dcredit, ocredit 설정 참조)으로 탐지됐지만, "
                    f"길이가 8자리 미만으로 설정되어 취약으로 판단\n"
                    f"{minlen_str}"
                )
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": f"패스워드 복잡도: {complex_cnt}\n{minlen_str}",
                    "vulnerabilityConditionReasonCode": "SRV-069"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

    # Set the result based on vul_flag
    if vul_flag:
        result = 'Y'
    else:
        result = 'N'
        
    # Assign the final reason string
    auto_result_reason = reason_maxStr + '\n' + reason_passwdStr
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_074(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    reasonStr = ""

    vulFlag = False
    shellUserMap = {}

    # Split the output into sections
    outputArr = split_output(output, 3)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    # Extract shell users and their shell paths
    passwd_file_pattern = re.compile(r"^\s*\$ awk[^\r\n]*/etc/passwd[^\r\n]*\r?\n([\s\S]+)", re.MULTILINE | re.DOTALL)
    passwd_file_match = passwd_file_pattern.search(outputArr[1])

    passwdStr = ""
    if passwd_file_match:
        passwdStr = passwd_file_match.group(1)
        
        shell_pattern = re.compile(r"^([^$].*?)(/.*?)$", re.MULTILINE)
        shell_matches = shell_pattern.finditer(passwdStr)
        
        for m in shell_matches:
            shellLine = m.group(0)
            if shellLine.lower().endswith("sh"):
                user = m.group(1).strip()
                shell = m.group(2).strip()
                shellUserMap[user] = shell
    else:
        auto_result_reason = "(*) 수동 판단 필요: /etc/passwd 파일 내용이 탐지되지 않았습니다.\n" + outputArr[1]
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    # Get current epoch days
    epochDays = int((datetime.now() - datetime(1970, 1, 1)).total_seconds() // (60 * 60 * 24))
    currentDate = datetime.now(timezone.utc)

    for user in shellUserMap.keys():
        pwVul = False
        pwDays = ""
        logVul = False
        logDays = ""

        # Check password last change date
        userEpoch = re.search(rf"{user}[\s]*([0-9]+)", outputArr[0])
        if userEpoch:
            lastChangeDays = int(userEpoch.group(1))
            if epochDays - lastChangeDays > 90:
                vulFlag = True
                pwVul = True
                pwDays = str(epochDays - lastChangeDays) + " days"
                reasonStr += f"{userEpoch.group(0)} ({pwDays})\n\n"

        # Check last login for non-root users
        if user.lower() != "root":
            userLastLog = re.search(rf"^\$ lastlog -u {user}[\s\S]*?------------", outputArr[2], re.MULTILINE)
            if userLastLog:
                userLogStr = userLastLog.group(0)
                if "never logged in" in userLogStr.lower() or "한번도 로그인한" in userLogStr.lower():
                    vulFlag = True
                    logVul = True
                    logDays = "로그인 기록 없음"
                    reasonStr += f"{user} ({logDays})\n\n"
                else:
                    dow_en = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
                    dow_ko = r"(?:월|화|수|목|금|토|일)"
                    dow = rf"(?:{dow_en}|{dow_ko})"
                    
                    pattern = rf"^{re.escape(user)}\s+(?:(?P<port>\S+)\s+)?(?:(?P<from>(?!{dow}\b)\S+)\s+)?(?P<latest>{dow}\s.+)$"
                    
                    # Perform the search with MULTILINE and IGNORECASE flags
                    rx = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.VERBOSE)
                    lastLoginTime = rx.search(userLogStr)

                    if lastLoginTime:
                        try:
                            loginDateStr = lastLoginTime.group("latest")
                            if "월" in loginDateStr: # Korean date format
                                _, rest = loginDateStr.split(maxsplit=1) # 요일 제외
                                loginDate = datetime.strptime(rest, "%m월 %d %H:%M:%S %z %Y")
                            else: # English date format
                                loginDate = datetime.strptime(loginDateStr, "%a %b %d %H:%M:%S %z %Y")

                            days = (currentDate - loginDate).days

                            if days > 90:
                                vulFlag = True
                                logVul = True
                                logDays = f"{days} days"
                                reasonStr += f"{lastLoginTime.group(0)} ({logDays})\n\n"
                                
                        except ValueError:
                            reasonStr += f"(*) 수동 판단 필요: {user} lastlog 명령어 결과 분석 중 Date Parsing 실패\n\n"

        # Construct vulnerability string if password or login is vulnerable
        if pwVul or logVul:
            reasonStr += "\n======================================\n"
            vulStr = f"{user}:\n"
            if pwVul:
                vulStr += f"\t비밀번호 장기간 미변경: {pwDays}\n"
            if logVul:
                vulStr += f"\t장기간 미로그인: {logDays}\n"
            
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": vulStr.strip(),
                "vulnerabilityConditionReasonCode": "SRV-074"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

    # Result summary
    if vulFlag:
        result = 'Y'
        auto_result_reason = (
            f"(-) 비밀번호 장기간 미변경, 장기간 비로그인 계정이 탐지되어 취약으로 판단(담당자 확인 필요)\n"
            f"\t장기간(90일 이상) 비로그인, 장기간(90일 이상) 비밀번호 미변경\n{reasonStr}"
        )
    else:
        result = 'N'
        auto_result_reason = (
            "(+) 비밀번호 장기간 미변경, 장기간 비로그인 계정이 탐지되지 않아 양호로 판단\n"
            "\t/etc/passwd, /etc/shadow, lastlog 명령을 자동 분석한 결과\n"
            "\t장기간(90일 이상) 비로그인, 장기간(90일 이상) 비밀번호 미변경 계정 미탐지"
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_127(output):
    result = 'N'
    reasonStr = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    authVulFlag = False
    accountVulFlag = True
    
    # Check for auth required configuration
    auth_matches = re.finditer(
        r"^\$ grep auth /etc/pam.d/(system-auth|password-auth|common-auth)[\s\S]*?------------",
        output,
        re.MULTILINE
    )
    
    notFoundAuth = True
    for match in auth_matches:
        filePath = f"/etc/pam.d/{match.group(1)}"
        authVal = match.group(0)
        auth_required_match = re.search(
            r"^\s*auth\s+required.*?(pam_faillock.so|pam_tally.so|pam_tally2.so).*?deny\s*=\s*([0-9]+)",
            authVal,
            re.MULTILINE
        )
        if auth_required_match:
            notFoundAuth = False
            
            denyVal = int(auth_required_match.group(2))
            if denyVal < 1:
                authVulFlag = True
                reasonStr += (
                    f"(-) 설정 파일에 auth required ({auth_required_match.group(1)}) 구문에 deny 설정이 1 미만으로 탐지되어 취약으로 판단\n"
                    f"\t{auth_required_match.group(0)}\n"
                )
            else:
                reasonStr += (
                    f"# {filePath} (양호 설정 탐지)\n\t{auth_required_match.group(0)}\n"
                )

    # Check if auth required configurations are missing
    if notFoundAuth:
        authVulFlag = True
        reasonStr += (
            "(-) auth 설정 파일에 auth required (pam_faillock.so|pam_tally2.so|pam_tally.so) "
            "구문이 없는 것으로 탐지되어 취약으로 판단\n"
        )

    # Check for account required configuration
    account_matches = re.finditer(
        r"^\$ grep account /etc/pam.d/(system-auth|password-auth|common-auth)[\s\S]*?------------",
        output,
        re.MULTILINE
    )
    for match in account_matches:
        filePath = f"/etc/pam.d/{match.group(1)}"
        accountVal = match.group(0)
        account_required_match = re.search(
            r"^\s*account\s+required\s+(pam_faillock.so|pam_tally.so|pam_tally2.so).*",
            accountVal,
            re.MULTILINE
        )
        if account_required_match:
            accountVulFlag = False
            reasonStr += (
                f"# {filePath} (양호 설정 탐지)\n\t{account_required_match.group(0)}\n"
            )

    # Check if account required configurations are missing
    if accountVulFlag:
        reasonStr += (
            "(-) auth 파일에 account required (pam_faillock.so|pam_tally2.so|pam_tally.so) "
            "구문이 없는 것으로 탐지되어 취약으로 판단\n"
        )

    # Final vulnerability assessment
    if authVulFlag or accountVulFlag:
        result = 'Y'
        auto_result_reason = (
            "(-) 계정 잠금 임계값 설정을 위한 (pam_faillock.so|pam_tally2.so|pam_tally.so) 모듈 설정이 "
            "미흡한 것으로 탐지되어 취약으로 판단\n" + reasonStr
        )
        vulnerability_condition_result_model = {
            "vulnerabilityConditionOutput": "password-auth 또는 system_auth 또는 common_auth 파일 내 (pam_faillock.so|pam_tally2.so|pam_tally.so) 모듈 설정 미흡",
            "vulnerabilityConditionReasonCode": "SRV-127"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
    else:
        result = 'N'
        auto_result_reason = (
            "(+) 계정 잠금 임계값 설정을 위한 pam_faillock.so 모듈 설정이 모두 설정된 것으로 "
            "탐지되어 양호로 판단\n" + reasonStr
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_131(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Split the output by the separator
    outputArr = split_output(output, 3)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    # Check for pam_wheel module configuration in the second part of the output
    m = re.search(r"^\s*auth\s+required\s+.*pam_wheel\.so.*", outputArr[1], re.MULTILINE)
    if m:
        result = 'N'
        auto_result_reason = (
            "(+) wheel 그룹만 su를 허용하는 pam_wheel 모듈 설정이 탐지되어 양호로 판단\n"
            + m.group(0).strip() + "\n"
            + outputArr[2]
        )
    else:
        result = 'Y'
        auto_result_reason = (
            "(-) wheel 그룹만 su를 허용하는 pam_wheel 모듈 설정이 탐지되지 않아 취약으로 판단\n"
            + outputArr[1]
        )
        vulnerability_condition_result_model = {
            "vulnerabilityConditionOutput": outputArr[1].strip(),
            "vulnerabilityConditionReasonCode": "SRV-131"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
    return result, auto_result_reason, vulnerability_condition_result_model_list

def main(xml_result_dict):
    # 사전을 JSON 형식으로 변환
    json_output = json.dumps(xml_result_dict, indent=4, ensure_ascii=False)

    data_dict = json.loads(json_output)
    results_dict = {}

    function_dispatcher = {
        "SRV-026": check_SRV_026,
        "SRV-069": check_SRV_069,
        "SRV-074": check_SRV_074,
        "SRV-127": check_SRV_127,
        "SRV-131": check_SRV_131,
    }

    # Process each key-value pair in the JSON data
    for key, output in data_dict.items():
        result = 'N'
        auto_result_reason = ""
        vul_result_model = []
        
        if key in function_dispatcher:
            returned_value = function_dispatcher[key](output)  # Call the appropriate function based on the key
        
            if isinstance(returned_value, tuple):
                result, auto_result_reason, vul_result_model = returned_value

        results_dict[key] = {'output': output, 'result': result, 'auto_result_reason': auto_result_reason, 'vul_result_model': vul_result_model}

    return results_dict
