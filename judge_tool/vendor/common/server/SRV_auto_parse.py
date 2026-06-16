# coding=utf-8
# VENDOR-EDIT(a): import 경로 변경
#   원본: from common.ServerConfigLoader.sclib import ...
#   변경: from judge_tool.vendor.common.server.sclib import ...
import re, json
import html
from judge_tool.vendor.common.server.sclib import robust_parse_xml
from judge_tool.vendor.common.server.sclib import get_check_service, get_remove_line, split_output

def get_check_file_perm(file_perm, index, permission):
    # file_perm을 공백으로 나누어 리스트로 만듦
    str_arr = file_perm.strip().split()
    first_str = str_arr[0]

    # 첫 번째 문자열이 특정 패턴으로 시작하는지 확인 (DateTokenConverter.CONVERTER_KEY처럼 처리)
    if len(first_str) > 0 and first_str.lower().startswith("d".lower()):  # "key"는 실제 패턴에 맞게 수정
        return False

    # 권한을 3자리씩 잘라서 추출 (3 * index에서 권한 3개를 추출)
    temp = first_str[1:][3 * index: (3 * index) + 3]  # 1번째부터 시작해서, 3자리씩 권한 부분을 잘라냄
    
    # permission을 '|'로 분할하여 배열로 만듦
    permission_arr = permission.split("|")
    
    # permission_arr에 포함된 권한이 temp에 있는지 확인
    for val in permission_arr:
        if val in temp:  # 권한이 존재하는지 체크
            return True

    return False

def get_check_dir_perm(dir_perm, index, permission):
    """
    특정 디렉터리 권한을 검사하는 함수.

    :param dir_perm: 검사할 디렉터리 권한 문자열 (예: 'drwxrwxrwx')
    :param index: 권한을 검사할 위치 (0: 소유자, 1: 그룹, 2: 기타)
    :param permission: 검사할 권한 문자열 (예: 'w', 'r|w')
    :return: 권한이 존재하면 True, 아니면 False
    """
    # 입력 문자열을 공백으로 나누어 리스트로 만듦
    str_arr = dir_perm.strip().split()
    if not str_arr:
        return False  # 빈 리스트인 경우 False 반환

    first_str = str_arr[0]

    # 첫 번째 문자열이 특정 패턴(CONVERTER_KEY)으로 시작하지 않으면 False 반환
    if len(first_str) > 0 and not first_str.lower().startswith('d'.lower()):
        return False

    # 권한 문자열에서 해당 위치의 권한 3자리를 추출
    # first_str[1:]은 파일 유형 문자를 제외한 권한 부분 (예: 'rwxr-xr-x')
    temp = first_str[1:][3 * index: (3 * index) + 3]

    # permission을 '|'로 분할하여 배열로 만듦
    permission_arr = permission.split("|")

    # permission_arr에 포함된 권한이 temp에 있는지 확인
    for val in permission_arr:
        if val in temp:
            return True

    return False

def permissions_to_octal(permissions):
    # 권한 문자열에서 '-'를 제거하고 각 위치에 따른 권한을 계산
    perms = permissions[1:]  # 'rw-r--r--' 권한 부분만 추출
    owner_perms = perms[0:3]  # 소유자 권한 (예: 'rw-')
    group_perms = perms[3:6]  # 그룹 권한 (예: 'r--')
    other_perms = perms[6:9]  # 기타 사용자 권한 (예: 'r--')

    # 각 권한 부분을 octal로 변환
    def calc_octal(p):
        return 4 * ('r' in p) + 2 * ('w' in p) + 1 * ('x' in p)

    return (calc_octal(owner_perms), calc_octal(group_perms), calc_octal(other_perms))

# 버전 비교 함수
def compare_versions(version1, version2):
    version1_nums = [int(num) for num in version1.split('.')]
    version2_nums = [int(num) for num in version2.split('.')]
    
    for num1, num2 in zip(version1_nums, version2_nums):
        if num1 > num2:
            return False
        elif num1 < num2: # 기준 버전이 더 높은 경우 취약
            return True
    return len(version1_nums) < len(version2_nums)

# 파일 권한을 파싱하는 함수
def parse_permissions(file_list):
    permissions = []
    for item in file_list:
        parts = item.split()  # 공백을 기준으로 문자열 분리
        if len(parts) > 0 and parts[0].startswith(('d', '-', 'l', 'c', 'b', 's', 'p')):
            # 첫 부분이 파일 유형과 권한을 나타내는 문자열인지 확인 (d: 디렉토리, -: 파일, l: 심볼릭 링크 등)
            permissions.append(parts[0])
    return permissions

def get_smtp_type(output : str) -> str:
    smtp_type = "sendmail"
    m2 = re.search(r"(ps -ef [\s\S]*?)\[ smtp", output) # 정규식을 사용하여 smtpType 파악
    
    if m2:
        smtp_status = m2.group(1).lower()
        if "postfix" in smtp_status:
            smtp_type = "postfix"
        elif "exim" in smtp_status:
            smtp_type = "exim"
    
    return smtp_type
    
############# dns bind option parser #############

# --------- 1) 스크립트 출력 분해 & HTML 언이스케이프 ---------
def split_script_output(raw: str):
    """
    '$ cat /path' 헤더를 기준으로 파일별 내용을 분리.
    '------------' 한 줄은 구분자로 간주하여 섹션을 끊습니다.
    return: { filepath: file_text (HTML 언이스케이프됨) }
    """
    sections = {}
    current_path = None
    buf = []

    lines = raw.splitlines()
    header_re = re.compile(r'^\s*\$+\s*cat\s+(\S+)\s*$')
    sep_re = re.compile(r'^\s*------------\s*$', re.IGNORECASE)

    def flush():
        nonlocal current_path, buf
        if current_path is not None:
            content = "\n".join(buf).strip()
            # sed로 이스케이프된 &, <, > 되돌리기
            sections[current_path] = html.unescape(content)
        buf = []

    for line in lines:
        if sep_re.match(line):
            # 구분자 만나면 현 블록 마감
            flush()
            current_path = None
            continue
        m = header_re.match(line)
        if m:
            # 이전 블록 마감 후 새 블록 시작
            flush()
            current_path = m.group(1)
            continue
        # 일반 라인
        if current_path is not None:
            buf.append(line)

    # 마지막 잔여 버퍼
    flush()
    return sections


# --------- 2) 주석 제거 (문자열 보존) ---------
def strip_comments(text: str) -> str:
    """
    //, #, /* */ 주석 제거. 문자열 리터럴 내부는 건드리지 않음.
    """
    res = []
    i, n = 0, len(text)
    NORMAL, IN_STR, IN_SLASH, IN_SL_COMMENT, IN_HASH_COMMENT, IN_ML_COMMENT = range(6)
    state = NORMAL
    quote = None

    while i < n:
        ch = text[i]
        nxt = text[i+1] if i+1 < n else ''

        if state == NORMAL:
            if ch in ('"', "'"):
                state = IN_STR
                quote = ch
                res.append(ch); i += 1
            elif ch == '/':
                if nxt == '/':
                    state = IN_SL_COMMENT; i += 2
                elif nxt == '*':
                    state = IN_ML_COMMENT; i += 2
                else:
                    res.append(ch); i += 1
            elif ch == '#':
                state = IN_HASH_COMMENT; i += 1
            else:
                res.append(ch); i += 1

        elif state == IN_STR:
            res.append(ch)
            if ch == '\\' and i + 1 < n:
                res.append(text[i+1]); i += 2; continue
            if ch == quote:
                state = NORMAL; quote = None
            i += 1

        elif state == IN_SL_COMMENT:
            if ch in ('\r', '\n'):
                res.append(ch); state = NORMAL
            i += 1

        elif state == IN_HASH_COMMENT:
            if ch in ('\r', '\n'):
                res.append(ch); state = NORMAL
            i += 1

        elif state == IN_ML_COMMENT:
            if ch == '*' and nxt == '/':
                state = NORMAL; i += 2
            else:
                i += 1

    return ''.join(res)


# --------- 3) options 블록 추출/파싱 ---------
def _is_word_boundary(prev_char: str, next_char: str) -> bool:
    prev_ok = (not prev_char) or not (prev_char.isalnum() or prev_char == '_')
    next_ok = (not next_char) or not (next_char.isalnum() or next_char == '_')
    return prev_ok and next_ok

def _find_matching_brace(s: str, open_idx: int) -> int:
    depth, i, n = 0, open_idx, len(s)
    in_str, q = False, None
    while i < n:
        ch = s[i]
        if in_str:
            if ch == '\\' and i + 1 < n:
                i += 2; continue
            if ch == q:
                in_str = False; q = None
            i += 1; continue
        if ch in ('"', "'"):
            in_str = True; q = ch; i += 1; continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1

def extract_options_blocks(clean_text: str):
    blocks = []
    i, n = 0, len(clean_text)
    kw = 'options'
    while i < n:
        j = clean_text.find(kw, i)
        if j == -1: break
        prev_char = clean_text[j-1] if j-1 >= 0 else ''
        next_char = clean_text[j+len(kw)] if j+len(kw) < n else ''
        if _is_word_boundary(prev_char, next_char):
            k = j + len(kw)
            while k < n and clean_text[k].isspace(): k += 1
            if k < n and clean_text[k] == '{':
                close_idx = _find_matching_brace(clean_text, k)
                if close_idx != -1:
                    inner = clean_text[k+1:close_idx]
                    blocks.append(inner)
                    i = close_idx + 1; continue
        i = j + len(kw)
    return blocks

def split_top_level_statements(block_text: str):
    stmts, buf = [], []
    depth, i, n = 0, 0, len(block_text)
    in_str, q = False, None
    while i < n:
        ch = block_text[i]
        if in_str:
            buf.append(ch)
            if ch == '\\' and i + 1 < n:
                buf.append(block_text[i+1]); i += 2; continue
            if ch == q:
                in_str = False; q = None
            i += 1; continue
        if ch in ('"', "'"):
            in_str = True; q = ch; buf.append(ch); i += 1; continue
        if ch == '{':
            depth += 1; buf.append(ch)
        elif ch == '}':
            depth -= 1; buf.append(ch)
        elif ch == ';' and depth == 0:
            stmt = ''.join(buf).strip()
            if stmt: stmts.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = ''.join(buf).strip()
    if tail: stmts.append(tail)
    return [s for s in (s.strip() for s in stmts) if s]

def parse_option_statement(stmt: str):
    m = re.match(r'^([A-Za-z_][A-Za-z0-9_-]*)\s*(.*)$', stmt)
    if not m: return (stmt.strip(), '')
    return m.group(1), m.group(2).strip()

def parse_named_conf_options(text: str):
    clean = strip_comments(text)
    blocks = extract_options_blocks(clean)
    results = []
    for block in blocks:
        for stmt in split_top_level_statements(block):
            name, value = parse_option_statement(stmt)
            if name:
                results.append((name, value))
    return results


# --------- 4) 최종: 스크립트 결과 → 옵션 dict ---------
def options_dict_from_script_output(raw_output: str) -> dict:
    """
    스크립트 전체 출력(raw_output)을 입력받아,
    등장한 모든 파일의 options 블록을 파싱해 dict로 합칩니다.
    마지막으로 등장한 동일 키가 우선합니다.
    """
    sections = split_script_output(raw_output)
    opts = {}
    # 파일 등장 순서대로 처리(출력 순서 유지)
    for path in sections:
        # named.boot는 보통 options 블록이 없음: 자동 건너뜀
        if path.endswith('named.boot'):
            continue
        pairs = parse_named_conf_options(sections[path])
        for k, v in pairs:
            opts[k] = v
    return opts


############## auto inspection function ##############

# 모든 반환 형식은 (Y/N), 자동분석 이유, 취약점 리스트 (취약할 경우)
# 수동 분석이 필수적인 항목 리스트
# SRV-022, SRV-027, SRV-069
# SRV-075, SRV-091, SRV-109
# SRV-112, SRV-115, SRV-118
# SRV-144, SRV-163, SRV-175

# 다른 플랫폼에 자동분석 위임 항목
# SRV-026, SRV-034(Solaris), SRV-069, 
# SRV-074, SRV-112(Solaris), SRV-127,
# SRV-131, SRV-134(Solaris), SRV-135(Solaris)

# 아래 함수는 해당 자산이 WST인지 SRV인지 구별하기 위한 역할
def check_WST(output):
    result = 'N'
    outputArr = split_output(output, 4)
    
    if get_check_service(outputArr[0], "http\\|https\\|http-alt\\|www\\|www-http\\|apache\\|apache2"):
        result = 'Y'
    if get_check_service(outputArr[1], "wsm\\|webtob\\|htl"):
        result = 'Y'
    if get_check_service(outputArr[2], "tomcat"):
        result = 'Y'
    if 'JEUS is NOT installed' not in outputArr[3]:
        result = 'Y'
    
    return result, '', {}

def check_SRV_001(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    # Split the output by the specified delimiter
    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    # Check if the SNMP service is running
    if not get_check_service(output, "snmp"):
        result = 'N'
        auto_result_reason = "(+) SNMP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]
        return result, auto_result_reason, vulnerability_condition_result_model_list

    # SNMP 서비스가 실행 중, 버전을 확인해야 한다.
    config_section = get_remove_line(get_remove_line(outputArr[1], "#"), "$")
    config_blocks = config_section.strip().split('------------')

    config_contents = {}
    config_contents['v12'] = []
    config_contents['v3'] = []
    is_safe = True
    
    for block in config_blocks:
        if "[check v1v2]" in block:
            lines = block.splitlines()
            for line in lines:
                if not line.strip():
                    continue
                if '[check v1v2]' not in line.strip():
                    config_contents['v12'].append(line.strip())
    
        elif "[check v3]" in block:
            lines = block.splitlines()
            for line in lines:
                if not line.strip():
                    continue
                if '[check v3]' not in line.strip():
                    config_contents['v3'].append(line.strip())

    # Check SNMP v1/v2 settings
    # 해당 내용이 있다면 일단 취약으로 판단 (v3가 가능한 곳에서 v1, v2를 허용하는 것은 취약)
    if len(config_contents['v12']) != 0:
        is_safe = False
        for line in config_contents['v12']:
            vulnerability_condition_result = {
                'vulnerabilityConditionOutput': line,
                'vulnerabilityConditionReasonCode': "SRV-001"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)
            reason_str += f"SNMP v1/v2 설정 발견: {line}\n"
            
    # Check SNMP v3 settings
    # authNoPriv 또는 noAuthNoPriv 값이 있는지 확인
    if len(config_contents['v3']) != 0:
        for line in config_contents['v3']:
            proc_line = line.strip().lower()
            if "noauthnopriv" in proc_line or "authnopriv" in proc_line:
                is_safe = False
                vulnerability_condition_result = {
                    'vulnerabilityConditionOutput': line,
                    'vulnerabilityConditionReasonCode': "SRV-001"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result)
                reason_str += f"SNMP v3 취약 설정 발견: {line}\n"
    
    if is_safe:
        result = 'N'
        auto_result_reason = (
            "(+) SNMP 서비스 실행 중이나 SNMPv3를 사용하고 취약한 authNoPriv 또는 noAuthNoPriv 보안 설정이 탐지되지 않아 양호로 판단\n"
        )
    
    else:
        result = 'Y'
        auto_result_reason = (
            "(-) SNMP 서비스가 실행 중이고, 취약한 SNMPv1/v2 설정 또는 SNMPv3의 authNoPriv 또는 noAuthNoPriv 보안 설정이 탐지되어 취약으로 판단\n"
            + reason_str
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_004(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Step 1: Remove lines starting with '#' and the specified constructor argument prefix
    cleaned_output = get_remove_line(get_remove_line(output, "#"), "$")

    # Step 2: Check if any of the SMTP-related services are running
    service_check = get_check_service(cleaned_output, 'smtp\\|sendmail\\|postfix\\|exim')

    if service_check:
        # SMTP-related service is running; flag as vulnerable
        result = 'Y'
        auto_result_reason = "(-) SMTP 서비스가 실행 중인 것으로 탐지되어 취약으로 판단(업무상 사용 여부 확인 필요)\n\n" + output.strip()
        vulnerability_condition_result = {
            'vulnerabilityConditionOutput': "불필요한 SMTP 서비스 실행 중",
            'vulnerabilityConditionReasonCode': "SRV-004"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result)
        
    else:
        result = 'N'
        auto_result_reason = "(+) SMTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n\n" + output.strip()
        
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_005(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    outputArr = split_output(output, 3)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    cleaned_outputArr = get_remove_line(get_remove_line(output, "#"), "$").splitlines()

    service_check = get_check_service(outputArr[0], 'smtp\\|sendmail\\|postfix\\|exim')
    
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) SMTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단"
    
    else:
        smtp_type = get_smtp_type(outputArr[0]) 
        
        if smtp_type == "exim":
            param_exist = False
            param_pattern = re.compile(r"(acl_smtp_expn|acl_smtp_vrfy).*")
            for match in param_pattern.finditer(outputArr[2]):
                param_exist = True
                reason_str += match.group(0) + "\n"
    
            if param_exist:
                auto_result_reason = "(*) 수동 판단 필요: acl_smtp_expn 또는 acl_smtp_vrfy 파라미터가 설정된 것으로 탐지되어 정책 확인 필요\n\n" + reason_str.strip()
                return result, auto_result_reason, vulnerability_condition_result_model_list
            else:
                result = 'N'
                auto_result_reason = "(+) exim.conf : acl_smtp_expn 및 acl_smtp_vrfy 파라미터가 없는 것으로 탐지되어 양호로 판단"
                return result, auto_result_reason, vulnerability_condition_result_model_list

        elif smtp_type == "postfix":
            auto_result_reason = "(*) 수동 판단 필요: postfix 관련 설정 파일 확인(/etc/postfix/main.cf)"
            return result, auto_result_reason, vulnerability_condition_result_model_list
        
        else: # sendmail
            expn = vrfy = False
            reason_str = ""
        
            for line in cleaned_outputArr:
                line = line.strip()
                if line.startswith("O PrivacyOptions"):
                    reason_str = line
                    if "goaway" in line.lower():
                        expn = vrfy = True
                    elif "noexpn" in line.lower():
                        expn = True
                    elif "novrfy" in line.lower():
                        vrfy = True
                    break
                
            if not expn:
                vulnerability_condition_result_model_list.append({
                    "vulnerabilityConditionOutput": "expn 명령어 실행 가능\n" + reason_str.strip(),
                    "vulnerabilityConditionReasonCode": "SRV-005"
                })
            
            if not vrfy:
                vulnerability_condition_result_model_list.append({
                    "vulnerabilityConditionOutput": "vrfy 명령어 실행 가능\n" + reason_str.strip(),
                    "vulnerabilityConditionReasonCode": "SRV-005"
                })
            
            if not expn or not vrfy:
                result = 'Y'
                auto_result_reason = "(-) sendmail.cf :: PrivacyOptions 필드에 noexpn 또는 novfry 지시어가 존재하지 않아 취약으로 판단\n\n" + reason_str.strip()
            else:
                result = 'N'
                auto_result_reason = "(+) sendmail.cf :: PrivacyOptions 필드에 noexpn, novfry 지시어가 존재(또는 goaway)하여 양호로 판단\n\n" + reason_str.strip()
            
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_006(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 3)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    cleaned_outputArr = get_remove_line(get_remove_line(output, "#"), "$").splitlines()

    service_check = get_check_service(outputArr[0], 'smtp\\|sendmail\\|postfix\\|exim')

    if not service_check:
        result = 'N'
        auto_result_reason = "(+) SMTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단"
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    else:
        smtp_type = get_smtp_type(outputArr[0])

        # Handling the 'exim' case
        if smtp_type == "exim":
            noVal = True
            reason_str = ""
            logLev = re.compile(r"^[^#\n]*log_level\s*=\s*([0-9]+)")
            for match in logLev.finditer(outputArr[2]):
                noVal = False
                reason_str += match.group(0).strip() + "\n"
                if int(match.group(1)) < 5:
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput": match.group(0).strip(),
                        "vulnerabilityConditionReasonCode": "SRV-006"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

            if not vulnerability_condition_result_model_list:
                result = 'N'
                if noVal:
                    auto_result_reason = "(+) exim.conf :: log_level 필드 값이 없는 것으로 탐지되어 양호로 판단(디폴트 값이 5)\n"
                else:
                    auto_result_reason = "(+) exim.conf :: log_level 필드 값이 5 이상인 것으로 탐지되어 양호로 판단\n\n" + reason_str.strip()
                return result, auto_result_reason, vulnerability_condition_result_model_list

            result = 'Y'
            auto_result_reason = "(-) exim.conf :: log_level 필드 값이 5 미만인 것으로 탐지되어 취약으로 판단\n\n" + reason_str.strip()
            return result, auto_result_reason, vulnerability_condition_result_model_list

        elif smtp_type == "postfix":
            auto_result_reason = "(*) 수동 판단 필요: postfix 관련 설정 파일 확인(syslog, /etc/postfix/main.cf), debug_peer_level 설정값이 기본값 이상의 수준인지 확인"
            return result, auto_result_reason, vulnerability_condition_result_model_list
        
        else: # Handling the 'sendmail' and others
            loglevel = False
            reason_str = ""
            try:
                for line in cleaned_outputArr:
                    line = line.strip()
                    if line.startswith("O LogLevel"):
                        reason_str = line
                        lineArr = line.split("=")
                        level = int(lineArr[1].strip())
                        if level >= 9:
                            loglevel = True
                        break
            except Exception as e:
                print(str(e))

            if not loglevel:
                vulnerability_condition_result_model2 = {
                    "vulnerabilityConditionOutput": reason_str,
                    "vulnerabilityConditionReasonCode": "SRV-006"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model2)
                
                result = 'Y'
                auto_result_reason = "(-) sendmail.cf :: LogLevel 필드 값이 9 미만이므로 취약으로 판단\n" + reason_str
            else:
                result = 'N'
                auto_result_reason = "(+) sendmail.cf :: LogLevel 필드 값이 9 이상이므로 양호로 판단\n" + reason_str
                
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_007(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 4)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    # 서비스 체크: outputArr[0]에서 SMTP 관련 서비스가 실행 중인지 확인
    service_check = get_check_service(outputArr[0], 'smtp\\|sendmail\\|postfix\\|exim')

    if not service_check:
        result = 'N'
        auto_result_reason = "(+) SMTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]
        
    else:
        smtp_type = get_smtp_type(outputArr[0])

        # smtp_type에 따라 appropriate outputArr 인덱스 선택
        if smtp_type == "postfix":
            relevant_output = outputArr[2].strip()
        elif smtp_type == "exim":
            relevant_output = outputArr[3].strip()
        else:
            relevant_output = outputArr[1].strip()
            
        auto_result_reason = (
            "(*) 수동 판단 필요: SMTP 서비스 패치 버전 및 해당 기관의 적절한 패치 관리 현황 등 종합적 판단 필요\n\n"
            + relevant_output
            + "\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n"
            + outputArr[0].strip()
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_008(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Split output into two parts based on the delimiter
    outputArr = split_output(output, 4)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
            
    outputArr2 = outputArr[1].splitlines()

    service_check = get_check_service(outputArr[0], 'smtp\\|sendmail\\|postfix\\|exim')

    # Check if SMTP service is running
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) SMTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]
        
    else:
        smtp_type = get_smtp_type(outputArr[0])
                
        if smtp_type == "postfix":
            reason_str = ""
            postfix_conf = re.finditer(r"(.*)(message_size_limit|header_size_limit|default_process_limit|local_destination_concurrency_limit|smtpd_recipient_limit)[\s]*=[\s]*([\d]+)", outputArr[2])
            for match in postfix_conf:
                reason_str += match.group(0) + "\n"
                if "#" not in match.group(1) and int(match.group(3)) == 0:
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': match.group(2).strip(),
                        'vulnerabilityConditionReasonCode': "SRV-008"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            if not vulnerability_condition_result_model_list:
                result = 'N'
                auto_result_reason = (
                    "(+) postfix main.cf :: message_size_limit, header_size_limit, default_process_limit, "
                    "local_destination_concurrency_limit, smtpd_recipient_limit 값이 설정되어 있거나 주석 처리(디폴트 값)로 탐지되어 양호로 판단\n\n" 
                    + reason_str
                )
            else:
                result = 'Y'
                auto_result_reason = (
                    "(-) postfix main.cf :: message_size_limit, header_size_limit, default_process_limit, "
                    "local_destination_concurrency_limit, smtpd_recipient_limit 값 중 0으로 설정된 값이 있는 것으로 탐지되어 취약으로 판단\n\n" 
                    + reason_str
                )
            
        elif smtp_type == "exim":
            reason_str = ""
            exim_conf = re.finditer(r"(.*)(message_size_limit|header_maxsize|queue_run_max|recipients_max)[\s]*=[\s]*([\d]+)", outputArr[3])
            for match in exim_conf:
                reason_str += match.group(0) + "\n"
                if "#" not in match.group(1) and int(match.group(3)) == 0:
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': match.group(2).strip(),
                        'vulnerabilityConditionReasonCode': "SRV-008"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            if not vulnerability_condition_result_model_list:
                result = 'N'
                auto_result_reason = (
                    "(+) exim.conf :: message_size_limit, header_maxsize, queue_run_max, "
                    "recipients_max 값이 설정되어 있거나 주석 처리(디폴트 값)로 탐지되어 양호로 판단\n\n" + reason_str
                )
            else:
                result = 'Y'
                auto_result_reason = (
                    "(-) exim.conf :: message_size_limit, header_maxsize, queue_run_max, "
                    "recipients_max 값 중 0으로 설정된 값이 있는 것으로 탐지되어 취약으로 판단\n\n" + reason_str
                )
                
        else: # sendmail
            cond = [False] * 5
            check_str = ["maxdaemonchildren", "connectionratethrottle", "minfreeblocks", "maxheaderslength", "maxmessagesize"]
            reason_str = ""
            
            for line in outputArr2:
                line = line.strip().lower()
                for i, check in enumerate(check_str):
                    if check in line:
                        cond[i] = True
                        if line.startswith(f"o {check}=0") or line.startswith("#"):
                            vulnerability_condition_result_model = {
                                'vulnerabilityConditionOutput': line.strip(),
                                'vulnerabilityConditionReasonCode': "SRV-008"
                            }
                            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                        reason_str += line.strip() + "\n"
                        
            for i, condition in enumerate(cond):
                if not condition:
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': f"{check_str[i]} 필드가 존재하지 않음",
                        'vulnerabilityConditionReasonCode': "SRV-008"
                    }
                    reason_str += f"{check_str[i]} 필드가 존재하지 않음\n"
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                    
            if not vulnerability_condition_result_model_list:
                result = 'N'
                auto_result_reason = (
                    "(+) sendmail.cf :: maxdaemonchildren, connectionratethrottle, minfreeblocks, "
                    "maxheaderslength, maxmessagesize 값이 설정되어 있는 것으로 탐지되어 양호로 판단\n" + reason_str
                )
            else:
                result = 'Y'
                auto_result_reason = (
                    "(-) sendmail.cf :: maxdaemonchildren, connectionratethrottle, minfreeblocks, "
                    "maxheaderslength, maxmessagesize 값이 0(제한없음)으로 설정되어있거나 존재하지 않는 설정이 있는 것으로 탐지되어 취약으로 판단\n" + reason_str
                )
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_009(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    outputArr = split_output(output, 6)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    service_check = get_check_service(outputArr[0], 'smtp\\|sendmail\\|postfix\\|exim')

    # Check if SMTP service is running
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) SMTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]
        
    else:
        smtp_type = get_smtp_type(outputArr[0])
                
        if smtp_type == "postfix":
            reason_str = ""
            relay_pol = re.finditer(r".*(smtpd_relay_restrictions|smtpd_recipient_restrictions).*", outputArr[4])
            for match in relay_pol:
                reason_str += match.group(0) + "\n"
            
            auto_result_reason = (
                "(*) 수동 판단 필요: smtpd_recipient_restrictions 또는 smtpd_relay_restrictions 구문에서 permit으로 허용된 네트워크의 적절성 판단 필요\n\n"
                + reason_str.strip()
            )
        
        elif smtp_type == "exim":
            reason_str = ""
            rcpt_pol = re.finditer(r"^[^#\n]*acl_smtp_rcpt.*", outputArr[5])
            for match in rcpt_pol:
                reason_str += match.group(0) + "\n-------------------------------------\n\n"
            
            acl_pol = re.search(r"begin\s+acl[\s\S]*?^begin", outputArr[5])
            if acl_pol:
                acl_content = acl_pol.group(0)
                conf_str = re.finditer(r"^[^#\n]*", acl_content)
                for match in conf_str:
                    line = match.group(0).strip()
                    if line:
                        reason_str += line + "\n"
                        
            auto_result_reason = (
                "(*) 수동 판단 필요: acl_smtp_rcpt 정책 구문에서 accept로 허용된 네트워크의 적절성 판단 필요\n\n"
                + reason_str.strip()
            )
            
        else:
            ver_flag = False
            # Check for version number (8.x, 9.x, 10.x)
            match = re.search(r"(8|9|10)\.([\d]{1,})[\.\\d]*", outputArr[1])
            if match:
                ver_val = int(match.group(2))
                if ver_val >= 9:
                    ver_flag = True
                    
            if ver_flag:
                promiscuous_relay_match = re.search(r".*promiscuous_relay.*", outputArr[2])
                if promiscuous_relay_match:
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': promiscuous_relay_match.group(0).strip(),
                        'vulnerabilityConditionReasonCode': "SRV-009"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                    
                    result = 'Y'
                    auto_result_reason = f"(-) 메일 릴레이 허용 설정(promiscuous_relay)이 탐지되어 취약으로 판단\n\n{promiscuous_relay_match.group(0).strip()}"
                else:
                    result = 'N'
                    auto_result_reason = f"(+) 메일 릴레이 허용 설정(promiscuous_relay)이 탐지되지 않아 양호로 판단\n\n{outputArr[2].strip()}"
            else:
                auto_result_reason = f"(*) 수동 판단 필요: SMTP 서비스 버전 9 미만으로 탐지되어 스팸 메일 방지 설정을 별도로 수행하였는지 확인 필요\n{outputArr[1]}\n{outputArr[3]}"

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_010(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Split the output into parts
    outputArr = split_output(output, 3)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    cleaned_outputArr = get_remove_line(get_remove_line(output, "#"), "$").splitlines()

    # Check if SMTP service is running
    service_check = get_check_service(output, 'smtp\\|sendmail\\|postfix\\|exim')
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) SMTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n\n" + outputArr[0].strip()
        
    else:
        smtp_type = get_smtp_type(outputArr[0])

        if smtp_type == "postfix":
            reason_str = ""
            
            # Check the file permissions for 'postsuper'
            # 정규식 패턴
            pattern = r"(^[drwxstDRWXSTlL\-]{10}).*"
            # re.search에서 플래그 직접 지정
            file_match = re.search(pattern, outputArr[2], re.IGNORECASE | re.MULTILINE)
            if file_match:
                file_perm = file_match.group(1).strip()
                reason_str += file_match.group(0).strip()
                if get_check_file_perm(file_perm, 2, r"x"):
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': file_match.group(0).strip(),
                        'vulnerabilityConditionReasonCode': "SRV-010"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            if not vulnerability_condition_result_model_list:
                result = 'N'
                auto_result_reason = "(+) postsuper 파일 others 실행 권한이 없는 것으로 탐지되어 양호로 판단\n\n" + reason_str.strip()
            else:
                result = 'Y'
                auto_result_reason = "(-) postsuper 파일 others 실행 권한이 있는 것으로 탐지되어 취약으로 판단\n\n" + reason_str.strip()
            
        elif smtp_type == "exim":
            auto_result_reason = "(*) 수동 판단 필요: exim 실행 파일 권한 점검, others 실행 권한이 있는지 확인\n"
            
        else: # sendmail
            restrictq = False
            reason_str = ""
            
            for line in cleaned_outputArr:
                line = line.strip()
                if line.startswith("O PrivacyOptions"):
                    reason_str += line + "\n"
                    if "restrictqrun" in line:
                        restrictq = True
                    break
                
            if not restrictq:
                vulnerability_condition_result_model2 = {
                    'vulnerabilityConditionOutput': "일반사용자의 Sendmail 실행 방지 미흡\n" + reason_str.strip(),
                    'vulnerabilityConditionReasonCode': "SRV-010"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model2)
                
                result = 'Y'
                auto_result_reason = "(-) sendmail.cf :: PrivacyOptions필드에 restrictqrun값이 존재하지 않는 것으로 탐지되어 취약으로 판단\n" + reason_str.strip()  # VENDOR-EDIT(bug): SRV-010-polarity — reason 문자열 역전 수정(KNOWN_BUGS.md 참조)
            else:
                result = 'N'
                auto_result_reason = "(+) sendmail.cf :: PrivacyOptions필드에 restrictqrun값이 존재하는 것으로 탐지되어 양호로 판단\n" + reason_str.strip()  # VENDOR-EDIT(bug): SRV-010-polarity — reason 문자열 역전 수정(KNOWN_BUGS.md 참조)
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_011(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    # 서비스 확인 (FTP 서비스가 실행 중인지 확인)
    service_check = get_check_service(output, 'ftp')
    
    # FTP 서비스가 실행 중이지 않으면 양호
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) FTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]
    
    else:
        root_exist = False
        reason_str = ""
        safe_str = ""
        
        # 'cat' 명령어와 관련된 부분을 정규표현식으로 검색
        m = re.compile(r"\$[\s]*cat.*[\s\S]*?------------", re.DOTALL).finditer(outputArr[1])
        for match in m:
            cat_res = match.group(0)
            
            # 'root' 계정이 있는지 확인
            if re.search(r"^root$", cat_res, re.MULTILINE):
                safe_str += match.group(0) + "\n\n"
                root_exist = True
            
            reason_str += match.group(0) + "\n\n"
        
        # root 계정이 없으면 취약으로 판단
        if not root_exist:
            vulnerability_condition_result_model = {
                'vulnerabilityConditionOutput': "ftpusers 파일 내 시스템 계정(root) 미존재",
                'vulnerabilityConditionReasonCode': "SRV-011"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            result = 'Y'
            auto_result_reason = "(-) ftpusers :: ftpusers 파일 내 root 계정이 존재하지 않는 것으로 탐지되어 취약으로 판단\n" + reason_str
        
        else:
            result = 'N'
            auto_result_reason = "(+) ftpusers :: ftpusers 파일 내 root 계정이 존재하는 것으로 탐지되어 양호로 판단\n" + safe_str
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_012(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    service_check = get_check_service(output, 'ftp')

    if service_check:
        pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE | re.IGNORECASE)
        matches = pattern.finditer(output)
        
        netrc = False    
        for m in matches:
            if m.group(1) != "----------":
                file_perm = m.group(1)
                file_entry = m.group(0).lower()

                if ".netrc" in file_entry:
                    netrc = True
                    
                    # .netrc 600 검사
                    if get_check_file_perm(file_perm, 0, r"x") or get_check_file_perm(file_perm, 1, r"r|w|x") or get_check_file_perm(file_perm, 2, r"r|w|x"):
                        vulnerability_condition_result_model = {
                            'vulnerabilityConditionOutput': f".netrc 파일 권한 취약 {m.group(0)}",
                            'vulnerabilityConditionReasonCode': "SRV-012"
                        }
                        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
        if not netrc:
            result = 'N'
            auto_result_reason = "(+) .netrc 파일이 존재하지 않아 양호로 판단\n"
        
        else:
            if vulnerability_condition_result_model_list:
                result = 'Y'
                auto_result_reason = "(-) .netrc 파일 권한 취약 및 파일 내 계정 별도로 수동 판단 필요\n"
            else:
                auto_result_reason = "(*) .netrc 파일 권한은 양호하나 파일 내 민감 계정 확인 필요\n"
    
    else:
        result = 'N'
        auto_result_reason = "(+) FTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n"

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_013(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    # 서비스 체크: outputArr[0]에서 FTP 서비스가 실행 중인지 확인
    service_check = get_check_service(outputArr[0], r'ftp')

    if not service_check: # FTP 서비스가 실행 중이지 않은 경우
        result = 'N'
        auto_result_reason =  "(+) FTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]

    else: # FTP 서비스가 실행 중인 경우
        # <Anonymous>...</Anonymous> 블록을 모두 찾기
        pattern_anonymous_block = re.compile(r"<Anonymous[\s\S]*?<\/Anonymous>", re.IGNORECASE)
        matches = pattern_anonymous_block.findall(outputArr[1])
        for match in matches:
            reason_str += match + "\n"

        # "Anonymous"를 포함하는 라인을 모두 찾기
        pattern_anonymous_line = re.compile(r".*Anonymous.*", re.IGNORECASE)
        lines = outputArr[1].splitlines()
        for line in lines:
            if pattern_anonymous_line.match(line):
                # 라인이 <Anonymous> 또는 </Anonymous>를 포함하지 않는 경우
                if not re.search(r"</?Anonymous>", line, re.IGNORECASE):
                    reason_str += line + "\n"

        # 불필요한 공백 제거
        reason_str = reason_str.strip()

        # 결과 메시지 구성
        if reason_str:
            auto_result_reason = (
                "(*) 수동 판단 필요: FTP 서비스 활성화로 탐지되어 anonymous 허용 여부 판단을 위한 설정 점검 필요\n"
                + reason_str
            )
        else:
            # <Anonymous> 블록이나 관련 라인이 없는 경우
            result = 'N'
            auto_result_reason = "(+) FTP 서비스가 실행 중이지만, anonymous 허용 설정이 취약하지 않은 것으로 탐지되어 양호로 판단\n"

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_014(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 3)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    # Check if the NFS service is running
    service_check = get_check_service(outputArr[0], "nfs")
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) NFS 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]

    else:
        vul_flag = False
    
        # Regular expression to match file permissions
        pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*")
        for line in outputArr[2].splitlines():
            m = pattern.match(line)
            if m:
                file_perm = m.group(1)
                fields = line.split()

                # Check file permissions for vulnerabilities
                if (get_check_file_perm(file_perm, 0, r"x") or
                    get_check_file_perm(file_perm, 1, r"w|x") or
                    get_check_file_perm(file_perm, 2, r"w|x") or
                    fields[2] != "root"):
                    
                    vul_flag = True
                    reason_str += "(-) NFS 설정 파일 접근 권한이 [소유자 root 권한 644] 보다 많은 권한이 탐지되어 취약으로 판단\n" + line + "\n"
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput": line,
                        "vulnerabilityConditionReasonCode": "SRV-014"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

        if vul_flag:
            result = 'Y'
            auto_result_reason = (
                f"(*) 수동 판단 필요: NFS 접근 통제 설정의 적절성 판단은 수동 점검 필요\n{outputArr[1]}\n\n"
                + reason_str
            )
        
        else:
            result = 'N'
            auto_result_reason = (
                f"(*) 수동 판단 필요: NFS 접근 통제 설정의 적절성 판단은 수동 점검 필요\n{outputArr[1]}\n\n"
                + "(+) NFS 설정 파일 접근 권한이 [소유자 root 권한 644] 보다 많은 권한이 탐지되지 않아 양호로 판단\n" + outputArr[2]
            )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_015(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    # Check if NFS service is running
    service_check = get_check_service(outputArr[0], 'nfs')
    
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) NFS 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]

    else:
        # Create vulnerability condition model if NFS service is running
        vulnerability_condition_result_model = {
            "vulnerabilityConditionOutput": "불필요한 NFS 서비스 실행 중",
            "vulnerabilityConditionReasonCode": "SRV-015"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
        result = 'Y'
        auto_result_reason = "(-) NFS 서비스가 실행 중인 것으로 탐지되어 취약으로 판단(업무상 사용 여부 확인 필요)\n" + output
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_016(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # List of RPC services to check
    rpcinfo = [
        "cms", "ttdbserver", "sadmin", "rusers", "wall", "spray", "rstat", "stat", 
        "nis", "pcnfs", "ypserv\\|ypbind\\|ypxfrd\\|yppasswdd\\|ypupdated", "rquota", 
        "kcms_server", "cachefs"
    ]

    # Iterate through each RPC service to check if it's active
    for rpc in rpcinfo:
        if get_check_service(output, rpc):
            result = 'Y'
            rpc_replace = rpc.replace('\\', '')
            auto_result_reason += f"(-) {rpc_replace} 서비스가 활성화된 것으로 탐지되어 취약으로 판단\n"
            # Search for the specific pattern in the output
            match = re.search(rf"\[ {rpc} \]\[S\][\s\S]*?\[ {rpc} \]\[E\]", output)
            if match:
                auto_result_reason += match.group(0) + "\n\n"
            # Add to the vulnerability condition list
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": rpc_replace,
                "vulnerabilityConditionReasonCode": "SRV-016"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

    if not vulnerability_condition_result_model_list:
        result = 'N'
        auto_result_reason = "(+) cms, ttdbserver, sadmin, rusers, wall, spray, rstat, stat, nis, pcnfs, ypserv, ypbind, ypxfrd, yppasswdd, ypupdated, rquota, kcms_server, cachefs 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + output

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_021(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    service_check = get_check_service(output, 'ftp')

    if service_check:
        auto_result_reason = "(*) 수동 판단 필요: FTP 서비스가 활성화된 것으로 탐지되어 설정에서 접근 제어 파라미터 점검 필요\n\n"
    else:
        result = 'N'
        auto_result_reason = "(+) FTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n\n"

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_022(output):
    result = 'N'
    auto_result_reason = "(*) 수동 판단 필요: 패스워드 크랙 시도 등을 통한 수동 점검 필요\n" + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_025(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    cleaned_output = get_remove_line(output, "#")
    outputArr = split_output(cleaned_output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    # Check if exec, rexec, login, rlogin, shell, or rshell services are active
    exec_service_check = get_check_service(outputArr[0], 'exec\\|rexec')
    login_service_check = get_check_service(outputArr[0], 'login\\|rlogin')
    shell_service_check = get_check_service(outputArr[0], 'shell\\|rshell')

    # Initialize variables for the number of services that are inactive
    except_cnt = 0
    is_safe = True
    reason_str = ""

    # Check if r-related services are active
    if not exec_service_check:
        except_cnt += 1
    if not login_service_check:
        except_cnt += 1
    if not shell_service_check:
        except_cnt += 1

    # If all r-related services are inactive, return the positive result
    if except_cnt >= 3:
        result = 'N'
        auto_result_reason = "(+) r계열 서비스[rexec, rlogin, rshell]가 모두 비활성화된 것으로 탐지되어 양호로 판단\n" + outputArr[0]
        
    else:
        # Check for vulnerable configurations in files
        file_output = outputArr[1].split("------------")
        for str_line in file_output:
            pattern = re.compile(r"^\s*\$\s*cat\s+([^\r\n]+)\s*\r?\n([\s\S]*)", re.MULTILINE)
            m = pattern.search(str_line)
            if m:
                file_name = m.group(1)
                vul_line = ""
                str2 = m.group(2)
                
                plus = re.compile(".*\\+.*", re.MULTILINE)
                plus_lines = plus.findall(str2)

                if plus_lines:
                    is_safe = False
                    vul_line = '\n'.join(plus_lines)
                    vul_out = "# " + file_name + "\n" + vul_line
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : vul_out.strip(),
                        "vulnerabilityConditionReasonCode": "SRV-025"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                    
                reason_str += m.group(0) + "\n"

        if not is_safe:
            result = 'Y'
            auto_result_reason = "(-) r계열 서비스가 실행 중이고, hosts.equiv 나 .rhost 파일에 '+' 와 같은 취약한 설정이 탐지되어 취약으로 판단\n" + reason_str
            
        else:
            result = 'N'
            auto_result_reason = "(+) r계열 서비스가 실행 중이나, hosts.equiv 나 .rhosts 파일에 '+' 와 같은 취약한 설정이 탐지되지 않아 양호로 판단\n" + reason_str
        
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_026(output):
    result = 'N'
    auto_result_reason = "(*) AIX, HP-UX, Solaris, Linux외 기타 OS로 탐지되어 수동 판단 필요\n" + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_027(output):
    result = 'N'
    auto_result_reason = "(*) 수동 판단 필요: 소프트웨어 또는 하드웨어 방화벽, TCP Wrapper 등 어떤 형태로든지 접근통제를 수행하고 있는지 확인 필요\n" + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_028(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    outputArr = split_output(output, 4)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    # Check if telnet and ssh services are active
    telnet_service_check = get_check_service(outputArr[0], 'telnet')
    ssh_service_check = get_check_service(outputArr[2], 'ssh\\|ssh-server')

    # Initialize the service count
    service_cnt = 0
    if telnet_service_check:
        service_cnt += 1
    if ssh_service_check:
        service_cnt += 1

    if service_cnt == 0:
        result = 'N'
        auto_result_reason = (
            "(+) telnet, ssh 서비스가 모두 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" +
            outputArr[0] + "\n" + outputArr[2]
        )
        
    else:
        # Corrected regular expression pattern and flags
        pattern = r"\$[\s]*?echo.*?[\r\n]*(\d+).*"
        flags = re.IGNORECASE | re.MULTILINE
        p = re.compile(pattern, flags)
        m = p.search(outputArr[1])
        
        if m:
            tmout_val = int(m.group(1))
            if tmout_val <= 900:
                result = 'N'
                auto_result_reason = (
                    "(+) TMOUT 환경변수가 설정되어있고 900초(15분) 이하로 설정된 것이 탐지되어 양호로 판단\n" +
                    m.group(0)
                )
            
            else: # If TMOUT value exceeds 900 seconds, flag as vulnerable
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": "TMOUT 설정 900초 초과로 설정됨:\n" + m.group(0),
                    "vulnerabilityConditionReasonCode": "SRV-028"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                
                result = 'Y'
                auto_result_reason = (
                    "(-) TMOUT 환경변수가 설정되어있지만 900초(15분) 초과로 설정된 것이 탐지되어 취약으로 판단(내부 규정 존재 시 확인 필요)\n" +
                    m.group(0)
                )
                
        else: # If TMOUT is not set at all, flag as vulnerable
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": "TMOUT 설정 없음",
                "vulnerabilityConditionReasonCode": "SRV-028"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            result = 'Y'
            auto_result_reason = (
                "(-) TMOUT 환경변수가 설정되지 않은 것으로 탐지되어 취약으로 판단\n" +
                outputArr[1]
            )
            
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_034(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    service_check = get_check_service(output, 'automountd\\|autofs')

    if not service_check:
        result = 'N'
        auto_result_reason = "(+) Automount 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + output

    else:
        vulnerability_condition_result_model = {
            "vulnerabilityConditionOutput": "불필요한 automountd 서비스 실행 중",
            "vulnerabilityConditionReasonCode": "SRV-034"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
        result = 'Y'
        auto_result_reason = "(-) 불필요한 서비스(automountd, autofs)가 실행 중인 것으로 탐지되어 취약으로 판단\n업무상 사용 시 양호(단, CVE-1999-0210 등의 취약점이 있는 버전일 경우는 취약)\n" + output

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_035(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    services = [
        "tftp", "talk", "ntalk", "finger", "exec\\|rexec", "login\\|rlogin", "shell\\|rshell", "echo", 
        "discard", "daytime", "chargen", "nis", "ypserv\\|ypbind\\|ypxfrd\\|yppasswdd\\|ypupdated"
    ]

    for service in services:
        service_replace = service.replace('\\', '')
        
        if get_check_service(output, service):
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": service_replace,
                "vulnerabilityConditionReasonCode": "SRV-035"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            reason_str = f"(-) 불필요한 서비스({service_replace})가 실행 중인 것으로 탐지되어 취약으로 판단\n"
            pattern = r'\[ ' + service + r' \]\[S\].*?\[ ' + service + r' \]\[E\]'
            regex = re.compile(pattern, re.MULTILINE | re.IGNORECASE | re.DOTALL)
            match = regex.search(output)
            if match:
                auto_result_reason += "\n" + reason_str + match.group(0) + "\n"
                
        else:
            auto_result_reason += f"\n(+) {service_replace} 서비스가 비활성화된 것으로 탐지되어 양호로 판단\n"
        
    if vulnerability_condition_result_model_list:
        result = 'Y'

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_037(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    service_check = get_check_service(output, 'ftp')

    if not service_check:
        result = 'N'
        auto_result_reason = "(+) FTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n"

    else:
        vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": "불필요한 FTP 서비스 실행 중",
                "vulnerabilityConditionReasonCode": "SRV-037"
            }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
        result = 'Y'
        auto_result_reason = "(-) FTP 서비스가 활성화된 것으로 탐지되어 취약으로 판단(업무상 사용 여부 확인 필요)\n"
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_062(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    # Check if DNS service is running
    service_check = get_check_service(output, 'dns')
    
    if not service_check: # If DNS service is not running
        result = 'N'
        auto_result_reason = "(+) DNS 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]
    
    else:
        options_dict = options_dict_from_script_output(outputArr[1])
        
        if options_dict:
            if options_dict.get('version', None):
                result = 'N'
                auto_result_reason = f"(+) options 섹션에 version 구문을 설정하여 버전 노출 방지 적용 중으로 탐지되어 양호로 판단:\nversion {options_dict.get('version', None)}\n"        
            else:
                # If 'version' is not found, it's a vulnerability
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": "DNS 버전 노출 방지 설정 미흡",
                    "vulnerabilityConditionReasonCode": "SRV-062"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                result = 'Y'
                auto_result_reason = "(-) options 섹션에 version 구문을 미설정하여 버전 노출 방지 미적용 중으로 탐지되어 취약으로 판단:\n" + outputArr[1]
        
        else:
            # If the options section is not found in the named.conf
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput": "DNS 버전 노출 방지 설정 미흡",
                "vulnerabilityConditionReasonCode": "SRV-062"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            result = 'Y'
            auto_result_reason = "(-) named.conf 설정에서 options 섹션 탐지 실패\n" + outputArr[1]

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_063(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    # Check if DNS service is running
    service_check = get_check_service(output, 'dns')

    if not service_check:
        result = 'N'
        auto_result_reason = "(+) DNS 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]
        
    else:
        options_dict = options_dict_from_script_output(outputArr[1])
        
        if options_dict:
            # Check if 'recursion yes;' is found
            recursion = options_dict.get('recursion', None)
            if recursion and 'yes' in recursion.lower():
                if options_dict.get('allow-recursion', None): # If 'allow-recursion' is also found, it means recursion is limited to certain hosts
                    result = 'N'
                    auto_result_reason = (
                        "(+) recursion yes; 설정이 탐지됐지만, allow-recursion으로 호스트를 제한하고 있는 것으로 탐지되어 양호로 판단\n"
                        + f"recursion {recursion}\nallow-recursion {options_dict.get('allow-recursion', None)}\n"
                    )
                else: # If 'allow-recursion' is not found, it's a vulnerability
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput": "recursion yes;",
                        "vulnerabilityConditionReasonCode": "SRV-063"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                    result = 'Y'
                    auto_result_reason = (
                        "(-) recursion yes; 설정이 탐지됐고, allow-recursion으로 호스트를 제한하고 있지 않은 것으로 탐지되어 취약으로 판단\n"
                        + f"recursion {recursion}\n"
                    )
                
            else: # If 'recursion yes;' is not found, it's safe
                result = 'N'
                auto_result_reason = "(+) recursion yes; 설정이 탐지되지 않아 양호로 판단\n" + outputArr[1]
                
        else:
            auto_result_reason = "(*) options 섹션 탐지 실패로 수동 확인 필요\n" + outputArr[1]
        
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_064(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    # Check if DNS service is running
    service_check = get_check_service(outputArr[0], 'dns')

    if not service_check:
        result = 'N'
        auto_result_reason = "(+) DNS 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]

    else: # If DNS service is running, return manual judgment message
        auto_result_reason = "(*) 수동 판단 필요: 스크립트 명령 결과를 확인하여 취약 버전 여부 확인 필요(GOOD,FAIR는 양호 | POOR는 취약)\n" + outputArr[1] + "\n" + outputArr[0]

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_066(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    service_check = get_check_service(outputArr[0], 'dns')
    
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) DNS 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]

    else:
        options_dict = options_dict_from_script_output(outputArr[1])
        
        if options_dict:
            allow_transfer = options_dict.get("allow-transfer", None)
            if allow_transfer and 'any' in allow_transfer:
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput": f"allow-transfer {allow_transfer}",
                    "vulnerabilityConditionReasonCode": "SRV-066"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                result = 'Y'
                auto_result_reason = (
                    "(-) allow-transfer 구문에 any 호스트 허용이 탐지되어 취약으로 판단\n" 
                    + f"allow-transfer {allow_transfer}\n"
                )
                
            elif allow_transfer:
                result = 'N'
                auto_result_reason = (
                    "(+) allow-transfer 구문이 존재하고, any 호스트 허용이 탐지되지 않아 양호로 판단\n" 
                    + f"allow-transfer {allow_transfer}\n"
                )
                
            else:
                vulnerability_condition_result_model2 = {
                    "vulnerabilityConditionOutput": "Zone Transfer 기능의 접근통제 없음",
                    "vulnerabilityConditionReasonCode": "SRV-066"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model2)
                
                result = 'Y'
                auto_result_reason = (
                    "(-) allow-transfer 구문으로 zone transfer 접근통제를 수행하고 있지 않은 것으로 탐지되어 취약으로 판단\n" 
                    + outputArr[1]
                )
                
        else:
            auto_result_reason = "(*) options 섹션 탐지 실패로 수동 확인 필요\n" + outputArr[1]

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_069(output):
    total_result = 'N'
    auto_result_reason = "(*) AIX, HP-UX, Solaris, Linux외 기타 OS로 탐지되어 수동 판단 필요\n" + output
    vulnerability_condition_result_model_list = []

    return total_result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_070(output):
    '''
    일단 /etc/passwd 파일 자체에 hash가 있는지는 검사
    /etc/shadow 또는 /etc/security/passwd를 안쓰면 무조건 취약으로 잡는 방식
    '''
    
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    vul_flag = False
    vul_str = ""
    
    # 정규식 패턴 컴파일
    pattern = r".*:(.*):.*:.*:.*:.*:.*"
    matches = re.finditer(pattern, output)

    # 정규식 매칭을 통한 해시 필드 탐색
    for m in matches:
        hash_field = m.group(1)
        if len(hash_field) > 15:
            vul_flag = True
            vul_str += m.group(0) + "\n"

    if vul_flag:
        # 취약점 정보 모델 추가
        vulnerability_condition_result_model = {
            'vulnerabilityConditionOutput': "/etc/passwd 파일 내 패스워드 Hash 존재",
            'vulnerabilityConditionReasonCode': "SRV-070"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        result = 'Y'
        auto_result_reason = "(-) /etc/passwd 파일 내 패스워드 hash가 탐지되어 취약으로 판단\n" + vul_str
        
    else:
        result = 'N'
        auto_result_reason = "(+) /etc/passwd 파일 내 패스워드 hash가 탐지되지 않아 양호로 판단\n" + output
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_073(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    commands = re.findall(r"\$(.*?)\n(.*?)(?=\n-|$)", output, re.DOTALL)
    command_results = {}
    target_group_names = ["root", "system", "wheel"] # 필요 시 관리자 그룹으로 조사할 그룹명 추가
    group_user_result = {}

    for command, result in commands:
        command_clean = command.strip()
        result_clean = result.strip()
        command_results[command_clean] = result_clean

    # 파싱된 그룹 라인 수를 추적 (데이터 부재 판정에 사용)
    parsed_group_lines = 0  # VENDOR-EDIT(c): SRV-073-no-group-data — 그룹데이터 부재 시 (*)수동(거짓양호 차단, Opus C-1)

    for command, result in command_results.items():
        group_gid_map = {}        # 그룹명 -> gid
        gid_members_map = {}      # gid -> {보조 멤버들}

        for raw in result.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(("+", "-")):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            gname, gid_str, members_str = parts[0], parts[2], parts[3]
            try:
                gid = int(gid_str)
            except ValueError:
                continue
            group_gid_map[gname] = gid
            members = set(m.strip() for m in (members_str or "").split(",") if m.strip())
            gid_members_map.setdefault(gid, set()).update(members)
            parsed_group_lines += 1  # VENDOR-EDIT(c): SRV-073-no-group-data

        gid_to_preferred_name = {}
        for name in target_group_names:
            if name in group_gid_map:
                gid = group_gid_map[name]
                if gid not in gid_to_preferred_name:
                    gid_to_preferred_name[gid] = name

        included_gids = set()

        for name in target_group_names:
            if name not in group_gid_map:
                continue
            gid = group_gid_map[name]
            members = set()
            # 보조 그룹 멤버
            members |= gid_members_map.get(gid, set())

            group_user_result[name] = sorted(members)
            included_gids.add(gid)

        break # loops at most once

    # VENDOR-EDIT(c): SRV-073-no-group-data — 그룹데이터 부재 시 (*)수동(거짓양호 차단, Opus C-1)
    # commands가 비었거나 /etc/group 형식 라인이 하나도 파싱되지 않은 경우
    # (권한거부·빈출력·무관 텍스트 모두 해당) → 자동 양호 불가, (*) 수동 반환.
    if not commands or parsed_group_lines == 0:
        auto_result_reason = (
            "(*) 수동 판단 필요: /etc/group 수집 결과 없음(권한거부/빈출력/무관 텍스트) — "
            "자동 양호 불가\n" + output
        )
        return result, auto_result_reason, vulnerability_condition_result_model_list

    man_inspect = False
    for group, users in group_user_result.items():
        if len(users) >= 2 or (len(users) == 1 and users[0] != "root"):
            man_inspect = True
            reason_str += f"{group}: {users}\n"

    if man_inspect:
        auto_result_reason = "(*) 수동 판단 필요: 관리자 그룹(root,wheel 등등)에 불필요한 사용자로 추정되는 계정 존재 여부 판단 필요\n" + reason_str
    else:
        result = 'N'
        auto_result_reason = "(+) 관리자 그룹(root,wheel 등등)에 불필요한 사용자로 추정되는 계정이 존재하지 않아 양호로 판단\n"

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_074(output):
    result = 'N'
    auto_result_reason = "(*) 수동 판단 필요: 장기간 비밀번호 미변경 계정 확인 및 업무상 사용 여부 확인 필요\n" + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_075(output):
    result = 'N'
    auto_result_reason = "(*) 수동 판단 필요: 패스워드 크랙 등으로 수동 점검 필요\n"
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_081(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []

    vul_flag = False
    one_vul = False
    vul_str = ""
    norm_str = ""

    outputArr = split_output(output, 3)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    ### 첫 번째 섹션 처리 ###
    pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches = pattern.finditer(outputArr[0])

    for m in matches:
        if m.group(1) != "----------":
            file_perm = m.group(1)
            if not file_perm.lower().startswith('d'):
                if get_check_file_perm(file_perm, 2, r"r|w"):
                    one_vul = True
                    vul_flag = True
                    vul_str += m.group(0) + "\n"
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-081"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += m.group(0) + "\n"
    
    if one_vul:
        reason_str = "(-) Cron 작업 파일 중, others 읽기 쓰기 권한이 존재하는 파일이 탐지되어 취약으로 판단\n" + vul_str
    else:
        reason_str = "(+) Cron 작업 파일 중, others 읽기 쓰기 권한이 존재하지 않아 양호로 판단\n" + norm_str
    reason_str += "\n\n"

    ### 두 번째 섹션 처리 ###
    pattern2 = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches2 = pattern2.finditer(outputArr[1])

    one_vul2 = False
    vul_str2 = ""
    norm_str2 = ""

    for m2 in matches2:
        if m2.group(1) != "----------":
            file_perm2 = m2.group(1)
            if not file_perm2.lower().startswith('d'):
                parts = m2.group(0).split()
                owner = parts[2] if len(parts) > 2 else ""
                if (
                    get_check_file_perm(file_perm2, 0, r"x") or
                    get_check_file_perm(file_perm2, 1, r"w|x") or
                    get_check_file_perm(file_perm2, 2, r"r|w|x") or
                    owner != "root"
                ):
                    one_vul2 = True
                    vul_flag = True
                    vul_str2 += m2.group(0) + "\n"
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m2.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-081"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str2 += m2.group(0) + "\n"

    if one_vul2:
        reason_str += "(-) at 접근제어 파일 중, [소유자 root 권한 640] 보다 많은 권한이 존재하는 파일이 탐지되어 취약으로 판단\n" + vul_str2
    else:
        reason_str += "(+) at 접근제어 파일 중, [소유자 root 권한 640] 보다 많은 권한이 존재하지 않아 양호로 판단\n" + norm_str2
    reason_str += "\n\n"

    ### 세 번째 섹션 처리 ###
    pattern3 = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches3 = pattern3.finditer(outputArr[2])

    one_vul3 = False
    vul_str3 = ""
    norm_str3 = ""

    for m3 in matches3:
        if m3.group(1) != "----------":
            file_perm3 = m3.group(1)
            if not file_perm3.lower().startswith('d'):
                parts = m3.group(0).split()
                owner = parts[2] if len(parts) > 2 else ""
                if (
                    get_check_file_perm(file_perm3, 0, r"x") or
                    get_check_file_perm(file_perm3, 1, r"w|x") or
                    get_check_file_perm(file_perm3, 2, r"r|w|x") or
                    owner != "root"
                ):
                    one_vul3 = True
                    vul_flag = True
                    vul_str3 += m3.group(0) + "\n"
                    vulnerability_condition_result_model3 = {
                        "vulnerabilityConditionOutput" : m3.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-081"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model3)
                else:
                    norm_str3 += m3.group(0) + "\n"

    if one_vul3:
        reason_str += "(-) cron allow|deny 파일 중, [소유자 root 권한 640] 보다 많은 권한이 존재하는 파일이 탐지되어 취약으로 판단\n" + vul_str3
    else:
        reason_str += "(+) cron allow|deny 중, [소유자 root 권한 640] 보다 많은 권한이 존재하지 않아 양호로 판단\n" + norm_str3

    if vul_flag:
        result = 'Y'
        
    auto_result_reason = reason_str
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_082(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    vul_flag = False
    vul_str = ""
    norm_str = ""

    # 정규 표현식 패턴 컴파일 (멀티라인 모드)
    pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches = pattern.finditer(output)

    for m in matches:
        # "----------" 라인은 무시
        if m.group(1) != "----------":
            file_perm = m.group(1)
            if file_perm.lower().startswith('d'): # SRV-082는 디렉토리 권한 검사 항목
                # Others 권한(position=2)에 'w' 권한이 있는지 검사
                if get_check_dir_perm(file_perm, 2, "w"):
                    vul_flag = True
                    vul_str += m.group(0) + "\n"
                    # VulnerabilityConditionResultModel 인스턴스 생성 및 리스트에 추가
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-082"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += m.group(0) + "\n"

    if vul_flag:
        result = 'Y'
        auto_result_reason = "(-) 시스템 주요 디렉터리 중, others 쓰기 권한이 존재하는 경로가 탐지되어 취약으로 판단\n" + vul_str
    else:
        result = 'N'
        auto_result_reason = "(+) 시스템 주요 디렉터리 중, others 쓰기 권한이 존재하는 경로가 탐지되지 않아 양호로 판단\n" + norm_str

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_083(output):
    # 스크립트 결과의 앞부분이 있으나 자동분석에서 사용되진 않음
    
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    vul_flag = False
    vul_str = ""
    norm_str = ""

    # 정규 표현식 패턴 컴파일 (멀티라인 및 대소문자 무시)
    pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches = pattern.finditer(output)

    for m in matches:
        if m.group(1) != "----------":
            file_perm = m.group(1)
            # CONVERTER_KEY로 시작하는 권한은 무시
            if not file_perm.lower().startswith('d'): # 해당 라인 필요한지는 모르겠지만 일단 유지
                # Others 권한(position=2)에 'w' 권한이 있는지 검사
                if get_check_file_perm(file_perm, 2, r"w"):
                    vul_flag = True
                    vul_str += m.group(0) + "\n"
                    # VulnerabilityConditionResultModel 인스턴스 생성 및 리스트에 추가
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-083"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += m.group(0) + "\n"

    if vul_flag:
        result = 'Y'
        auto_result_reason = "(-) 시스템 스타트업 스크립트 중, others 쓰기 권한이 존재하는 파일이 탐지되어 취약으로 판단\n" + vul_str
    else:
        result = 'N'
        auto_result_reason = "(+) 시스템 스타트업 스크립트 중, others 쓰기 권한이 존재하지 않아 양호로 판단\n" + norm_str

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_084(output):
    '''
    스크립트에서 나오는 파일 순서
    0: /etc/passwd                                     : 644
    1: /etc/security/passwd(AIX) /etc/shadow(rest)     : 600
    2: /etc/hosts                                      : 644
    3: /etc/inetd.conf /etc/xinetd.conf                : 600
    4: /etc/syslog.conf /etc/rsyslog.conf              : 644
    5: /etc/services                                   : 644
    6: /etc/hosts.lpd                                  : 640
    7: /tcb/files/auth/$dir/$user (HP-UX)              : 664`
    '''
    
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    vul_flag = False

    # 정규 표현식 패턴 컴파일 (멀티라인 및 대소문자 무시)
    pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches = pattern.finditer(output)

    for m in matches:
        # "----------" 라인은 무시
        if m.group(1) != "----------":
            file_perm = m.group(1)
            file_entry = m.group(0).lower()
            fields = m.group(0).split()
            file_path = fields[-1] if len(fields) > 0 else ""

            # 첫 번째 그룹이 정의되어 있지 않으면 무시
            if len(fields) < 3:
                continue

            owner = fields[2]

            # 첫 번째 파일 그룹 검사 (644)
            if ("/etc/passwd" in file_entry or
                ("/etc/hosts" in file_entry and ".lpd" not in file_entry) or
                "syslog.conf" in file_entry or
                "/etc/services" in file_entry):
                if (get_check_file_perm(file_perm, 0, r"x") or
                    get_check_file_perm(file_perm, 1, r"w|x") or
                    get_check_file_perm(file_perm, 2, r"w|x") or
                    owner != "root"):
                    
                    vul_flag = True
                    reason_str += f"(-) {file_path} 접근 권한이 [소유자 root 권한 644] 보다 많은 권한이 탐지되어 취약으로 판단\n{m.group(0)}\n\n"
                    
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-084"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    reason_str += f"(+) {file_path} 접근 권한이 [소유자 root 권한 644] 보다 많은 권한이 탐지되지 않아 양호로 판단\n{m.group(0)}\n\n"

            # 두 번째 파일 그룹 검사 (600)
            if ("/etc/security/passwd" in file_entry or
                "inetd.conf" in file_entry or
                "/etc/shadow" in file_entry):
                if (get_check_file_perm(file_perm, 0, r"x") or
                    get_check_file_perm(file_perm, 1, r"r|w|x") or
                    get_check_file_perm(file_perm, 2, r"r|w|x") or
                    owner != "root"):
                    
                    vul_flag = True
                    reason_str += f"(-) {file_path} 접근 권한이 [소유자 root 권한 600] 보다 많은 권한이 탐지되어 취약으로 판단\n{m.group(0)}\n\n"
                    
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-084"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    reason_str += f"(+) {file_path} 접근 권한이 [소유자 root 권한 600] 보다 많은 권한이 탐지되지 않아 양호로 판단\n{m.group(0)}\n\n"

            # 세 번째 파일 그룹 검사 (640)
            if "/etc/hosts.lpd" in file_entry:
                if (get_check_file_perm(file_perm, 0, r"x") or
                    get_check_file_perm(file_perm, 1, r"w|x") or
                    get_check_file_perm(file_perm, 2, r"r|w|x") or
                    owner != "root"):
                    
                    vul_flag = True
                    reason_str += f"(-) {file_path} 접근 권한이 [소유자 root 권한 640] 보다 많은 권한이 탐지되어 취약으로 판단\n{m.group(0)}\n\n"
                    
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-084"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    reason_str += f"(+) {file_path} 접근 권한이 [소유자 root 권한 640] 보다 많은 권한이 탐지되지 않아 양호로 판단\n{m.group(0)}\n\n"

            # 네 번째 파일 그룹 검사 (664)
            if "/tcb/files/auth/" in file_entry:
                if (get_check_file_perm(file_perm, 0, r"x") or
                    get_check_file_perm(file_perm, 1, r"x") or
                    get_check_file_perm(file_perm, 2, r"w|x") or
                    owner != "root"):
                    
                    vul_flag = True
                    reason_str += f"(-) {file_path} 접근 권한이 [소유자 root 권한 664] 보다 많은 권한이 탐지되어 취약으로 판단\n{m.group(0)}\n\n"
                    
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-084"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    reason_str += f"(+) {file_path} 접근 권한이 [소유자 root 권한 664] 보다 많은 권한이 탐지되지 않아 양호로 판단\n{m.group(0)}\n\n"

    if vul_flag:
        result = 'Y'
    
    auto_result_reason = reason_str
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_087(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    vul_flag = False
    vul_str = ""
    file_map = {}

    # 정규 표현식 패턴 컴파일 (멀티라인 및 대소문자 무시)
    pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches = pattern.finditer(output)

    for m in matches:
        # "----------" 라인은 무시
        if m.group(1) != "----------":
            file_perm = m.group(1)
            fields = m.group(0).split()
            file_path = fields[-1].strip() if len(fields) > 0 else ""

            # 파일 경로가 이미 처리된 경우 무시
            if get_check_file_perm(file_perm, 2, r"x") and file_path not in file_map:
                vul_flag = True
                vul_str += m.group(0) + "\n"
                file_map[file_path] = "VUL"

                # VulnerabilityConditionResultModel 인스턴스 생성 및 리스트에 추가
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput" : m.group(0),
                    "vulnerabilityConditionReasonCode" : "SRV-087"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

                # 이유 문자열에 추가
                reason_str += f"(-) 컴파일러 {file_path}에 others 실행 권한이 탐지되어 취약으로 판단\n{m.group(0)}\n\n"

    if vul_flag:
        result = 'Y'
        auto_result_reason = reason_str
    else:
        result = 'N'
        auto_result_reason = "(+) 컴파일러가 존재하지 않거나 others 실행 권한이 탐지되지 않아 양호로 판단\n" + output

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_091(output):
    result = 'N'
    auto_result_reason = '(*) 수동 판단 필요: 불필요하게 SUID, SGID bit가 설정된 것으로 추정되는 파일의 점검 판단 필요\n' + output
    vulnerability_condition_result_model_list = []
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_092(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 3)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    ### 첫 번째 섹션 처리 ###
    isSafe1 = True
    pattern1 = re.compile(r"(.*current[\s\S]*?)------------", re.MULTILINE | re.IGNORECASE)
    matches1 = pattern1.finditer(outputArr[0])
    
    for m in matches1:
        isSafe1 = False
        reason_str += m.group(1) + "\n"
        
        vulnerability_condition_result_model = {
            "vulnerabilityConditionOutput" : m.group(1),
            "vulnerabilityConditionReasonCode" : "SRV-092"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
    
    if isSafe1:
        auto_result_reason = "(+) 사용자 홈 디렉터리와 실소유자가 일치하지 않는 디렉터리가 탐지되지 않아서 양호로 판단\n\t(스크립트 명령어 결과 값이 비어있으므로, UID 와 홈 디렉터리 소유자가 다른 계정이 없는 것으로 판단)\n"
    else:
        auto_result_reason = "(-) 사용자 홈 디렉터리와 실소유자가 일치하지 않아 취약으로 판단(업무상 필요로 인한 설정 여부는 확인 필요)\n" + reason_str
    
    auto_result_reason += "\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n"
    reason_str = ""
    
    ### 두 번째 섹션 처리 ###
    isSafe2 = True
    pattern2 = re.compile(r"(.*:.*:.*:.*:.*:.*:.*)", re.MULTILINE)
    matches2 = pattern2.finditer(outputArr[1])

    homeMap = {}

    for m in matches2:
        entry = m.group(1)
        fields = entry.split(":")
        if len(fields) < 7:
            continue  # 필드가 부족하면 무시
        
        user = fields[0]
        home = fields[5]
        uid = fields[2]
        shell = fields[6]
        user2 = f"{user}:{uid}"
        
        if shell.upper().endswith("SH"):
            if home in homeMap and int(uid) >= 1000:
                isSafe2 = False
                diffUser = homeMap[home]
                vulStrVar = f"{user2}:\"{home}\" == {diffUser}:\"{home}\"\n"
                reason_str += vulStrVar
                
                vulnerability_condition_result_model = {
                    "vulnerabilityConditionOutput" : vulStrVar.strip(),
                    "vulnerabilityConditionReasonCode" : "SRV-092"
                }
                vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            homeMap[home] = user2

    if isSafe2:
        auto_result_reason += "(+) 홈 디렉터리가 동일한 서로 다른 계정이 탐지되지 않아서 양호로 판단\n\t(/etc/passwd 파일 분석 결과 홈 디렉터리가 동일한 계정 없음)\n"
    else:
        auto_result_reason += (
            "(-) 홈 디렉터리가 동일한 계정이 존재하여 취약으로 판단(업무상 필요에 의한 설정 여부는 확인 필요)\n"
            "[형식] (user name):(uid):(home directory)\n----------------------------------------\n"
            + reason_str
        )
    
    auto_result_reason += "\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n"
    reason_str = ""
    
    ### 세 번째 섹션 처리 ###
    isSafe3 = True
    pattern3 = re.compile(r"(d[sStTrwx\-]{9}).*", re.MULTILINE)
    matches3 = pattern3.finditer(outputArr[2])
    
    allStr = ""
    vulStr = ""
    
    for m in matches3:
        allStr += m.group(0) + "\n"
        dir_perm = m.group(1)
    
        if get_check_dir_perm(dir_perm, 2, r"w"):
            isSafe3 = False
            vulStr += m.group(0) + "\n"
            
            vulnerability_condition_result_model = {
                "vulnerabilityConditionOutput" : m.group(0),
                "vulnerabilityConditionReasonCode" : "SRV-092"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
    
    if isSafe3:
        auto_result_reason += "(+) 사용자 홈 디렉터리에 Others 쓰기 권한이 탐지되지 않아 양호로 판단:\n" + allStr + "\n"
    else:
        auto_result_reason += "(-) 사용자 홈 디렉터리에 Others 쓰기 권한이 탐지되어 취약으로 판단:\n" + vulStr
        
    if isSafe1 and isSafe2 and isSafe3:
        result = 'N'
    else:
        result = 'Y'
        
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_093(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    vul_flag = False
    vul_str = ""
    norm_str = ""

    # 정규 표현식 패턴 컴파일 (멀티라인 모드)
    pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches = pattern.finditer(output)

    for m in matches:
        if m.group(1) != "----------":
            filePerm = m.group(1)
            # 'others' 권한(position=2)에 'w' 권한이 있는지 검사
            if not filePerm.lower().startswith('d'):
                if get_check_file_perm(filePerm, 2, r"w"):
                    vul_flag = True
                    vul_str += m.group(0) + "\n"
                    # VulnerabilityConditionResultModel 인스턴스 생성 및 리스트에 추가
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-093"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += m.group(0) + "\n"

    if vul_flag:
        result = 'Y'
        auto_result_reason = (
            "(-) .sh, .log, .pl과 같은 파일에, others 쓰기 권한이 존재하는 파일이 탐지되어 취약으로 판단(필요 여부 확인 필요)\n" 
            + vul_str
        )
    else:
        result = 'N'
        auto_result_reason = (
            "(+) .sh, .log, .pl과 같은 파일에, others 쓰기 권한이 존재되지 않아 양호로 판단\n" 
            + norm_str
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_094(output):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []

    vul_flag = False
    vul_str = ""
    norm_str = ""

    # 정규 표현식 패턴 컴파일 (멀티라인 모드)
    pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches = pattern.finditer(output)
    vuln_files = {}

    for m in matches:
        if m.group(1) != "----------":
            filePerm = m.group(1)
            file_entry = m.group(0).split(" : ")[-1].strip()
            
            if not filePerm.lower().startswith('d'):
                # 'others' 권한(position=2)에 'w' 권한이 있는지 검사
                if get_check_file_perm(filePerm, 2, r"w") and file_entry not in vuln_files:
                    vul_flag = True
                    vul_str += m.group(0) + "\n"
                    # VulnerabilityConditionResultModel 인스턴스 생성 및 리스트에 추가
                    vulnerability_condition_result_model = {
                        "vulnerabilityConditionOutput" : m.group(0),
                        "vulnerabilityConditionReasonCode" : "SRV-094"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                    vuln_files[file_entry] = "VUL"
                else:
                    norm_str += m.group(0) + "\n"

    if vul_flag:
        result = 'Y'
        auto_result_reason = (
            "(-) Cron 작업이 참조하는 파일 중, others 쓰기 권한이 존재하는 파일이 탐지되어 취약으로 판단(필요 여부 확인 필요)\n"
            + vul_str
        )
    else:
        result = 'N'
        auto_result_reason = (
            "(+) Cron 작업이 참조하는 파일 중, others 쓰기 권한이 존재하지 않아 양호로 판단\n"
            + norm_str
        )

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_095(output):
    # Initialize result and reason
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Initialize vulnerability flag and accumulator
    vul_flag = False
    vul_str = ""

    # Define the regex pattern to match lines starting with file permission indicators
    pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)

    # Find all matches in the output
    matches = pattern.finditer(output)

    for match in matches:
        permission = match.group(1)
        line = match.group(0)

        # Check if the permissions are not all dashes (i.e., there are some permissions set)
        if permission != "----------":
            vul_flag = True
            vul_str += line + '\n'
            
            # Create a vulnerability condition result model (represented as a dictionary)
            vulnerability_condition_result = {
                'vulnerabilityConditionOutput': line,
                'vulnerabilityConditionReasonCode': "SRV-095"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result)

    if vul_flag:
        result = 'Y'
        auto_result_reason = (
            "(-) 존재하지 않는 UID, GID가 소유자로 설정된 파일이 탐지되어 취약으로 판단\n"
            + vul_str
        )
    else:
        result = 'N'
        auto_result_reason = (
            "(+) 존재하지 않는 UID, GID가 소유자로 설정된 파일이 탐지되지 않아 양호로 판단\n"
            + output
        )
        
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_096(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    vul_flag = False
    vul_str = ""
    norm_str = ""
    
    # 컴파일된 정규식 객체 생성
    compiled_pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    
    # output에서 패턴 매칭 시도
    for match in compiled_pattern.finditer(output):
        file_perm = match.group(1)
        if file_perm != "----------":
            fields = match.group(0).split()
            file_path = fields[-1]
            
            if file_path.lower().endswith((".profile", ".login", "shrc")):
                if get_check_file_perm(file_perm, 2, r"r|w|x"):
                    vul_flag = True
                    vul_str += match.group(0) + "\n"
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': match.group(0),
                        'vulnerabilityConditionReasonCode': "SRV-096"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += match.group(0) + "\n"

    # If vulnerabilities are found, set result and reason
    if vul_flag:
        result = 'Y'
        auto_result_reason = "(-) 사용자 환경 설정 파일 중, others 읽기/쓰기/실행 권한이 존재하는 파일이 탐지되어 취약으로 판단\n" + vul_str
    else:
        result = 'N'
        auto_result_reason = "(+) 사용자 환경 설정 파일 중, others 읽기/쓰기/실행 권한이 존재하는 파일이 탐지되지 않아 양호로 판단\n" + norm_str

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_108(output):
    '''
    디렉토리가 아닌 로그 파일들에 대한 644 검사
    예외 파일 :
    /var/log/wtmp의 경우는 664 (권한 변경 불가)
    /var/log/btmp의 경우는 660 (권한 변경 불가) 
    /var/log/lastlog의 경우는 664 (권한 변경 불가)
    '''
    
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    vul_flag = False
    vul_str = ""
    norm_str = ""

    # Define the regex pattern
    pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
    matches = pattern.finditer(output)

    # Iterate over the matches found in the output
    for match in matches:
        file_perm = match.group(1)
        #print("file_perm : ", file_perm)
        if file_perm != "----------" and not file_perm.lower().startswith('d'):
            fields = match.group(0).split()
            file_path = fields[-1]
            
            if 'btmp' in file_path: # 660
                if (get_check_file_perm(file_perm, 0, r"x")
                    or get_check_file_perm(file_perm, 1, r"x")
                    or get_check_file_perm(file_perm, 2, r"r|w|x")):
                    vul_flag = True
                    vul_str += match.group(0) + "\n"
                    # Add vulnerability result model
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': match.group(0),
                        'vulnerabilityConditionReasonCode': "SRV-108"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += match.group(0) + "\n"
            
            elif 'wtmp' in file_path or 'lastlog' in file_path: # 664
                if (get_check_file_perm(file_perm, 0, r"x")
                    or get_check_file_perm(file_perm, 1, r"x")
                    or get_check_file_perm(file_perm, 2, r"w|x")):
                    vul_flag = True
                    vul_str += match.group(0) + "\n"
                    # Add vulnerability result model
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': match.group(0),
                        'vulnerabilityConditionReasonCode': "SRV-108"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += match.group(0) + "\n"
            
            else: # 644
                if (get_check_file_perm(file_perm, 0, r"x")
                    or get_check_file_perm(file_perm, 1, r"w|x")
                    or get_check_file_perm(file_perm, 2, r"w|x")):
                    vul_flag = True
                    vul_str += match.group(0) + "\n"
                    # Add vulnerability result model
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': match.group(0),
                        'vulnerabilityConditionReasonCode': "SRV-108"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += match.group(0) + "\n"

    # If vulnerabilities are found, set result and reason
    if vul_flag:
        result = 'Y'
        auto_result_reason = "(-) 로그 파일 중, 필요 이상의 권한이 존재하는 파일이 탐지되어 취약으로 판단\n" + vul_str
    else:
        result = 'N'
        auto_result_reason = "(+) 로그 파일 중, 필요 이상의 권한이 존재하는 파일이 탐지되지 않아 양호로 판단\n" + norm_str

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_109(output):
    result = 'N'
    auto_result_reason = '(*) 수동 판단 필요: syslog 및 기타 로그 설정을 확인하여, [로그인 감사 로그, su 로그] 등을 기록하게 설정되었는지 점검 필요\n' + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_112(output):
    result = 'N'
    auto_result_reason = "(*) 수동 판단 필요: syslog 및 기타 로그 설정을 확인하여, cron 로그를 기록하게 설정되었는지 점검 필요\n" + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_115(output):
    result = 'N'
    auto_result_reason = "(*) 수동 판단 필요: 담당자 인터뷰를 통해 로그의 보고 및 검토 수행 여부 확인 필요\n" + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_118(output):
    result = 'N'
    auto_result_reason = "(*) 수동 판단 필요: 적용된 보안 패치를 검토하고 인터뷰 등을 통한 수동 점검 필요\n" + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_121(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Define the regex pattern to match the PATH environment variable output
    pattern = r'(?im)^\$\s*echo\s*\\?\$PATH[^\r\n]*\r?\n(?P<path>[^\r\n]+)'

    m = re.search(pattern, output, re.MULTILINE)
    
    if not m:
        auto_result_reason = "(*) PATH 환경 변수 구문이 탐지되지 않아 수동 판단 필요\n\n" + output
    else:
        path_val = m.group('path')
        # Check if the PATH variable contains certain patterns indicating a vulnerability
        
        if ('.:' in path_val or './:' in path_val or '::' in path_val):
            # Add vulnerability details to the result list
            vulnerability_condition_result_model = {
                'vulnerabilityConditionOutput': path_val,
                'vulnerabilityConditionReasonCode': "SRV-121"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            result = 'Y'
            auto_result_reason = "(-) PATH 환경 변수에 '.', './', '::' 등 현재 디렉터리가 탐지되어 취약으로 판단\n" + path_val
            
        else:
            result = 'N'
            auto_result_reason = (
                "(+) PATH 환경 변수에 '.', './', '::' 등 현재 디렉터리가 탐지되지 않아 양호로 판단"
                "\n\t(마지막 순서로 설정된 현재 디렉터리는 양호로 판단)"
                "\n(*) 다른 프로파일에 존재하는 PATH 값은 수동으로 확인 필요\n\n" + output
            )

    # KSHTODO: CommonConf 부분 파싱이 필요할 경우에 여기에 추가하도록 한다.
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_122(output):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []

    # Define the regex pattern to match the umask command result
    pattern = r"(?im)^\$[\s]+umask[\s]+[\r\n]*([\d]*)"

    # Search for the umask value in the output
    m = re.search(pattern, output)
    
    if not m:
        auto_result_reason = "(*) umask 명령 결과가 정상적으로 탐지되지 않아서 수동 판단 필요\n" + output
    else:
        umask_val = int(m.group(1))
        if umask_val < 22:
            # Add vulnerability details to the result list
            vulnerability_condition_result_model = {
                'vulnerabilityConditionOutput': m.group(0),
                'vulnerabilityConditionReasonCode': "SRV-122"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            result = 'Y'
            auto_result_reason = (
                f"(-) umask 명령 결과가 022 미만으로 탐지되어 취약으로 판단: {str(umask_val).zfill(3)}"
                "\n\n(*) 다른 프로파일에 존재하는 umask 값은 수동으로 확인 필요\n" + output
            )
        else:
            result = 'N'
            auto_result_reason = (
                f"(+) umask 명령 결과가 022 이상으로 탐지되어 양호로 판단: {str(umask_val).zfill(3)}"
                "\n\n(*) 다른 프로파일에 존재하는 umask 값은 수동으로 확인 필요\n" + output
            )
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_127(output):
    result = 'N'
    auto_result_reason = '(*) AIX, HP-UX, Solaris, Linux외 기타 OS로 탐지되어 수동 판단 필요\n' + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_131(output):
    result = 'N'
    auto_result_reason = '(*) AIX, HP-UX, Solaris, Linux외 기타 OS로 탐지되어 수동 판단 필요\n' + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_133(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    # Define the regex pattern to match file content and file path
    pattern = re.compile(
        r'(?ms)^\s*\$\s*cat\s+(?P<path>[^\r\n]+)\r?\n(?P<body>.*?)(?=^\s*-{6,}\s*$|\Z)'
    )
    
    allow_exist = False
    deny_exist = False
    deny_content = False

    # Search for the pattern in the output
    for match in pattern.finditer(output):
        file_path = match.group(1)
        file_content = match.group(2).strip()
        
        # Check for 'cat:' errors in the content
        no_file = re.match(r"^cat:.*", file_content)
        if not no_file:
            if "allow".lower() in file_path.lower():
                allow_exist = True
                if file_content:
                    pass  # Additional checks can be done here
            if "deny" in file_path.lower():
                deny_exist = True
                if file_content:
                    deny_content = True
    
    # Determine the reason based on flags
    if allow_exist:
        result = 'N'
        auto_result_reason = "(+) cron allow 파일이 존재하는 것으로 탐지되어 양호로 판단(불필요한 것으로 추정되는 계정 등록은 확인 필요)\n" + output
        
    elif deny_exist:
        if deny_content:
            result = 'N'
            auto_result_reason = "(+) cron deny 파일만 존재하지만, cron deny 파일 내 계정이 등록된 것으로 탐지되어 양호로 판단\n" + output
        else:
            # Add vulnerability details to the result list
            vulnerability_condition_result_model = {
                'vulnerabilityConditionOutput': "cron allow 파일이 존재하지 않고, cron deny 파일 내 등록된 계정 없음",
                'vulnerabilityConditionReasonCode': "SRV-133"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            
            result = 'Y'
            auto_result_reason = "(-) cron deny 파일만 존재하는데, cron deny 파일 내 계정이 등록되지 않은 것으로 탐지되어 취약으로 판단\n" + output
        
    else:
        result = 'N'
        auto_result_reason = "(+) cron allow, deny 파일이 모두 존재하지 않는 것으로 탐지되어 양호로 판단(이 경우 root만 허용됨)\n" + output
            
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_142(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    is_safe = True
    uid_map = {}

    # First regex pattern to map UID to user
    pattern = r"(.*?):.*?:(.*?):.*?:.*?:.*?:.*"
    for match in re.finditer(pattern, output):
        uid_map[match.group(2)] = match.group(1)

    vul_str = ""
    
    # Second regex pattern to check for duplicate UIDs
    for match in re.finditer(pattern, output):
        uid = match.group(2)
        
        if uid in uid_map and uid_map[uid] != match.group(1):
            is_safe = False
            vul_str += f"{uid_map[uid]}({uid}) = {match.group(1)}({uid})\n"
            # Add vulnerability condition result
            vulnerability_condition_result_model = {
                'vulnerabilityConditionOutput': vul_str.strip(),
                'vulnerabilityConditionReasonCode': "SRV-142"
            }
            vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

    if is_safe:
        result = 'N'
        auto_result_reason = "(+) UID가 중복인 계정이 탐지되지 않아 양호로 판단\n" + output.strip()
    else:
        result = 'Y'
        auto_result_reason = "(-) UID가 중복 부여된 계정이 존재하는 것으로 탐지되어 취약으로 판단\n" + vul_str
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_144(output):
    result = 'N'
    auto_result_reason = '(*) 수동 판단 필요: /dev 경로에 불필요한 것으로 추정되는 파일이 존재하는지 판단 필요\n' + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_147(output):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []
    
    service_check = get_check_service(output, 'snmp')

    if not service_check:
        result = 'N'
        auto_result_reason = "(+) SNMP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + output

    else:
        vulnerability_condition_result_model = {
            'vulnerabilityConditionOutput': "불필요한 SNMP 서비스 실행중",
            'vulnerabilityConditionReasonCode': "SRV-142"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
        result = 'Y'
        auto_result_reason = "(-) SNMP 서비스가 실행 중으로 탐지되어 취약으로 판단(업무상 사용 여부 확인 필요)\n" + output
    
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_158(output):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []

    service_check = get_check_service(output, 'telnet')

    if not service_check:
        result = 'N'
        auto_result_reason = "(+) Telnet 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + output

    else:
        vulnerability_condition_result_model = {
            'vulnerabilityConditionOutput': "불필요한 telnet 서비스 실행중",
            'vulnerabilityConditionReasonCode': "SRV-158"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
        
        result = 'Y'
        auto_result_reason = "(-) Telnet 서비스가 실행 중으로 탐지되어 취약으로 판단(업무상 사용 여부 확인 필요)\n" + output

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_161(output):
    result = 'N'
    auto_result_reason = ''
    vulnerability_condition_result_model_list = []
    
    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    vul_str = ""
    norm_str = ""
    vul_flag = False
    
    service_check = get_check_service(outputArr[0], "ftp")
    
    # FTP 서비스가 실행 중이지 않으면 정상으로 판단
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) FTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]
    
    else:
        m = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE)
        matches = m.finditer(outputArr[1])

        for match in matches:
            permission_str = match.group(1)
            whole_line = match.group(0)
            
            if permission_str != "----------":
                file_perm = permission_str
                fields = whole_line.split()

                # ls -l 출력은 최소한 3개 이상의 필드(권한 이후의 필드들)를 기대하므로,
                # 필드 개수가 부족하면 바로 취약 처리하도록 함.
                if (len(fields) < 4
                    or get_check_file_perm(file_perm, 0, r"x") 
                    or get_check_file_perm(file_perm, 1, r"w|x") 
                    or get_check_file_perm(file_perm, 2, r"r|w|x")
                    or fields[2] != "root"):
                    
                    vul_flag = True
                    vul_str += f"{whole_line}" + '\n'

                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': permission_str.strip(),
                        'vulnerabilityConditionReasonCode': "SRV-161"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += f"{whole_line}"+ '\n'
    
        if vul_flag:
            result = 'Y'
            auto_result_reason = "(-) ftpusers 파일 중 [소유자 root, 권한 640] 보다 많은 권한을 가진 파일이 탐지되어 취약으로 판단\n" + vul_str.strip()
        else:
            result = 'N'
            auto_result_reason = "(+) ftpusers 파일 중 [소유자 root, 권한 640] 보다 많은 권한을 가진 파일이 탐지되지 않아 양호로 판단\n" + norm_str.strip()
        
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_163(output):
    result = 'N'
    auto_result_reason = '(*) 수동 판단 필요: 시스템 사용 주의사항 출력 설정의 적절성의 수동 판단 필요\n' + output
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_164(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    is_safe = True
    gid_map = {}

    m = re.compile(r"(.*?):.*?:.*?:(.*?):.*?:.*?:.*", re.MULTILINE)
    matches = m.findall(outputArr[0])
    for match in matches:
        gid_map.setdefault(match[1], {}).setdefault(match[0], None)

    m2 = re.compile(r".*?:.*?:(.*?):(.*)", re.MULTILINE)
    matches2 = m2.findall(outputArr[1])

    vul_str = ""
    norm_str = ""

    for match in matches2:
        gid = match[0]
        member = match[1]

        if int(gid) >= 1000:
            if len(member) == 0:
                if gid not in gid_map:
                    is_safe = False
                    result_str = ":".join(match).strip()
                    vul_str += result_str + '\n'
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': result_str,
                        'vulnerabilityConditionReasonCode': "SRV-164"
                    }

                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
                else:
                    norm_str += f"/etc/passwd 파일에서 구성원 확인됨: {gid}:{','.join(gid_map[gid])}\n"
            else:
                norm_str += f"/etc/group 파일에서 구성원 확인됨: {':'.join(match)}\n"

    if is_safe:
        result = 'N'
        auto_result_reason = f"(+) 모든 그룹에 구성원이 존재하는 것으로 탐지되어 양호로 판단(GID 1000이상만 확인)\n{norm_str}"
    else:
        result = 'Y'
        auto_result_reason = f"(-) 구성원이 존재하지 않는 그룹이 탐지되어 취약으로 판단(GID 1000이상만 확인)\n{vul_str}"

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_165(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    shell_str = ""
    m = re.compile(r"(.*?):.*?:.*?:.*?:.*?:.*?:(.*)", re.MULTILINE)
    matches = m.findall(output)

    for match in matches:
        user = match[0].strip()
        shell_type = match[1].strip()
        if shell_type.lower().endswith("sh"):
            shell_str += f"{user}:{shell_type}\n"

    auto_result_reason = f"(*) 수동 판단 필요: 불필요하게 shell이 부여된 것으로 추정되는 계정이 존재하는지 판단 필요\n{shell_str}"
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_166(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    line_arr = output.split('\n')
    reason_str = "(*) 수동 판단 필요: 불필요한 것으로 추정되는 숨김 파일이 존재하는지 판단 필요\n"

    # 형식을 따르는 것 중 숨김 파일만, 형식을 안따르는 일반 라인들은 그대로 포함
    for line in line_arr:
        m = re.match(r"(^[drwxstDRWXSTlL\-]{10}).*", line)
        if m:
            fields = m.group(0).split()
            if fields[-1].startswith("."):
                reason_str += line + '\n'
        else:
            reason_str += line + '\n'

    auto_result_reason = reason_str
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_170(output):
    result = 'N'
    reason_str = ""
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 4)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list
    
    service_check = get_check_service(outputArr[0], "smtp\\|sendmail\\|postfix\\|exim")
    
    if not service_check:
        result = 'N'
        auto_result_reason = "(+) SMTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + outputArr[0]

    else:
        smtp_type = get_smtp_type(outputArr[0])

        if smtp_type == "postfix":
            banner_pattern = re.compile(r"^[^#\n]*smtpd_banner.*", re.MULTILINE)
            for match in banner_pattern.finditer(outputArr[2]):
                if "$mail_version" in match.group(0).lower():
                    reason_str += match.group(0) + '\n'
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': match.group(0).strip(),
                        'vulnerabilityConditionReasonCode': "SRV-170"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            if not reason_str:
                reason_str = outputArr[2]
                
        elif smtp_type == "exim":
            banner_pattern2 = re.compile(r"^[^#\n]*smtp_banner.*", re.MULTILINE)
            for match in banner_pattern2.finditer(outputArr[3]):
                if "$version_number" in match.group(0).lower():
                    reason_str += match.group(0) + '\n'
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': match.group(0).strip(),
                        'vulnerabilityConditionReasonCode': "SRV-170"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            if not reason_str:
                reason_str = outputArr[3]
                
        else:
            banner_pattern3 = re.compile(r"^[^#\n]*SmtpGreetingMessage.*", re.MULTILINE)
            for match in banner_pattern3.finditer(outputArr[1]):
                if "$v" in match.group(0).lower():
                    reason_str += match.group(0) + '\n'
                    vulnerability_condition_result_model = {
                        'vulnerabilityConditionOutput': match.group(0).strip(),
                        'vulnerabilityConditionReasonCode': "SRV-170"
                    }
                    vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)
            if not reason_str:
                reason_str = outputArr[1]
                
        if not vulnerability_condition_result_model_list:
            result = 'N'
            auto_result_reason = "(+) 배너 설정이 없거나, 버전 옵션이 탐지되지 않아 양호로 판단\n\n" + reason_str.strip()
            
        else:
            result = 'Y'
            auto_result_reason = "(-) 배너 설정에 버전 옵션이 탐지되어 취약으로 판단\n\n" + reason_str.strip()
    
    return result, auto_result_reason, vulnerability_condition_result_model_list
    
def check_SRV_171(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    service_check = get_check_service(outputArr[0], 'ftp')

    if service_check:
        auto_result_reason = "(*) 수동 판단 필요: FTP 버전 정보가 노출되는 설정인지 확인 필요\n\n" + outputArr[1] + "\n\n" + outputArr[0]
    else:
        result = 'N'
        auto_result_reason = "(+) FTP 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n\n" + outputArr[0]

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_173(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []

    outputArr = split_output(output, 2)
    if not outputArr:
        auto_result_reason = "(*) 수동 판단 필요: 출력 데이터가 예상된 형식으로 분리되지 않았습니다.\n" + output
        return result, auto_result_reason, vulnerability_condition_result_model_list

    service_check = get_check_service(outputArr[0], 'dns')

    if service_check:
        auto_result_reason = "(*) 수동 판단 필요: allow-update 또는 update-policy 정책 확인 후 판단\n\n" + outputArr[1] + "\n\n" + outputArr[0]
    else:
        result = 'N'
        auto_result_reason = "(+) DNS 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n\n" + outputArr[0]

    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_174(output):
    result = 'N'
    auto_result_reason = ""
    vulnerability_condition_result_model_list = []
    
    m = re.compile(r".*(?:[0-9]{1,3}\.){3}[0-9]{1,3}:53[\s]+.*", re.MULTILINE)

    matches = m.findall(output)
    if matches:
        vulnerability_condition_result_model = {
            'vulnerabilityConditionOutput': "불필요한 DNS 서비스 실행중",
            'vulnerabilityConditionReasonCode': "SRV-174"
        }
        vulnerability_condition_result_model_list.append(vulnerability_condition_result_model)

        result = 'Y'
        auto_result_reason = "(-) DNS 53번 포트가 열려있는 것으로 탐지되어 취약으로 판단(업무상 사용 여부 확인 필요)\n"
        for match in matches:
            auto_result_reason += match + '\n'

    else:
        auto_result_reason = "(+) DNS 53번 포트가 열려있지 않은 것으로 탐지되어 양호로 판단\n" + output
        
    return result, auto_result_reason, vulnerability_condition_result_model_list

def check_SRV_175(output):
    result = 'N'
    auto_result_reason = '(*) 수동 판단 필요: NTP 동기화 서버가 올바로 설정됐는지 확인\n\n' + output.strip()
    vulnerability_condition_result_model_list = []

    return result, auto_result_reason, vulnerability_condition_result_model_list


################## main function ##################

def main(filePath):
    xml_result_dict, failed_lines = robust_parse_xml(filePath)
    
    # 사전을 JSON 형식으로 변환
    json_output = json.dumps(xml_result_dict, indent=4, ensure_ascii=False)
    #print(json_output)

    data_dict = json.loads(json_output)
    # Initialize a dictionary to store the results
    results_dict = {}

    # Function dispatcher maps PRCS IDs to their respective check functions
    function_dispatcher = {
        "WST-CHK": check_WST,
        "SRV-001": check_SRV_001,
        "SRV-004": check_SRV_004,
        "SRV-005": check_SRV_005,
        "SRV-006": check_SRV_006,
        "SRV-007": check_SRV_007,
        "SRV-008": check_SRV_008,
        "SRV-009": check_SRV_009,
        "SRV-010": check_SRV_010,
        "SRV-011": check_SRV_011,
        "SRV-012": check_SRV_012,
        "SRV-013": check_SRV_013,
        "SRV-014": check_SRV_014,
        "SRV-015": check_SRV_015,
        "SRV-016": check_SRV_016,
        "SRV-021": check_SRV_021,
        "SRV-022": check_SRV_022,
        "SRV-025": check_SRV_025,
        "SRV-026": check_SRV_026,
        "SRV-027": check_SRV_027,
        "SRV-028": check_SRV_028,
        "SRV-034": check_SRV_034,
        "SRV-035": check_SRV_035,
        "SRV-037": check_SRV_037,
        "SRV-062": check_SRV_062,
        "SRV-063": check_SRV_063,
        "SRV-064": check_SRV_064,
        "SRV-066": check_SRV_066,
        "SRV-069": check_SRV_069,
        "SRV-070": check_SRV_070,
        "SRV-073": check_SRV_073,
        "SRV-074": check_SRV_074,
        "SRV-075": check_SRV_075,
        "SRV-081": check_SRV_081,
        "SRV-082": check_SRV_082,
        "SRV-083": check_SRV_083,
        "SRV-084": check_SRV_084,
        "SRV-087": check_SRV_087,
        "SRV-091": check_SRV_091,
        "SRV-092": check_SRV_092,
        "SRV-093": check_SRV_093,
        "SRV-094": check_SRV_094,
        "SRV-095": check_SRV_095,
        "SRV-096": check_SRV_096,
        "SRV-108": check_SRV_108,
        "SRV-109": check_SRV_109,
        "SRV-112": check_SRV_112,
        "SRV-115": check_SRV_115,
        "SRV-118": check_SRV_118,
        "SRV-121": check_SRV_121,
        "SRV-122": check_SRV_122,
        "SRV-127": check_SRV_127,
        "SRV-131": check_SRV_131,
        "SRV-133": check_SRV_133,
        "SRV-142": check_SRV_142,
        "SRV-144": check_SRV_144,
        "SRV-147": check_SRV_147,
        "SRV-158": check_SRV_158,
        "SRV-161": check_SRV_161,
        "SRV-163": check_SRV_163,
        "SRV-164": check_SRV_164,
        "SRV-165": check_SRV_165,
        "SRV-166": check_SRV_166,
        "SRV-170": check_SRV_170,
        "SRV-171": check_SRV_171,
        "SRV-173": check_SRV_173,
        "SRV-174": check_SRV_174,
        "SRV-175": check_SRV_175,
    }

    # Process each key-value pair in the JSON data
    for key, output in data_dict.items():
        # set default values
        result = 'N'
        auto_result_reason = ""
        vul_result_model = []
        
        if key in function_dispatcher:
            returned_value = function_dispatcher[key](output)  # Call the appropriate function based on the key
        
            if isinstance(returned_value, tuple):
                result, auto_result_reason, vul_result_model = returned_value
            
        # Store the output and result in the dictionary
        results_dict[key] = {'output': output, 'result': result, 'auto_result_reason': auto_result_reason, 'vul_result_model': vul_result_model}

    return xml_result_dict, results_dict, failed_lines
