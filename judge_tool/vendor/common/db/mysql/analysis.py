from datetime import datetime, timedelta
import re

# VENDOR-EDIT(c): R-026 umask 헬퍼 (2026-06-18)
# umask 8진 문자열에서 group/other 자리를 추출해 위반 여부를 반환한다.
# 양호 조건: group 자리(마지막3자리 중 2번째) ≥ 2  AND  other 자리(마지막 자리) ≥ 2.
# 즉 "022 이상" 기준. umask 022 → group=2, other=2 → 양호.
# umask 020 → other=0 → 취약. umask 002 → group=0 → 취약. umask 000 → 취약.
# 반환: True = 위반(취약), False = 양호.
# 파싱 불가(8진 토큰 없음) → None 반환 — 호출자(lambda)가 falsy로 처리해 violations 미포함.
# 어댑터 모드F(_UMASK_GUARD)가 "파싱 불가 = 판단보류"를 별도로 처리한다.
_UMASK_TOKEN_RE = re.compile(r'\b(0*[0-7]{1,4})\b')

def _umask_is_violation(output: str):
    """umask output 문자열에서 8진수 umask를 파싱해 위반(True)/양호(False)/파싱불가(None) 반환."""
    if not isinstance(output, str):
        return None
    s = output.strip()
    # 8진 토큰 추출 (마지막 토큰이 umask 값)
    tokens = _UMASK_TOKEN_RE.findall(s)
    if not tokens:
        return None
    raw = tokens[-1].lstrip('0') or '0'
    # umask는 최대 4자리(특수비트+3). 마지막 3자리를 owner/group/other로 해석.
    padded = raw.zfill(3)[-3:]
    try:
        group_digit = int(padded[1])   # 가운데 자리 = group mask
        other_digit = int(padded[2])   # 마지막 자리 = other mask
    except (ValueError, IndexError):
        return None
    # 위반: group < 2 또는 other < 2
    return not (group_digit >= 2 and other_digit >= 2)


class MySQLAnalysis:
    def __init__(self, config, data={}):
        self.today = datetime.now()
        self.exception = config['exception']
        self.rules = config['rules']
        self.data = data
        self.result = {}
        self.dbm_result = {}
        
    @property
    def run(self):
        print("[*] MySQL Analysis Start")
        self.dbm_result = {}
        
        self.dbm_001()
        self.dbm_003()
        self.dbm_004()
        self.dbm_005()
        self.dbm_006()
        self.dbm_007()
        self.dbm_008()
        self.dbm_009()
        self.dbm_011()
        self.dbm_013()
        self.dbm_016()
        self.dbm_017()
        self.dbm_019()
        self.dbm_020()
        self.dbm_022()  # permission
        self.dbm_024()
        self.dbm_025()
        self.dbm_026()  # umask
        self.dbm_028()
        self.dbm_033()  # master slave setting
        
        return self.dbm_result

    def dbm_process_data(self, result_key, data_key, conditions): 
        try:    
            if data_key in self.data:
                if self.data[data_key].get('NOTE', None):
                    self.dbm_result[result_key].append({"@@@": self.data[data_key]['NOTE']})
                
                if 'Note' in self.rules[result_key]:
                    self.dbm_result[result_key].append(self.rules[result_key]['Note'])
                
                for datum in self.data[data_key].get('RESULT', []):
                    if all(condition(datum) for condition in conditions):
                        if 'alert' in self.rules[result_key]:
                            self.dbm_result[result_key].append(self.rules[result_key]['alert'])
                            break
                        elif type(datum) == str:
                            self.dbm_result[result_key].append({"*": datum})
                        else:
                            self.dbm_result[result_key].append(datum)
                
                # remove duplicate
                self.dbm_result[result_key] = [dict(t) for t in {tuple(d.items()) for d in self.dbm_result[result_key]}]
                
        except Exception as e:
            print(f"[!] Exception Occurred MySQL {result_key}: {str(e)}")
            
    def dbm_001(self, result_key='DBM-001'):
        # 계정의 비밀번호가 취약하게 설정된 경우, password hash crack이 필요하므로 수동 검사
        self.dbm_result[result_key] = []
        
    def dbm_003(self, result_key='DBM-003'):
        # 업무상 불필요한 계정 존재
        self.dbm_result[result_key] = []
        
        # mysql 버전에 따라 사용해야 할 condition lambda 함수 set이 달라짐
        cond_1 = [
            lambda datum: datum.get('ACCOUNT_LOCKED', None) is not None,
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
            lambda datum: datum['ACCOUNT_LOCKED'] in self.rules[result_key]['ACCOUNT_LOCKED'],
        ]
        cond_2 = [
            lambda datum: datum.get('PASSWORD_EXPIRED', None) is not None,
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
            lambda datum: datum['PASSWORD_EXPIRED'] in self.rules[result_key]['PASSWORD_EXPIRED'],
        ]
        
        self.dbm_process_data(result_key, 'DBM-003', cond_1)
        self.dbm_process_data(result_key, 'DBM-003', cond_2)
        
    def dbm_004(self, result_key='DBM-004'):
        # 업무상 불필요하게 관리자 권한이 부여된 계정 존재
        self.dbm_result[result_key] = []
        conditions =  [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'].replace("'", "") not in self.exception[result_key]['PRIVILEGE_TYPE'],
            lambda datum: datum['PRIVILEGE_TYPE'] in self.rules[result_key]['PRIVILEGE_TYPE'],
        ]
        self.dbm_process_data(result_key, 'DBM-004', conditions)
        
    def dbm_005(self, result_key='DBM-005'):
        # 데이터베이스 내 중요정보 암호화 미적용
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-005', [lambda datum: True])
        
    def dbm_006(self, result_key='DBM-006'):
        # 로그인 실패 횟수에 따른 접속 제한 설정 미흡
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-006', [
            lambda datum: datum['USER_ATTRIBUTES'] == "",
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
        ])
        
        self.dbm_process_data(result_key, 'DBM-006', [
            lambda datum: datum['USER_ATTRIBUTES'] != "",
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
            lambda datum: int(datum['USER_ATTRIBUTES']) > int(self.rules['DBM-006']['USER_ATTRIBUTES'][0])
        ])
        
    def dbm_007(self, result_key='DBM-007'):
        # 비밀번호의 복잡도 정책 설정 미흡
        self.dbm_result[result_key] = []
        
        # validate_password.so plugin is not loaded!
        self.dbm_process_data(result_key, 'DBM-007', [
            lambda datum: 'not loaded' in str(datum)
        ])

        # validate_password_policy 변수가 존재하고, 그 값이 규칙에 명시된 값이 아닌 경우
        self.dbm_process_data(result_key, 'DBM-007', [
            lambda datum: datum['VARIABLE_NAME'] in ["validate_password_policy", "validate_password.policy"],
            lambda datum: datum['VARIABLE_VALUE'] in self.rules[result_key]['VARIABLE_VALUE'],
        ])
        
    def dbm_008(self, result_key='DBM-008'):
        # 주기적인 비밀번호 변경 미흡
        # 기준 분기별(90일)
        self.dbm_result[result_key] = []
        current_date = datetime.now()
        
        self.dbm_process_data(result_key, 'DBM-008', [
            lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: current_date > datetime.strptime(datum['PASSWORD_LAST_CHANGED'], '%Y-%m-%d') + timedelta(days=int(self.rules[result_key]['DAY'][0]))
        ])
        
    def dbm_009(self, result_key='DBM-009'):
        # 사용되지 않는 세션 종료 미흡
        # 기준 900초 -> 15분
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-009', [
            lambda datum: datum['VARIABLE_NAME'] not in self.exception[result_key]['VARIABLE_NAME'],
            lambda datum: datum['VARIABLE_NAME'] in self.rules[result_key]['VARIABLE_NAME'],
            lambda datum: int(datum['VARIABLE_VALUE']) > int(self.rules[result_key]['TIME'][0])
        ])
        
    def dbm_011(self, result_key='DBM-011'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: 'not loaded' in str(datum)
        ])
        
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'] == "audit_log_file",
            lambda datum: datum['VARIABLE_VALUE'] in self.rules[result_key]['VARIABLE_VALUE']
        ])
        
    def dbm_013(self, result_key='DBM-013'):
        # 원격 접속에 대한 접근 제어 미흡
        # 기준 : mysql.user 테이블에서 계정별 Host 칼럼에 '%' 또는 '_'(와일드카드)가 포함된 경우 취약
        # VENDOR-EDIT(c): R-MY013 — 기존 정확매칭 ['%'] → '%' in HOST 포함 매칭으로 확장.
        #   '%' 전체 와일드카드뿐 아니라 '10.%'(서브넷), '%.domain.com'(부분 와일드카드) 등
        #   광역 원격허용은 모두 취약. localhost/특정IP/특정호스트(와일드카드 없음) → 양호.
        #   거짓양호 갭(부분 와일드카드 미탐) 차단. 예외계정(exception USER) 제외 유지.
        # VENDOR-EDIT(b): R-MY013 exception USER 비움 — 원격접근통제 항목에선 어떤 계정도
        #   와일드카드-Host 검사에서 면제하면 안 됨. root@% 거짓양호 차단.
        # VENDOR-EDIT(b): R-MY013 '_' 단일문자 와일드카드 추가 — '10.0.0._' 등 미탐 차단.
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-013', [
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: '%' in datum['HOST'] or '_' in datum['HOST'],
        ])
        
    def dbm_016(self, result_key='DBM-016'):
        self.dbm_result[result_key] = []
        
        def get_last_number(ver_val):
            match = re.match(r'^\d+\.\d+\.(\d+)', ver_val)
            if match:
                return match[1]
            return '0'
        
        def get_major_minor(ver_val):
            match = re.match(r'^(\d+\.\d+)', ver_val)
            if match:
                return match[1]
            return 'None'
        
        self.dbm_process_data(result_key, 'DBM-016', [
            lambda datum: datum['VARIABLE_NAME']=="version",
            lambda datum: int(get_last_number(datum['VARIABLE_VALUE'])) 
                        < int(self.rules[result_key]['VERSION'][get_major_minor(datum['VARIABLE_VALUE'])].split('.')[-1])
        ])
        
    def dbm_017(self, result_key='DBM-017'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-017_1', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE'],
        ])
        self.dbm_process_data(result_key, 'DBM-017_2', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE'],
        ])
        self.dbm_process_data(result_key, 'DBM-017_3', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE'],
        ])
        self.dbm_process_data(result_key, 'DBM-017_4', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE'],
        ])
        
    def dbm_019(self, result_key='DBM-019'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-019', [
            lambda datum: datum['VARIABLE_NAME'] == 'password_history',
            lambda datum: int(datum['VARIABLE_VALUE']) <= int(self.rules[result_key]['HISTORY'][0])
        ])
        self.dbm_process_data(result_key, 'DBM-019', [
            lambda datum: datum['VARIABLE_NAME'] == 'password_reuse_interval',
            lambda datum: int(datum['VARIABLE_VALUE']) <= int(self.rules[result_key]['REUSE'][0])
        ])
        
    def dbm_020(self, result_key='DBM-020'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-020', [
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
        ])
        
    def dbm_022(self, result_key='DBM-022'):
        self.dbm_result[result_key] = []
        pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE | re.IGNORECASE)
        
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
        
        try:
            if 'DBM-022' in self.data:
                for datum in self.data['DBM-022']['RESULT']:
                    dbm_022_result = datum['output']
                    matches = pattern.finditer(dbm_022_result)
                    
                    for m in matches:
                        file_perm = m.group(1)
                        file_entry = m.group(0).lower()
                        
                        if get_check_file_perm(file_perm, 0, r"x") or get_check_file_perm(file_perm, 1, r"w|x") or get_check_file_perm(file_perm, 2, r"r|w|x"):
                            self.dbm_result[result_key].append(file_entry)
                            
        except Exception as e:
            print("[!] Exception Occurred Mysql DBM-022: " + str(e))

    def dbm_024(self, result_key='DBM-024'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-024_1', [
            lambda datum: datum['IS_GRANTABLE']=="YES",
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        self.dbm_process_data(result_key, 'DBM-024_2', [
            lambda datum: datum['IS_GRANTABLE']=="YES",
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        self.dbm_process_data(result_key, 'DBM-024_3', [
            lambda datum: datum['IS_GRANTABLE']=="YES",
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        self.dbm_process_data(result_key, 'DBM-024_4', [
            lambda datum: datum['IS_GRANTABLE']=="YES",
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        
    def dbm_025(self, result_key='DBM-025'):
        # 서비스 지원이 종료된(EoS) 데이터베이스 사용
        current_date = datetime.now()
        self.dbm_result[result_key] = []
        
        def get_major_minor(ver_val):
            match = re.match(r'^(\d+\.\d+)', ver_val)
            if match:
                return match[1]
            return 'None'
        
        self.dbm_process_data(result_key, 'DBM-025', [
            lambda datum: datum['VARIABLE_NAME']=="version",
            lambda datum: current_date > datetime.strptime(self.rules[result_key]['VERSION'][get_major_minor(datum['VARIABLE_VALUE'])],'%Y-%m-%d')
        ])
        
    def dbm_026(self, result_key='DBM-026'):
        # 데이터베이스 구동 계정의 umask 설정 미흡
        # VENDOR-EDIT(c): R-026 umask 판정 수정 (2026-06-18)
        # 수정 전: int(output)%100에 "3"/"4"/"5" 포함 여부 — 10진 파싱 + 잘못된 휴리스틱(거짓양호)
        # 수정 후: 8진 umask 파싱 → group≥2 AND other≥2 이면 양호, 아니면 취약.
        #         파싱 불가(8진 토큰 없음) → violations에 추가하지 않음(어댑터 모드F 가드가 판단보류 처리).
        self.dbm_result[result_key] = []

        self.dbm_process_data(result_key, 'DBM-026', [
            lambda datum: _umask_is_violation(datum.get('output', ''))
        ])
        
    def dbm_028(self, result_key='DBM-028'):
        # 데이터가 너무 많아 봐야하는 부분만 rules에 추가
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-028_1', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        self.dbm_process_data(result_key, 'DBM-028_2', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        self.dbm_process_data(result_key, 'DBM-028_3', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        self.dbm_process_data(result_key, 'DBM-028_4', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        
    def dbm_033(self, result_key='DBM-033'):
        # DB 이중화 구성 시 비밀번호 평문 노출
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-033', [
            lambda datum: datum['PASSWORD'] != "",
        ])