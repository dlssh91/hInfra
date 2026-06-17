from datetime import datetime
import re

class MariaDBAnalysis:
    def __init__(self, config, data={}):
        self.today = datetime.now()
        self.exception = config['exception']
        self.rules = config['rules']
        self.data = data
        self.result = {}
        self.dbm_result = {}
    
    @property
    def run(self):
        print("[*] MariaDB Analysis Start")
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
        self.dbm_025()  # sql version
        self.dbm_026()  # umask
        self.dbm_028()
        
        return self.dbm_result
    
    def dbm_process_data(self, result_key, data_key, conditions):
        try:
            if data_key in self.data:
                # 스크립트 내의 note 가져오기
                if self.data[data_key].get('NOTE', None):
                    self.dbm_result[result_key].append({"@@@": self.data[data_key]['NOTE']})
                
                # config 내의 note 가져오기
                if 'Note' in self.rules[result_key]:
                    self.dbm_result[result_key].append(self.rules[result_key]['Note'])
                
                for datum in self.data[data_key].get('RESULT', []):
                    if all(condition(datum) for condition in conditions):
                        if type(datum) == str:
                            self.dbm_result[result_key].append({"*": datum})
                        else:
                            self.dbm_result[result_key].append(datum)
                
                # remove duplicate
                self.dbm_result[result_key] = [dict(t) for t in {tuple(d.items()) for d in self.dbm_result[result_key]}]
                
        except Exception as e:
            print(f"[!] Exception Occurred MariaDB {result_key}: {str(e)}")
    
    def dbm_001(self, result_key='DBM-001'):
        self.dbm_result[result_key] = []
        
    def dbm_003(self, result_key='DBM-003'):
        # 업무상 불필요한 계정 존재
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-003', [
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
            lambda datum: datum['PASSWORD_EXPIRED'] in self.rules[result_key]['PASSWORD_EXPIRED'],
        ])
        
    def dbm_004(self, result_key='DBM-004'):
        # 업무상 불필요하게 관리자 권한이 부여된 계정 존재
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-004', [
            lambda datum: datum['GRANTEE'].replace("'", "") not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'].replace("'", "") not in self.exception[result_key]['PRIVILEGE_TYPE'],
            lambda datum: datum['PRIVILEGE_TYPE'] in self.rules[result_key]['PRIVILEGE_TYPE'],
        ])
        
    def dbm_005(self, result_key='DBM-005'):
        # 데이터베이스 내 중요정보 암호화 미흡
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-005', [lambda datum: True])
        
    def dbm_006(self, result_key='DBM-006'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-006', [
            lambda datum: type(datum) == str,
            lambda datum: "MAX_PASSWORD_ERRORS" in datum
        ])
        self.dbm_process_data(result_key, 'DBM-006', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'] in self.rules[result_key]['VARIABLE_NAME'],
            lambda datum: int(datum['VARIABLE_VALUE']) > int(self.rules[result_key]['VARIABLE_VALUE'][0])
        ])
        
    def dbm_007(self, result_key='DBM-007'):
        # 비밀번호의 복잡도 정책 설정 미흡
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-007', [
            lambda datum: type(datum) == str,
            lambda datum: "not loaded" in datum
        ])
        
        self.dbm_process_data(result_key, 'DBM-007', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'] in ["SIMPLE_PASSWORD_CHECK_DIGITS", "SIMPLE_PASSWORD_CHECK_LETTERS_SAME_CASE", 
                                                     "SIMPLE_PASSWORD_CHECK_OTHER_CHARACTERS", "SIMPLE_PASSWORD_CHECK_MINIMAL_LENGTH"],
            lambda datum: int(datum['VARIABLE_VALUE']) < int(self.rules[result_key][datum['VARIABLE_NAME']][0])
        ])
        
    def dbm_008(self, result_key='DBM-008'):
        # 주기적인 비밀번호 변경 미흡
        # 기준 분기별(90일)
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-008', [
            lambda datum: type(datum) == str,
            lambda datum: "DEFAULT_PASSWORD_LIFETIME is supported for" in datum
        ])
        self.dbm_process_data(result_key, 'DBM-008', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'] == "DEFAULT_PASSWORD_LIFETIME",
            lambda datum: int(datum['VARIABLE_VALUE']) > int(self.rules[result_key]['DAY'][0]) or int(datum['VARIABLE_VALUE']) == 0
        ])
        
    def dbm_009(self, result_key='DBM-009'):
        # 사용되지 않는 세션 종료 미흡
        # 기준 900초 -> 15분
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-009', [
            lambda datum: datum['VARIABLE_NAME'] in self.rules[result_key]['VARIABLE_NAME'],
            lambda datum: int(datum['VARIABLE_VALUE']) > int(self.rules[result_key]['TIME'][0])
        ])
    
    def dbm_011(self, result_key='DBM-011'):
        # 감사 로그 수집 및 백업 미흡
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: type(datum) == str,
            lambda datum: "not loaded" in datum
        ])
        
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'].upper() == "SERVER_AUDIT_FILE_PATH",
            lambda datum: datum['VARIABLE_VALUE'] in self.rules['DBM-011']['VARIABLE_VALUE']
        ])
    
    def dbm_013(self, result_key='DBM-013'):
        # 원격 접속에 대한 접근 제어 미흡
        # 기준 : mysql.user 테이블에서 계정별 Host 칼럼에 '%' 또는 '_'(와일드카드)가 포함된 경우 취약
        # VENDOR-EDIT(c): R-MA013 — 기존 정확매칭 ['%'] → '%' in HOST 포함 매칭으로 확장.
        #   '%' 전체 와일드카드뿐 아니라 '10.%'(서브넷), '%.domain.com'(부분 와일드카드) 등
        #   광역 원격허용은 모두 취약. localhost/특정IP/특정호스트(와일드카드 없음) → 양호.
        #   거짓양호 갭(부분 와일드카드 미탐) 차단. 예외계정(exception USER) 제외 유지.
        # VENDOR-EDIT(b): R-MA013 exception USER 비움 — 원격접근통제 항목에선 어떤 계정도
        #   와일드카드-Host 검사에서 면제하면 안 됨. root@% 거짓양호 차단.
        # VENDOR-EDIT(b): R-MA013 '_' 단일문자 와일드카드 추가 — '10.0.0._' 등 미탐 차단.
        self.dbm_result[result_key] = []

        self.dbm_process_data(result_key, 'DBM-013', [
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: '%' in datum['HOST'] or '_' in datum['HOST'],
        ])
        
    def dbm_016(self, result_key='DBM-016'):
        self.dbm_result[result_key] = []
        
    def dbm_017(self, result_key='DBM-017'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-017_1', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        self.dbm_process_data(result_key, 'DBM-017_2', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        self.dbm_process_data(result_key, 'DBM-017_3', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        self.dbm_process_data(result_key, 'DBM-017_4', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        
    def dbm_019(self, result_key='DBM-019'):
        # 비밀번호 재사용 방지 설정 미흡
        # VENDOR-EDIT(c): R-MA019-polarity — xlsx 판단기준은 "설정 여부"(이진).
        #   PASSWORD_REUSE_CHECK_INTERVAL > 0 → 재사용방지 설정됨 → 양호.
        #   INTERVAL == 0 → 무제한(미설정) → 취약.
        #   기존 코드: INTERVAL > DAY[0] or INTERVAL == 0 → 취약 (역전 오판, 60일 등 강한 설정도 취약).
        #   수정: INTERVAL == 0 만 위반 조건. DAY 임계값 개념 없음.
        self.dbm_result[result_key] = []

        self.dbm_process_data(result_key, 'DBM-019', [
            lambda datum: type(datum) == str,
            lambda datum: "not loaded" in datum
        ])

        self.dbm_process_data(result_key, 'DBM-019', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'] == "PASSWORD_REUSE_CHECK_INTERVAL",
            lambda datum: int(datum['VARIABLE_VALUE']) == 0
        ])
        
    def dbm_020(self, result_key='DBM-020'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-020', [
            lambda datum: datum['USER'] not in self.exception[result_key]['USER']
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
            print("[!] Exception Occurred MariaDB DBM-022: " + str(e))
        
    def dbm_024(self, result_key='DBM-024'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-024_1', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['IS_GRANTABLE'] == "YES",
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        
        self.dbm_process_data(result_key, 'DBM-024_2', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['IS_GRANTABLE'] == "YES",
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        
        self.dbm_process_data(result_key, 'DBM-024_3', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['IS_GRANTABLE'] == "YES",
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])
        
        self.dbm_process_data(result_key, 'DBM-024_4', [
            lambda datum: datum['GRANTEE'] not in self.exception[result_key]['GRANTEE'],
            lambda datum: datum['IS_GRANTABLE'] == "YES",
            lambda datum: datum['PRIVILEGE_TYPE'] not in self.exception[result_key]['PRIVILEGE_TYPE']
        ])

    def dbm_025(self, result_key='DBM-025'):
        self.dbm_result[result_key] = []
        
    def dbm_026(self, result_key='DBM-026'):
        # 데이터베이스 구동 계정의 umask 설정 미흡
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-026', [
            lambda datum: any(sub in str(int(datum['output'])%100) for sub in ["3", "4", "5"])
        ])
    
    def dbm_028(self, result_key='DBM-028'):
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