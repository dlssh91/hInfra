from datetime import datetime

class MariaDBCloudAnalysis:
    def __init__(self, config, data={}):
        self.today = datetime.now()
        self.exception = config['exception']
        self.rules = config['rules']
        self.data = data
        self.result = {}
        self.dbm_result = {}
        
    @property
    def run(self):
        print("[*] MariaDB Cloud Analysis Start")
        self.dbm_result = {}
        
        self.dbm_001()
        self.dbm_003()
        self.dbm_004()
        self.dbm_005()
        self.dbm_006()
        self.dbm_007()
        self.dbm_008()
        self.dbm_008()
        self.dbm_009()
        self.dbm_011()
        self.dbm_013()
        self.dbm_016()
        self.dbm_017()
        self.dbm_019()
        self.dbm_020()
        self.dbm_024()
        self.dbm_025()
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
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-003', [
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
            lambda datum: datum['PASSWORD_EXPIRED'] in self.rules[result_key]['PASSWORD_EXPIRED'],
        ])
        
    def dbm_004(self, result_key='DBM-004'):
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
            lambda datum: "MAX_PASSWORD_ERRORS is supported for" in datum
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
            lambda datum: datum['VARIABLE_NAME'].upper() == "SERVER_AUDIT_EVENTS",
            lambda datum: 'CONNECT' not in datum['VARIABLE_VALUE'].upper()
                            or 'QUERY' not in datum['VARIABLE_VALUE'].upper()
                            or 'TABLE' not in datum['VARIABLE_VALUE'].upper()
        ])

        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'].upper() == "SERVER_AUDIT_EXCL_USERS",
            lambda datum: datum['VARIABLE_VALUE'] != ""
        ])
        
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'].upper() == "SERVER_AUDIT_LOGGING",
            lambda datum: datum['VARIABLE_VALUE'].upper() != "ON"
        ])
        
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'].upper() == "SERVER_AUDIT_INCL_USERS",
            lambda datum: datum['VARIABLE_VALUE'] != ""
        ])
        
    def dbm_013(self, result_key='DBM-013'):
        # 원격 접속에 대한 접근 제어 미흡
        # 기준 : mysql.user 테이블에서 계정별 Host 칼럼이 %인 경우 취약
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-013', [
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: datum['HOST'] in self.rules[result_key]['HOST']
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
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-019', [
            lambda datum: type(datum) == str,
            lambda datum: "not loaded" in datum
        ])
        
        self.dbm_process_data(result_key, 'DBM-019', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'] == "PASSWORD_REUSE_CHECK_INTERVAL",
            lambda datum: int(datum['VARIABLE_VALUE']) > int(self.rules[result_key]['DAY'][0]) or int(datum['VARIABLE_VALUE']) == 0
        ])
        
    def dbm_020(self, result_key='DBM-020'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-020', [
            lambda datum: datum['USER'] not in self.exception[result_key]['USER']
        ])
        
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
        
        
        