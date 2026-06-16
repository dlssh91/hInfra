from datetime import datetime, timedelta
import re

class MySQLCloudAnalysis:
    def __init__(self, config, data={}):
        self.today = datetime.now()
        self.exception = config['exception']
        self.rules = config['rules']
        self.data = data
        self.result = {}
        self.dbm_result = {}
        
    @property
    def run(self):
        print("[*] MySQL Cloud Analysis Start")
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
        self.dbm_028()
        
        return self.dbm_result
        
    # 일단 무슨 함수인지 파악 필요
    # {DBM-??? : {..., RESULT: [{XXX : YYY}]}}
    # DBM-???을 data_key로 사용
    # RESULT의 각 항목에 대해서 condition 항목을 만족하는지 검사
    # 결과로서는 datum 한 줄씩 추가되며 for문 순회 후 중복 제거
    # 최종 결과에 포함된다는 것은 취약하다는 뜻
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
    
    #########################################################################################################
    
    # result_key : 최종 결과물로서 사용될 인덱스 값 (평가 항목 코드를 사용)
    # data_key   : .txt 파일 파싱의 결과물의 인덱스 값
    # conditions : datum 한 줄에 대해서 검사할 lambda 함수들의 list, 모두 참일 경우 datum이 취약하다고 판단
    
    #########################################################################################################
    
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
        conditions = [
            lambda datum: datum['FAILED_LOGIN_ATTEMPTS'] == "" 
                          or int(datum['FAILED_LOGIN_ATTEMPTS']) == 0 
                          or int(datum['FAILED_LOGIN_ATTEMPTS']) > int(self.rules[result_key]['USER_ATTRIBUTES'][0]),
            lambda datum: datum['PASSWORD_LOCK_TIME_DAYS'] == "" 
                          or int(datum['PASSWORD_LOCK_TIME_DAYS']) == 0,
            lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
        ]
        self.dbm_process_data(result_key, 'DBM-006', conditions)    
    
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
        self.dbm_process_data(result_key, 'DBM-008_1', [
            lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: current_date > datetime.strptime(datum['PASSWORD_LAST_CHANGED'], '%Y-%m-%d') + timedelta(days=int(self.rules[result_key]['DAY'][0]))
        ])
        
        self.dbm_process_data(result_key, 'DBM-008_2', [
            lambda datum: datum['VARIABLE_NAME'] == 'default_password_lifetime',
            lambda datum: datum['VALUE'] != '90'
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
            lambda datum: datum['VARIABLE_NAME'] == "audit_log_enabled",
            lambda datum: datum['VARIABLE_VALUE'] not in ["ON", "1"]
        ])
        
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'] == "server_audit_logging",
            lambda datum: datum['VARIABLE_VALUE'] not in ["ON", "1"]
        ])
        
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: type(datum) == dict,
            lambda datum: datum['VARIABLE_NAME'] == "server_audit_logs_upload",
            lambda datum: datum['VARIABLE_VALUE'] not in ["ON", "1"]
        ])
    
    def dbm_013(self, result_key='DBM-013'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-013', [
            lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
            lambda datum: datum['HOST'] in self.rules[result_key]['HOST'],
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
        self.dbm_process_data(result_key, 'DBM-022', [lambda datum: True])
    
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