from datetime import datetime
import json

class PostgreSQLCloudAnalysis:
    def __init__(self, config, data={}):
        self.today = datetime.now()
        self.exception = config['exception']
        self.rules = config['rules']
        self.data = data
        self.result = {}
        self.dbm_result = {}
        
    @property
    def run(self):
        print("[*] PostgreSQL Cloud Analysis Start")
        self.dbm_result = {}
        
        self.dbm_003()
        self.dbm_004()
        self.dbm_007()
        self.dbm_008()
        self.dbm_009()
        self.dbm_011()
        self.dbm_013()
        self.dbm_015()
        self.dbm_016()
        self.dbm_017()
        self.dbm_020()
        self.dbm_022()
        self.dbm_024()
        self.dbm_028()
        self.dbm_032()
        
        return self.dbm_result
    
    def dbm_process_data_no_remove_duplicates(self, result_key, data_key, conditions):
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
                        self.dbm_result[result_key].append(datum)
                
        except Exception as e:
            print(f"[!] Exception Occurred PostgreSQL {result_key}: {str(e)}")
    
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
                        self.dbm_result[result_key].append(datum)
                
                # remove duplicate
                self.dbm_result[result_key] = [dict(t) for t in {tuple(d.items()) for d in self.dbm_result[result_key]}]
                
        except Exception as e:
            print(f"[!] Exception Occurred PostgreSQL {result_key}: {str(e)}")
    
    def dbm_003(self, result_key='DBM-003'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-003', [
            lambda datum: datum['rolvaliduntil'] == None,
            lambda datum: 'pg_' not in datum['rolname'],
            lambda datum: datum['rolname'] not in self.exception[result_key]['rolname']
        ])
        
    def dbm_004(self, result_key='DBM-004'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-004', [
            lambda datum: datum['rolsuper'] == 't' and datum['rolcreatedb'] == 't' and datum['rolcreaterole'] == 't',
            lambda datum: datum['rolname'] not in self.exception[result_key]['rolname'],
        ])
    
    # 현재 스크립트에서는 passwordcheck.so load 여부 검사, 평가 기준과 상이하므로 확인 필요
    def dbm_007(self, result_key='DBM-007'):
        self.dbm_result[result_key] = []
    
    def dbm_008(self, result_key='DBM-008'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-008', [
            lambda datum: datum['rolvaliduntil'] == None,
            lambda datum: datum['rolcanlogin'] == 't' # expire 미설정 = 취약
        ])
        
        def get_date_diff(date_str):
            now = datetime.now()
            now = now.strftime('%Y%m%d')
            nowp = datetime.strptime(now, '%Y%m%d')
            
            expiredDate = datetime.strptime(date_str.split(' ')[0], "%Y-%m-%d")
            date_diff = nowp - expiredDate
            return date_diff.days
        
        self.dbm_process_data(result_key, 'DBM-008', [
            lambda datum: datum['rolvaliduntil'] != None,
            lambda datum: get_date_diff(datum['rolvaliduntil']) > 90, # 90일 이상 차이가 날 경우 취약
        ])
    
    def dbm_009(self, result_key='DBM-009'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-009', [
            lambda datum: 'idle_in_transaction_session_timeout' in datum['setting_name'] and int(datum['value']) <= 900
        ])
        
    # 추후 정확한 기준 여부 및 출력 요건 살펴보기
    def dbm_011(self, result_key='DBM-011'):
        self.dbm_result[result_key] = []

        # 취약 설정일 경우 True, 보안 설정일 경우 False 반환
        def check_config_011(config_list = []):
            expected = {
                "pgaudit.log": "ddl,role,read,write",
                "pgaudit.log_parameter": "off",
                "pgaudit.log_rows": "off",
                "pgaudit.role": "rds_pgaudit",
            }

            # 정규화(소문자+strip)
            expected_norm = {k.strip().lower(): str(v).strip().lower() for k, v in expected.items()}

            # 입력 리스트 -> dict (소문자+strip)
            values = {}
            for item in config_list:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                value = item.get("value")
                if isinstance(name, str):
                    key = name.strip().lower()
                    val = (str(value).strip().lower() if value is not None else "")
                    values[key] = val

            # 1) 필수 키 존재 여부
            required_keys = set(expected_norm.keys())
            if not required_keys.issubset(values.keys()):
                return True  # 누락 → 비준수(True)

            # 2) 값 검사
            def split_set(s: str):
                # 콤마 분리 후 공백 제거, 빈 토큰 제거
                return {tok.strip() for tok in s.split(",") if tok.strip()}

            for k, exp_val in expected_norm.items():
                act_val = values[k]

                if k == "pgaudit.log":
                    # 포함 검사 (순서무관/초과허용)
                    exp_set = split_set(exp_val)
                    act_set = split_set(act_val)
                    if not exp_set.issubset(act_set):
                        return True  # 기대 항목을 모두 포함하지 않음 → 비준수
                else:
                    # 정확 일치
                    if act_val != exp_val:
                        return True

            # 모든 조건 충족 → 준수(False)
            return False
        
        # AWS 및 Azure 용도에서 다르게 동작하도록
        
        # AWS 용 
        # pgaudit 설정 없음
        self.dbm_process_data_no_remove_duplicates(result_key, 'DBM-011', [
            lambda datum: datum.get('setting_name', None) is not None,
            lambda datum: datum['setting_name'] == 'shared_preload_libraries',
            lambda datum: 'pgaudit' not in datum['value']
        ])
        
        # pgaudit 설정이 제대로 구성되지 않음
        self.dbm_process_data_no_remove_duplicates(result_key, 'DBM-011', [
            lambda datum: datum.get('setting_name', None) is not None,
            lambda datum: datum['setting_name'] == 'shared_preload_libraries',
            lambda datum: 'pgaudit' in datum['value'],
            lambda datum: check_config_011(datum['pgaudit_settings'])
        ])
        
        # Azure 용
        self.dbm_process_data_no_remove_duplicates(result_key, 'DBM-011', [
            lambda datum: datum.get('pgaudit_status', None) is not None,
            lambda datum: datum['pgaudit_status'] != 'LOADED'
        ])
        
        self.dbm_process_data_no_remove_duplicates(result_key, 'DBM-011', [
            lambda datum: datum.get('pgaudit_status', None) is not None,
            lambda datum: datum['pgaudit_status'] == 'LOADED',
            lambda datum: datum["source_parameter"] == 'azure.extensions',
            lambda datum: 'PGAUDIT' not in datum["value"]
        ])
        
        # PGAUDIT까지 세팅되어 있으나 설정이 제대로 구성되지 않음
        self.dbm_process_data_no_remove_duplicates(result_key, 'DBM-011', [
            lambda datum: datum.get('pgaudit_status', None) is not None,
            lambda datum: datum['pgaudit_status'] == 'LOADED',
            lambda datum: datum["source_parameter"] == 'azure.extensions',
            lambda datum: 'PGAUDIT' in datum["value"],
            lambda datum: check_config_011(datum['pgaudit_settings'])
        ])
        
        seen = set()
        unique = []
        
        for d in self.dbm_result[result_key]:
            key = json.dumps(d, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            unique.append(d)
    
        self.dbm_result[result_key] = unique
    
    # 현 상태에 NOTE만 올라가도록 수정
    # {"NOTE": "클라우드 콘솔의 네트워크 설정(예: AWS Security Group, Azure Network Security Group) 및 '퍼블릭 액세스' 옵션으로 제어"},
    # {"NOTE": "퍼블릭 액세스 허용 설정은 클라우드 관리체계(가상자원에 대한 퍼블릭 액세스 허용) 스크립트 참고"}
    def dbm_013(self, result_key='DBM-013'):
        self.dbm_result[result_key] = []
    
    def dbm_015(self, result_key='DBM-015'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-015_1', [
            lambda datum: datum['privilege_type'].upper() in ['INSERT', 'SELECT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCE', 'TRIGGER']
        ])
        self.dbm_process_data(result_key, 'DBM-015_2', [
            lambda datum: datum['privilege_type'].upper() in ['INSERT', 'SELECT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCE', 'TRIGGER']
        ])
        self.dbm_process_data(result_key, 'DBM-015_3', [
            lambda datum: datum['privilege_type'].upper() in ['INSERT', 'SELECT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCE', 'TRIGGER']
        ])
    
    def dbm_016(self, result_key='DBM-016'):
        self.dbm_result[result_key] = []
        patch_list = self.rules[result_key]['version']
        
        def check_minor_ver(ver_str):
            check_arr = ver_str.split(' ')[1].split('.')
            cur_major_version = check_arr[0]
            cur_minor_version = check_arr[1]
            
            if int(cur_major_version) >= 10 and int(cur_major_version) <= 17:
                latest_minor_ver = patch_list[cur_major_version].split('.')[1]
            else:
                latest_minor_ver = '99'
                
            return int(latest_minor_ver) > int(cur_minor_version)
        
        self.dbm_process_data(result_key, 'DBM-016', [    
            lambda datum: check_minor_ver(datum['version'])
        ])
    
    def dbm_017(self, result_key='DBM-017'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-017_1', [
            lambda datum: datum['grantee'] == 'PUBLIC'
        ])
        self.dbm_process_data(result_key, 'DBM-017_2', [
            lambda datum: datum['grantee'] == 'PUBLIC'
        ])
        
    def dbm_020(self, result_key='DBM-020'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-020', [
            lambda datum: datum['rolname'] not in self.exception[result_key]['rolname']
        ])

    # "설치형DB: 서버 스크립트 참고, 그 외: 클라우드 관리체계 스크립트 참고"     
    def dbm_022(self, result_key='DBM-022'):
        self.dbm_result[result_key] = []
    
    def dbm_024(self, result_key='DBM-024'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-024_1', [
            lambda datum: datum['privilege_type'].upper() in ['INSERT', 'SELECT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCE', 'TRIGGER']
        ])
        self.dbm_process_data(result_key, 'DBM-024_2', [
            lambda datum: datum['privilege_type'].upper() in ['INSERT', 'SELECT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCE', 'TRIGGER']
        ])
        self.dbm_process_data(result_key, 'DBM-024_3', [
            lambda datum: datum['privilege_type'].upper() in ['INSERT', 'SELECT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCE', 'TRIGGER']
        ])
        
    def dbm_028(self, result_key='DBM-028'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-028_1', [
            lambda datum: True,
        ])
        self.dbm_process_data(result_key, 'DBM-028_2', [
            lambda datum: True,
        ])
        self.dbm_process_data(result_key, 'DBM-028_3', [
            lambda datum: True,
        ])
    
    # 수동 점검 사항으로 교체됨
    def dbm_032(self, result_key='DBM-032'):
        self.dbm_result[result_key] = []