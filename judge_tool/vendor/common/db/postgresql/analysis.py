from datetime import datetime
import re

class PostgreSQLAnalysis:
    def __init__(self, config, data={}):
        self.today = datetime.now()
        self.exception = config['exception']
        self.rules = config['rules']
        self.data = data
        self.result = {}
        self.dbm_result = {}
    
    @property
    def run(self):
        print("[*] PostgreSQL Analysis Start")
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
        self.dbm_015()
        self.dbm_016()
        self.dbm_017()
        self.dbm_019()
        self.dbm_020()
        self.dbm_022()
        self.dbm_024()
        self.dbm_025()
        self.dbm_026()
        self.dbm_028()
        self.dbm_032()
        
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
                        self.dbm_result[result_key].append(datum)
                
                # remove duplicate
                self.dbm_result[result_key] = [dict(t) for t in {tuple(d.items()) for d in self.dbm_result[result_key]}]
                
        except Exception as e:
            print(f"[!] Exception Occurred PostgreSQL {result_key}: {str(e)}")
            
    def dbm_001(self, result_key='DBM-001'):
        self.dbm_result[result_key] = []
        
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
    
    def dbm_005(self, result_key='DBM-005'):
        self.dbm_result[result_key] = []

    def dbm_006(self, result_key='DBM-006'):
        self.dbm_result[result_key] = []
    
    # 기존 코드에서는 passwordcheck.so load 여부 검사, 현재 평가 기준과 상이하므로 확인 필요
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
        # VENDOR-EDIT(bug): DBM-009 극성 수정 — KNOWN_BUGS §R-PG009.
        #   원본: int(value) <= 900 → 취약 (거꾸로: 300초=15분이내 종료=양호인데 취약 오판).
        #   수정: 값==0(비활성) 또는 >900(너무 김) → 취약. (idle_in_transaction만 커버)
        self.dbm_process_data(result_key, 'DBM-009', [
            lambda datum: 'idle_in_transaction_session_timeout' in datum['setting_name'] and (int(datum['value']) == 0 or int(datum['value']) > 900)
        ])
    
    def dbm_011(self, result_key='DBM-011'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: '로드된 라이브러리가 없습니다.' in str(datum)
        ])
    
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
        
    def dbm_019(self, result_key='DBM-019'):
        self.dbm_result[result_key] = []
        
    def dbm_020(self, result_key='DBM-020'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-020', [
            lambda datum: datum['rolname'] not in self.exception[result_key]['rolname']
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
        
        file_640_list = ['/pg_hba.conf', '/postgresql.conf', '/pg_ident.conf']
        
        try:
            if 'DBM-022' in self.data:
                for datum in self.data['DBM-022']['RESULT']:
                    dbm_022_result = datum['output']
                    matches = pattern.finditer(dbm_022_result)
                    
                    for m in matches:
                        if m.group(1) != "----------":
                            file_perm = m.group(1)
                            file_entry = m.group(0).lower()
                                    
                            if any(k in file_entry for k in file_640_list):
                                if get_check_file_perm(file_perm, 1, r"w|x") or get_check_file_perm(file_perm, 2, r"r|w|x"):
                                    self.dbm_result[result_key].append(file_entry)
                                    
        except Exception as e:
            print("[!] Exception Occurred PostgreSQL DBM-022: " + str(e))
            
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
        
    def dbm_025(self, result_key='DBM-025'):
        self.dbm_result[result_key] = []
        
        def compare_eos_date(ver_str, today):
            cur_ver = ver_str.split(' ')[1]
            cur_ver_arr = cur_ver.split('.')
            cur_major_version = cur_ver_arr[0]
            
            eos_list = self.rules[result_key]['version']
            
            if cur_major_version == '10':
                eos_date = eos_list['10']
            elif cur_major_version == '11':
                eos_date = eos_list['11']
            elif cur_major_version == '12':
                eos_date = eos_list['12']
            elif cur_major_version == '13':
                eos_date = eos_list['13']
            elif cur_major_version == '14':
                eos_date = eos_list['14']
            elif cur_major_version == '15':
                eos_date = eos_list['15']
            elif cur_major_version == '16':
                eos_date = eos_list['16']
            elif cur_major_version == '17':
                eos_date = eos_list['17']
            else:
                return True
            
            eos_date_p = datetime.strptime(eos_date, "%Y-%m-%d")
            return today > eos_date_p
        
        self.dbm_process_data(result_key, 'DBM-025', [
            lambda datum: compare_eos_date(datum['version'], self.today)
        ])
        
    def dbm_026(self, result_key='DBM-026'):
        # 데이터베이스 구동 계정의 umask 설정 미흡
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-026', [
            lambda datum: any(sub in str(int(datum['output'])%100) for sub in ["3", "4", "5"])
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