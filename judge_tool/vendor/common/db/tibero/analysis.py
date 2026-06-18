from datetime import datetime
import re

# VENDOR-EDIT(c): R-026 umask 헬퍼 (2026-06-18)
_UMASK_TOKEN_RE = re.compile(r'\b(0*[0-7]{1,4})\b')

def _umask_is_violation(output: str):
    """umask output 문자열에서 8진수 umask를 파싱해 위반(True)/양호(False)/파싱불가(None) 반환."""
    if not isinstance(output, str):
        return None
    s = output.strip()
    tokens = _UMASK_TOKEN_RE.findall(s)
    if not tokens:
        return None
    raw = tokens[-1].lstrip('0') or '0'
    padded = raw.zfill(3)[-3:]
    try:
        group_digit = int(padded[1])
        other_digit = int(padded[2])
    except (ValueError, IndexError):
        return None
    return not (group_digit >= 2 and other_digit >= 2)


'''
테스트 시스템 : docker pull dimensigon/tibero
'''

class TiberoAnalysis:
    def __init__(self, config, data={}):
        self.today = datetime.now()
        self.exception = config['exception']
        self.rules = config['rules']
        self.data = data
        self.result = {}
        self.dbm_result = {}
        
    @property
    def run(self):
        print("[*] Tibero Analysis Start")
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
        self.dbm_030()
        
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
            print(f"[!] Exception Occurred Tibero {result_key}: {str(e)}")
    
    def dbm_001(self, result_key='DBM-001'):
        self.dbm_result[result_key] = []
    
    # 기존에는 expiry_date 관련 항목이 있어도 보질 않는데
    def dbm_003(self, result_key='DBM-003'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-003', [
            lambda datum: datum['username'] not in self.exception[result_key]['username'],
            lambda datum: datum['account_status'] not in self.exception[result_key]['account_status']
        ])
        self.dbm_process_data(result_key, 'DBM-003', [
            lambda datum: datum['expiry_date'] == ''
        ])
        
    def dbm_004(self, result_key='DBM-004'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-004_1', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee'],
            lambda datum: datum['admin_option'] == "YES"
        ])
        self.dbm_process_data(result_key, 'DBM-004_2', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee']
        ])
        
        # 기존 코드에서 주석 처리된 부분 포팅
        # self.dbm_process_data(result_key, 'DBM-004_3', [
        #     lambda datum: datum['grantee'] not in self.exception[result_key]['grantee']
        # ])
        # self.dbm_process_data(result_key, 'DBM-004_4', [
        #     lambda datum: datum['grantee'] not in self.exception[result_key]['grantee']
        # ])
        
    def dbm_005(self, result_key='DBM-005'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-005', [
            lambda datum: datum['table_name'] not in self.exception[result_key]['table_name']
        ])
        
    def dbm_006(self, result_key='DBM-006'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-006', [
            lambda datum: datum['profile'] not in self.exception[result_key]['profile'],
            lambda datum: datum['resource_name'] in self.rules[result_key]['resource_name'],
            lambda datum: datum['limit'] in self.rules[result_key]['limit']
        ])
        
    def dbm_007(self, result_key='DBM-007'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-007_1', [
            lambda datum: datum['limit'] not in self.exception[result_key]['limit'],
            lambda datum: datum['profile'] not in self.exception[result_key]['profile'],
            lambda datum: datum['limit'] in self.rules[result_key]['limit']
        ])
        
    def dbm_008(self, result_key='DBM-008'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-008', [
            lambda datum: datum['username'] not in self.exception[result_key]['username'],
            lambda datum: datum['profile'] not in self.exception[result_key]['profile'],
            lambda datum: datum['limit'] in self.rules[result_key]['limit']
        ])
        
    def dbm_009(self, result_key='DBM-009'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-009', [
            lambda datum: datum['name'] not in self.exception[result_key]['name'],
            lambda datum: int(datum['value']) < 900
        ])
        
    def dbm_011(self, result_key='DBM-011'):
        self.dbm_result[result_key] = []
        cnt = 0
        
        try:
            if 'DBM-011' in self.data:
                for datum in self.data['DBM-011'].get('RESULT', []):
                    if datum['value'].upper() != 'NONE':
                        cnt += 1
                if cnt == 0:
                    self.dbm_result[result_key].append(self.rules[result_key]['default'])
                        
        except Exception as e:
            print(f"[!] Exception Occurred Tibero {result_key}: {str(e)}")
            
    def dbm_013(self, result_key='DBM-013'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-013', [
            lambda datum: datum['value'] == ''
        ])
    
    def dbm_015(self, result_key='DBM-015'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-015_1', [
            lambda datum: True
        ])
        self.dbm_process_data(result_key, 'DBM-015_2', [
            lambda datum: True
        ])
        self.dbm_process_data(result_key, 'DBM-015_3', [
            lambda datum: True
        ])
    
    def dbm_016(self, result_key='DBM-016'):
        self.dbm_result[result_key] = []
        
    def dbm_017(self, result_key='DBM-017'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-017', [
            lambda datum: True
        ])
    
    def dbm_019(self, result_key='DBM-019'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-019', [
            lambda datum: datum['limit'] == 'UNLIMITED',
            lambda datum: datum['username'] not in self.exception[result_key]['username'],
            lambda datum: datum['profile'] not in self.exception[result_key]['profile']
        ])
    
    def dbm_020(self, result_key='DBM-020'):
        self.dbm_result[result_key] = []
        
    def dbm_022(self, result_key='DBM-022'):
        self.dbm_result[result_key] = []
        pattern = re.compile(r"(^[drwxstDRWXSTlL\-]{10}).*", re.MULTILINE | re.IGNORECASE)
        
        def get_check_file_perm(file_perm, index, permission):
            # file_perm을 공백으로 나누어 리스트로 만듦
            str_arr = file_perm.strip().split()
            first_str = str_arr[0]

            # 첫 번째 문자열이 특정 패턴으로 시작하는지 확인 (DateTokenConverter.CONVERTER_KEY처럼 처리)
            if len(first_str) > 0 and first_str.lower().startswith(("d", "l")):  # R-022L: 디렉터리(d)·심볼릭링크(l) 제외 — 심링크 권한(lrwxrwxrwx)은 타깃과 무관, 거짓취약 방지
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
        
        file_700_list = ['/bin/tbboot', '/bin/tbsvr', '/bin/tblistener', '/bin/tbcm', '/bin/tbcmbin', '/bin/tbcmobs',
                         '/bin/oerr', '/bin/tbctl', '/bin/tbinfo', '/bin/tkprof', '/bin/tbupdater']
        
        try:
            if 'DBM-022' in self.data:
                for datum in self.data['DBM-022']['RESULT']:
                    dbm_022_result = datum['output']
                    matches = pattern.finditer(dbm_022_result)
                    
                    for m in matches:
                        if m.group(1) != "----------":
                            file_perm = m.group(1)
                            file_entry = m.group(0).lower()
                            
                            if any(k in file_entry for k in file_700_list):
                                if get_check_file_perm(file_perm, 1, r"r|w|x") or get_check_file_perm(file_perm, 2, r"r|w|x"):
                                    self.dbm_result[result_key].append(file_entry)
                            
        except Exception as e:
            print("[!] Exception Occurred Tibero DBM-022: " + str(e))
    
    def dbm_024(self, result_key='DBM-024'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-024_1', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee'],
            lambda datum: datum['ADMIN_OPTION'] == "YES"
        ])
        self.dbm_process_data(result_key, 'DBM-024_2', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee'],
            lambda datum: datum['ADMIN_OPTION'] == "YES"
        ])
        self.dbm_process_data(result_key, 'DBM-024_3', [
            lambda datum: True
        ])
    
    def dbm_025(self, result_key='DBM-025'):
        self.dbm_result[result_key] = []
        
    def dbm_026(self, result_key='DBM-026'):
        # 데이터베이스 구동 계정의 umask 설정 미흡
        # VENDOR-EDIT(c): R-026 umask 판정 수정 (2026-06-18)
        self.dbm_result[result_key] = []

        self.dbm_process_data(result_key, 'DBM-026', [
            lambda datum: _umask_is_violation(datum.get('output', ''))
        ])
    
    def dbm_028(self, result_key='DBM-028'):
        self.dbm_result[result_key] = []
        self.dbm_result[result_key].append(self.rules[result_key]['default'])
        
        self.dbm_process_data(result_key, 'DBM-028', [
            lambda datum: datum['owner'] not in self.exception[result_key]['owner']
        ])
    
    def dbm_030(self, result_key='DBM-030'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-030_1', [
            lambda datum: datum['table'] == "AUD$",
            lambda datum: datum['owner'] != "SYS"
        ])
        self.dbm_process_data(result_key, 'DBM-030_2', [
            lambda datum: datum['table'] == "AUD$",
            lambda datum: datum['owner'] != "SYS"
        ])