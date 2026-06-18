import re
from datetime import datetime
from dateutil.relativedelta import relativedelta
from packaging import version

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

class OracleAnalysis:
    def __init__(self, config, data={}):
        self.today = datetime.now()
        self.exception = config['exception']
        self.rules = config['rules']
        self.data = data
        self.result = {}
        self.dbm_result = {}
        
        # DBM-001
        self.john = []
        self.hashcat_112 = []  # 11+S
        self.hashcat_3100 = []  # 7+H
        self.hashcat_12300 = []  # 12+T
        self.hashcat_plain = []
        
    @property
    def run(self):
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
        self.dbm_014()
        self.dbm_015()
        self.dbm_016()  # sql secure patch
        self.dbm_017()
        self.dbm_019()
        self.dbm_020()
        self.dbm_022()  # permission
        self.dbm_024()
        self.dbm_025()  # sql version get version first and use it to DBM-012
        self.dbm_026()  # umask
        self.dbm_028()
        self.dbm_029()
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
            print(f"[!] Exception Occurred Oracle {result_key}: {str(e)}")

    def dbm_001(self, result_key='DBM-001'):
        self.dbm_result[result_key] = []
        
        def parse_spare4(spare4: str):
            parts = {"S": None, "H": None, "T": None}
            for tag, hx in re.findall(r'(?i)\b([SHT])\s*:\s*([0-9A-F]+)\b', spare4 or ""):
                parts[tag.upper()] = hx.upper()

            s, t = parts["S"], parts["T"]
            s_hash = s[:40] if s and len(s) >= 40 else (s or None)
            s_salt = s[40:60] if s and len(s) >= 60 else None
            t_ver  = t[:-32] if t and len(t) > 32 else (t or None)
            t_avd  = t[-32:] if t and len(t) >= 32 else None
            return {
                "S": {"raw": s, "hash": s_hash, "salt": s_salt},
                "H": {"raw": parts["H"]},
                "T": {"raw": t, "verifier": t_ver, "auth_vfr_data": t_avd},
            }
            
        try:
            if 'DBM-001' in self.data:
                for datum in self.data['DBM-001'].get('RESULT', []):
                    name = datum['name']
                    spare4 = datum['spare4']
                    password = datum['password']
                    
                    if spare4 != '':
                        parsed_spare4 = parse_spare4(spare4)
                        spare4_s = parsed_spare4['S']['raw']
                        spare4_t = parsed_spare4['T']['raw']
                         
                        if spare4_s != None:
                            self.john.append(name + ':' + spare4_s)
                            self.hashcat_112.append(name + ":" + parsed_spare4['S']['hash'] + ':' + parsed_spare4['S']['salt'])
                        elif spare4_t != None:
                            self.hashcat_12300.append(name + ":" + spare4_t)
                        
                    if password != '': # 10G(구버전) 비밀번호 검증자 존재, 반드시 16자리 hex 문자열, 3100으로 crack 시도
                        if len(password) == 16:
                            self.hashcat_3100.append(name + ':' + password + ':' + name)
                        else:
                            self.hashcat_plain.append(datum)
                
                if self.hashcat_112:
                    self.dbm_result[result_key].append(self.hashcat_112)
                if self.hashcat_3100:
                    self.dbm_result[result_key].append(self.hashcat_3100)
                if self.hashcat_12300:
                    self.dbm_result[result_key].append(self.hashcat_12300)
                if self.hashcat_plain:
                    self.dbm_result[result_key].append(self.hashcat_plain)
                    
        except Exception as e:
            print("[!] Exception Occurred oracle DBM-001: " + str(e))
            
    # oracle expiry_date 기본 출력 형식 가변화가 가능하다. -> 우선 형식 두 가지 중 하나 선택 가능하도록 수정
    def dbm_003(self, result_key='DBM-003'):
        self.dbm_result[result_key] = []
        limit_modify_date = self.today - relativedelta(months=self.rules[result_key]['date_range'])
        
        _DATE_FORMATS = (
            '%d-%b-%y',            # 예: 22-SEP-25  (Python은 %y=00~68→2000~2068, 69~99→1900~1999)
            '%Y-%m-%d',   # 예: 2025-09-22
        )
        
        def parse_expiry_date(s):
            if s is None:
                return None
            s = str(s).strip()
            if not s:
                return None
            for fmt in _DATE_FORMATS:
                try:
                    return datetime.strptime(s, fmt)
                except ValueError:
                    pass
                
        def expiry_before_limit(datum, limit_modify_date):
            d = parse_expiry_date(str(datum['expiry_date']))
            return d is not None and limit_modify_date > d
        
        self.dbm_process_data(result_key, 'DBM-003', [
            lambda datum: datum['last_login'] in self.rules[result_key]['last_login'],
            lambda datum: datum['account_status'] not in self.exception[result_key]['account_status'],
            lambda datum: datum['expiry_date'],
            lambda datum: expiry_before_limit(datum, limit_modify_date)
        ])
        self.dbm_process_data(result_key, 'DBM-003_11g', [
            lambda datum: datum['last_login'] in self.rules[result_key]['last_login'],
            lambda datum: datum['account_status'] not in self.exception[result_key]['account_status'],
            lambda datum: datum['expiry_date'],
            lambda datum: expiry_before_limit(datum, limit_modify_date)
        ])
        self.dbm_process_data(result_key, 'DBM-003_12c', [
            lambda datum: datum['last_login'] in self.rules[result_key]['last_login'],
            lambda datum: datum['account_status'] not in self.exception[result_key]['account_status'],
            lambda datum: datum['expiry_date'],
            lambda datum: expiry_before_limit(datum, limit_modify_date)
        ])
        
    def dbm_004(self, result_key='DBM-004'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-004_1', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee']
        ])
        self.dbm_process_data(result_key, 'DBM-004_2', [
            lambda datum: datum['username'] not in self.exception[result_key]['username']
        ])
        self.dbm_process_data(result_key, 'DBM-004_3', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee']
        ])
        
    def dbm_005(self, result_key='DBM-005'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-005', [
            lambda datum: True
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
            lambda datum: datum['profile'] not in self.exception[result_key]['profile']
        ])
        
    def dbm_008(self, result_key='DBM-008'):
        self.dbm_result[result_key] = []
        limit_modify_date = self.today - relativedelta(months=self.rules[result_key]['date_range'])
        self.dbm_process_data(result_key, 'DBM-008_1', [
            lambda datum: datum['name'] not in self.exception[result_key]['name'],
            lambda datum: limit_modify_date > datetime.strptime(str(datum['ptime']), '%d-%b-%y')
        ])
        # self.dbm_process_data(result_key, 'DBM-008_2', [
        #     lambda datum: datum['profile'] not in self.exception['DBM-008']['profile'],
        #     lambda datum: datum['limit'] in self.rules['DBM-008']['limit']
        # ])
        
    def dbm_009(self, result_key='DBM-009'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-009', [
            lambda datum: datum['profile'] not in self.exception['DBM-009']['profile'],
            lambda datum: datum['resource_name'] in self.rules['DBM-009']['resource_name'],
            lambda datum: datum['limit'] in self.rules['DBM-009']['limit']
        ])
        
    def dbm_011(self, result_key='DBM-011'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: datum['value'].upper() == 'NONE'
        ])
    
    # xml 결과로 출력
    def dbm_012(self, result_key='DBM-012'):
        self.dbm_result[result_key] = []
    
    # xml 결과로 출력
    def dbm_013(self, result_key='DBM-013'):
        # ⚠️ STUB — [lambda datum: True] 과탐(무조건 취약). 결정론 부적합.
        # DET_SOURCE.yaml: oracle DBM-013 = STUB → gate(handled=False) → LLM 라우팅.
        # 이 코드는 gate에 막혀 실행되지 않음. 혼란 방지를 위해 주석 유지.
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-013', [
            lambda datum: True  # 미사용(STUB, gate 차단) — 과탐 위험으로 결정론 비활성
        ])
        
    def dbm_014(self, result_key='DBM-014'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-014', [
            lambda datum: datum['value'].upper() != self.rules[result_key]['value']
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
            lambda datum: datum['owner'] not in self.exception[result_key]['owner'],
            lambda datum: datum['TABLE_NAME'] not in self.exception[result_key]['TABLE_NAME']
        ])
    
    def dbm_016(self, result_key='DBM-016'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-016_11g', [
            lambda datum: datum['version'],
            lambda datum: version.parse(re.sub(re.compile(r'[^\d.]'), '', datum['version'])) < version.parse(
                self.rules[result_key]['version']['11g'])
        ])
        self.dbm_process_data(result_key, 'DBM-016_12c', [
            lambda datum: datum['version'],
            lambda datum: version.parse(re.sub(re.compile(r'[^\d.]'), '', datum['version'])) < version.parse(
                self.rules[result_key]['version']['12c'])
        ])
        self.dbm_process_data(result_key, 'DBM-016_19c', [
            lambda datum: datum['version'],
            lambda datum: version.parse(re.sub(re.compile(r'[^\d.]'), '', datum['version'])) < version.parse(
                self.rules[result_key]['version']['19c'])
        ])
        
    def dbm_017(self, result_key='DBM-017'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-017', [
            lambda datum: datum['grantee'] not in self.exception['DBM-017']['grantee'],
            lambda datum: datum['privilege'] not in self.exception['DBM-017']['privilege'],
            lambda datum: datum['TABLE_NAME'] not in self.exception['DBM-017']['TABLE_NAME']
        ])
        
    def dbm_019(self, result_key='DBM-019'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-019', [
            lambda datum: datum['limit'] == 'UNLIMITED',
            lambda datum: datum['username'] not in self.exception['DBM-019']['username'],
            lambda datum: datum['profile'] not in self.exception['DBM-019']['profile']
        ])

    def dbm_020(self, result_key='DBM-020'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-020_11g', [
            lambda datum: datum['account_status'] == 'OPEN',
            lambda datum: datum['username'] not in self.exception['DBM-020']['username']
        ])
        self.dbm_process_data(result_key, 'DBM-020_12c', [
            lambda datum: datum['account_status'] == 'OPEN',
            lambda datum: datum['username'] not in self.exception['DBM-020']['username']
        ])
    
    # xml 결과로 출력
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
        
        file_755_list = ['/bin/oracle', '/bin/sqlplus', '/bin/sqlldr', '/bin/sqlload', 
                         '/bin/proc', '/bin/oraenv', '/bin/oerr', '/bin/exp', '/bin/imp', 
                         '/bin/tkprof', '/bin/tnsping', '/bin/wrap']
        
        file_644_list = ['/network/admin/listener.ora', '/network/admin/sqlnet.ora', 
                         '/network/admin/tnsnames.ora', '/network/admin/protocol.ora']
        
        file_640_list = ['/dbs/init.ora']
        
        try:
            if 'DBM-022' in self.data:
                for datum in self.data['DBM-022']['RESULT']:
                    dbm_022_result = datum['output']
                    matches = pattern.finditer(dbm_022_result)
                    
                    for m in matches:
                        if m.group(1) != "----------":
                            file_perm = m.group(1)
                            file_entry = m.group(0).lower()
                            
                            if any(k in file_entry for k in file_755_list):
                                if get_check_file_perm(file_perm, 1, r"w") or get_check_file_perm(file_perm, 2, r"w"):
                                    self.dbm_result[result_key].append(file_entry)
                                
                            elif any(k in file_entry for k in file_644_list):
                                if get_check_file_perm(file_perm, 1, r"w|x") or get_check_file_perm(file_perm, 2, r"w|x"):
                                    self.dbm_result[result_key].append(file_entry)
                                    
                            elif any(k in file_entry for k in file_640_list):
                                if get_check_file_perm(file_perm, 1, r"w|x") or get_check_file_perm(file_perm, 2, r"r|w|x"):
                                    self.dbm_result[result_key].append(file_entry)
                            
        except Exception as e:
            print("[!] Exception Occurred Oracle DBM-022: " + str(e))
            
    def dbm_024(self, result_key='DBM-024'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-024_1', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee']
        ])
        self.dbm_process_data(result_key, 'DBM-024_2', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee']
        ])
        self.dbm_process_data(result_key, 'DBM-024_3', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee']
        ])
        
    def dbm_025(self, result_key='DBM-025'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-025', [
            lambda datum: version.parse(re.sub(re.compile(r'[^\d.]'), '', datum['version_info'])) < version.parse(self.rules[result_key]['version'])
        ])

    # xml 결과로 출력
    def dbm_026(self, result_key='DBM-026'):
        # 데이터베이스 구동 계정의 umask 설정 미흡
        # VENDOR-EDIT(c): R-026 umask 판정 수정 (2026-06-18)
        self.dbm_result[result_key] = []

        self.dbm_process_data(result_key, 'DBM-026', [
            lambda datum: _umask_is_violation(datum.get('output', ''))
        ])
        
    def dbm_028(self, result_key='DBM-028'):
        # 데이터가 너무 많아 봐야하는 부분만 rules에 추가
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-028_1', [
            lambda datum: datum['owner'] in self.rules[result_key]['owner']
        ])
        self.dbm_process_data(result_key, 'DBM-028_2', [
            lambda datum: datum['grantee'] in self.rules[result_key]['grantee'],
        ])
        
    def dbm_029(self, result_key='DBM-029'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-029', [
            lambda datum: datum['value'] in self.rules['DBM-029']['value']
        ])

    def dbm_030(self, result_key='DBM-030'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-030_1', [
            lambda datum: datum['owner'] not in self.exception['DBM-030']['owner']
        ])
        self.dbm_process_data(result_key, 'DBM-030_2', [
            lambda datum: datum['owner'] not in self.exception['DBM-030']['owner']
        ])