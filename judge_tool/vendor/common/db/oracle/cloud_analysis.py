import re
from datetime import datetime
from dateutil.relativedelta import relativedelta
from packaging import version

class OracleCloudAnalysis:
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
        print("[*] Oracle Cloud Analysis Start")
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
        self.dbm_014()
        self.dbm_015()
        self.dbm_016()
        self.dbm_017()
        self.dbm_019()
        self.dbm_020()
        self.dbm_024()
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

    # 원본에 복잡한 로직이 있는데 그거 가져다가 쓰면 되려나
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

    # oracle expiry_date 기본 출력 형식이 어떻게 되어있지?
    # 출력 형식 가변화가 가능하다. -> 우선 형식 두 가지 중 하나 선택 가능하도록 수정
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
        self.dbm_process_data(result_key, 'DBM-005', [lambda datum: True])

    def dbm_006(self, result_key='DBM-006'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-006', [
            lambda datum: datum['profile'] not in self.exception[result_key]['profile'],
            lambda datum: datum['resource_name'] in self.rules[result_key]['resource_name'],
            lambda datum: datum['limit'] in self.rules[result_key]['limit']
        ])

    # 7-1에 대한 점검만 이루어지는 중, 7-2는 어떤 용도인지 문의
    def dbm_007(self, result_key='DBM-007'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-007_1', [
            lambda datum: datum['limit'] not in self.exception[result_key]['limit'],
            lambda datum: datum['profile'] not in self.exception[result_key]['profile']
        ])

    # 현재 ptime만 체크하고 있는데 (8-1), 8-2 세팅 점검이 필요하지 않은지 살펴볼 필요 있음
    def dbm_008(self, result_key='DBM-008'):
        self.dbm_result[result_key] = []
        limit_modify_date = self.today - relativedelta(months=self.rules[result_key]['date_range'])
        self.dbm_process_data(result_key, 'DBM-008_1', [
            lambda datum: datum['name'] not in self.exception[result_key]['name'],
            lambda datum: limit_modify_date > datetime.strptime(str(datum['ptime']), '%d-%b-%y')
        ])
        
    def dbm_009(self, result_key='DBM-009'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-009', [
            lambda datum: datum['profile'] not in self.exception[result_key]['profile'],
            lambda datum: datum['resource_name'] in self.rules[result_key]['resource_name'],
            lambda datum: datum['limit'] in self.rules[result_key]['limit']
        ])
        
    def dbm_011(self, result_key='DBM-011'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-011', [
            lambda datum: datum['value'].upper() == 'NONE'
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

    # 현재 스크립트 출력 결과에서 12c 부분에 19c 관련 정보가 들어가 있어서 정상적인 버전 비교 불가, 수정 필요
    # 또한 기존 스크립트와는 달리 patch_id를 기준으로 결과값이 도출되는데 최신 데이터를 어디서 받을 수 있을 지 논의 필요\
    # 우선 전체 주석 처리하고 추후 수정하는 방향으로
    def dbm_016(self, result_key='DBM-016'):
        self.dbm_result[result_key] = []
        
        # VERSION_RE = re.compile(r'\d+(?:\.\d+)+')
        # def extract_version(s: str, default: str = "") -> str:
        #     m = VERSION_RE.search(s)
        #     return m.group(0) if m else default
        
        # self.dbm_process_data(result_key, 'DBM-016_11g', [
        #     lambda datum: datum['version'],
        #     lambda datum: version.parse(re.sub(re.compile(r'[^\d.]'), '', datum['version'])) 
        #                 < version.parse(self.rules[result_key]['version']['11g'])
        # ])
        # self.dbm_process_data(result_key, 'DBM-016_12c', [
        #     lambda datum: datum['version'],
        #     lambda datum: version.parse(re.sub(re.compile(r'[^\d.]'), '', datum['version'])) < version.parse(
        #         self.rules[result_key]['version']['12c'])
        # ])
        # self.dbm_process_data(result_key, 'DBM-016_19c', [
        #     lambda datum: datum['version'],
        #     lambda datum: version.parse(re.sub(re.compile(r'[^\d.]'), '', datum['version'])) < version.parse(
        #         self.rules[result_key]['version']['19c'])
        # ])

    def dbm_017(self, result_key='DBM-017'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-017', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee'],
            lambda datum: datum['privilege'] not in self.exception[result_key]['privilege'],
            lambda datum: datum['TABLE_NAME'] not in self.exception[result_key]['TABLE_NAME']
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
        self.dbm_process_data(result_key, 'DBM-020_11g', [
            lambda datum: datum['account_status'] == 'OPEN',
            lambda datum: datum['username'] not in self.exception[result_key]['username']
        ])
        self.dbm_process_data(result_key, 'DBM-020_12c', [
            lambda datum: datum['account_status'] == 'OPEN',
            lambda datum: datum['username'] not in self.exception[result_key]['username']
        ])
        
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
            lambda datum: datum['value'] in self.rules[result_key]['value']
        ])

    def dbm_030(self, result_key='DBM-030'):
        self.dbm_result[result_key] = []
        self.dbm_process_data(result_key, 'DBM-030_1', [
            lambda datum: datum['owner'] not in self.exception[result_key]['owner']
        ])
        self.dbm_process_data(result_key, 'DBM-030_2', [
            lambda datum: datum['owner'] not in self.exception[result_key]['owner']
        ])
