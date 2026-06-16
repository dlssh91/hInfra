from datetime import datetime
from dateutil.relativedelta import relativedelta
import re

class MSSQLCloudAnalysis:
    def __init__(self, config, data={}):
        self.today = datetime.now()
        self.exception = config['exception']
        self.rules = config['rules']
        self.data = data
        self.result = {}
        self.dbm_result = {}
        
    @property
    def run(self):
        print("[*] MSSQL Cloud Analysis Start")
        self.dbm_result = {}
        
        self.dbm_003()  # 6개월 이상 수정이력이 없으면 취약 -> 완료
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
        self.dbm_020()
        self.dbm_022()
        self.dbm_024()
        self.dbm_028()
        
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
        
    def dbm_003(self, result_key='DBM-003'):
        self.dbm_result[result_key] = []
        
        def comp_modify_date(date_str):
            modify_lim_date = self.rules[result_key]['modify_date'] # 기본 설정값 6개월, 필요시 config-rules-DBM-003 항목 수정
            proc_date_str = '-'.join(date_str.split(' ')[:3])
            
            try:
                mod_date = datetime.strptime(proc_date_str, '%b-%d-%Y')
                delta = relativedelta(self.today, mod_date)
                
                relative_month = 0
                if delta.years > 0:
                    relative_month = delta.years * 12
                relative_month = relative_month + delta.months
                
                return relative_month > int(modify_lim_date)
            except:
                return True
        
        self.dbm_process_data(result_key, 'DBM-003_1', [
            lambda datum: datum['is_disabled'] == '0',
            lambda datum: comp_modify_date(datum['modify_date']),
        ])
        
        # DBM-003_2
        
    def dbm_004(self, result_key='DBM-004'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-004', [
            lambda datum: datum['sysadmin'] != '0' or datum['serveradmin'] != '0' or datum['securityadmin'] != '0',
            lambda datum: datum['name'] != 'sa',
            lambda datum: '##MS' not in datum['name'],
            lambda datum: 'BUILTIN' not in datum['name'],
            lambda datum: 'NT AUTHORITY' not in datum['name'],
        ])
        
    def dbm_005(self, result_key='DBM-005'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-005', [
            lambda datum: datum['sample'] is not None,
        ])
        
    def dbm_006(self, result_key='DBM-006'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-006', [
            lambda datum: datum['is_policy_checked'] == "0",
        ])
        
    def dbm_007(self, result_key='DBM-007'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-007', [
            lambda datum: datum['is_policy_checked'] == "0",
        ])
        
    def dbm_008(self, result_key='DBM-008'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-008', [
            lambda datum: int(datum['days_after_changed']) > 90,
        ])
        
    # last_request_time을 내부 규정과 수동으로 비교
    def dbm_009(self, result_key='DBM-009'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-009', [
            lambda datum: True,
        ])
        
    def dbm_011(self, result_key='DBM-011'):
        self.dbm_result[result_key] = []
        
    def dbm_013(self, result_key='DBM-013'):
        self.dbm_result[result_key] = []
    
    def dbm_015(self, result_key='DBM-015'):
        self.dbm_result[result_key] = []

        self.dbm_process_data(result_key, 'DBM-015', [
            lambda datum: datum['permission_name'] not in self.exception[result_key]['permission_name'],
            lambda datum: datum['permission_name'] in self.rules[result_key]['permission_name'],
        ])
        
    def dbm_016(self, result_key='DBM-016'):
        self.dbm_result[result_key] = []
        
        def check_latest_version(ver_str):
            pattern = r"(\d+\.\d+\.\d+\.\d+)"
            ver_match = re.search(pattern, ver_str)
            
            if ver_match:
                current_patch_version = ver_match.group(1)
                current_patch_version = current_patch_version.split('.')
            
                latest_patch_ver = self.rules[result_key]['version']
                if current_patch_version[0] == '11':
                    latest_patch_ver = latest_patch_ver['2012']
                elif current_patch_version[0] == '12':
                    latest_patch_ver = latest_patch_ver['2014']
                elif current_patch_version[0] == '13':
                    latest_patch_ver = latest_patch_ver['2016']
                elif current_patch_version[0] == '14':
                    latest_patch_ver = latest_patch_ver['2017']
                elif current_patch_version[0] == '15':
                    latest_patch_ver = latest_patch_ver['2019']  
                elif current_patch_version[0] == '16':
                    latest_patch_ver = latest_patch_ver['2022']
                
                latest_patch_ver = latest_patch_ver.split('.')

                return int(current_patch_version[2]) < int(latest_patch_ver[2])
            
            return True
        
        self.dbm_process_data(result_key, 'DBM-016', [
            lambda datum: check_latest_version(datum['version_info']),
        ])
        
    def dbm_017(self, result_key='DBM-017'):
        self.dbm_result[result_key] = []
        
    def dbm_020(self, result_key='DBM-020'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-020', [
            lambda datum: datum['is_disabled'] == '0',
            lambda datum: datum['name'] not in self.exception[result_key]['name'],
        ])
    
    def dbm_022(self, result_key='DBM-022'):
        self.dbm_result[result_key] = []
        
    def dbm_024(self, result_key='DBM-024'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-024', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee'],
            lambda datum: datum['grantee'] in self.rules[result_key]['grantee'],
        ])
    
    def dbm_028(self, result_key='DBM-028'):
        self.dbm_result[result_key] = []
        
        self.dbm_process_data(result_key, 'DBM-028', [
            lambda datum: datum['grantee'] not in self.exception[result_key]['grantee'],
            lambda datum: datum['grantee'] in self.rules[result_key]['grantee'],
        ])