[AWS]
1. 사전 준비
  - 점검 대상 계정(IAM 사용자)에 'ReadOnlyAccess' 관리형 정책 연결
  - 계정별 Access Key ID, Secret Access Key 확인
    * 계정 분리 정책으로 인해 각 운영 계정에서 개별적으로 실행 필요

2. 스크립트 실행 방법
  - 전달된 스크립트 파일을 AWS CLI가 설치된 운영 단말로 이동
  - 스크립트에 실행 권한 부여
    > chmod +x fsec_aws_script.sh
  - 운영계정별로 실행 후 Access Key ID, Secret Access Key 입력
    > ./fsec_aws_script.sh
    > AWS Access Key ID: <Access Key ID 입력>
    > AWS Secret Access Key: <Secret Access Key 입력>
    > Default Region Name [ap-northeast-2]: <Region 입력>

3. 스크립트 결과물
  - 스크립트 실행 디렉토리에 운영계정별 결과파일 생성
    : aws_report_YYYYMMDD_HHMMSS_<account-alias>.xml

4. 주의사항
  - 스크립트 실행 후 점검 대상 계정에 연결된 'ReadOnlyAccess' 관리형 정책 연결 해제
  - 스크립트 실행을 위해 입력된 Access Key 정보가 유출되지 않도록 주의


[Azure]
1. 사전 준비
  - 점검 대상 구독에 'Reader' 역할을 가진 서비스 주체(Service Principal) 생성
  - 구독별 Client ID, Client Secret, Tenant ID, Subscription ID 확인
    > az ad sp create-for-rbac --name "Security-Audit-SP-<YYYYMMDD>" --role Reader --scopes /subscriptions/<SUBSCRIPTION_ID>
      * 구독 분리 정책으로 인해 각 구독에서 개별적으로 실행 필요
  - (Bastion 사용 시) Azure CLI 확장 설치 필요
    1) 인터넷 연결된 별도 환경에서 확장 설치
      > az extension add -n bastion --upgrade
    2) 생성된 확장 파일 디렉토리(~/.azure/cliextensions/bastion)를 검토 후 대상 시스템의 동일 경로에 반영

2. 스크립트 실행 방법
  - 전달된 스크립트 파일을 Azure CLI가 설치된 운영 단말로 이동
  - 스크립트에 실행 권한 부여
    > chmod +x fsec_azure_script.sh
  - 구독별로 실행 후 Client ID, Client Secret, Tenant ID, Subscription ID 입력
    > ./fsec_azure_script.sh
    > Client ID: <Client ID 입력>
    > Client Secret: <Client Secret 입력>
    > Tenant ID: <Tenant ID 입력>
    > Subscription ID: <Subscription ID 입력>

3. 스크립트 결과물
  - 스크립트 실행 디렉토리에 구독별 결과파일 생성
    : azure_report_YYYYMMDD_HHMMSS_<sp-name>.xml

4. 주의사항
  - 스크립트 실행 후 생성한 서비스 주체 삭제
    > az ad sp delete --id <CLIENT_ID>
  - 스크립트 실행을 위해 입력된 인증 정보가 유출되지 않도록 주의
