# Wazuh 경보를 Endpoint EDR 콘솔로 받기

사내에 함께 운영하는 **Wazuh(오픈소스 EDR)** 의 경보를 이 콘솔의 **경보 화면**에서 같이 보기 위한 단방향 연동입니다.
Wazuh 가 경보를 수집 서버의 웹훅(`POST /v1/wazuh`)으로 보내면, `alerts` 테이블에 `source='wazuh'` 로 저장되어
기존 경보·인시던트·알림 연동(슬랙·이메일)과 같은 흐름을 탑니다. **받기만 하며 Wazuh·PC 를 제어하지 않습니다.**

## 1. 수집 서버 쪽 설정 (`.env`)

```
WAZUH_WEBHOOK_SECRET=<충분히 긴 무작위 문자열>   # Wazuh 가 보낼 때 Authorization: Bearer 로 쓰는 공유 비밀
WAZUH_TENANT_ID=<회사 조직(tenant) UUID>         # 경보를 넣을 조직. 보통 회사 1개의 tenant id
```

두 값이 모두 있어야 `/v1/wazuh` 웹훅이 열립니다(둘 중 하나라도 비면 꺼짐). 수집 서버를 다시 시작하세요.
`WAZUH_TENANT_ID` 는 `select id, name from tenants;` 로 확인합니다.

## 2. Wazuh 매니저 쪽 설정

1. 이 폴더의 두 파일을 Wazuh 매니저의 `/var/ossec/integrations/` 에 복사하고 실행 권한을 줍니다.
   ```
   cp custom-edr custom-edr.py /var/ossec/integrations/
   chown root:wazuh /var/ossec/integrations/custom-edr /var/ossec/integrations/custom-edr.py
   chmod 750       /var/ossec/integrations/custom-edr /var/ossec/integrations/custom-edr.py
   ```
2. `/var/ossec/etc/ossec.conf` 에 integration 블록을 추가합니다. `<level>` 로 보낼 최소 심각도를 정해 소음을 줄입니다(예: 7 이상).
   ```xml
   <integration>
     <name>custom-edr</name>
     <hook_url>https://ingest.bing.co.kr/v1/wazuh</hook_url>
     <api_key>위 WAZUH_WEBHOOK_SECRET 과 같은 값</api_key>
     <level>7</level>
     <alert_format>json</alert_format>
   </integration>
   ```
3. Wazuh 매니저를 다시 시작합니다: `systemctl restart wazuh-manager`

## 3. 확인

- Wazuh 에서 경보가 날 만한 동작(예: 존재하지 않는 사용자로 SSH 로그인 실패 여러 번)을 일으킵니다.
- 콘솔 **경보** 화면에서 출처 필터를 **Wazuh** 로 두면 받은 경보가 보입니다. 각 경보에는 `Wazuh` 배지가 붙습니다.
- 심각도는 Wazuh rule level 로 정합니다: 12↑ 긴급, 9↑ 높음, 7↑ 보통, 그 미만 낮음.
- 장치는 Wazuh 에이전트 이름(hostname)으로 맞춥니다. 못 맞추면 장치 없이 경보만 보입니다.

## 메모
- 같은 Wazuh 경보 id 는 한 번만 저장됩니다(중복 방지).
- Wazuh 경보도 콘솔의 알림 연동(슬랙·이메일) 조건에 걸리면 함께 발송됩니다.
- 전송 실패 시 재시도·큐가 필요하면 Wazuh 쪽 integrator 설정으로 처리하세요(이 스크립트는 1회 POST).
