#!/usr/bin/env python3
# Wazuh → Endpoint EDR 콘솔 연동 integration 스크립트.
#   Wazuh integrator 가 경보가 날 때마다 이 스크립트를 부른다:
#     custom-edr <알림파일경로> <api_key(=웹훅 비밀)> <hook_url(=.../v1/wazuh)>
#   받은 경보 JSON 을 수집 서버의 /v1/wazuh 웹훅으로 그대로 POST 한다.
# 받기만 하는 단방향 연동이다. Wazuh 나 PC 를 제어하지 않는다. 표준 라이브러리만 쓴다.
import json
import sys
import urllib.request

def main():
    if len(sys.argv) < 4:
        sys.exit("usage: custom-edr <alert_file> <api_key> <hook_url>")
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(alert_file, "r", encoding="utf-8", errors="replace") as f:
        alert = json.load(f)

    data = json.dumps(alert).encode("utf-8")
    req = urllib.request.Request(hook_url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer " + api_key)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except Exception as e:
        # 전송 실패는 조용히 기록만(Wazuh 로그로). 경보 유실을 막으려면 Wazuh 쪽 재시도·큐를 쓴다.
        sys.stderr.write("custom-edr 전송 실패: %s\n" % e)
        sys.exit(1)

if __name__ == "__main__":
    main()
