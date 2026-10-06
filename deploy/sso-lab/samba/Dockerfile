# 테스트용 Active Directory (Samba AD DC) — 개인 PC SSO 실험 전용 이미지
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update \
 && apt-get install -y --no-install-recommends samba samba-ad-dc samba-ad-provision samba-dsdb-modules winbind krb5-user ldap-utils \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/ad-entrypoint.sh
# Windows 에서 CRLF 로 체크아웃돼도 동작하도록 줄바꿈 정리
RUN sed -i 's/\r$//' /usr/local/bin/ad-entrypoint.sh && chmod +x /usr/local/bin/ad-entrypoint.sh
VOLUME ["/var/lib/samba"]
EXPOSE 88 389 636
ENTRYPOINT ["/usr/local/bin/ad-entrypoint.sh"]
