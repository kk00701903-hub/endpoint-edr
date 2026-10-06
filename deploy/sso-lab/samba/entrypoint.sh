#!/usr/bin/env bash
# =====================================================================
# 테스트용 Active Directory (Samba AD DC) — 개인 PC SSO 실험 전용
#   처음 실행: 도메인 만들기 → 서비스 계정·그룹·테스트 사용자 넣기 → 실행
#   두 번째부터: 저장된 도메인으로 바로 실행 (데이터는 볼륨 /var/lib/samba)
# 회사 AD 를 흉내 낼 뿐이며 회사 AD 에는 아무것도 하지 않는다.
# =====================================================================
set -euo pipefail

REALM="${AD_REALM:-BING.TEST}"            # Kerberos 영역(대문자 도메인)
DOMAIN="${AD_DOMAIN:-BING}"               # NetBIOS 이름 (회사: BING)
ADMIN_PASS="${AD_ADMIN_PASSWORD:-Adm1n!Lab2026}"
SVC_PASS="${AD_SVC_PASSWORD:-Svc!Keycloak2026}"
USER_PASS="${AD_USER_PASSWORD:-Passw0rd!Lab}"
DNS_FORWARDER="${AD_DNS_FORWARDER:-8.8.8.8}"
PRIVATE="/var/lib/samba/private"

lower() { echo "$1" | tr '[:upper:]' '[:lower:]'; }
BASE_DN="DC=$(lower "$REALM" | sed 's/\./,DC=/g')"
MAIL_DOMAIN="$(lower "$REALM")"

if [ ! -f "$PRIVATE/sam.ldb" ]; then
  echo "[ad] 도메인 $REALM ($DOMAIN) 를 처음 만듭니다"
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --realm="$REALM" --domain="$DOMAIN" --server-role=dc --dns-backend=SAMBA_INTERNAL \
    --use-rfc2307 --adminpass="$ADMIN_PASS" \
    --option="dns forwarder = $DNS_FORWARDER"
  # 실험용: 컨테이너 사이 389 단순 바인드 허용(회사 AD 는 LDAPS 636 을 쓴다)
  sed -i '/^\[global\]/a\\tldap server require strong auth = no' /etc/samba/smb.conf
  # 컨테이너를 새로 만들어도 설정이 남도록 데이터 볼륨에 보관
  cp /etc/samba/smb.conf /var/lib/samba/smb.conf.saved

  # 테스트 편의: 비밀번호 만료·복잡도 기록 끄기(계정 잠금 시험은 아래 비활성 계정으로)
  samba-tool domain passwordsettings set --max-pwd-age=0 --history-length=0 >/dev/null

  # ---- 조직 구성 ----
  samba-tool ou add "OU=EDR,$BASE_DN" --description="엔드포인트 관제 콘솔 권한 그룹"
  for g in EDR-Admins EDR-Analysts EDR-Viewers; do
    samba-tool group add "$g" --groupou="OU=EDR" --description="엔드포인트 관제 ${g#EDR-}"
  done

  # Keycloak 이 AD 를 "읽기만" 할 때 쓰는 서비스 계정
  samba-tool user create svc-keycloak "$SVC_PASS" --description="Keycloak LDAP 읽기 전용" >/dev/null
  samba-tool user setexpiry svc-keycloak --noexpiry >/dev/null

  # 테스트 사용자: 아이디:성:이름:그룹  (그룹이 비면 콘솔 권한 없음)
  while IFS=: read -r id sn given group; do
    samba-tool user create "$id" "$USER_PASS" --surname="$sn" --given-name="$given" \
      --mail-address="$id@$MAIL_DOMAIN" --department="정보전략팀" >/dev/null
    samba-tool user setexpiry "$id" --noexpiry >/dev/null
    [ -n "$group" ] && samba-tool group addmembers "$group" "$id" >/dev/null
    echo "[ad] 사용자 $id ($sn$given) ${group:-그룹 없음}"
  done <<'USERS'
kim.admin:김:관리:EDR-Admins
lee.analyst:이:분석:EDR-Analysts
park.viewer:박:열람:EDR-Viewers
choi.none:최:무권한:
jung.locked:정:잠김:EDR-Analysts
USERS
  # 퇴사자·잠긴 계정 흉내
  samba-tool user disable jung.locked >/dev/null
  echo "[ad] jung.locked 는 비활성(잠긴 계정)"
  echo "[ad] 준비 완료 — 기준 DN: $BASE_DN, 서비스 계정: CN=svc-keycloak,CN=Users,$BASE_DN"
fi

[ -f /var/lib/samba/smb.conf.saved ] && cp /var/lib/samba/smb.conf.saved /etc/samba/smb.conf
# Kerberos 설정(도메인 컨트롤러 자신용)
[ -f "$PRIVATE/krb5.conf" ] && cp "$PRIVATE/krb5.conf" /etc/krb5.conf

echo "[ad] Samba AD DC 실행 (LDAP 389, LDAPS 636, Kerberos 88)"
exec samba --foreground --no-process-group --debug-stdout --debuglevel="${AD_DEBUG:-1}"
