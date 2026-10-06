// Package notify 는 경보 알림을 바깥으로 내보내는 송신기들이다(슬랙·이메일·SIEM).
//
// 원칙
//   - 보내기만 한다. 엔드포인트를 제어하지 않는다.
//   - 비밀값(슬랙 웹훅 URL, SMTP 비밀번호)은 .env 에서 읽는다. DB 에는 .env 키 이름(secret_ref)만 있다.
//   - 표준 라이브러리만 쓴다(외부 의존성 추가 없음).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Channel 은 notification_channels 행에서 전송에 필요한 부분.
type Channel struct {
	ID        int64
	Kind      string // slack | email | syslog | webhook
	Target    string // 이메일 주소(쉼표), 슬랙 표시용 채널명, syslog host:port
	SecretRef string // 비밀값이 든 .env 키 이름
}

// Message 는 outbox payload 에서 만든 보낼 내용.
type Message struct {
	RuleID        string `json:"rule_id"`
	Severity      string `json:"severity"`
	Title         string `json:"title"`
	DeviceID      string `json:"device_id,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	Tactic        string `json:"tactic,omitempty"`
	Technique     string `json:"technique,omitempty"`
	TechniqueName string `json:"technique_name,omitempty"`
	Test          bool   `json:"test,omitempty"`
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

// secret 은 .env 에서 secret_ref 키로 읽은 값(없으면 빈 문자열).
func (c Channel) secret() string {
	if c.SecretRef == "" {
		return ""
	}
	return os.Getenv(c.SecretRef)
}

// Send 는 채널 종류에 맞게 보낸다.
//
// 시험용: 환경변수 EDR_NOTIFY_SINK 가 설정돼 있으면 실제 전송 대신 그 파일에 한 줄(JSON)로 남긴다.
// (통합 테스트가 네트워크 없이 끝까지 확인할 수 있게 한다.)
func Send(ctx context.Context, c Channel, msg Message) error {
	if sink := os.Getenv("EDR_NOTIFY_SINK"); sink != "" {
		rec, _ := json.Marshal(map[string]any{"channel_id": c.ID, "kind": c.Kind, "target": c.Target, "msg": msg})
		f, err := os.OpenFile(sink, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(append(rec, '\n'))
		return err
	}

	switch c.Kind {
	case "slack":
		return sendSlack(ctx, c, msg)
	case "webhook":
		return sendWebhook(ctx, c, msg)
	case "email":
		return sendEmail(c, msg)
	case "syslog":
		return sendSyslog(c, msg)
	default:
		return fmt.Errorf("알 수 없는 채널 종류: %s", c.Kind)
	}
}

func line(msg Message) string {
	var b strings.Builder
	if msg.Test {
		b.WriteString("[테스트] ")
	}
	fmt.Fprintf(&b, "[%s] %s", strings.ToUpper(msg.Severity), msg.Title)
	if msg.RuleID != "" && msg.RuleID != "TEST" {
		fmt.Fprintf(&b, " (%s", msg.RuleID)
		if msg.Technique != "" {
			fmt.Fprintf(&b, " · %s %s", msg.Technique, msg.TechniqueName)
		}
		b.WriteString(")")
	}
	return b.String()
}

// ---------------- 슬랙 ----------------
// secret_ref 가 가리키는 .env 값 = Incoming Webhook URL.
func sendSlack(ctx context.Context, c Channel, msg Message) error {
	url := c.secret()
	if url == "" {
		return fmt.Errorf("슬랙 웹훅 URL(.env %s)이 비어 있습니다", c.SecretRef)
	}
	body, _ := json.Marshal(map[string]string{"text": line(msg)})
	return postJSON(ctx, url, body)
}

// ---------------- 일반 웹훅(JSON 그대로) ----------------
func sendWebhook(ctx context.Context, c Channel, msg Message) error {
	url := c.secret()
	if url == "" {
		url = c.Target
	}
	if url == "" {
		return fmt.Errorf("웹훅 URL 이 비어 있습니다")
	}
	body, _ := json.Marshal(msg)
	return postJSON(ctx, url, body)
}

func postJSON(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("전송 실패: HTTP %d", resp.StatusCode)
	}
	return nil
}

// ---------------- 이메일(SMTP) ----------------
// SMTP 서버 설정은 .env 공통값. 채널 target = 받는 사람(쉼표 구분).
//
//	SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_USER(선택), SMTP_PASS(선택)
func sendEmail(c Channel, msg Message) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	from := os.Getenv("SMTP_FROM")
	if host == "" || port == "" || from == "" {
		return fmt.Errorf("SMTP 설정(.env SMTP_HOST/SMTP_PORT/SMTP_FROM)이 비어 있습니다")
	}
	var to []string
	for _, a := range strings.Split(c.Target, ",") {
		if a = strings.TrimSpace(a); a != "" {
			to = append(to, a)
		}
	}
	if len(to) == 0 {
		return fmt.Errorf("받는 사람이 없습니다")
	}
	subject := line(msg)
	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n",
		from, strings.Join(to, ", "), subject)
	bodyText := subject
	if msg.DeviceID != "" {
		bodyText += "\r\n장치: " + msg.DeviceID
	}
	if msg.CreatedAt != "" {
		bodyText += "\r\n발생: " + msg.CreatedAt
	}
	var auth smtp.Auth
	if u := os.Getenv("SMTP_USER"); u != "" {
		auth = smtp.PlainAuth("", u, os.Getenv("SMTP_PASS"), host)
	}
	return smtp.SendMail(net.JoinHostPort(host, port), auth, from, to, []byte(headers+bodyText))
}

// ---------------- SIEM(Syslog, RFC 5424 비슷하게 JSON 메시지) ----------------
// target = "host:port" (기본 UDP) 또는 "host:port/tcp".
func sendSyslog(c Channel, msg Message) error {
	addr := c.Target
	network := "udp"
	if strings.HasSuffix(addr, "/tcp") {
		network, addr = "tcp", strings.TrimSuffix(addr, "/tcp")
	} else {
		addr = strings.TrimSuffix(addr, "/udp")
	}
	if addr == "" {
		return fmt.Errorf("syslog 대상(host:port)이 비어 있습니다")
	}
	// severity → syslog 우선순위(facility local0=16). critical/high=alert(1)/err(3), medium=warning(4), low=notice(5)
	sev := map[string]int{"critical": 1, "high": 3, "medium": 4, "low": 5}[msg.Severity]
	if sev == 0 {
		sev = 5
	}
	pri := 16*8 + sev
	payload, _ := json.Marshal(msg)
	ts := time.Now().Format(time.RFC3339)
	host, _ := os.Hostname()
	packet := fmt.Sprintf("<%d>1 %s %s endpoint-edr - %s - %s", pri, ts, host, msg.RuleID, string(payload))

	conn, err := net.DialTimeout(network, addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write([]byte(packet))
	return err
}
