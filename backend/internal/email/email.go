// Package email provides a minimal SMTP sender used by the internal email
// endpoint. It sends a single-recipient UTF-8 HTML message over implicit TLS
// (SMTPS, port 465) using the configured Aliyun DirectMail account.
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Message is a single-recipient UTF-8 HTML email.
type Message struct {
	To             string
	Subject        string
	HTML           string
	MessageID      string
	IdempotencyKey string
}

// Config holds the SMTP account settings. Values are intentionally plain
// strings so callers can pass config.EmailConfig fields directly.
type Config struct {
	Host        string
	Port        int
	User        string
	Password    string
	FromAddress string
	FromName    string
}

// Sender sends email messages.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// SMTP is a net/smtp based Sender using implicit TLS.
type SMTP struct {
	config Config
}

// NewSMTP validates the config and returns an SMTP sender. An empty host
// yields an error so callers can fail closed when no sender is configured.
func NewSMTP(config Config) (*SMTP, error) {
	if config.Host == "" {
		return nil, errors.New("email: SMTP host is not configured")
	}
	if config.Port == 0 {
		config.Port = 465
	}
	if config.FromAddress == "" {
		return nil, errors.New("email: from address is not configured")
	}
	return &SMTP{config: config}, nil
}

// Send delivers msg to the configured SMTP server over implicit TLS.
func (s *SMTP) Send(ctx context.Context, msg Message) error {
	if s == nil || s.config.Host == "" {
		return errors.New("email: SMTP sender is not configured")
	}
	if err := validateMessage(msg); err != nil {
		return err
	}

	addr := net.JoinHostPort(s.config.Host, strconv.Itoa(s.config.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("email: dial %s: %w", addr, err)
	}
	deadline := time.Now().Add(15 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := rawConn.SetDeadline(deadline); err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("email: set connection deadline: %w", err)
	}
	conn := tls.Client(rawConn, &tls.Config{ServerName: s.config.Host, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("email: tls handshake: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return fmt.Errorf("email: smtp handshake: %w", err)
	}
	defer client.Close()

	if s.config.User != "" || s.config.Password != "" {
		auth := smtp.PlainAuth("", s.config.User, s.config.Password, s.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email: smtp auth: %w", err)
		}
	}
	if err := client.Mail(s.config.FromAddress); err != nil {
		return fmt.Errorf("email: smtp mail from: %w", err)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return fmt.Errorf("email: smtp rcpt to: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("email: smtp data: %w", err)
	}

	body, err := renderMessage(s.config.FromAddress, s.config.FromName, msg)
	if err != nil {
		return err
	}
	if _, err := writer.Write(body); err != nil {
		return fmt.Errorf("email: write body: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("email: close data: %w", err)
	}
	return client.Quit()
}

func validateMessage(msg Message) error {
	if msg.To == "" {
		return errors.New("email: missing recipient")
	}
	if len(msg.To) > 254 {
		return errors.New("email: recipient too long")
	}
	if msg.Subject == "" || len(msg.Subject) > 160 {
		return errors.New("email: subject must be 1..160 bytes")
	}
	if msg.HTML == "" || len(msg.HTML) > 1<<20 {
		return errors.New("email: html body must be 1 byte..1 MiB")
	}
	if msg.MessageID != "" {
		if len(msg.MessageID) > 254 || !strings.HasPrefix(msg.MessageID, "<") || !strings.HasSuffix(msg.MessageID, ">") || strings.ContainsAny(msg.MessageID, "\r\n \t") || !strings.Contains(msg.MessageID, "@") {
			return errors.New("email: invalid Message-ID")
		}
	}
	if msg.IdempotencyKey != "" && (!validEmailHeaderValue(msg.IdempotencyKey, 200) || strings.ContainsAny(msg.IdempotencyKey, " <>@")) {
		return errors.New("email: invalid idempotency key")
	}
	if address, err := mail.ParseAddress(msg.To); err != nil || address.Address != msg.To {
		return errors.New("email: invalid recipient")
	}
	return nil
}

func validEmailHeaderValue(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n")
}

func renderMessage(fromAddress, fromName string, msg Message) ([]byte, error) {
	var buf bytes.Buffer
	from := fromAddress
	if fromName != "" {
		from = fmt.Sprintf("%s <%s>", mime.QEncoding.Encode("UTF-8", fromName), fromAddress)
	}
	buf.WriteString("From: " + from + "\r\n")
	buf.WriteString("To: " + msg.To + "\r\n")
	buf.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", msg.Subject) + "\r\n")
	if msg.MessageID != "" {
		buf.WriteString("Message-ID: " + msg.MessageID + "\r\n")
	}
	if msg.IdempotencyKey != "" {
		buf.WriteString("X-UnitedPass-Idempotency-Key: " + msg.IdempotencyKey + "\r\n")
	}
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	buf.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(msg.HTML)
	buf.WriteString("\r\n")
	return buf.Bytes(), nil
}
