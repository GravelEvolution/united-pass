package internalsms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultEndpoint = "https://internal-msc.moonstone.org.cn/api/open/v1/sms/send"
	DefaultFrom     = "MoonStone"

	internationalChannel = "international"
	notifyMessageType    = "NOTIFY"

	maxResponseBytes = 1 << 20
)

type Config struct {
	Endpoint string
	APIKey   string
	From     string
	Timeout  time.Duration
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

func NewClient(cfg Config, httpClient *http.Client) *Client {
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultEndpoint
	}
	if cfg.From == "" {
		cfg.From = DefaultFrom
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{cfg: cfg, httpClient: httpClient}
}

func (c *Client) SendCode(ctx context.Context, phone, code string) error {
	if c == nil || c.cfg.APIKey == "" || c.cfg.Endpoint == "" {
		return fmt.Errorf("internalsms: client is not configured")
	}
	number := strings.TrimPrefix(strings.TrimSpace(phone), "+")
	if number == "" {
		return fmt.Errorf("internalsms: empty phone number")
	}
	payload, err := json.Marshal(sendRequest{
		Channel:      internationalChannel,
		PhoneNumbers: []string{number},
		From:         c.cfg.From,
		Message:      fmt.Sprintf("Your MoonStone verification code is %s", code),
		MessageType:  notifyMessageType,
	})
	if err != nil {
		return fmt.Errorf("internalsms: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("internalsms: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.cfg.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("internalsms: send request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("internalsms: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("internalsms: http %d: %s", resp.StatusCode, summarize(body))
	}
	var envelope sendResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("internalsms: decode response: %w", err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("internalsms: %s: %s", envelope.Error.Code, envelope.Error.Message)
	}
	if envelope.Data == nil || envelope.Data.Code != "OK" {
		return fmt.Errorf("internalsms: unexpected response: %s", summarize(body))
	}
	return nil
}

type sendRequest struct {
	Channel      string   `json:"channel"`
	PhoneNumbers []string `json:"phoneNumbers"`
	From         string   `json:"from"`
	Message      string   `json:"message"`
	MessageType  string   `json:"messageType"`
}

type sendResponse struct {
	Data *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func summarize(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 512 {
		return trimmed[:512]
	}
	if trimmed == "" {
		return "<empty>"
	}
	return trimmed
}
