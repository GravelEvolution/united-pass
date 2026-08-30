package config

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	runtimeEnvNamePattern = regexp.MustCompile(`"(UP_[A-Z0-9_]+)"`)
	templateEntryPattern  = regexp.MustCompile(`^(UP_[A-Z0-9_]+)=(.*)$`)
	defaultOffBoolPattern = regexp.MustCompile(`boolOr\("(UP_[A-Z0-9_]+)",\s*false\)`)
	sensitiveEnvPattern   = regexp.MustCompile(`(?:SECRET|PASSWORD|TOKEN|_PASS$|ENCRYPTION_KEY$|RETAINED_DECRYPTION_KEYS$|KEYRING_PATH$|SERVICE_ACCOUNT_KEY_FILE$|DATABASE_URL$|REDIS_URL$)`)
	ipv4LiteralPattern    = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
)

var developmentTemplateOnlyVariables = map[string]struct{}{
	"UP_SSH_HOST":          {},
	"UP_SSH_PORT":          {},
	"UP_SSH_USER":          {},
	"UP_SSH_KEY":           {},
	"UP_SSH_PASSWORD":      {},
	"UP_LOCAL_PG_PORT":     {},
	"UP_LOCAL_REDIS_PORT":  {},
	"UP_REMOTE_PG_PORT":    {},
	"UP_REMOTE_REDIS_PORT": {},
	"UP_REMOTE_DB_BIND":    {},
	"UP_REMOTE_REDIS_BIND": {},
}

func TestEnvTemplateCoversRuntimeVariables(t *testing.T) {
	configSource, _, entries := readEnvTemplateContract(t)
	runtimeNames := matchedNames(runtimeEnvNamePattern, configSource)

	var missing []string
	for name := range runtimeNames {
		if _, ok := entries[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range developmentTemplateOnlyVariables {
		if _, ok := entries[name]; !ok {
			missing = append(missing, name)
		}
	}
	var unexpected []string
	for name := range entries {
		if _, runtime := runtimeNames[name]; runtime {
			continue
		}
		if _, developmentOnly := developmentTemplateOnlyVariables[name]; !developmentOnly {
			unexpected = append(unexpected, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	if len(missing) != 0 || len(unexpected) != 0 {
		t.Fatalf(".env.template contract drift: missing=%v unexpected=%v", missing, unexpected)
	}
}

func TestEnvTemplateLoadsAsSafeDevelopmentConfig(t *testing.T) {
	configSource, _, entries := readEnvTemplateContract(t)
	for name := range matchedNames(runtimeEnvNamePattern, configSource) {
		t.Setenv(name, normalizedTemplateValue(entries[name]))
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load rejected .env.template values: %v", err)
	}
	if cfg.Environment != EnvironmentDevelopment {
		t.Fatalf("template environment = %q, want development", cfg.Environment)
	}
}

func TestEnvTemplateKeepsFeaturesOffAndSensitiveValuesEmpty(t *testing.T) {
	configSource, templateSource, entries := readEnvTemplateContract(t)
	for name := range matchedNames(defaultOffBoolPattern, configSource) {
		if value := normalizedTemplateValue(entries[name]); value != "false" {
			t.Errorf("default-off feature %s = %q, want false", name, entries[name])
		}
	}

	// These values identify a real deployment even when they are not secrets.
	// Keeping them empty prevents a copied template from targeting production.
	deploymentIdentityNames := []string{
		"UP_SSH_HOST",
		"UP_SSH_USER",
		"UP_AUTH_PROVIDER_BASE_URL",
		"UP_AUTH_PROVIDER_PROJECT_ID",
		"UP_AUTH_PROVIDER_ORGANIZATION_ID",
		"UP_AUTH_PROVIDER_CLIENT_ID",
		"UP_AUTH_PROVIDER_DOMAIN",
		"UP_OAUTH_PUBLIC_ORIGIN",
		"UP_DREAMUP_OWNER_USER_ID",
		"UP_DREAMUP_MOBILE_DELEGATION_ISSUER",
		"UP_DREAMUP_DELEGATION_ISSUER",
		"UP_DREAMUP_ADMIN_ORIGIN",
		"UP_WECHAT_MINIPROGRAM_APP_ID",
		"UP_ALIYUN_SMS_ACCESS_KEY_ID",
		"UP_ALIYUN_SMS_SIGN_NAME",
		"UP_ALIYUN_SMS_TEMPLATE_CODE",
		"UP_FEISHU_APP_ID",
		"UP_FEISHU_TENANT_ID",
		"UP_FEISHU_REDIRECT_URL",
		"UP_CERBOS_PDP_URL",
		"UP_CERBOS_ADMIN_URL",
		"UP_CERBOS_ADMIN_USERNAME",
		"UP_SMTP_HOST",
		"UP_SMTP_USER",
		"UP_SMTP_FROM",
		"UP_SMTP_FROM_NAME",
		"UP_RISK_TURNSTILE_SITE_KEY",
		"UP_RISK_TURNSTILE_HOSTNAME",
		"UP_RISK_RECAPTCHA_SITE_KEY",
		"UP_RISK_RECAPTCHA_HOSTNAME",
	}
	for _, name := range deploymentIdentityNames {
		if !safeEmptyOrPlaceholder(entries[name]) {
			t.Errorf("deployment-specific %s must be empty or an explicit placeholder, got %q", name, entries[name])
		}
	}

	for name, value := range entries {
		if sensitiveEnvPattern.MatchString(name) && name != "UP_SSH_KEY" && !strings.HasPrefix(name, "UP_SECRET_ROTATION_") && !safeEmptyOrPlaceholder(value) {
			t.Errorf("sensitive %s must be empty or an explicit placeholder, got %q", name, value)
		}
	}

	for _, raw := range ipv4LiteralPattern.FindAllString(templateSource, -1) {
		if address := net.ParseIP(raw); address != nil && !address.IsLoopback() {
			t.Errorf(".env.template contains non-loopback IP literal %q", raw)
		}
	}
	for _, forbidden := range []string{
		"/srv/",
		"/var/backups/",
		"-----begin private key-----",
		"sk_live_",
		"ghp_",
		"akia",
	} {
		if strings.Contains(strings.ToLower(templateSource), forbidden) {
			t.Errorf(".env.template contains forbidden production or secret marker %q", forbidden)
		}
	}
}

func readEnvTemplateContract(t *testing.T) (configSource, templateSource string, entries map[string]string) {
	t.Helper()
	root := findBackendRootForEnvTemplate(t)
	configBytes, err := os.ReadFile(filepath.Join(root, "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	templateBytes, err := os.ReadFile(filepath.Join(root, ".env.template"))
	if err != nil {
		t.Fatalf("read .env.template: %v", err)
	}

	entries = make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(templateBytes)))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		match := templateEntryPattern.FindStringSubmatch(line)
		if match == nil {
			t.Fatalf(".env.template line %d is not a KEY=VALUE entry: %q", lineNumber, line)
		}
		if _, duplicate := entries[match[1]]; duplicate {
			t.Fatalf(".env.template repeats %s", match[1])
		}
		entries[match[1]] = strings.TrimSpace(match[2])
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan .env.template: %v", err)
	}
	return string(configBytes), string(templateBytes), entries
}

func findBackendRootForEnvTemplate(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for range 5 {
		if _, err := os.Stat(filepath.Join(directory, ".env.template")); err == nil {
			if _, err := os.Stat(filepath.Join(directory, "internal", "config", "config.go")); err == nil {
				return directory
			}
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	t.Fatal("backend root containing .env.template and internal/config/config.go not found")
	return ""
}

func matchedNames(pattern *regexp.Regexp, source string) map[string]struct{} {
	names := make(map[string]struct{})
	for _, match := range pattern.FindAllStringSubmatch(source, -1) {
		names[match[1]] = struct{}{}
	}
	return names
}

func normalizedTemplateValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && ((raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'')) {
		return raw[1 : len(raw)-1]
	}
	return raw
}

func safeEmptyOrPlaceholder(raw string) bool {
	value := normalizedTemplateValue(raw)
	return value == "" || (strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">"))
}
