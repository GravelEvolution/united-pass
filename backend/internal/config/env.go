//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: .env file loader helpers
//

package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadDotEnv reads a .env file if it exists and sets environment variables for
// any key that is not already present in the process environment. Existing
// system environment variables always take precedence — .env never overrides.
//
// This loader is intentionally minimal: no variable expansion, no export
// keyword, no multi-line values. It exists solely so local development can
// use an ignored .env file instead of exporting variables in every shell.
//
// Production deployments should inject environment variables through the
// process manager or orchestration system, not through .env files.
func LoadDotEnv(path string) (loaded int, err error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("open env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := parseEnvLine(line)
		if !ok {
			return loaded, fmt.Errorf("env file line %d: malformed entry", lineNum)
		}

		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, value); err != nil {
				return loaded, fmt.Errorf("set env %q: %w", key, err)
			}
			loaded++
		}
	}

	if err := scanner.Err(); err != nil {
		return loaded, fmt.Errorf("scan env file: %w", err)
	}
	return loaded, nil
}

// parseEnvLine splits a "KEY=VALUE" line, stripping optional surrounding quotes
// from the value. Returns ok=false if the line does not contain '='.
func parseEnvLine(line string) (key, value string, ok bool) {
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		return "", "", false
	}

	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])

	// Strip matching surrounding quotes.
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
	}

	return key, value, true
}
