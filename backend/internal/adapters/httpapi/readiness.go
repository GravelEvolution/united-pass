//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Readiness probe handler
//

package httpapi

import (
	"context"
	"fmt"
	"time"
)

// RedisChecker verifies Redis connectivity for readiness checks.
type RedisChecker struct {
	pinger interface {
		Ping(ctx context.Context) error
	}
	timeout time.Duration
}

// NewRedisChecker builds a readiness checker for Redis. The pinger interface is
// satisfied by the redis.Client wrapper.
func NewRedisChecker(pinger interface {
	Ping(ctx context.Context) error
}, timeout time.Duration) *RedisChecker {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &RedisChecker{pinger: pinger, timeout: timeout}
}

func (c *RedisChecker) Name() string { return "redis" }

func (c *RedisChecker) Check(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := c.pinger.Ping(checkCtx); err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	return nil
}
