package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	k, _ := dreamupdelegation.LoadKeyring(os.Args[1])
	s, _ := dreamupdelegation.NewAdministratorSigner(k, dreamupdelegation.SignerConfig{Issuer: os.Args[2], Audience: os.Args[3], TTL: dreamupdelegation.MaxOrdinaryTTL, ClockSkew: dreamupdelegation.MaxClockSkew, Now: func() time.Time { return time.Now().UTC() }})
	now := time.Now().UTC()
	p := "/internal/v1/events/evt_dreamup_shanghai_2026/applications"
	pq, _ := dreamupdelegation.CanonicalPathAndQuery(p, nil)
	sum := sha256.Sum256(nil)
	bh := hex.EncodeToString(sum[:])
	jti := fmt.Sprintf("req_diag_%08d", time.Now().UnixNano()%100000000)
	a, _ := s.SignAdministrator(dreamupdelegation.AdministratorAssertion{Subject: identity.UserID("user_diag_1"), JWTID: jti, Capability: "event.application.read_basic", Method: "GET", PathAndQuery: pq, BodySHA256: bh, EventID: "evt_dreamup_shanghai_2026", Role: adminroles.RoleAdmin, RoleBindingID: "arb_diag_1", RoleVersion: 1, ChallengeVersion: 1, AuthTime: now.Add(-time.Minute), StepUpAt: now.Add(-30 * time.Second)})
	req, _ := http.NewRequest("GET", "http://127.0.0.1:18084"+p, nil)
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("X-Request-Id", jti)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("http:", err)
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Printf("STATUS=%d\nBODY=%.400s\n", resp.StatusCode, b)
}
