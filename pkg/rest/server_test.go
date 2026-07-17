//nolint:errcheck // test assertions
package rest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func newTestUID(t *testing.T) *identity.UIDZeroSoulbound {
	t.Helper()
	return identity.NewUIDZero("test-root-identity-for-testing", true)
}

func newTestEngine(t *testing.T, uid *identity.UIDZeroSoulbound) *consensus.Engine {
	t.Helper()
	node := consensus.Node{UID: *uid, Addr: "test-node"}
	eng := consensus.NewEngine(node, 100*time.Millisecond)
	eng.Start()
	t.Cleanup(eng.Stop)
	return eng
}

func newTestServer(t *testing.T, eng *consensus.Engine, uid *identity.UIDZeroSoulbound, opts ...ServerOption) *Server {
	t.Helper()
	s, err := NewServer(eng, uid, opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	return s
}

func signRequest(uid *identity.UIDZeroSoulbound, body, method, path, timestamp string) string {
	signed := body + "||" + method + "||" + path + "||" + timestamp
	return hex.EncodeToString(identity.SignDilithium(uid.SecretKey, []byte(signed)))
}

func ts() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func TestHealthEndpoint(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "ok" {
		t.Fatalf("expected status ok, got %s", result.Status)
	}
}

func TestStateRootEndpoint(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/state-root")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "ok" {
		t.Fatalf("expected status ok, got %s", result.Status)
	}
}

func TestSubmitAndVerify(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts1 := ts()
	body := `{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitter":"test-user","label":"test-entry"}`
	sig := signRequest(uid, body, "POST", "/v1/submit", ts1)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts1)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var result apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "ok" {
		t.Fatalf("expected status ok, got %s", result.Status)
	}

	verifyTS := ts()
	verifySig := signRequest(uid, "", "GET", "/v1/verify/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", verifyTS)

	vreq, _ := http.NewRequest("GET", srv.URL+"/v1/verify/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	vreq.Header.Set("X-UID0-RootID", uid.ID())
	vreq.Header.Set("X-Signature", verifySig)
	vreq.Header.Set("X-Timestamp", verifyTS)

	vresp, err := http.DefaultClient.Do(vreq)
	if err != nil {
		t.Fatal(err)
	}
	defer vresp.Body.Close()

	if vresp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for verify, got %d", vresp.StatusCode)
	}
}

func TestSubmitInvalidHash(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts := ts()
	body := `{"hash":"invalid","submitter":"test","label":"test"}`
	sig := signRequest(uid, body, "POST", "/v1/submit", ts)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSubmitZeroHash(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts := ts()
	body := `{"hash":"0000000000000000000000000000000000000000000000000000000000000000","submitter":"test","label":"test"}`
	sig := signRequest(uid, body, "POST", "/v1/submit", ts)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for zero hash, got %d", resp.StatusCode)
	}
}

func TestSubmitEmptySubmitter(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts := ts()
	body := `{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitter":"","label":"test"}`
	sig := signRequest(uid, body, "POST", "/v1/submit", ts)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty submitter, got %d", resp.StatusCode)
	}
}

func TestAuthenticationMissingHeaders(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","submitter":"test","label":"test"}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing auth, got %d", resp.StatusCode)
	}
}

func TestAuthenticationStaleTimestamp(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","submitter":"test","label":"test"}`
	oldTS := fmt.Sprintf("%d", time.Now().Add(-2*time.Minute).Unix())
	sig := signRequest(uid, body, "POST", "/v1/submit", oldTS)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", oldTS)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale timestamp, got %d", resp.StatusCode)
	}
}

func TestVerifyNotFound(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts := ts()
	sig := signRequest(uid, "", "GET", "/v1/verify/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", ts)

	req, _ := http.NewRequest("GET", srv.URL+"/v1/verify/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", nil)
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unanchored hash, got %d", resp.StatusCode)
	}
}

func TestGetBlock(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts1 := ts()
	body := `{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitter":"test","label":"test"}`
	sig1 := signRequest(uid, body, "POST", "/v1/submit", ts1)

	req1, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req1.Header.Set("X-UID0-RootID", uid.ID())
	req1.Header.Set("X-Signature", sig1)
	req1.Header.Set("X-Timestamp", ts1)
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp1.StatusCode)
	}

	ts2 := ts()
	sig2 := signRequest(uid, "", "GET", "/v1/block/0", ts2)
	req2, _ := http.NewRequest("GET", srv.URL+"/v1/block/0", nil)
	req2.Header.Set("X-UID0-RootID", uid.ID())
	req2.Header.Set("X-Signature", sig2)
	req2.Header.Set("X-Timestamp", ts2)

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
}

func TestUnknownRootID(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	unknownUID := identity.NewUIDZero("unknown-uid-for-testing", true)
	ts := ts()
	body := `{"hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","submitter":"test","label":"test"}`
	sig := signRequest(unknownUID, body, "POST", "/v1/submit", ts)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", unknownUID.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown root, got %d", resp.StatusCode)
	}
}

func TestWhitelistRejectsUnknown(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid, WithAllowedRoots("some-other-root"))
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts := ts()
	body := `{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitter":"test","label":"test"}`
	sig := signRequest(uid, body, "POST", "/v1/submit", ts)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for root not in whitelist, got %d", resp.StatusCode)
	}
}

func TestWhitelistAcceptsAllowed(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid, WithAllowedRoots(uid.ID()))
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts := ts()
	body := `{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitter":"test","label":"test"}`
	sig := signRequest(uid, body, "POST", "/v1/submit", ts)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for whitelisted root, got %d", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid, WithRateLimit(1))
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts := ts()
	body := `{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitter":"test","label":"first"}`
	sig := signRequest(uid, body, "POST", "/v1/submit", ts)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for first request, got %d", resp.StatusCode)
	}

	ts2 := fmt.Sprintf("%d", time.Now().Unix())
	body2 := `{"hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","submitter":"test","label":"second"}`
	sig2 := signRequest(uid, body2, "POST", "/v1/submit", ts2)

	req2, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body2))
	req2.Header.Set("X-UID0-RootID", uid.ID())
	req2.Header.Set("X-Signature", sig2)
	req2.Header.Set("X-Timestamp", ts2)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for rate limited request, got %d", resp2.StatusCode)
	}
}

func TestExtraFieldsRejected(t *testing.T) {
	uid := newTestUID(t)
	eng := newTestEngine(t, uid)
	s := newTestServer(t, eng, uid)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ts := ts()
	body := `{"hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","submitter":"test","label":"test","extra":"field"}`
	sig := signRequest(uid, body, "POST", "/v1/submit", ts)

	req, _ := http.NewRequest("POST", srv.URL+"/v1/submit", strings.NewReader(body))
	req.Header.Set("X-UID0-RootID", uid.ID())
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for extra fields, got %d", resp.StatusCode)
	}
}
