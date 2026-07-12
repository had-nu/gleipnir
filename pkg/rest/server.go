package rest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/validation"
)

const (
	maxLabelLen   = 1024
	maxBodyBytes  = 4096
	maxTimestampSkew = 30

	errInvalidJSON     = "INVALID_JSON"
	errInvalidHash     = "INVALID_HASH"
	errEmptySubmitter  = "EMPTY_SUBMITTER"
	errLabelTooLong    = "LABEL_TOO_LONG"
	errExtraFields     = "EXTRA_FIELDS"
	errStaleTimestamp  = "STALE_TIMESTAMP"
	errUnknownRoot     = "UNKNOWN_ROOT"
	errInvalidSig      = "INVALID_SIGNATURE"
	errNotFound        = "NOT_FOUND"
	errRateLimited     = "RATE_LIMITED"
	errQueueFull       = "QUEUE_FULL"
	errInternal        = "INTERNAL_ERROR"
)

type Server struct {
	engine       *consensus.Engine
	nodeUID      *identity.UIDZeroSoulbound
	keys         map[string]*identity.UIDZeroSoulbound
	allowedRoots map[string]bool
	rateLimiter  *perRootLimiter
	httpServer   *http.Server
	startTime    time.Time
	mu           sync.RWMutex
}

type perRootLimiter struct {
	mu        sync.Mutex
	windows   map[string]*slidingWindow
	maxReq    int
	windowDur time.Duration
}

type slidingWindow struct {
	entries []int64
}

type submitRequest struct {
	Hash      string `json:"hash"`
	Submitter string `json:"submitter"`
	Label     string `json:"label"`
}

type apiResponse struct {
	Status string      `json:"status"`
	Code   string      `json:"code,omitempty"`
	Message string     `json:"message,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

func apiError(code string, msg string) apiResponse {
	return apiResponse{Status: "error", Code: code, Message: msg}
}

func apiOK(data interface{}) apiResponse {
	return apiResponse{Status: "ok", Data: data}
}

func NewServer(engine *consensus.Engine, nodeUID *identity.UIDZeroSoulbound, opts ...ServerOption) (*Server, error) {
	s := &Server{
		engine:       engine,
		nodeUID:      nodeUID,
		keys:         make(map[string]*identity.UIDZeroSoulbound),
		allowedRoots: make(map[string]bool),
		rateLimiter: &perRootLimiter{
			windows:   make(map[string]*slidingWindow),
			maxReq:    5000,
			windowDur: time.Minute,
		},
		startTime: time.Now(),
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	s.keys[nodeUID.ID()] = nodeUID
	if s.allowedRoots != nil && len(s.allowedRoots) > 0 {
		log.Printf("rest: whitelist enabled (%d roots)", len(s.allowedRoots))
	}
	return s, nil
}

type ServerOption func(*Server) error

func WithKeysDir(path string) ServerOption {
	return func(s *Server) error {
		entries, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("read keys dir: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(path, e.Name())
			data, err := os.ReadFile(p)
			if err != nil {
				log.Printf("rest: skip %s: %v", p, err)
				continue
			}
			uid, err := identity.UnmarshalCBOR(data)
			if err != nil {
				log.Printf("rest: skip %s (not a valid UID): %v", p, err)
				continue
			}
			s.keys[uid.ID()] = uid
			log.Printf("rest: loaded UID %s from %s", uid.ID(), p)
		}
		return nil
	}
}

func WithAllowedRoots(roots string) ServerOption {
	return func(s *Server) error {
		for _, r := range strings.Split(roots, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				s.allowedRoots[r] = true
			}
		}
		return nil
	}
}

func WithRateLimit(maxPerMinute int) ServerOption {
	return func(s *Server) error {
		if maxPerMinute > 0 {
			s.rateLimiter.maxReq = maxPerMinute
		}
		return nil
	}
}

func (rl *perRootLimiter) Allow(rootID string) bool {
	rl.mu.Lock()
	w, ok := rl.windows[rootID]
	if !ok {
		w = &slidingWindow{entries: make([]int64, 0, rl.maxReq)}
		rl.windows[rootID] = w
	}
	rl.mu.Unlock()

	now := time.Now().Unix()
	cutoff := now - int64(rl.windowDur.Seconds())

	var valid []int64
	for _, t := range w.entries {
		if t >= cutoff {
			valid = append(valid, t)
		}
	}
	w.entries = valid

	if len(w.entries) >= rl.maxReq {
		return false
	}
	w.entries = append(w.entries, now)
	return true
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/submit", s.withAuth(s.handleSubmit))
	mux.HandleFunc("GET /v1/verify/", s.withAuth(s.handleVerify))
	mux.HandleFunc("GET /v1/block/", s.withAuth(s.handleGetBlock))
	mux.HandleFunc("GET /v1/health", s.optionalAuth(s.handleHealth))
	mux.HandleFunc("GET /v1/state-root", s.optionalAuth(s.handleStateRoot))
	return withCORS(mux)
}

func (s *Server) ListenAndServe(addr, certFile, keyFile string) error {
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
	}

	log.Printf("rest: listening on %s", addr)
	if certFile != "" && keyFile != "" {
		return s.httpServer.ListenAndServeTLS(certFile, keyFile)
	}
	log.Printf("rest: WARNING — TLS not configured, running in plain HTTP mode")
	return s.httpServer.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-UID0-RootID, X-Signature, X-Timestamp")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sanitizeError(err string) string {
	if len(err) > 200 {
		return err[:200]
	}
	return err
}

func (s *Server) authenticate(r *http.Request) (string, error) {
	rootID := r.Header.Get("X-UID0-RootID")
	sigHex := r.Header.Get("X-Signature")
	tsStr := r.Header.Get("X-Timestamp")

	if rootID == "" || sigHex == "" || tsStr == "" {
		return "", errors.New("missing authentication headers")
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", errors.New("invalid X-Timestamp")
	}

	skew := math.Abs(float64(time.Now().Unix() - ts))
	if skew > maxTimestampSkew {
		return "", errors.New(errStaleTimestamp)
	}

	s.mu.RLock()
	uid, known := s.keys[rootID]
	s.mu.RUnlock()
	if !known {
		return "", errors.New(errUnknownRoot)
	}

	s.mu.RLock()
	whitelistEnabled := len(s.allowedRoots) > 0
	allowed := whitelistEnabled && s.allowedRoots[rootID]
	s.mu.RUnlock()
	if whitelistEnabled && !allowed {
		return "", errors.New(errUnknownRoot)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", errors.New("cannot read body")
	}
	r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return "", errors.New("invalid signature encoding")
	}

	signed := string(body) + "||" + r.Method + "||" + r.URL.Path + "||" + tsStr
	if !identity.VerifyDilithium(uid.PublicKey, []byte(signed), sig) {
		return "", errors.New(errInvalidSig)
	}

	return rootID, nil
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rootID, err := s.authenticate(r)
		if err != nil {
			code := errInvalidSig
			msg := sanitizeError(err.Error())
			switch err.Error() {
			case errStaleTimestamp:
				code = errStaleTimestamp
				msg = "request timestamp is too old or in the future"
			case errUnknownRoot:
				code = errUnknownRoot
				msg = "unknown RootID"
			}
			writeJSON(w, http.StatusUnauthorized, apiError(code, msg))
			return
		}

		if !s.rateLimiter.Allow(rootID) {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, apiError(errRateLimited, "rate limit exceeded for root "+rootID))
			return
		}

		next(w, r)
	}
}

func (s *Server) optionalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-UID0-RootID") != "" {
			_, err := s.authenticate(r)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, apiError(errInvalidSig, "authentication failed"))
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var req submitRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var syntaxErr *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		switch {
		case errors.As(err, &syntaxErr):
			writeJSON(w, http.StatusBadRequest, apiError(errInvalidJSON, "invalid JSON syntax"))
		case errors.As(err, &typeErr):
			writeJSON(w, http.StatusBadRequest, apiError(errInvalidJSON, "invalid field type"))
		default:
			writeJSON(w, http.StatusBadRequest, apiError(errExtraFields, "unknown field in JSON body"))
		}
		return
	}

	if len(req.Hash) != 64 {
		writeJSON(w, http.StatusBadRequest, apiError(errInvalidHash, "hash must be 64 hex characters"))
		return
	}
	hashBytes, err := hex.DecodeString(req.Hash)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError(errInvalidHash, "hash is not valid hex"))
		return
	}
	var h [32]byte
	copy(h[:], hashBytes)
	if validation.IsZeroHash(h) {
		writeJSON(w, http.StatusBadRequest, apiError(errInvalidHash, "zero hash not allowed"))
		return
	}

	if req.Submitter == "" {
		writeJSON(w, http.StatusBadRequest, apiError(errEmptySubmitter, "submitter must not be empty"))
		return
	}

	if len(req.Label) > maxLabelLen {
		writeJSON(w, http.StatusBadRequest, apiError(errLabelTooLong, "label exceeds maximum length"))
		return
	}

	entry := chain.ProvenanceEntry{
		Hash:      h,
		Submitter: []byte(req.Submitter),
		Timestamp: time.Now().UnixNano(),
		Label:     req.Label,
	}

	if err := s.engine.Enqueue(entry); err != nil {
		var ve *validation.ValidationError
		if errors.As(err, &ve) {
			switch ve.Code {
			case "RATE_LIMITED":
				w.Header().Set("Retry-After", "60")
				writeJSON(w, http.StatusTooManyRequests, apiError(errRateLimited, ve.Message))
			default:
				writeJSON(w, http.StatusBadRequest, apiError(ve.Code, ve.Message))
			}
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError(errInternal, "internal error"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	proof, err := s.engine.WaitForAnchor(ctx, h)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError(errQueueFull, "timeout waiting for anchor"))
		return
	}

	writeJSON(w, http.StatusCreated, apiOK(map[string]interface{}{
		"hash":        req.Hash,
		"block_index": proof.BlockIndex,
		"block_time":  proof.BlockTime,
		"state_root":  hex.EncodeToString(proof.StateRoot),
		"smt_proof":   hex.EncodeToString(proof.SMTProof),
		"submitter":   string(proof.Submitter),
		"label":       proof.Label,
	}))
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	hashHex := strings.TrimPrefix(r.URL.Path, "/v1/verify/")
	if hashHex == "" || len(hashHex) != 64 {
		writeJSON(w, http.StatusBadRequest, apiError(errInvalidHash, "hash must be 64 hex characters"))
		return
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError(errInvalidHash, "hash is not valid hex"))
		return
	}
	var h [32]byte
	copy(h[:], hashBytes)

	proof, ok := s.engine.LookupHash(h)
	if !ok {
		writeJSON(w, http.StatusNotFound, apiError(errNotFound, "hash not anchored"))
		return
	}

	writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"hash":        hashHex,
		"block_index": proof.BlockIndex,
		"block_time":  proof.BlockTime,
		"state_root":  hex.EncodeToString(proof.StateRoot),
		"smt_proof":   hex.EncodeToString(proof.SMTProof),
		"submitter":   string(proof.Submitter),
		"label":       proof.Label,
	}))
}

func (s *Server) handleGetBlock(w http.ResponseWriter, r *http.Request) {
	indexStr := strings.TrimPrefix(r.URL.Path, "/v1/block/")
	index, err := strconv.ParseUint(indexStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError(errInvalidJSON, "block index must be an unsigned integer"))
		return
	}

	block := s.engine.GetBlock(index)
	if block == nil {
		writeJSON(w, http.StatusNotFound, apiError(errNotFound, "block not found"))
		return
	}

	entries := make([]map[string]interface{}, len(block.Anchored))
	for i, e := range block.Anchored {
		entries[i] = map[string]interface{}{
			"hash":      hex.EncodeToString(e.Hash[:]),
			"submitter": string(e.Submitter),
			"timestamp": e.Timestamp,
			"label":     e.Label,
		}
	}

	sigs := make([]string, len(block.Sigs))
	for i, sig := range block.Sigs {
		sigs[i] = hex.EncodeToString(sig)
	}

	validators := make([]string, len(block.Validators))
	for i, v := range block.Validators {
		validators[i] = hex.EncodeToString(v)
	}

	writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"index":       block.Index,
		"prev_hash":   hex.EncodeToString(block.PrevHash),
		"state_root":  hex.EncodeToString(block.StateRoot),
		"proposer":    hex.EncodeToString(block.Proposer),
		"anchored":    entries,
		"lambda1":     block.Lambda1,
		"timestamp":   block.Timestamp,
		"signatures":  sigs,
		"validators":  validators,
		"quorum": map[string]interface{}{
			"total":    block.Quorum.TotalValidators,
			"required": block.Quorum.RequiredSigs,
		},
	}))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := s.engine.GetHealth()
	root := s.engine.GetStateRoot()

	writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"node_id":        s.nodeUID.ID(),
		"block_height":   health.BlockHeight,
		"pending_hashes": health.PendingHashes,
		"lambda1":        health.Lambda1,
		"active_peers":   health.ActivePeers,
		"total_peers":    health.TotalPeers,
		"state_root":     hex.EncodeToString(root),
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
	}))
}

func (s *Server) handleStateRoot(w http.ResponseWriter, r *http.Request) {
	root := s.engine.GetStateRoot()
	blockHeight := s.engine.BlockCount()

	writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"state_root":   hex.EncodeToString(root),
		"block_height": blockHeight,
	}))
}


