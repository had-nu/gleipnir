//nolint:errcheck // test/demo tool
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"lukechampine.com/blake3"

	"github.com/had-nu/gleipnir/pkg/identity"
)

//go:embed index.html
var staticFiles embed.FS

type DerivationStep struct {
	Label string `json:"label"`
	Index uint32 `json:"index"`
}

type ChildUID struct {
	UID            *identity.UIDZeroSoulbound
	Name           string          `json:"name"`
	Role           string          `json:"role"`
	DerivationPath []DerivationStep `json:"derivation_path"`
	CreatedAt      int64           `json:"created_at"`
}

type DeriveRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type DeriveResponse struct {
	UIDID          string           `json:"uid_id"`
	DerivationPath []DerivationStep `json:"derivation_path"`
	PublicKey      string           `json:"public_key"`
}

type AnchorRequest struct {
	UIDID string `json:"uid_id"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

type AnchorResponse struct {
	BlockIndex uint64 `json:"block_index"`
	StateRoot  string `json:"state_root"`
	Hash       string `json:"hash"`
}

type CubeRoom struct {
	companyUID  *identity.UIDZeroSoulbound
	gleipnirURL string
	children    []*ChildUID
	deriveIndex map[string]uint32
	startTime   time.Time
}

func main() {
	listen := flag.String("listen", ":3000", "Cube Room listen address")
	uidFile := flag.String("uid", "", "Company UID0 CBOR file")
	gleipnir := flag.String("gleipnir", "http://localhost:8080", "Gleipnir REST API base URL")
	flag.Parse()

	if *uidFile == "" {
		log.Fatal("--uid is required (path to company UID0 CBOR file)")
	}

	data, err := os.ReadFile(*uidFile)
	if err != nil {
		log.Fatalf("read uid file: %v", err)
	}

	uid, err := identity.UnmarshalCBOR(data)
	if err != nil {
		log.Fatalf("unmarshal uid: %v", err)
	}

	log.Printf("Cube Room loaded company UID0: %s", uid.ID())

	srv := &CubeRoom{
		companyUID:  uid,
		gleipnirURL: strings.TrimRight(*gleipnir, "/"),
		children:    make([]*ChildUID, 0),
		deriveIndex: make(map[string]uint32),
		startTime:   time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleRoot)
	mux.HandleFunc("/api/derive", srv.handleDerive)
	mux.HandleFunc("/api/anchor", srv.handleAnchor)
	mux.HandleFunc("/api/status", srv.handleStatus)

	log.Printf("Cube Room listening on %s", *listen)
	log.Printf("  Gleipnir backend: %s", srv.gleipnirURL)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("cube-room: %v", err)
	}
}

func (s *CubeRoom) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFiles.ReadFile("index.html")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (s *CubeRoom) handleDerive(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req DeriveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Name == "" || req.Role == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and role required"})
		return
	}

	child, err := s.deriveChild(req.Name, req.Role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, DeriveResponse{
		UIDID:          child.UID.ID(),
		DerivationPath: child.DerivationPath,
		PublicKey:      hex.EncodeToString(child.UID.PublicKey[:]),
	})
}

func (s *CubeRoom) handleAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req AnchorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	var child *ChildUID
	for _, c := range s.children {
		if c.UID.ID() == req.UIDID {
			child = c
			break
		}
	}
	if child == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "child UID not found — derive first"})
		return
	}

	contextRecord := map[string]interface{}{
		"uid":                req.UIDID,
		"name":               req.Name,
		"role":               req.Role,
		"timestamp":          time.Now().Unix(),
		"type":               "onboarding-context",
		"derivation_path":    child.DerivationPath,
	}
	contextJSON, _ := json.Marshal(contextRecord)

	hash := identity.Hash(contextJSON)
	hashHex := hex.EncodeToString(hash)

	submitBody := fmt.Sprintf(
		`{"hash":"%s","submitter":"%s","label":"cube-onboarding-%s"}`,
		hashHex, s.companyUID.ID(), req.Name,
	)

	ts := time.Now().Unix()
	tsStr := strconv.FormatInt(ts, 10)
	sigMaterial := submitBody + "||POST||/v1/submit||" + tsStr
	sig := identity.SignDilithium(s.companyUID.SecretKey, []byte(sigMaterial))

	httpReq, err := http.NewRequest("POST", s.gleipnirURL+"/v1/submit", strings.NewReader(submitBody))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-UID0-RootID", s.companyUID.ID())
	httpReq.Header.Set("X-Signature", hex.EncodeToString(sig))
	httpReq.Header.Set("X-Timestamp", tsStr)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "gleipnir unreachable: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	var gleipnirResp struct {
		Status string `json:"status"`
		Data   struct {
			BlockIndex uint64 `json:"block_index"`
			BlockTime  int64  `json:"block_time"`
			StateRoot  string `json:"state_root"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&gleipnirResp)

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": fmt.Sprintf("gleipnir returned %d: %s", resp.StatusCode, string(bodyBytes)),
		})
		return
	}

	writeJSON(w, http.StatusOK, AnchorResponse{
		BlockIndex: gleipnirResp.Data.BlockIndex,
		StateRoot:  gleipnirResp.Data.StateRoot,
		Hash:       hashHex,
	})
}

func (s *CubeRoom) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(s.gleipnirURL + "/v1/health")
	gleipnirOK := err == nil
	if resp != nil && resp.StatusCode != http.StatusOK {
		gleipnirOK = false
	}
	if resp != nil {
		resp.Body.Close()
	}

	var gleipnirInfo interface{}
	if gleipnirOK {
		resp2, err := http.Get(s.gleipnirURL + "/v1/health")
		if err == nil {
			defer resp2.Body.Close()
			var healthData struct {
				Data struct {
					NodeID       string `json:"node_id"`
					BlockHeight  uint64 `json:"block_height"`
					PendingHashes int   `json:"pending_hashes"`
				} `json:"data"`
			}
			json.NewDecoder(resp2.Body).Decode(&healthData)
			gleipnirInfo = healthData.Data
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"company_uid":    s.companyUID.ID(),
		"children_count": len(s.children),
		"gleipnir":       gleipnirOK,
		"gleipnir_info":  gleipnirInfo,
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
	})
}

func (s *CubeRoom) deriveChild(name, role string) (*ChildUID, error) {
	roleLabel := fmt.Sprintf("role-%s", strings.ToLower(strings.ReplaceAll(role, " ", "-")))
	nameLabel := fmt.Sprintf("member-%s", strings.ToLower(strings.ReplaceAll(name, " ", "-")))

	roleIndex := s.nextIndex(roleLabel)
	roleSeed := deriveSeed(s.companyUID.SecretKey, roleLabel, roleIndex)

	nameIndex := s.nextIndex(nameLabel)
	nameSeed := deriveSeed(roleSeed, nameLabel, nameIndex)

	childSeedHex := hex.EncodeToString(nameSeed)
	var networkID [32]byte
	copy(networkID[:], []byte("gleipnir-frontend-network"))
	childUID, err := identity.NewUIDZero(childSeedHex, networkID, true)
	if err != nil {
		return nil, err
	}

	hash := blake3.Sum256(append(nameSeed, []byte("rootid")...))
	var rootID [16]byte
	copy(rootID[:], hash[:16])
	childUID.RootID = rootID

	path := []DerivationStep{
		{Label: roleLabel, Index: roleIndex},
		{Label: nameLabel, Index: nameIndex},
	}

	child := &ChildUID{
		UID:            childUID,
		Name:           name,
		Role:           role,
		DerivationPath: path,
		CreatedAt:      time.Now().Unix(),
	}

	s.children = append(s.children, child)
	return child, nil
}

func (s *CubeRoom) nextIndex(label string) uint32 {
	idx := s.deriveIndex[label]
	s.deriveIndex[label] = idx + 1
	return idx
}

func deriveSeed(parentKey []byte, label string, index uint32) []byte {
	mac := hmac.New(sha256.New, parentKey)
	mac.Write([]byte(label))
	b := make([]byte, 4)
	b[0] = byte(index >> 24)
	b[1] = byte(index >> 16)
	b[2] = byte(index >> 8)
	b[3] = byte(index)
	mac.Write(b)
	parentSecret := mac.Sum(nil)

	info := []byte("gleipnir-uid-derivation-v1")
	kdf := hkdf.Expand(sha256.New, parentSecret, info)
	childSeed := make([]byte, 64)
	if _, err := io.ReadFull(kdf, childSeed); err != nil {
		panic(err)
	}
	return childSeed
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}
