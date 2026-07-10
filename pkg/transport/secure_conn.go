package transport

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/had-nu/gleipnir/pkg/identity"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type SecureConn struct {
	conn net.Conn
	aead cipher.AEAD
}

func ServerHandshake(conn net.Conn, sk, pk []byte, peerID string) (*SecureConn, PeerInfo, error) {
	return kemHandshake(conn, sk, pk, peerID, false)
}

func ClientHandshake(conn net.Conn, sk, pk []byte, peerID string) (*SecureConn, PeerInfo, error) {
	return kemHandshake(conn, sk, pk, peerID, true)
}

func kemHandshake(conn net.Conn, sk, pk []byte, peerID string, dialer bool) (*SecureConn, PeerInfo, error) {
	var peerInfo PeerInfo

	myPKMsg := append(padPeerID(peerID), pk...)
	peerPKMsg := make([]byte, 32+1568)

	if dialer {
		if _, err := conn.Write(myPKMsg); err != nil {
			return nil, PeerInfo{}, err
		}
		if _, err := io.ReadFull(conn, peerPKMsg); err != nil {
			return nil, PeerInfo{}, err
		}
	} else {
		if _, err := io.ReadFull(conn, peerPKMsg); err != nil {
			return nil, PeerInfo{}, err
		}
		if _, err := conn.Write(myPKMsg); err != nil {
			return nil, PeerInfo{}, err
		}
	}

	peerInfo.PeerID = trimPeerID(peerPKMsg[:32])
	peerInfo.PublicKey = peerPKMsg[32:]

	var sharedSecret []byte

	if dialer {
		ct, ss, err := identity.KyberEncapsulate(peerInfo.PublicKey)
		if err != nil {
			return nil, PeerInfo{}, err
		}
		sharedSecret = ss
		if _, err := conn.Write(ct); err != nil {
			return nil, PeerInfo{}, err
		}
	} else {
		ct := make([]byte, 1568)
		if _, err := io.ReadFull(conn, ct); err != nil {
			return nil, PeerInfo{}, err
		}
		ss, err := identity.KyberDecapsulate(sk, ct)
		if err != nil {
			return nil, PeerInfo{}, err
		}
		sharedSecret = ss
	}

	key := deriveKey(sharedSecret, peerID, peerInfo.PeerID)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, PeerInfo{}, err
	}

	return &SecureConn{conn: conn, aead: aead}, peerInfo, nil
}

func (s *SecureConn) WriteMessage(data []byte) error {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.aead.Seal(nil, nonce, data, nil)

	frame := make([]byte, 4+12+len(ct))
	binary.BigEndian.PutUint32(frame[:4], uint32(12+len(ct)))
	copy(frame[4:], nonce)
	copy(frame[4+12:], ct)

	_, err := s.conn.Write(frame)
	return err
}

func (s *SecureConn) ReadMessage() ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(s.conn, lenBuf); err != nil {
		return nil, err
	}
	frameLen := binary.BigEndian.Uint32(lenBuf)
	if frameLen > 1024*1024+12 {
		return nil, errors.New("message too large")
	}

	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(s.conn, frame); err != nil {
		return nil, err
	}

	nonce := frame[:12]
	ct := frame[12:]

	plaintext, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (s *SecureConn) Close() error {
	return s.conn.Close()
}

func padPeerID(id string) []byte {
	b := make([]byte, 32)
	copy(b, []byte(id))
	return b
}

func trimPeerID(b []byte) string {
	var out []byte
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

func deriveKey(secret []byte, id1, id2 string) []byte {
	if id1 > id2 {
		id1, id2 = id2, id1
	}
	h := hkdf.New(sha256.New, secret, []byte("gleipnir-kem-v1"), []byte(id1+id2))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		panic(err)
	}
	return key
}
