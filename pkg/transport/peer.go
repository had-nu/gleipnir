package transport

type PeerInfo struct {
	PeerID   string
	Addr     string
	PublicKey []byte
}

type MessageType byte

const (
	MsgGossipEntry MessageType = iota + 1
	MsgGossipBlock
	MsgGossipSig
	MsgPing
	MsgPong
)

type Message struct {
	Type    MessageType
	Payload []byte
	From    string
}
