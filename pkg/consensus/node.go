// IPC node and peer types.
package consensus

import "github.com/had-nu/gleipnir/pkg/identity"

type Node struct {
	UID   identity.UIDZeroSoulbound
	Peers []Peer
	Addr  string
}

type Peer struct {
	UID   identity.UIDZeroSoulbound
	Addr  string
	Alive bool
}
