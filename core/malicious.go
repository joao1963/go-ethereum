package core

import (
	"github.com/ethereum/go-ethereum/crypto"
	"os"
)

var (
	Malicious           = os.Getenv("MALICIOUS") != ""
	MaliciousParentHash = crypto.Keccak256Hash([]byte("parent"))
	CheckpointNumber    = uint64(0)
)
