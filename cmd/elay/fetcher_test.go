package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/naoina/toml"
)

func TestParseHead(t *testing.T) {
	data, err := os.ReadFile("./head.resp")
	if err != nil {
		t.Fatal(err)
	}
	var block bellatrixBlock
	if err := json.Unmarshal(data, &block); err != nil {
		t.Fatal(err)
	}
	payload := block.Data.Message.Body.ExecutionPayload
	t.Logf("payload parent: %x\n", payload.ParentHash)
	payload2 := payload.toExecutableDataV1()
	t.Logf("%v", payload2)
}
