package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/core/vm"
	"os"
	"strings"
	"testing"
	"time"
)

func FuzzFoo(f *testing.F) {
	//	binaries := "/home/user/go/src/github.com/holiman/txparse/eofparse/eofparse,/home/user/go/src/github.com/holiman/txparse/eofparse/eofparse"
	var bins []string
	if binaries, err := os.ReadFile("binaries.txt"); err != nil {
		f.Fatal(err)
	} else {
		for _, x := range strings.Split(strings.TrimSpace(string(binaries)), "\n") {
			x = strings.TrimSpace(x)
			if len(x) > 0 && !strings.HasPrefix(x, "#") {
				bins = append(bins, x)
			}
		}
	}
	if len(bins) < 2 {
		fmt.Printf("Usage: comparer parser1,parser2,... \n")
		fmt.Printf("Pipe input to process")
		f.Fatal("error")
	}
	var inputs = make(chan string)
	var outputs = make(chan string)
	go func() {
		err := doit(bins, inputs, outputs)
		f.Log("Done")
		if err != nil {
			f.Fatalf("exec error: %v", err)
		}
	}()
	f.Log("Sleeping 10s")
	time.Sleep(10 * time.Second)

	f.Log("Seeding corpus")
	// Seed with corpus
	for i := 0; ; i++ {
		fname := fmt.Sprintf("../eofdump/testdata/eof_corpus_%d.txt", i)
		corpus, err := os.Open(fname)
		if err != nil {
			break
		}
		f.Logf("Reading seed data from %v", fname)
		scanner := bufio.NewScanner(corpus)
		scanner.Buffer(make([]byte, 1024), 10*1024*1024)
		for scanner.Scan() {
			s := scanner.Text()
			if len(s) >= 2 && strings.HasPrefix(s, "0x") {
				s = s[2:]
			}
			b, err := hex.DecodeString(s)
			if err != nil {
				panic(err) // rotten corpus
			}
			f.Add(b)
		}
		corpus.Close()
		if err := scanner.Err(); err != nil {
			panic(err) // rotten corpus
		}
	}

	// Generate vectors

	f.Fuzz(func(t *testing.T, data []byte) {
		testUnmarshal(data) // This is for coverage guidance
		inputs <- fmt.Sprintf("%#x", data)
		errStr := <-outputs
		if len(errStr) != 0 {
			t.Fatal(errStr)
		}
	})

}

func testUnmarshal(data []byte) {
	var (
		jt = vm.NewPragueEOFInstructionSetForTesting()
		c  vm.Container
	)
	if err := c.UnmarshalBinary(data, true); err == nil {
		c.ValidateCode(&jt, true)
		if have := c.MarshalBinary(); !bytes.Equal(have, data) {
			panic("Unmarshal-> Marshal failure!")
		}
	}
	if err := c.UnmarshalBinary(data, false); err == nil {
		c.ValidateCode(&jt, false)
		if have := c.MarshalBinary(); !bytes.Equal(have, data) {
			panic("Unmarshal-> Marshal failure!")
		}
	}
}
