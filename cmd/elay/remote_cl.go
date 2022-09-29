package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/core/beacon"
)

// remoteCL represents a remote CL client
type remoteCL struct {
	address       string
	client        *http.Client
	customHeaders map[string]string
}

func newRemoteCL(address, name string, customHeaders map[string]string) (*remoteCL, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	return &remoteCL{
		address:       address,
		client:        client,
		customHeaders: customHeaders,
	}, nil
}

func (r *remoteCL) GetHeadBlock() (resp beacon.ExecutableDataV1, err error) {
	return r.GetBlock("head")
}
func (r *remoteCL) GetFinalizedBlock() (resp beacon.ExecutableDataV1, err error) {
	return r.GetBlock("finalized")
}

// GetBlock fetches a block from the remote CL node. The specifier can be:
// - "finalized",
// - "head",
// - a number
func (r *remoteCL) GetBlock(specifier string) (resp beacon.ExecutableDataV1, err error) {
	var path = fmt.Sprintf("eth/v2/beacon/blocks/%v", specifier)

	var internal bellatrixBlock
	url := fmt.Sprintf("%v/%v", r.address, path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return resp, err
	}
	for k, v := range r.customHeaders {
		req.Header.Set(k, v)
	}
	if res, err := r.client.Do(req); err != nil {
		return resp, err
	} else if body, err := ioutil.ReadAll(res.Body); err != nil {
		return resp, err
	} else if err := json.Unmarshal(body, &internal); err != nil {
		fmt.Printf("%v\n", string(body))

		return resp, err
	}
	return internal.Data.Message.Body.ExecutionPayload.toExecutableDataV1(), nil
}
