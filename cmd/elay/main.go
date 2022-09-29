// Copyright 2022 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"encoding/json"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/eth/catalyst"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/urfave/cli/v2"
	"net"
	"net/http"
)

var (
	app           = flags.NewApp("Exection Layer Relay")
	verbosityFlag = &cli.IntFlag{
		Name:  "verbosity",
		Usage: "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail",
		Value: 3,
	}
	configFileFlag = &cli.StringFlag{
		Name:  "config",
		Usage: "TOML configuration file",
	}
)

func init() {
	app.Name = "ELay"
	app.Flags = []cli.Flag{
		utils.AuthListenFlag,
		utils.AuthPortFlag,
		utils.AuthVirtualHostsFlag,
		utils.JWTSecretFlag,
		configFileFlag,
		verbosityFlag,
	}
	app.Action = relay

}
func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func relay(c *cli.Context) error {
	api, err := newRelayPI()
	if err != nil {
		utils.Fatalf("Error: %v", err)
	}
	rpcAPI := []rpc.API{
		{
			Namespace: "engine",
			Service:   api,
		},
	}
	srv := rpc.NewServer()
	if err := node.RegisterApis(rpcAPI, []string{"engine"}, srv); err != nil {
		utils.Fatalf("Could not register API: %w", err)
	}
	vhosts := utils.SplitAndTrim(c.String(utils.AuthVirtualHostsFlag.Name))
	handler := node.NewHTTPHandlerStack(srv, []string{}, vhosts, nil)
	httpEndpoint := fmt.Sprintf("%s:%d", c.String(utils.AuthListenFlag.Name), c.Int(utils.AuthPortFlag.Name))
	if httpServer, addr, err := node.StartHTTPEndpoint(httpEndpoint, rpc.DefaultHTTPTimeouts, handler); err != nil {
		utils.Fatalf("Could not start RPC api: %v", err)
	} else {
		log.Info("HTTP endpoint opened", "url", fmt.Sprintf("http://%v/", addr))
		defer func() {
			httpServer.Shutdown(context.Background())
			log.Info("HTTP endpoint closed")
		}()
	}
	abortChan := make(chan os.Signal, 1)
	signal.Notify(abortChan, os.Interrupt)
	sig := <-abortChan
	log.Info("Exiting...", "signal", sig)
	return nil
}

type relayPI struct {
	els []catalyst.API
}

func newRelayPI() (*relayPI, error) {
	newRemoteEL("http://bench01.ethdevops.io:8545", "bench01", "the jwt secret", nil)
	newRemoteEL("http://bench02.ethdevops.io:8545", "bench01", "the jwt secret", nil)
	newRemoteEL("http://bench03.ethdevops.io:8545", "bench01", "the jwt secret", nil)
	newRemoteEL("http://bench04.ethdevops.io:8545", "bench01", "the jwt secret", nil)
	// TODO soup up some TOML to configure the ELs
	return &relayPI{}, nil
}

func (r *relayPI) ForkchoiceUpdatedV1(update beacon.ForkchoiceStateV1, payloadAttributes *beacon.PayloadAttributesV1) (beacon.ForkChoiceResponse, error) {
	for _, el := range r.els[1:] {
		go func(el catalyst.API) {
			if _, err := el.ForkchoiceUpdatedV1(update, payloadAttributes); err != nil {
				log.Info("Remote call error", "method", "FCUV1", "err", err)
			}
		}(el)
	}
	return r.els[0].ForkchoiceUpdatedV1(update, payloadAttributes)
}

func (r *relayPI) ExchangeTransitionConfigurationV1(config beacon.TransitionConfigurationV1) (*beacon.TransitionConfigurationV1, error) {
	for _, el := range r.els[1:] {
		go func(el catalyst.API) {
			if _, err := el.ExchangeTransitionConfigurationV1(config); err != nil {
				log.Info("Remote call error", "method", "ETCV1", "err", err)
			}

		}(el)
	}
	return r.els[0].ExchangeTransitionConfigurationV1(config)
}

func (r *relayPI) GetPayloadV1(payloadID beacon.PayloadID) (*beacon.ExecutableDataV1, error) {
	return nil, errors.New("GetPayloadV1 not supported")
}

func (r *relayPI) NewPayloadV1(params beacon.ExecutableDataV1) (beacon.PayloadStatusV1, error) {
	for _, el := range r.els[1:] {
		go func(el catalyst.API) {
			if _, err := el.NewPayloadV1(params); err != nil {
				log.Info("Remote call error", "method", "NPV1", "err", err)
			}
		}(el)
	}
	return r.els[0].NewPayloadV1(params)
}

// remoteEL represents a remote Execution Layer client.
type remoteEL struct {
	addr          net.Addr
	cli           rpc.Client
	jwtSecret     string
	customHeaders http.Header
}

func newRemoteEL(addr, name, jwtSecret string, customHeaders http.Header) (*remoteEL, error) {
	return &remoteEL{}, nil
	// 	r.cli.SetHeader()
}

func (r *remoteEL) ForkchoiceUpdatedV1(update beacon.ForkchoiceStateV1, payloadAttributes *beacon.PayloadAttributesV1) (beacon.ForkChoiceResponse, error) {
	var raw json.RawMessage
	var resp beacon.ForkChoiceResponse
	err := r.cli.CallContext(context.Background(), &raw, "engine_forkchoiceUpdatedV1", update, payloadAttributes)
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

func (r *remoteEL) ExchangeTransitionConfigurationV1(config beacon.TransitionConfigurationV1) (*beacon.TransitionConfigurationV1, error) {
	var raw json.RawMessage
	err := r.cli.CallContext(context.Background(), &raw, "engine_exchangeTransitionConfigurationV1", config)
	if err != nil {
		return nil, err
	}
	var resp beacon.TransitionConfigurationV1
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (r *remoteEL) GetPayloadV1(payloadID beacon.PayloadID) (*beacon.ExecutableDataV1, error) {
	return nil, errors.New("GetPayloadV1 not supported")
}

func (r *remoteEL) NewPayloadV1(params beacon.ExecutableDataV1) (beacon.PayloadStatusV1, error) {
	var raw json.RawMessage
	var resp beacon.PayloadStatusV1
	err := r.cli.CallContext(context.Background(), &raw, "engine_newPayloadV1", params)
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}
