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
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/eth/catalyst"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/naoina/toml"
	"github.com/urfave/cli/v2"
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
		Value: "conf.toml",
	}
)

func init() {
	app.Name = "ELay"
	app.Flags = []cli.Flag{
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
	log.Root().SetHandler(log.LvlFilterHandler(log.Lvl(c.Int(verbosityFlag.Name)), log.StreamHandler(os.Stdout, log.TerminalFormat(true))))
	conffile := c.String(configFileFlag.Name)
	var config Config
	if data, err := os.ReadFile(conffile); err != nil {
		log.Error("Error reading config file", "file", conffile, "err", err)
		return err
	} else if err := toml.Unmarshal(data, &config); err != nil {
		log.Error("Error reading config file", "file", config, "err", err)
		return err
	}
	log.Info("Spinning up muxer...")
	mux, err := newRelayPI(config.ElClients)
	if err != nil {
		return err
	}
	log.Info("Spinning up relayer...")
	fetcher, err := newFetcher(config.ClClient, mux)
	fetcher.Start()
	abortChan := make(chan os.Signal, 1)
	signal.Notify(abortChan, os.Interrupt)
	sig := <-abortChan
	log.Info("Exiting...", "signal", sig)
	fetcher.Stop()
	return nil
}

type relayPI struct {
	els []catalyst.API
}

func newRelayPI(config []ELConfig) (*relayPI, error) {
	var els []catalyst.API
	for _, conf := range config {
		el, err := newRemoteEL(conf.Address, conf.Name, conf.JwtSecret, conf.Headers)
		if err != nil {
			return nil, err
		}
		els = append(els, el)
	}
	return &relayPI{els: els}, nil
}

func (r *relayPI) ForkchoiceUpdatedV1(update beacon.ForkchoiceStateV1, payloadAttributes *beacon.PayloadAttributesV1) (beacon.ForkChoiceResponse, error) {
	for _, el := range r.els[1:] {
		go func(el catalyst.API) {
			if _, err := el.ForkchoiceUpdatedV1(update, payloadAttributes); err != nil {
				log.Info("Remote call error", "method", "FCUV1", "err", err)
			}
		}(el)
	}
	a, err := r.els[0].ForkchoiceUpdatedV1(update, payloadAttributes)
	if err != nil {
		log.Info("Remote call error", "method", "FCUV1", "err", err)
	}
	return a, err
}

func (r *relayPI) NewPayloadV1(params beacon.ExecutableDataV1) (beacon.PayloadStatusV1, error) {
	for _, el := range r.els[1:] {
		go func(el catalyst.API) {
			if _, err := el.NewPayloadV1(params); err != nil {
				log.Info("Remote call error", "method", "NPV1", "err", err)
			}
		}(el)
	}
	a, err := r.els[0].NewPayloadV1(params)
	if err != nil {
		log.Info("Remote call error", "method", "NPV1", "err", err)
	}
	return a, err
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
