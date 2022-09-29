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
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/eth/catalyst"
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
	}
)

func init() {
	app.Name = "ELay"
	app.Flags = []cli.Flag{
		utils.AuthListenFlag,
		utils.AuthPortFlag,
		utls.AuthVirtualHostsFlag,
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

}

type relayPI struct {
	els []catalyst.API
}

func (r relayPI) ForkchoiceUpdatedV1(update beacon.ForkchoiceStateV1, payloadAttributes *beacon.PayloadAttributesV1) (beacon.ForkChoiceResponse, error) {
	for _, el := range els[1:] {
		go func(el catalyst.API) {
			el.ForkchoiceUpdatedV1(update, payloadAttributes)
		}(el)
	}
	return els[0].ForkchoiceUpdatedV1(update, payloadAttributes)
}

func (r relayPI) ExchangeTransitionConfigurationV1(config beacon.TransitionConfigurationV1) (*beacon.TransitionConfigurationV1, error) {
	for _, el := range els[1:] {
		go func(el catalyst.API) {
			el.ExchangeTransitionConfigurationV1(config)
		}(el)
	}
	return els[0].ExchangeTransitionConfigurationV1(config)
}

func (r relayPI) GetPayloadV1(payloadID beacon.PayloadID) (*beacon.ExecutableDataV1, error) {
	return nil, errors.New("GetPayloadV1 not supported")
}

func (r relayPI) NewPayloadV1(params beacon.ExecutableDataV1) (beacon.PayloadStatusV1, error) {
	for _, el := range els[1:] {
		go func(el catalyst.API) {
			el.NewPayloadV1(params)
		}(el)
	}
	return els[0].NewPayloadV1(params)
}
