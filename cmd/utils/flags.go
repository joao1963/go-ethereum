// Copyright 2015 The go-ethereum Authors
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

// Package utils contains internal helper functions for go-ethereum commands.
package utils

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	godebug "runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	flags2 "github.com/ethereum/go-ethereum/cmd/utils/flags"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/fdlimit"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool/blobpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/catalyst"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/gasprice"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/remotedb"
	"github.com/ethereum/go-ethereum/ethstats"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/metrics/exp"
	"github.com/ethereum/go-ethereum/metrics/influxdb"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/hashdb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	gopsutil "github.com/shirou/gopsutil/mem"
	"github.com/urfave/cli/v2"
)

// These are all the command line flags we support.
// If you add to this list, please remember to include the
// flag in the appropriate command definition.
//
// The flags are defined here so their names and help texts
// are the same for all commands.

// MakeDataDir retrieves the currently requested data directory, terminating
// if none (or the empty string) is specified. If the node is starting a testnet,
// then a subdirectory of the specified datadir will be used.
func MakeDataDir(ctx *cli.Context) string {
	if path := ctx.String(flags2.DataDirFlag.Name); path != "" {
		if ctx.Bool(flags2.SepoliaFlag.Name) {
			return filepath.Join(path, "sepolia")
		}
		if ctx.Bool(flags2.HoleskyFlag.Name) {
			return filepath.Join(path, "holesky")
		}
		return path
	}
	Fatalf("Cannot determine default data directory, please set manually (--datadir)")
	return ""
}

// setNodeKey creates a node key from set command line flags, either loading it
// from a file or as a specified hex value. If neither flags were provided, this
// method returns nil and an ephemeral key is to be generated.
func setNodeKey(ctx *cli.Context, cfg *p2p.Config) {
	var (
		hex  = ctx.String(flags2.NodeKeyHexFlag.Name)
		file = ctx.String(flags2.NodeKeyFileFlag.Name)
		key  *ecdsa.PrivateKey
		err  error
	)
	switch {
	case file != "" && hex != "":
		Fatalf("Options %q and %q are mutually exclusive", flags2.NodeKeyFileFlag.Name, flags2.NodeKeyHexFlag.Name)
	case file != "":
		if key, err = crypto.LoadECDSA(file); err != nil {
			Fatalf("Option %q: %v", flags2.NodeKeyFileFlag.Name, err)
		}
		cfg.PrivateKey = key
	case hex != "":
		if key, err = crypto.HexToECDSA(hex); err != nil {
			Fatalf("Option %q: %v", flags2.NodeKeyHexFlag.Name, err)
		}
		cfg.PrivateKey = key
	}
}

// setNodeUserIdent creates the user identifier from CLI flags.
func setNodeUserIdent(ctx *cli.Context, cfg *node.Config) {
	if identity := ctx.String(flags2.IdentityFlag.Name); len(identity) > 0 {
		cfg.UserIdent = identity
	}
}

// setBootstrapNodes creates a list of bootstrap nodes from the command line
// flags, reverting to pre-configured ones if none have been specified.
// Priority order for bootnodes configuration:
//
// 1. --bootnodes flag
// 2. Config file
// 3. Network preset flags (e.g. --holesky)
// 4. default to mainnet nodes
func setBootstrapNodes(ctx *cli.Context, cfg *p2p.Config) {
	urls := params.MainnetBootnodes
	if ctx.IsSet(flags2.BootnodesFlag.Name) {
		urls = SplitAndTrim(ctx.String(flags2.BootnodesFlag.Name))
	} else {
		if cfg.BootstrapNodes != nil {
			return // Already set by config file, don't apply defaults.
		}
		switch {
		case ctx.Bool(flags2.HoleskyFlag.Name):
			urls = params.HoleskyBootnodes
		case ctx.Bool(flags2.SepoliaFlag.Name):
			urls = params.SepoliaBootnodes
		}
	}
	cfg.BootstrapNodes = mustParseBootnodes(urls)
}

func mustParseBootnodes(urls []string) []*enode.Node {
	nodes := make([]*enode.Node, 0, len(urls))
	for _, url := range urls {
		if url != "" {
			node, err := enode.Parse(enode.ValidSchemes, url)
			if err != nil {
				log.Crit("Bootstrap URL invalid", "enode", url, "err", err)
				return nil
			}
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// setBootstrapNodesV5 creates a list of bootstrap nodes from the command line
// flags, reverting to pre-configured ones if none have been specified.
func setBootstrapNodesV5(ctx *cli.Context, cfg *p2p.Config) {
	urls := params.V5Bootnodes
	switch {
	case ctx.IsSet(flags2.BootnodesFlag.Name):
		urls = SplitAndTrim(ctx.String(flags2.BootnodesFlag.Name))
	case cfg.BootstrapNodesV5 != nil:
		return // already set, don't apply defaults.
	}

	cfg.BootstrapNodesV5 = make([]*enode.Node, 0, len(urls))
	for _, url := range urls {
		if url != "" {
			node, err := enode.Parse(enode.ValidSchemes, url)
			if err != nil {
				log.Error("Bootstrap URL invalid", "enode", url, "err", err)
				continue
			}
			cfg.BootstrapNodesV5 = append(cfg.BootstrapNodesV5, node)
		}
	}
}

// setListenAddress creates TCP/UDP listening address strings from set command
// line flags
func setListenAddress(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.IsSet(flags2.ListenPortFlag.Name) {
		cfg.ListenAddr = fmt.Sprintf(":%d", ctx.Int(flags2.ListenPortFlag.Name))
	}
	if ctx.IsSet(flags2.DiscoveryPortFlag.Name) {
		cfg.DiscAddr = fmt.Sprintf(":%d", ctx.Int(flags2.DiscoveryPortFlag.Name))
	}
}

// setNAT creates a port mapper from command line flags.
func setNAT(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.IsSet(flags2.NATFlag.Name) {
		natif, err := nat.Parse(ctx.String(flags2.NATFlag.Name))
		if err != nil {
			Fatalf("Option %s: %v", flags2.NATFlag.Name, err)
		}
		cfg.NAT = natif
	}
}

// SplitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
func SplitAndTrim(input string) (ret []string) {
	l := strings.Split(input, ",")
	for _, r := range l {
		if r = strings.TrimSpace(r); r != "" {
			ret = append(ret, r)
		}
	}
	return ret
}

// setHTTP creates the HTTP RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setHTTP(ctx *cli.Context, cfg *node.Config) {
	if ctx.Bool(flags2.HTTPEnabledFlag.Name) {
		if cfg.HTTPHost == "" {
			cfg.HTTPHost = "127.0.0.1"
		}
		if ctx.IsSet(flags2.HTTPListenAddrFlag.Name) {
			cfg.HTTPHost = ctx.String(flags2.HTTPListenAddrFlag.Name)
		}
	}

	if ctx.IsSet(flags2.HTTPPortFlag.Name) {
		cfg.HTTPPort = ctx.Int(flags2.HTTPPortFlag.Name)
	}

	if ctx.IsSet(flags2.AuthListenFlag.Name) {
		cfg.AuthAddr = ctx.String(flags2.AuthListenFlag.Name)
	}

	if ctx.IsSet(flags2.AuthPortFlag.Name) {
		cfg.AuthPort = ctx.Int(flags2.AuthPortFlag.Name)
	}

	if ctx.IsSet(flags2.AuthVirtualHostsFlag.Name) {
		cfg.AuthVirtualHosts = SplitAndTrim(ctx.String(flags2.AuthVirtualHostsFlag.Name))
	}

	if ctx.IsSet(flags2.HTTPCORSDomainFlag.Name) {
		cfg.HTTPCors = SplitAndTrim(ctx.String(flags2.HTTPCORSDomainFlag.Name))
	}

	if ctx.IsSet(flags2.HTTPApiFlag.Name) {
		cfg.HTTPModules = SplitAndTrim(ctx.String(flags2.HTTPApiFlag.Name))
	}

	if ctx.IsSet(flags2.HTTPVirtualHostsFlag.Name) {
		cfg.HTTPVirtualHosts = SplitAndTrim(ctx.String(flags2.HTTPVirtualHostsFlag.Name))
	}

	if ctx.IsSet(flags2.HTTPPathPrefixFlag.Name) {
		cfg.HTTPPathPrefix = ctx.String(flags2.HTTPPathPrefixFlag.Name)
	}
	if ctx.IsSet(flags2.AllowUnprotectedTxs.Name) {
		cfg.AllowUnprotectedTxs = ctx.Bool(flags2.AllowUnprotectedTxs.Name)
	}

	if ctx.IsSet(flags2.BatchRequestLimit.Name) {
		cfg.BatchRequestLimit = ctx.Int(flags2.BatchRequestLimit.Name)
	}

	if ctx.IsSet(flags2.BatchResponseMaxSize.Name) {
		cfg.BatchResponseMaxSize = ctx.Int(flags2.BatchResponseMaxSize.Name)
	}
}

// setGraphQL creates the GraphQL listener interface string from the set
// command line flags, returning empty if the GraphQL endpoint is disabled.
func setGraphQL(ctx *cli.Context, cfg *node.Config) {
	if ctx.IsSet(flags2.GraphQLCORSDomainFlag.Name) {
		cfg.GraphQLCors = SplitAndTrim(ctx.String(flags2.GraphQLCORSDomainFlag.Name))
	}
	if ctx.IsSet(flags2.GraphQLVirtualHostsFlag.Name) {
		cfg.GraphQLVirtualHosts = SplitAndTrim(ctx.String(flags2.GraphQLVirtualHostsFlag.Name))
	}
}

// setWS creates the WebSocket RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setWS(ctx *cli.Context, cfg *node.Config) {
	if ctx.Bool(flags2.WSEnabledFlag.Name) {
		if cfg.WSHost == "" {
			cfg.WSHost = "127.0.0.1"
		}
		if ctx.IsSet(flags2.WSListenAddrFlag.Name) {
			cfg.WSHost = ctx.String(flags2.WSListenAddrFlag.Name)
		}
	}
	if ctx.IsSet(flags2.WSPortFlag.Name) {
		cfg.WSPort = ctx.Int(flags2.WSPortFlag.Name)
	}

	if ctx.IsSet(flags2.WSAllowedOriginsFlag.Name) {
		cfg.WSOrigins = SplitAndTrim(ctx.String(flags2.WSAllowedOriginsFlag.Name))
	}

	if ctx.IsSet(flags2.WSApiFlag.Name) {
		cfg.WSModules = SplitAndTrim(ctx.String(flags2.WSApiFlag.Name))
	}

	if ctx.IsSet(flags2.WSPathPrefixFlag.Name) {
		cfg.WSPathPrefix = ctx.String(flags2.WSPathPrefixFlag.Name)
	}
}

// setIPC creates an IPC path configuration from the set command line flags,
// returning an empty string if IPC was explicitly disabled, or the set path.
func setIPC(ctx *cli.Context, cfg *node.Config) {
	CheckExclusive(ctx, flags2.IPCDisabledFlag, flags2.IPCPathFlag)
	switch {
	case ctx.Bool(flags2.IPCDisabledFlag.Name):
		cfg.IPCPath = ""
	case ctx.IsSet(flags2.IPCPathFlag.Name):
		cfg.IPCPath = ctx.String(flags2.IPCPathFlag.Name)
	}
}

// setLes shows the deprecation warnings for LES flags.
func setLes(ctx *cli.Context, cfg *ethconfig.Config) {
	if ctx.IsSet(LightServeFlag.Name) {
		log.Warn("The light server has been deprecated, please remove this flag", "flag", LightServeFlag.Name)
	}
	if ctx.IsSet(LightIngressFlag.Name) {
		log.Warn("The light server has been deprecated, please remove this flag", "flag", LightIngressFlag.Name)
	}
	if ctx.IsSet(LightEgressFlag.Name) {
		log.Warn("The light server has been deprecated, please remove this flag", "flag", LightEgressFlag.Name)
	}
	if ctx.IsSet(LightMaxPeersFlag.Name) {
		log.Warn("The light server has been deprecated, please remove this flag", "flag", LightMaxPeersFlag.Name)
	}
	if ctx.IsSet(LightNoPruneFlag.Name) {
		log.Warn("The light server has been deprecated, please remove this flag", "flag", LightNoPruneFlag.Name)
	}
	if ctx.IsSet(LightNoSyncServeFlag.Name) {
		log.Warn("The light server has been deprecated, please remove this flag", "flag", LightNoSyncServeFlag.Name)
	}
}

// MakeDatabaseHandles raises out the number of allowed file handles per process
// for Geth and returns half of the allowance to assign to the database.
func MakeDatabaseHandles(max int) int {
	limit, err := fdlimit.Maximum()
	if err != nil {
		Fatalf("Failed to retrieve file descriptor allowance: %v", err)
	}
	switch {
	case max == 0:
		// User didn't specify a meaningful value, use system limits
	case max < 128:
		// User specified something unhealthy, just use system defaults
		log.Error("File descriptor limit invalid (<128)", "had", max, "updated", limit)
	case max > limit:
		// User requested more than the OS allows, notify that we can't allocate it
		log.Warn("Requested file descriptors denied by OS", "req", max, "limit", limit)
	default:
		// User limit is meaningful and within allowed range, use that
		limit = max
	}
	raised, err := fdlimit.Raise(uint64(limit))
	if err != nil {
		Fatalf("Failed to raise file descriptor allowance: %v", err)
	}
	return int(raised / 2) // Leave half for networking and other stuff
}

// MakeAddress converts an account specified directly as a hex encoded string or
// a key index in the key store to an internal account representation.
func MakeAddress(ks *keystore.KeyStore, account string) (accounts.Account, error) {
	// If the specified account is a valid address, return it
	if common.IsHexAddress(account) {
		return accounts.Account{Address: common.HexToAddress(account)}, nil
	}
	// Otherwise try to interpret the account as a keystore index
	index, err := strconv.Atoi(account)
	if err != nil || index < 0 {
		return accounts.Account{}, fmt.Errorf("invalid account address or index %q", account)
	}
	log.Warn("-------------------------------------------------------------------")
	log.Warn("Referring to accounts by order in the keystore folder is dangerous!")
	log.Warn("This functionality is deprecated and will be removed in the future!")
	log.Warn("Please use explicit addresses! (can search via `geth account list`)")
	log.Warn("-------------------------------------------------------------------")

	accs := ks.Accounts()
	if len(accs) <= index {
		return accounts.Account{}, fmt.Errorf("index %d higher than number of accounts %d", index, len(accs))
	}
	return accs[index], nil
}

// setEtherbase retrieves the etherbase from the directly specified command line flags.
func setEtherbase(ctx *cli.Context, cfg *ethconfig.Config) {
	if ctx.IsSet(MinerEtherbaseFlag.Name) {
		log.Warn("Option --miner.etherbase is deprecated as the etherbase is set by the consensus client post-merge")
	}
	if !ctx.IsSet(flags2.MinerPendingFeeRecipientFlag.Name) {
		return
	}
	addr := ctx.String(flags2.MinerPendingFeeRecipientFlag.Name)
	if strings.HasPrefix(addr, "0x") || strings.HasPrefix(addr, "0X") {
		addr = addr[2:]
	}
	b, err := hex.DecodeString(addr)
	if err != nil || len(b) != common.AddressLength {
		Fatalf("-%s: invalid pending block producer address %q", flags2.MinerPendingFeeRecipientFlag.Name, addr)
		return
	}
	cfg.Miner.PendingFeeRecipient = common.BytesToAddress(b)
}

// MakePasswordList reads password lines from the file specified by the global --password flag.
func MakePasswordList(ctx *cli.Context) []string {
	path := ctx.Path(flags2.PasswordFileFlag.Name)
	if path == "" {
		return nil
	}
	text, err := os.ReadFile(path)
	if err != nil {
		Fatalf("Failed to read password file: %v", err)
	}
	lines := strings.Split(string(text), "\n")
	// Sanitise DOS line endings.
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines
}

func SetP2PConfig(ctx *cli.Context, cfg *p2p.Config) {
	setNodeKey(ctx, cfg)
	setNAT(ctx, cfg)
	setListenAddress(ctx, cfg)
	setBootstrapNodes(ctx, cfg)
	setBootstrapNodesV5(ctx, cfg)

	if ctx.IsSet(flags2.MaxPeersFlag.Name) {
		cfg.MaxPeers = ctx.Int(flags2.MaxPeersFlag.Name)
	}
	ethPeers := cfg.MaxPeers
	log.Info("Maximum peer count", "ETH", ethPeers, "total", cfg.MaxPeers)

	if ctx.IsSet(flags2.MaxPendingPeersFlag.Name) {
		cfg.MaxPendingPeers = ctx.Int(flags2.MaxPendingPeersFlag.Name)
	}
	if ctx.IsSet(flags2.NoDiscoverFlag.Name) {
		cfg.NoDiscovery = true
	}

	CheckExclusive(ctx, flags2.DiscoveryV4Flag, flags2.NoDiscoverFlag)
	CheckExclusive(ctx, flags2.DiscoveryV5Flag, flags2.NoDiscoverFlag)
	cfg.DiscoveryV4 = ctx.Bool(flags2.DiscoveryV4Flag.Name)
	cfg.DiscoveryV5 = ctx.Bool(flags2.DiscoveryV5Flag.Name)

	if netrestrict := ctx.String(flags2.NetrestrictFlag.Name); netrestrict != "" {
		list, err := netutil.ParseNetlist(netrestrict)
		if err != nil {
			Fatalf("Option %q: %v", flags2.NetrestrictFlag.Name, err)
		}
		cfg.NetRestrict = list
	}

	if ctx.Bool(flags2.DeveloperFlag.Name) {
		// --dev mode can't use p2p networking.
		cfg.MaxPeers = 0
		cfg.ListenAddr = ""
		cfg.NoDial = true
		cfg.NoDiscovery = true
		cfg.DiscoveryV5 = false
	}
}

// SetNodeConfig applies node-related command line flags to the config.
func SetNodeConfig(ctx *cli.Context, cfg *node.Config) {
	SetP2PConfig(ctx, &cfg.P2P)
	setIPC(ctx, cfg)
	setHTTP(ctx, cfg)
	setGraphQL(ctx, cfg)
	setWS(ctx, cfg)
	setNodeUserIdent(ctx, cfg)
	SetDataDir(ctx, cfg)
	setSmartCard(ctx, cfg)

	if ctx.IsSet(flags2.JWTSecretFlag.Name) {
		cfg.JWTSecret = ctx.String(flags2.JWTSecretFlag.Name)
	}

	if ctx.IsSet(flags2.EnablePersonal.Name) {
		cfg.EnablePersonal = true
	}

	if ctx.IsSet(flags2.ExternalSignerFlag.Name) {
		cfg.ExternalSigner = ctx.String(flags2.ExternalSignerFlag.Name)
	}

	if ctx.IsSet(flags2.KeyStoreDirFlag.Name) {
		cfg.KeyStoreDir = ctx.String(flags2.KeyStoreDirFlag.Name)
	}
	if ctx.IsSet(flags2.DeveloperFlag.Name) {
		cfg.UseLightweightKDF = true
	}
	if ctx.IsSet(flags2.LightKDFFlag.Name) {
		cfg.UseLightweightKDF = ctx.Bool(flags2.LightKDFFlag.Name)
	}
	if ctx.IsSet(NoUSBFlag.Name) || cfg.NoUSB {
		log.Warn("Option nousb is deprecated and USB is deactivated by default. Use --usb to enable")
	}
	if ctx.IsSet(flags2.USBFlag.Name) {
		cfg.USB = ctx.Bool(flags2.USBFlag.Name)
	}
	if ctx.IsSet(flags2.InsecureUnlockAllowedFlag.Name) {
		cfg.InsecureUnlockAllowed = ctx.Bool(flags2.InsecureUnlockAllowedFlag.Name)
	}
	if ctx.IsSet(flags2.DBEngineFlag.Name) {
		dbEngine := ctx.String(flags2.DBEngineFlag.Name)
		if dbEngine != "leveldb" && dbEngine != "pebble" {
			Fatalf("Invalid choice for db.engine '%s', allowed 'leveldb' or 'pebble'", dbEngine)
		}
		log.Info(fmt.Sprintf("Using %s as db engine", dbEngine))
		cfg.DBEngine = dbEngine
	}
	// deprecation notice for log debug flags (TODO: find a more appropriate place to put these?)
	if ctx.IsSet(LogBacktraceAtFlag.Name) {
		log.Warn("log.backtrace flag is deprecated")
	}
	if ctx.IsSet(LogDebugFlag.Name) {
		log.Warn("log.debug flag is deprecated")
	}
}

func setSmartCard(ctx *cli.Context, cfg *node.Config) {
	// Skip enabling smartcards if no path is set
	path := ctx.String(flags2.SmartCardDaemonPathFlag.Name)
	if path == "" {
		return
	}
	// Sanity check that the smartcard path is valid
	fi, err := os.Stat(path)
	if err != nil {
		log.Info("Smartcard socket not found, disabling", "err", err)
		return
	}
	if fi.Mode()&os.ModeType != os.ModeSocket {
		log.Error("Invalid smartcard daemon path", "path", path, "type", fi.Mode().String())
		return
	}
	// Smartcard daemon path exists and is a socket, enable it
	cfg.SmartCardDaemonPath = path
}

func SetDataDir(ctx *cli.Context, cfg *node.Config) {
	switch {
	case ctx.IsSet(flags2.DataDirFlag.Name):
		cfg.DataDir = ctx.String(flags2.DataDirFlag.Name)
	case ctx.Bool(flags2.DeveloperFlag.Name):
		cfg.DataDir = "" // unless explicitly requested, use memory databases
	case ctx.Bool(flags2.SepoliaFlag.Name) && cfg.DataDir == node.DefaultDataDir():
		cfg.DataDir = filepath.Join(node.DefaultDataDir(), "sepolia")
	case ctx.Bool(flags2.HoleskyFlag.Name) && cfg.DataDir == node.DefaultDataDir():
		cfg.DataDir = filepath.Join(node.DefaultDataDir(), "holesky")
	}
}

func setGPO(ctx *cli.Context, cfg *gasprice.Config) {
	if ctx.IsSet(flags2.GpoBlocksFlag.Name) {
		cfg.Blocks = ctx.Int(flags2.GpoBlocksFlag.Name)
	}
	if ctx.IsSet(flags2.GpoPercentileFlag.Name) {
		cfg.Percentile = ctx.Int(flags2.GpoPercentileFlag.Name)
	}
	if ctx.IsSet(flags2.GpoMaxGasPriceFlag.Name) {
		cfg.MaxPrice = big.NewInt(ctx.Int64(flags2.GpoMaxGasPriceFlag.Name))
	}
	if ctx.IsSet(flags2.GpoIgnoreGasPriceFlag.Name) {
		cfg.IgnorePrice = big.NewInt(ctx.Int64(flags2.GpoIgnoreGasPriceFlag.Name))
	}
}

func setTxPool(ctx *cli.Context, cfg *legacypool.Config) {
	if ctx.IsSet(flags2.TxPoolLocalsFlag.Name) {
		locals := strings.Split(ctx.String(flags2.TxPoolLocalsFlag.Name), ",")
		for _, account := range locals {
			if trimmed := strings.TrimSpace(account); !common.IsHexAddress(trimmed) {
				Fatalf("Invalid account in --txpool.locals: %s", trimmed)
			} else {
				cfg.Locals = append(cfg.Locals, common.HexToAddress(account))
			}
		}
	}
	if ctx.IsSet(flags2.TxPoolNoLocalsFlag.Name) {
		cfg.NoLocals = ctx.Bool(flags2.TxPoolNoLocalsFlag.Name)
	}
	if ctx.IsSet(flags2.TxPoolJournalFlag.Name) {
		cfg.Journal = ctx.String(flags2.TxPoolJournalFlag.Name)
	}
	if ctx.IsSet(flags2.TxPoolRejournalFlag.Name) {
		cfg.Rejournal = ctx.Duration(flags2.TxPoolRejournalFlag.Name)
	}
	if ctx.IsSet(flags2.TxPoolPriceLimitFlag.Name) {
		cfg.PriceLimit = ctx.Uint64(flags2.TxPoolPriceLimitFlag.Name)
	}
	if ctx.IsSet(flags2.TxPoolPriceBumpFlag.Name) {
		cfg.PriceBump = ctx.Uint64(flags2.TxPoolPriceBumpFlag.Name)
	}
	if ctx.IsSet(flags2.TxPoolAccountSlotsFlag.Name) {
		cfg.AccountSlots = ctx.Uint64(flags2.TxPoolAccountSlotsFlag.Name)
	}
	if ctx.IsSet(flags2.TxPoolGlobalSlotsFlag.Name) {
		cfg.GlobalSlots = ctx.Uint64(flags2.TxPoolGlobalSlotsFlag.Name)
	}
	if ctx.IsSet(flags2.TxPoolAccountQueueFlag.Name) {
		cfg.AccountQueue = ctx.Uint64(flags2.TxPoolAccountQueueFlag.Name)
	}
	if ctx.IsSet(flags2.TxPoolGlobalQueueFlag.Name) {
		cfg.GlobalQueue = ctx.Uint64(flags2.TxPoolGlobalQueueFlag.Name)
	}
	if ctx.IsSet(flags2.TxPoolLifetimeFlag.Name) {
		cfg.Lifetime = ctx.Duration(flags2.TxPoolLifetimeFlag.Name)
	}
}

func setBlobPool(ctx *cli.Context, cfg *blobpool.Config) {
	if ctx.IsSet(flags2.BlobPoolDataDirFlag.Name) {
		cfg.Datadir = ctx.String(flags2.BlobPoolDataDirFlag.Name)
	}
	if ctx.IsSet(flags2.BlobPoolDataCapFlag.Name) {
		cfg.Datacap = ctx.Uint64(flags2.BlobPoolDataCapFlag.Name)
	}
	if ctx.IsSet(flags2.BlobPoolPriceBumpFlag.Name) {
		cfg.PriceBump = ctx.Uint64(flags2.BlobPoolPriceBumpFlag.Name)
	}
}

func setMiner(ctx *cli.Context, cfg *miner.Config) {
	if ctx.Bool(MiningEnabledFlag.Name) {
		log.Warn("The flag --mine is deprecated and will be removed")
	}
	if ctx.IsSet(flags2.MinerExtraDataFlag.Name) {
		cfg.ExtraData = []byte(ctx.String(flags2.MinerExtraDataFlag.Name))
	}
	if ctx.IsSet(flags2.MinerGasLimitFlag.Name) {
		cfg.GasCeil = ctx.Uint64(flags2.MinerGasLimitFlag.Name)
	}
	if ctx.IsSet(flags2.MinerGasPriceFlag.Name) {
		cfg.GasPrice = flags.GlobalBig(ctx, flags2.MinerGasPriceFlag.Name)
	}
	if ctx.IsSet(flags2.MinerRecommitIntervalFlag.Name) {
		cfg.Recommit = ctx.Duration(flags2.MinerRecommitIntervalFlag.Name)
	}
	if ctx.IsSet(MinerNewPayloadTimeoutFlag.Name) {
		log.Warn("The flag --miner.newpayload-timeout is deprecated and will be removed, please use --miner.recommit")
		cfg.Recommit = ctx.Duration(MinerNewPayloadTimeoutFlag.Name)
	}
}

func setRequiredBlocks(ctx *cli.Context, cfg *ethconfig.Config) {
	requiredBlocks := ctx.String(flags2.EthRequiredBlocksFlag.Name)
	if requiredBlocks == "" {
		if ctx.IsSet(LegacyWhitelistFlag.Name) {
			log.Warn("The flag --whitelist is deprecated and will be removed, please use --eth.requiredblocks")
			requiredBlocks = ctx.String(LegacyWhitelistFlag.Name)
		} else {
			return
		}
	}
	cfg.RequiredBlocks = make(map[uint64]common.Hash)
	for _, entry := range strings.Split(requiredBlocks, ",") {
		parts := strings.Split(entry, "=")
		if len(parts) != 2 {
			Fatalf("Invalid required block entry: %s", entry)
		}
		number, err := strconv.ParseUint(parts[0], 0, 64)
		if err != nil {
			Fatalf("Invalid required block number %s: %v", parts[0], err)
		}
		var hash common.Hash
		if err = hash.UnmarshalText([]byte(parts[1])); err != nil {
			Fatalf("Invalid required block hash %s: %v", parts[1], err)
		}
		cfg.RequiredBlocks[number] = hash
	}
}

// CheckExclusive verifies that only a single instance of the provided flags was
// set by the user. Each flag might optionally be followed by a string type to
// specialize it further.
func CheckExclusive(ctx *cli.Context, args ...interface{}) {
	set := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		// Make sure the next argument is a flag and skip if not set
		flag, ok := args[i].(cli.Flag)
		if !ok {
			panic(fmt.Sprintf("invalid argument, not cli.Flag type: %T", args[i]))
		}
		// Check if next arg extends current and expand its name if so
		name := flag.Names()[0]

		if i+1 < len(args) {
			switch option := args[i+1].(type) {
			case string:
				// Extended flag check, make sure value set doesn't conflict with passed in option
				if ctx.String(flag.Names()[0]) == option {
					name += "=" + option
					set = append(set, "--"+name)
				}
				// shift arguments and continue
				i++
				continue

			case cli.Flag:
			default:
				panic(fmt.Sprintf("invalid argument, not cli.Flag or string extension: %T", args[i+1]))
			}
		}
		// Mark the flag if it's set
		if ctx.IsSet(flag.Names()[0]) {
			set = append(set, "--"+name)
		}
	}
	if len(set) > 1 {
		Fatalf("Flags %v can't be used at the same time", strings.Join(set, ", "))
	}
}

// SetEthConfig applies eth-related command line flags to the config.
func SetEthConfig(ctx *cli.Context, stack *node.Node, cfg *ethconfig.Config) {
	// Avoid conflicting network flags
	CheckExclusive(ctx, flags2.MainnetFlag, flags2.DeveloperFlag, flags2.SepoliaFlag, flags2.HoleskyFlag)
	CheckExclusive(ctx, flags2.DeveloperFlag, flags2.ExternalSignerFlag) // Can't use both ephemeral unlocked and external signer

	// Set configurations from CLI flags
	setEtherbase(ctx, cfg)
	setGPO(ctx, &cfg.GPO)
	setTxPool(ctx, &cfg.TxPool)
	setBlobPool(ctx, &cfg.BlobPool)
	setMiner(ctx, &cfg.Miner)
	setRequiredBlocks(ctx, cfg)
	setLes(ctx, cfg)

	// Cap the cache allowance and tune the garbage collector
	mem, err := gopsutil.VirtualMemory()
	if err == nil {
		if 32<<(^uintptr(0)>>63) == 32 && mem.Total > 2*1024*1024*1024 {
			log.Warn("Lowering memory allowance on 32bit arch", "available", mem.Total/1024/1024, "addressable", 2*1024)
			mem.Total = 2 * 1024 * 1024 * 1024
		}
		allowance := int(mem.Total / 1024 / 1024 / 3)
		if cache := ctx.Int(flags2.CacheFlag.Name); cache > allowance {
			log.Warn("Sanitizing cache to Go's GC limits", "provided", cache, "updated", allowance)
			ctx.Set(flags2.CacheFlag.Name, strconv.Itoa(allowance))
		}
	}
	// Ensure Go's GC ignores the database cache for trigger percentage
	cache := ctx.Int(flags2.CacheFlag.Name)
	gogc := math.Max(20, math.Min(100, 100/(float64(cache)/1024)))

	log.Debug("Sanitizing Go's GC trigger", "percent", int(gogc))
	godebug.SetGCPercent(int(gogc))

	if ctx.IsSet(flags2.SyncTargetFlag.Name) {
		cfg.SyncMode = downloader.FullSync // dev sync target forces full sync
	} else if ctx.IsSet(flags2.SyncModeFlag.Name) {
		cfg.SyncMode = *flags.GlobalTextMarshaler(ctx, flags2.SyncModeFlag.Name).(*downloader.SyncMode)
	}
	if ctx.IsSet(flags2.NetworkIdFlag.Name) {
		cfg.NetworkId = ctx.Uint64(flags2.NetworkIdFlag.Name)
	}
	if ctx.IsSet(flags2.CacheFlag.Name) || ctx.IsSet(flags2.CacheDatabaseFlag.Name) {
		cfg.DatabaseCache = ctx.Int(flags2.CacheFlag.Name) * ctx.Int(flags2.CacheDatabaseFlag.Name) / 100
	}
	cfg.DatabaseHandles = MakeDatabaseHandles(ctx.Int(flags2.FDLimitFlag.Name))
	if ctx.IsSet(flags2.AncientFlag.Name) {
		cfg.DatabaseFreezer = ctx.String(flags2.AncientFlag.Name)
	}

	if gcmode := ctx.String(flags2.GCModeFlag.Name); gcmode != "full" && gcmode != "archive" {
		Fatalf("--%s must be either 'full' or 'archive'", flags2.GCModeFlag.Name)
	}
	if ctx.IsSet(flags2.GCModeFlag.Name) {
		cfg.NoPruning = ctx.String(flags2.GCModeFlag.Name) == "archive"
	}
	if ctx.IsSet(flags2.CacheNoPrefetchFlag.Name) {
		cfg.NoPrefetch = ctx.Bool(flags2.CacheNoPrefetchFlag.Name)
	}
	// Read the value from the flag no matter if it's set or not.
	cfg.Preimages = ctx.Bool(flags2.CachePreimagesFlag.Name)
	if cfg.NoPruning && !cfg.Preimages {
		cfg.Preimages = true
		log.Info("Enabling recording of key preimages since archive mode is used")
	}
	if ctx.IsSet(flags2.StateHistoryFlag.Name) {
		cfg.StateHistory = ctx.Uint64(flags2.StateHistoryFlag.Name)
	}
	if ctx.IsSet(flags2.StateSchemeFlag.Name) {
		cfg.StateScheme = ctx.String(flags2.StateSchemeFlag.Name)
	}
	// Parse transaction history flag, if user is still using legacy config
	// file with 'TxLookupLimit' configured, copy the value to 'TransactionHistory'.
	if cfg.TransactionHistory == ethconfig.Defaults.TransactionHistory && cfg.TxLookupLimit != ethconfig.Defaults.TxLookupLimit {
		log.Warn("The config option 'TxLookupLimit' is deprecated and will be removed, please use 'TransactionHistory'")
		cfg.TransactionHistory = cfg.TxLookupLimit
	}
	if ctx.IsSet(flags2.TransactionHistoryFlag.Name) {
		cfg.TransactionHistory = ctx.Uint64(flags2.TransactionHistoryFlag.Name)
	} else if ctx.IsSet(TxLookupLimitFlag.Name) {
		log.Warn("The flag --txlookuplimit is deprecated and will be removed, please use --history.transactions")
		cfg.TransactionHistory = ctx.Uint64(TxLookupLimitFlag.Name)
	}
	if ctx.String(flags2.GCModeFlag.Name) == "archive" && cfg.TransactionHistory != 0 {
		cfg.TransactionHistory = 0
		log.Warn("Disabled transaction unindexing for archive node")

		cfg.StateScheme = rawdb.HashScheme
		log.Warn("Forcing hash state-scheme for archive mode")
	}
	if ctx.IsSet(flags2.CacheFlag.Name) || ctx.IsSet(flags2.CacheTrieFlag.Name) {
		cfg.TrieCleanCache = ctx.Int(flags2.CacheFlag.Name) * ctx.Int(flags2.CacheTrieFlag.Name) / 100
	}
	if ctx.IsSet(flags2.CacheFlag.Name) || ctx.IsSet(flags2.CacheGCFlag.Name) {
		cfg.TrieDirtyCache = ctx.Int(flags2.CacheGCFlag.Name) * ctx.Int(flags2.CacheGCFlag.Name) / 100
	}
	if ctx.IsSet(flags2.CacheFlag.Name) || ctx.IsSet(flags2.CacheSnapshotFlag.Name) {
		cfg.SnapshotCache = ctx.Int(flags2.CacheFlag.Name) * ctx.Int(flags2.CacheSnapshotFlag.Name) / 100
	}
	if ctx.IsSet(flags2.CacheLogSizeFlag.Name) {
		cfg.FilterLogCacheSize = ctx.Int(flags2.CacheLogSizeFlag.Name)
	}
	if !ctx.Bool(flags2.SnapshotFlag.Name) || cfg.SnapshotCache == 0 {
		// If snap-sync is requested, this flag is also required
		if cfg.SyncMode == downloader.SnapSync {
			if !ctx.Bool(flags2.SnapshotFlag.Name) {
				log.Warn("Snap sync requested, enabling --snapshot")
			}
			if cfg.SnapshotCache == 0 {
				log.Warn("Snap sync requested, resetting --cache.snapshot")
				cfg.SnapshotCache = ctx.Int(flags2.CacheFlag.Name) * flags2.CacheSnapshotFlag.Value / 100
			}
		} else {
			cfg.TrieCleanCache += cfg.SnapshotCache
			cfg.SnapshotCache = 0 // Disabled
		}
	}
	if ctx.IsSet(flags2.DocRootFlag.Name) {
		cfg.DocRoot = ctx.String(flags2.DocRootFlag.Name)
	}
	if ctx.IsSet(flags2.VMEnableDebugFlag.Name) {
		// TODO(fjl): force-enable this in --dev mode
		cfg.EnablePreimageRecording = ctx.Bool(flags2.VMEnableDebugFlag.Name)
	}

	if ctx.IsSet(flags2.RPCGlobalGasCapFlag.Name) {
		cfg.RPCGasCap = ctx.Uint64(flags2.RPCGlobalGasCapFlag.Name)
	}
	if cfg.RPCGasCap != 0 {
		log.Info("Set global gas cap", "cap", cfg.RPCGasCap)
	} else {
		log.Info("Global gas cap disabled")
	}
	if ctx.IsSet(flags2.RPCGlobalEVMTimeoutFlag.Name) {
		cfg.RPCEVMTimeout = ctx.Duration(flags2.RPCGlobalEVMTimeoutFlag.Name)
	}
	if ctx.IsSet(flags2.RPCGlobalTxFeeCapFlag.Name) {
		cfg.RPCTxFeeCap = ctx.Float64(flags2.RPCGlobalTxFeeCapFlag.Name)
	}
	if ctx.IsSet(flags2.NoDiscoverFlag.Name) {
		cfg.EthDiscoveryURLs, cfg.SnapDiscoveryURLs = []string{}, []string{}
	} else if ctx.IsSet(flags2.DNSDiscoveryFlag.Name) {
		urls := ctx.String(flags2.DNSDiscoveryFlag.Name)
		if urls == "" {
			cfg.EthDiscoveryURLs = []string{}
		} else {
			cfg.EthDiscoveryURLs = SplitAndTrim(urls)
		}
	}
	// Override any default configs for hard coded networks.
	switch {
	case ctx.Bool(flags2.MainnetFlag.Name):
		if !ctx.IsSet(flags2.NetworkIdFlag.Name) {
			cfg.NetworkId = 1
		}
		cfg.Genesis = core.DefaultGenesisBlock()
		SetDNSDiscoveryDefaults(cfg, params.MainnetGenesisHash)
	case ctx.Bool(flags2.HoleskyFlag.Name):
		if !ctx.IsSet(flags2.NetworkIdFlag.Name) {
			cfg.NetworkId = 17000
		}
		cfg.Genesis = core.DefaultHoleskyGenesisBlock()
		SetDNSDiscoveryDefaults(cfg, params.HoleskyGenesisHash)
	case ctx.Bool(flags2.SepoliaFlag.Name):
		if !ctx.IsSet(flags2.NetworkIdFlag.Name) {
			cfg.NetworkId = 11155111
		}
		cfg.Genesis = core.DefaultSepoliaGenesisBlock()
		SetDNSDiscoveryDefaults(cfg, params.SepoliaGenesisHash)
	case ctx.Bool(flags2.DeveloperFlag.Name):
		if !ctx.IsSet(flags2.NetworkIdFlag.Name) {
			cfg.NetworkId = 1337
		}
		cfg.SyncMode = downloader.FullSync
		// Create new developer account or reuse existing one
		var (
			developer  accounts.Account
			passphrase string
			err        error
		)
		if list := MakePasswordList(ctx); len(list) > 0 {
			// Just take the first value. Although the function returns a possible multiple values and
			// some usages iterate through them as attempts, that doesn't make sense in this setting,
			// when we're definitely concerned with only one account.
			passphrase = list[0]
		}

		// Unlock the developer account by local keystore.
		var ks *keystore.KeyStore
		if keystores := stack.AccountManager().Backends(keystore.KeyStoreType); len(keystores) > 0 {
			ks = keystores[0].(*keystore.KeyStore)
		}
		if ks == nil {
			Fatalf("Keystore is not available")
		}

		// Figure out the dev account address.
		// setEtherbase has been called above, configuring the miner address from command line flags.
		if cfg.Miner.PendingFeeRecipient != (common.Address{}) {
			developer = accounts.Account{Address: cfg.Miner.PendingFeeRecipient}
		} else if accs := ks.Accounts(); len(accs) > 0 {
			developer = ks.Accounts()[0]
		} else {
			developer, err = ks.NewAccount(passphrase)
			if err != nil {
				Fatalf("Failed to create developer account: %v", err)
			}
		}
		// Make sure the address is configured as fee recipient, otherwise
		// the miner will fail to start.
		cfg.Miner.PendingFeeRecipient = developer.Address

		if err := ks.Unlock(developer, passphrase); err != nil {
			Fatalf("Failed to unlock developer account: %v", err)
		}
		log.Info("Using developer account", "address", developer.Address)

		// Create a new developer genesis block or reuse existing one
		cfg.Genesis = core.DeveloperGenesisBlock(ctx.Uint64(flags2.DeveloperGasLimitFlag.Name), &developer.Address)
		if ctx.IsSet(flags2.DataDirFlag.Name) {
			chaindb := tryMakeReadOnlyDatabase(ctx, stack)
			if rawdb.ReadCanonicalHash(chaindb, 0) != (common.Hash{}) {
				cfg.Genesis = nil // fallback to db content

				//validate genesis has PoS enabled in block 0
				genesis, err := core.ReadGenesis(chaindb)
				if err != nil {
					Fatalf("Could not read genesis from database: %v", err)
				}
				if !genesis.Config.TerminalTotalDifficultyPassed {
					Fatalf("Bad developer-mode genesis configuration: terminalTotalDifficultyPassed must be true")
				}
				if genesis.Config.TerminalTotalDifficulty == nil {
					Fatalf("Bad developer-mode genesis configuration: terminalTotalDifficulty must be specified")
				} else if genesis.Config.TerminalTotalDifficulty.Cmp(big.NewInt(0)) != 0 {
					Fatalf("Bad developer-mode genesis configuration: terminalTotalDifficulty must be 0")
				}
				if genesis.Difficulty.Cmp(big.NewInt(0)) != 0 {
					Fatalf("Bad developer-mode genesis configuration: difficulty must be 0")
				}
			}
			chaindb.Close()
		}
		if !ctx.IsSet(flags2.MinerGasPriceFlag.Name) {
			cfg.Miner.GasPrice = big.NewInt(1)
		}
	default:
		if cfg.NetworkId == 1 {
			SetDNSDiscoveryDefaults(cfg, params.MainnetGenesisHash)
		}
	}
	// Set any dangling config values
	if ctx.String(flags2.CryptoKZGFlag.Name) != "gokzg" && ctx.String(flags2.CryptoKZGFlag.Name) != "ckzg" {
		Fatalf("--%s flag must be 'gokzg' or 'ckzg'", flags2.CryptoKZGFlag.Name)
	}
	log.Info("Initializing the KZG library", "backend", ctx.String(flags2.CryptoKZGFlag.Name))
	if err := kzg4844.UseCKZG(ctx.String(flags2.CryptoKZGFlag.Name) == "ckzg"); err != nil {
		Fatalf("Failed to set KZG library implementation to %s: %v", ctx.String(flags2.CryptoKZGFlag.Name), err)
	}
	// VM tracing config.
	if ctx.IsSet(flags2.VMTraceFlag.Name) {
		if name := ctx.String(flags2.VMTraceFlag.Name); name != "" {
			cfg.VMTrace = name
			cfg.VMTraceJsonConfig = ctx.String(flags2.VMTraceJsonConfigFlag.Name)
		}
	}
}

// SetDNSDiscoveryDefaults configures DNS discovery with the given URL if
// no URLs are set.
func SetDNSDiscoveryDefaults(cfg *ethconfig.Config, genesis common.Hash) {
	if cfg.EthDiscoveryURLs != nil {
		return // already set through flags/config
	}
	protocol := "all"
	if url := params.KnownDNSNetwork(genesis, protocol); url != "" {
		cfg.EthDiscoveryURLs = []string{url}
		cfg.SnapDiscoveryURLs = cfg.EthDiscoveryURLs
	}
}

// RegisterEthService adds an Ethereum client to the stack.
// The second return value is the full node instance.
func RegisterEthService(stack *node.Node, cfg *ethconfig.Config) (*eth.EthAPIBackend, *eth.Ethereum) {
	backend, err := eth.New(stack, cfg)
	if err != nil {
		Fatalf("Failed to register the Ethereum service: %v", err)
	}
	stack.RegisterAPIs(tracers.APIs(backend.APIBackend))
	return backend.APIBackend, backend
}

// RegisterEthStatsService configures the Ethereum Stats daemon and adds it to the node.
func RegisterEthStatsService(stack *node.Node, backend *eth.EthAPIBackend, url string) {
	if err := ethstats.New(stack, backend, backend.Engine(), url); err != nil {
		Fatalf("Failed to register the Ethereum Stats service: %v", err)
	}
}

// RegisterFullSyncTester adds the full-sync tester service into node.
func RegisterFullSyncTester(stack *node.Node, eth *eth.Ethereum, target common.Hash) {
	catalyst.RegisterFullSyncTester(stack, eth, target)
	log.Info("Registered full-sync tester", "hash", target)
}

func SetupMetrics(ctx *cli.Context) {
	if metrics.Enabled {
		log.Info("Enabling metrics collection")

		var (
			enableExport   = ctx.Bool(flags2.MetricsEnableInfluxDBFlag.Name)
			enableExportV2 = ctx.Bool(flags2.MetricsEnableInfluxDBV2Flag.Name)
		)

		if enableExport || enableExportV2 {
			CheckExclusive(ctx, flags2.MetricsEnableInfluxDBFlag, flags2.MetricsEnableInfluxDBV2Flag)

			v1FlagIsSet := ctx.IsSet(flags2.MetricsInfluxDBUsernameFlag.Name) ||
				ctx.IsSet(flags2.MetricsInfluxDBPasswordFlag.Name)

			v2FlagIsSet := ctx.IsSet(flags2.MetricsInfluxDBTokenFlag.Name) ||
				ctx.IsSet(flags2.MetricsInfluxDBOrganizationFlag.Name) ||
				ctx.IsSet(flags2.MetricsInfluxDBBucketFlag.Name)

			if enableExport && v2FlagIsSet {
				Fatalf("Flags --influxdb.metrics.organization, --influxdb.metrics.token, --influxdb.metrics.bucket are only available for influxdb-v2")
			} else if enableExportV2 && v1FlagIsSet {
				Fatalf("Flags --influxdb.metrics.username, --influxdb.metrics.password are only available for influxdb-v1")
			}
		}

		var (
			endpoint = ctx.String(flags2.MetricsInfluxDBEndpointFlag.Name)
			database = ctx.String(flags2.MetricsInfluxDBDatabaseFlag.Name)
			username = ctx.String(flags2.MetricsInfluxDBUsernameFlag.Name)
			password = ctx.String(flags2.MetricsInfluxDBPasswordFlag.Name)

			token        = ctx.String(flags2.MetricsInfluxDBTokenFlag.Name)
			bucket       = ctx.String(flags2.MetricsInfluxDBBucketFlag.Name)
			organization = ctx.String(flags2.MetricsInfluxDBOrganizationFlag.Name)
		)

		if enableExport {
			tagsMap := SplitTagsFlag(ctx.String(flags2.MetricsInfluxDBTagsFlag.Name))

			log.Info("Enabling metrics export to InfluxDB")

			go influxdb.InfluxDBWithTags(metrics.DefaultRegistry, 10*time.Second, endpoint, database, username, password, "geth.", tagsMap)
		} else if enableExportV2 {
			tagsMap := SplitTagsFlag(ctx.String(flags2.MetricsInfluxDBTagsFlag.Name))

			log.Info("Enabling metrics export to InfluxDB (v2)")

			go influxdb.InfluxDBV2WithTags(metrics.DefaultRegistry, 10*time.Second, endpoint, token, bucket, organization, "geth.", tagsMap)
		}

		if ctx.IsSet(flags2.MetricsHTTPFlag.Name) {
			address := net.JoinHostPort(ctx.String(flags2.MetricsHTTPFlag.Name), fmt.Sprintf("%d", ctx.Int(flags2.MetricsPortFlag.Name)))
			log.Info("Enabling stand-alone metrics HTTP endpoint", "address", address)
			exp.Setup(address)
		} else if ctx.IsSet(flags2.MetricsPortFlag.Name) {
			log.Warn(fmt.Sprintf("--%s specified without --%s, metrics server will not start.", flags2.MetricsPortFlag.Name, flags2.MetricsHTTPFlag.Name))
		}
	}
}

func SplitTagsFlag(tagsFlag string) map[string]string {
	tags := strings.Split(tagsFlag, ",")
	tagsMap := map[string]string{}

	for _, t := range tags {
		if t != "" {
			kv := strings.Split(t, "=")

			if len(kv) == 2 {
				tagsMap[kv[0]] = kv[1]
			}
		}
	}

	return tagsMap
}

// MakeChainDatabase opens a database using the flags passed to the client and will hard crash if it fails.
func MakeChainDatabase(ctx *cli.Context, stack *node.Node, readonly bool) ethdb.Database {
	var (
		cache   = ctx.Int(flags2.CacheFlag.Name) * ctx.Int(flags2.CacheDatabaseFlag.Name) / 100
		handles = MakeDatabaseHandles(ctx.Int(flags2.FDLimitFlag.Name))
		err     error
		chainDb ethdb.Database
	)
	switch {
	case ctx.IsSet(flags2.RemoteDBFlag.Name):
		log.Info("Using remote db", "url", ctx.String(flags2.RemoteDBFlag.Name), "headers", len(ctx.StringSlice(flags2.HttpHeaderFlag.Name)))
		client, err := DialRPCWithHeaders(ctx.String(flags2.RemoteDBFlag.Name), ctx.StringSlice(flags2.HttpHeaderFlag.Name))
		if err != nil {
			break
		}
		chainDb = remotedb.New(client)
	default:
		chainDb, err = stack.OpenDatabaseWithFreezer("chaindata", cache, handles, ctx.String(flags2.AncientFlag.Name), "", readonly)
	}
	if err != nil {
		Fatalf("Could not open database: %v", err)
	}
	return chainDb
}

// tryMakeReadOnlyDatabase try to open the chain database in read-only mode,
// or fallback to write mode if the database is not initialized.
func tryMakeReadOnlyDatabase(ctx *cli.Context, stack *node.Node) ethdb.Database {
	// If the database doesn't exist we need to open it in write-mode to allow
	// the engine to create files.
	readonly := true
	if rawdb.PreexistingDatabase(stack.ResolvePath("chaindata")) == "" {
		readonly = false
	}
	return MakeChainDatabase(ctx, stack, readonly)
}

func IsNetworkPreset(ctx *cli.Context) bool {
	for _, flag := range flags2.NetworkFlags {
		bFlag, _ := flag.(*cli.BoolFlag)
		if ctx.IsSet(bFlag.Name) {
			return true
		}
	}
	return false
}

func DialRPCWithHeaders(endpoint string, headers []string) (*rpc.Client, error) {
	if endpoint == "" {
		return nil, errors.New("endpoint must be specified")
	}
	if strings.HasPrefix(endpoint, "rpc:") || strings.HasPrefix(endpoint, "ipc:") {
		// Backwards compatibility with geth < 1.5 which required
		// these prefixes.
		endpoint = endpoint[4:]
	}
	var opts []rpc.ClientOption
	if len(headers) > 0 {
		customHeaders := make(http.Header)
		for _, h := range headers {
			kv := strings.Split(h, ":")
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid http header directive: %q", h)
			}
			customHeaders.Add(kv[0], kv[1])
		}
		opts = append(opts, rpc.WithHeaders(customHeaders))
	}
	return rpc.DialOptions(context.Background(), endpoint, opts...)
}

func MakeGenesis(ctx *cli.Context) *core.Genesis {
	var genesis *core.Genesis
	switch {
	case ctx.Bool(flags2.MainnetFlag.Name):
		genesis = core.DefaultGenesisBlock()
	case ctx.Bool(flags2.HoleskyFlag.Name):
		genesis = core.DefaultHoleskyGenesisBlock()
	case ctx.Bool(flags2.SepoliaFlag.Name):
		genesis = core.DefaultSepoliaGenesisBlock()
	case ctx.Bool(flags2.DeveloperFlag.Name):
		Fatalf("Developer chains are ephemeral")
	}
	return genesis
}

// MakeChain creates a chain manager from set command line flags.
func MakeChain(ctx *cli.Context, stack *node.Node, readonly bool) (*core.BlockChain, ethdb.Database) {
	var (
		gspec   = MakeGenesis(ctx)
		chainDb = MakeChainDatabase(ctx, stack, readonly)
	)
	config, err := core.LoadChainConfig(chainDb, gspec)
	if err != nil {
		Fatalf("%v", err)
	}
	engine, err := ethconfig.CreateConsensusEngine(config, chainDb)
	if err != nil {
		Fatalf("%v", err)
	}
	if gcmode := ctx.String(flags2.GCModeFlag.Name); gcmode != "full" && gcmode != "archive" {
		Fatalf("--%s must be either 'full' or 'archive'", flags2.GCModeFlag.Name)
	}
	scheme, err := rawdb.ParseStateScheme(ctx.String(flags2.StateSchemeFlag.Name), chainDb)
	if err != nil {
		Fatalf("%v", err)
	}
	cache := &core.CacheConfig{
		TrieCleanLimit:      ethconfig.Defaults.TrieCleanCache,
		TrieCleanNoPrefetch: ctx.Bool(flags2.CacheNoPrefetchFlag.Name),
		TrieDirtyLimit:      ethconfig.Defaults.TrieDirtyCache,
		TrieDirtyDisabled:   ctx.String(flags2.GCModeFlag.Name) == "archive",
		TrieTimeLimit:       ethconfig.Defaults.TrieTimeout,
		SnapshotLimit:       ethconfig.Defaults.SnapshotCache,
		Preimages:           ctx.Bool(flags2.CachePreimagesFlag.Name),
		StateScheme:         scheme,
		StateHistory:        ctx.Uint64(flags2.StateHistoryFlag.Name),
	}
	if cache.TrieDirtyDisabled && !cache.Preimages {
		cache.Preimages = true
		log.Info("Enabling recording of key preimages since archive mode is used")
	}
	if !ctx.Bool(flags2.SnapshotFlag.Name) {
		cache.SnapshotLimit = 0 // Disabled
	}
	// If we're in readonly, do not bother generating snapshot data.
	if readonly {
		cache.SnapshotNoBuild = true
	}

	if ctx.IsSet(flags2.CacheFlag.Name) || ctx.IsSet(flags2.CacheTrieFlag.Name) {
		cache.TrieCleanLimit = ctx.Int(flags2.CacheFlag.Name) * ctx.Int(flags2.CacheTrieFlag.Name) / 100
	}
	if ctx.IsSet(flags2.CacheFlag.Name) || ctx.IsSet(flags2.CacheGCFlag.Name) {
		cache.TrieDirtyLimit = ctx.Int(flags2.CacheFlag.Name) * ctx.Int(flags2.CacheGCFlag.Name) / 100
	}
	vmcfg := vm.Config{
		EnablePreimageRecording: ctx.Bool(flags2.VMEnableDebugFlag.Name),
	}
	if ctx.IsSet(flags2.VMTraceFlag.Name) {
		if name := ctx.String(flags2.VMTraceFlag.Name); name != "" {
			config := json.RawMessage(ctx.String(flags2.VMTraceJsonConfigFlag.Name))
			t, err := tracers.LiveDirectory.New(name, config)
			if err != nil {
				Fatalf("Failed to create tracer %q: %v", name, err)
			}
			vmcfg.Tracer = t
		}
	}
	// Disable transaction indexing/unindexing by default.
	chain, err := core.NewBlockChain(chainDb, cache, gspec, nil, engine, vmcfg, nil)
	if err != nil {
		Fatalf("Can't create BlockChain: %v", err)
	}

	return chain, chainDb
}

// MakeConsolePreloads retrieves the absolute paths for the console JavaScript
// scripts to preload before starting.
func MakeConsolePreloads(ctx *cli.Context) []string {
	// Skip preloading if there's nothing to preload
	if ctx.String(flags2.PreloadJSFlag.Name) == "" {
		return nil
	}
	// Otherwise resolve absolute paths and return them
	var preloads []string

	for _, file := range strings.Split(ctx.String(flags2.PreloadJSFlag.Name), ",") {
		preloads = append(preloads, strings.TrimSpace(file))
	}
	return preloads
}

// MakeTrieDatabase constructs a trie database based on the configured scheme.
func MakeTrieDatabase(ctx *cli.Context, disk ethdb.Database, preimage bool, readOnly bool, isVerkle bool) *triedb.Database {
	config := &triedb.Config{
		Preimages: preimage,
		IsVerkle:  isVerkle,
	}
	scheme, err := rawdb.ParseStateScheme(ctx.String(flags2.StateSchemeFlag.Name), disk)
	if err != nil {
		Fatalf("%v", err)
	}
	if scheme == rawdb.HashScheme {
		// Read-only mode is not implemented in hash mode,
		// ignore the parameter silently. TODO(rjl493456442)
		// please config it if read mode is implemented.
		config.HashDB = hashdb.Defaults
		return triedb.NewDatabase(disk, config)
	}
	if readOnly {
		config.PathDB = pathdb.ReadOnly
	} else {
		config.PathDB = pathdb.Defaults
	}
	return triedb.NewDatabase(disk, config)
}
