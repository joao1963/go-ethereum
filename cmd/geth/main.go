// Copyright 2014 The go-ethereum Authors
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

// geth is a command-line client for Ethereum.
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/console/prompt"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/internal/debug"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/node"
	"go.uber.org/automaxprocs/maxprocs"

	// Force-load the tracer engines to trigger registration
	_ "github.com/ethereum/go-ethereum/eth/tracers/js"
	_ "github.com/ethereum/go-ethereum/eth/tracers/live"
	_ "github.com/ethereum/go-ethereum/eth/tracers/native"

	flags2 "github.com/ethereum/go-ethereum/cmd/utils/flags"
	"github.com/urfave/cli/v2"
)

const (
	clientIdentifier = "geth" // Client identifier to advertise over the network
)

var (
	// flags that configure the node
	nodeFlags = flags.Merge([]cli.Flag{
		flags2.IdentityFlag,
		flags2.UnlockedAccountFlag,
		flags2.PasswordFileFlag,
		flags2.BootnodesFlag,
		flags2.MinFreeDiskSpaceFlag,
		flags2.KeyStoreDirFlag,
		flags2.ExternalSignerFlag,
		utils.NoUSBFlag, // deprecated
		flags2.USBFlag,
		flags2.SmartCardDaemonPathFlag,
		flags2.OverrideCancun,
		flags2.OverrideVerkle,
		flags2.EnablePersonal,
		flags2.TxPoolLocalsFlag,
		flags2.TxPoolNoLocalsFlag,
		flags2.TxPoolJournalFlag,
		flags2.TxPoolRejournalFlag,
		flags2.TxPoolPriceLimitFlag,
		flags2.TxPoolPriceBumpFlag,
		flags2.TxPoolAccountSlotsFlag,
		flags2.TxPoolGlobalSlotsFlag,
		flags2.TxPoolAccountQueueFlag,
		flags2.TxPoolGlobalQueueFlag,
		flags2.TxPoolLifetimeFlag,
		flags2.BlobPoolDataDirFlag,
		flags2.BlobPoolDataCapFlag,
		flags2.BlobPoolPriceBumpFlag,
		flags2.SyncModeFlag,
		flags2.SyncTargetFlag,
		flags2.ExitWhenSyncedFlag,
		flags2.GCModeFlag,
		flags2.SnapshotFlag,
		utils.TxLookupLimitFlag, // deprecated
		flags2.TransactionHistoryFlag,
		flags2.StateHistoryFlag,
		utils.LightServeFlag,    // deprecated
		utils.LightIngressFlag,  // deprecated
		utils.LightEgressFlag,   // deprecated
		utils.LightMaxPeersFlag, // deprecated
		utils.LightNoPruneFlag,  // deprecated
		flags2.LightKDFFlag,
		utils.LightNoSyncServeFlag, // deprecated
		flags2.EthRequiredBlocksFlag,
		utils.LegacyWhitelistFlag, // deprecated
		flags2.BloomFilterSizeFlag,
		flags2.CacheFlag,
		flags2.CacheDatabaseFlag,
		flags2.CacheTrieFlag,
		utils.CacheTrieJournalFlag,   // deprecated
		utils.CacheTrieRejournalFlag, // deprecated
		flags2.CacheGCFlag,
		flags2.CacheSnapshotFlag,
		flags2.CacheNoPrefetchFlag,
		flags2.CachePreimagesFlag,
		flags2.CacheLogSizeFlag,
		flags2.FDLimitFlag,
		flags2.CryptoKZGFlag,
		flags2.ListenPortFlag,
		flags2.DiscoveryPortFlag,
		flags2.MaxPeersFlag,
		flags2.MaxPendingPeersFlag,
		utils.MiningEnabledFlag, // deprecated
		flags2.MinerGasLimitFlag,
		flags2.MinerGasPriceFlag,
		utils.MinerEtherbaseFlag, // deprecated
		flags2.MinerExtraDataFlag,
		flags2.MinerRecommitIntervalFlag,
		flags2.MinerPendingFeeRecipientFlag,
		utils.MinerNewPayloadTimeoutFlag, // deprecated
		flags2.NATFlag,
		flags2.NoDiscoverFlag,
		flags2.DiscoveryV4Flag,
		flags2.DiscoveryV5Flag,
		utils.LegacyDiscoveryV5Flag, // deprecated
		flags2.NetrestrictFlag,
		flags2.NodeKeyFileFlag,
		flags2.NodeKeyHexFlag,
		flags2.DNSDiscoveryFlag,
		flags2.DeveloperFlag,
		flags2.DeveloperGasLimitFlag,
		flags2.DeveloperPeriodFlag,
		flags2.VMEnableDebugFlag,
		flags2.VMTraceFlag,
		flags2.VMTraceJsonConfigFlag,
		flags2.NetworkIdFlag,
		flags2.EthStatsURLFlag,
		flags2.NoCompactionFlag,
		flags2.GpoBlocksFlag,
		flags2.GpoPercentileFlag,
		flags2.GpoMaxGasPriceFlag,
		flags2.GpoIgnoreGasPriceFlag,
		configFileFlag,
		utils.LogDebugFlag,
		utils.LogBacktraceAtFlag,
		flags2.BeaconApiFlag,
		flags2.BeaconApiHeaderFlag,
		flags2.BeaconThresholdFlag,
		flags2.BeaconNoFilterFlag,
		flags2.BeaconConfigFlag,
		flags2.BeaconGenesisRootFlag,
		flags2.BeaconGenesisTimeFlag,
		flags2.BeaconCheckpointFlag,
	}, flags2.NetworkFlags, flags2.DatabaseFlags)

	rpcFlags = []cli.Flag{
		flags2.HTTPEnabledFlag,
		flags2.HTTPListenAddrFlag,
		flags2.HTTPPortFlag,
		flags2.HTTPCORSDomainFlag,
		flags2.AuthListenFlag,
		flags2.AuthPortFlag,
		flags2.AuthVirtualHostsFlag,
		flags2.JWTSecretFlag,
		flags2.HTTPVirtualHostsFlag,
		flags2.GraphQLEnabledFlag,
		flags2.GraphQLCORSDomainFlag,
		flags2.GraphQLVirtualHostsFlag,
		flags2.HTTPApiFlag,
		flags2.HTTPPathPrefixFlag,
		flags2.WSEnabledFlag,
		flags2.WSListenAddrFlag,
		flags2.WSPortFlag,
		flags2.WSApiFlag,
		flags2.WSAllowedOriginsFlag,
		flags2.WSPathPrefixFlag,
		flags2.IPCDisabledFlag,
		flags2.IPCPathFlag,
		flags2.InsecureUnlockAllowedFlag,
		flags2.RPCGlobalGasCapFlag,
		flags2.RPCGlobalEVMTimeoutFlag,
		flags2.RPCGlobalTxFeeCapFlag,
		flags2.AllowUnprotectedTxs,
		flags2.BatchRequestLimit,
		flags2.BatchResponseMaxSize,
	}

	metricsFlags = []cli.Flag{
		flags2.MetricsEnabledFlag,
		utils.MetricsEnabledExpensiveFlag,
		flags2.MetricsHTTPFlag,
		flags2.MetricsPortFlag,
		flags2.MetricsEnableInfluxDBFlag,
		flags2.MetricsInfluxDBEndpointFlag,
		flags2.MetricsInfluxDBDatabaseFlag,
		flags2.MetricsInfluxDBUsernameFlag,
		flags2.MetricsInfluxDBPasswordFlag,
		flags2.MetricsInfluxDBTagsFlag,
		flags2.MetricsEnableInfluxDBV2Flag,
		flags2.MetricsInfluxDBTokenFlag,
		flags2.MetricsInfluxDBBucketFlag,
		flags2.MetricsInfluxDBOrganizationFlag,
	}
)

var app = flags.NewApp("the go-ethereum command line interface")

func init() {
	// Initialize the CLI app and start Geth
	app.Action = geth
	app.Commands = []*cli.Command{
		// See chaincmd.go:
		initCommand,
		importCommand,
		exportCommand,
		importHistoryCommand,
		exportHistoryCommand,
		importPreimagesCommand,
		removedbCommand,
		dumpCommand,
		dumpGenesisCommand,
		// See accountcmd.go:
		accountCommand,
		walletCommand,
		// See consolecmd.go:
		consoleCommand,
		attachCommand,
		javascriptCommand,
		// See misccmd.go:
		versionCommand,
		versionCheckCommand,
		licenseCommand,
		// See config.go
		dumpConfigCommand,
		// see dbcmd.go
		dbCommand,
		// See cmd/utils/flags_legacy.go
		utils.ShowDeprecated,
		// See snapshot.go
		snapshotCommand,
		// See verkle.go
		verkleCommand,
	}
	if logTestCommand != nil {
		app.Commands = append(app.Commands, logTestCommand)
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = flags.Merge(
		nodeFlags,
		rpcFlags,
		consoleFlags,
		debug.Flags,
		metricsFlags,
	)
	flags.AutoEnvVars(app.Flags, "GETH")

	app.Before = func(ctx *cli.Context) error {
		maxprocs.Set() // Automatically set GOMAXPROCS to match Linux container CPU quota.
		flags.MigrateGlobalFlags(ctx)
		if err := debug.Setup(ctx); err != nil {
			return err
		}
		flags.CheckEnvVars(ctx, app.Flags, "GETH")
		return nil
	}
	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		prompt.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// prepare manipulates memory cache allowance and setups metric system.
// This function should be called before launching devp2p stack.
func prepare(ctx *cli.Context) {
	// If we're running a known preset, log it for convenience.
	switch {
	case ctx.IsSet(flags2.SepoliaFlag.Name):
		log.Info("Starting Geth on Sepolia testnet...")

	case ctx.IsSet(flags2.HoleskyFlag.Name):
		log.Info("Starting Geth on Holesky testnet...")

	case ctx.IsSet(flags2.DeveloperFlag.Name):
		log.Info("Starting Geth in ephemeral dev mode...")
		log.Warn(`You are running Geth in --dev mode. Please note the following:

  1. This mode is only intended for fast, iterative development without assumptions on
     security or persistence.
  2. The database is created in memory unless specified otherwise. Therefore, shutting down
     your computer or losing power will wipe your entire block data and chain state for
     your dev environment.
  3. A random, pre-allocated developer account will be available and unlocked as
     eth.coinbase, which can be used for testing. The random dev account is temporary,
     stored on a ramdisk, and will be lost if your machine is restarted.
  4. Mining is enabled by default. However, the client will only seal blocks if transactions
     are pending in the mempool. The miner's minimum accepted gas price is 1.
  5. Networking is disabled; there is no listen-address, the maximum number of peers is set
     to 0, and discovery is disabled.
`)

	case !ctx.IsSet(flags2.NetworkIdFlag.Name):
		log.Info("Starting Geth on Ethereum mainnet...")
	}
	// If we're a full node on mainnet without --cache specified, bump default cache allowance
	if !ctx.IsSet(flags2.CacheFlag.Name) && !ctx.IsSet(flags2.NetworkIdFlag.Name) {
		// Make sure we're not on any supported preconfigured testnet either
		if !ctx.IsSet(flags2.HoleskyFlag.Name) &&
			!ctx.IsSet(flags2.SepoliaFlag.Name) &&
			!ctx.IsSet(flags2.DeveloperFlag.Name) {
			// Nope, we're really on mainnet. Bump that cache up!
			log.Info("Bumping default cache on mainnet", "provided", ctx.Int(flags2.CacheFlag.Name), "updated", 4096)
			ctx.Set(flags2.CacheFlag.Name, strconv.Itoa(4096))
		}
	}

	// Start metrics export if enabled
	utils.SetupMetrics(ctx)

	// Start system runtime metrics collection
	go metrics.CollectProcessMetrics(3 * time.Second)
}

// geth is the main entry point into the system if no special subcommand is run.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
func geth(ctx *cli.Context) error {
	if args := ctx.Args().Slice(); len(args) > 0 {
		return fmt.Errorf("invalid command: %q", args[0])
	}

	prepare(ctx)
	stack := makeFullNode(ctx)
	defer stack.Close()

	startNode(ctx, stack, false)
	stack.Wait()
	return nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC/IPC interfaces and the
// miner.
func startNode(ctx *cli.Context, stack *node.Node, isConsole bool) {
	// Start up the node itself
	utils.StartNode(ctx, stack, isConsole)

	// Unlock any account specifically requested
	unlockAccounts(ctx, stack)

	// Register wallet event handlers to open and auto-derive wallets
	events := make(chan accounts.WalletEvent, 16)
	stack.AccountManager().Subscribe(events)

	// Create a client to interact with local geth node.
	rpcClient := stack.Attach()
	ethClient := ethclient.NewClient(rpcClient)

	go func() {
		// Open any wallets already attached
		for _, wallet := range stack.AccountManager().Wallets() {
			if err := wallet.Open(""); err != nil {
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet event till termination
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived:
				if err := event.Wallet.Open(""); err != nil {
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}
			case accounts.WalletOpened:
				status, _ := event.Wallet.Status()
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

				var derivationPaths []accounts.DerivationPath
				if event.Wallet.URL().Scheme == "ledger" {
					derivationPaths = append(derivationPaths, accounts.LegacyLedgerBaseDerivationPath)
				}
				derivationPaths = append(derivationPaths, accounts.DefaultBaseDerivationPath)

				event.Wallet.SelfDerive(derivationPaths, ethClient)

			case accounts.WalletDropped:
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()

	// Spawn a standalone goroutine for status synchronization monitoring,
	// close the node when synchronization is complete if user required.
	if ctx.Bool(flags2.ExitWhenSyncedFlag.Name) {
		go func() {
			sub := stack.EventMux().Subscribe(downloader.DoneEvent{})
			defer sub.Unsubscribe()
			for {
				event := <-sub.Chan()
				if event == nil {
					continue
				}
				done, ok := event.Data.(downloader.DoneEvent)
				if !ok {
					continue
				}
				if timestamp := time.Unix(int64(done.Latest.Time), 0); time.Since(timestamp) < 10*time.Minute {
					log.Info("Synchronisation completed", "latestnum", done.Latest.Number, "latesthash", done.Latest.Hash(),
						"age", common.PrettyAge(timestamp))
					stack.Close()
				}
			}
		}()
	}
}

// unlockAccounts unlocks any account specifically requested.
func unlockAccounts(ctx *cli.Context, stack *node.Node) {
	var unlocks []string
	inputs := strings.Split(ctx.String(flags2.UnlockedAccountFlag.Name), ",")
	for _, input := range inputs {
		if trimmed := strings.TrimSpace(input); trimmed != "" {
			unlocks = append(unlocks, trimmed)
		}
	}
	// Short circuit if there is no account to unlock.
	if len(unlocks) == 0 {
		return
	}
	// If insecure account unlocking is not allowed if node's APIs are exposed to external.
	// Print warning log to user and skip unlocking.
	if !stack.Config().InsecureUnlockAllowed && stack.Config().ExtRPCEnabled() {
		utils.Fatalf("Account unlock with HTTP access is forbidden!")
	}
	backends := stack.AccountManager().Backends(keystore.KeyStoreType)
	if len(backends) == 0 {
		log.Warn("Failed to unlock accounts, keystore is not available")
		return
	}
	ks := backends[0].(*keystore.KeyStore)
	passwords := utils.MakePasswordList(ctx)
	for i, account := range unlocks {
		unlockAccount(ks, account, i, passwords)
	}
}
