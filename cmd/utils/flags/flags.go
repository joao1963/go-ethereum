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

// Package flags contains common command-line flags for go-ethereum commands.
package flags

import (
	"strings"
	
	bparams "github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/node"
	pcsclite "github.com/gballet/go-libpcsclite"
	"github.com/urfave/cli/v2"
)

var (
	// General settings
	DataDirFlag = &flags.DirectoryFlag{
		Name:     "datadir",
		Usage:    "Data directory for the databases and keystore",
		Value:    flags.DirectoryString(node.DefaultDataDir()),
		Category: flags.EthCategory,
	}
	RemoteDBFlag = &cli.StringFlag{
		Name:     "remotedb",
		Usage:    "URL for remote database",
		Category: flags.LoggingCategory,
	}
	DBEngineFlag = &cli.StringFlag{
		Name:     "db.engine",
		Usage:    "Backing database implementation to use ('pebble' or 'leveldb')",
		Value:    node.DefaultConfig.DBEngine,
		Category: flags.EthCategory,
	}
	AncientFlag = &flags.DirectoryFlag{
		Name:     "datadir.ancient",
		Usage:    "Root directory for ancient data (default = inside chaindata)",
		Category: flags.EthCategory,
	}
	MinFreeDiskSpaceFlag = &flags.DirectoryFlag{
		Name:     "datadir.minfreedisk",
		Usage:    "Minimum free disk space in MB, once reached triggers auto shut down (default = --cache.gc converted to MB, 0 = disabled)",
		Category: flags.EthCategory,
	}
	KeyStoreDirFlag = &flags.DirectoryFlag{
		Name:     "keystore",
		Usage:    "Directory for the keystore (default = inside the datadir)",
		Category: flags.AccountCategory,
	}
	USBFlag = &cli.BoolFlag{
		Name:     "usb",
		Usage:    "Enable monitoring and management of USB hardware wallets",
		Category: flags.AccountCategory,
	}
	SmartCardDaemonPathFlag = &cli.StringFlag{
		Name:     "pcscdpath",
		Usage:    "Path to the smartcard daemon (pcscd) socket file",
		Value:    pcsclite.PCSCDSockName,
		Category: flags.AccountCategory,
	}
	NetworkIdFlag = &cli.Uint64Flag{
		Name:     "networkid",
		Usage:    "Explicitly set network id (integer)(For testnets: use --sepolia, --holesky instead)",
		Value:    ethconfig.Defaults.NetworkId,
		Category: flags.EthCategory,
	}
	MainnetFlag = &cli.BoolFlag{
		Name:     "mainnet",
		Usage:    "Ethereum mainnet",
		Category: flags.EthCategory,
	}
	SepoliaFlag = &cli.BoolFlag{
		Name:     "sepolia",
		Usage:    "Sepolia network: pre-configured proof-of-work test network",
		Category: flags.EthCategory,
	}
	HoleskyFlag = &cli.BoolFlag{
		Name:     "holesky",
		Usage:    "Holesky network: pre-configured proof-of-stake test network",
		Category: flags.EthCategory,
	}
	// Dev mode
	DeveloperFlag = &cli.BoolFlag{
		Name:     "dev",
		Usage:    "Ephemeral proof-of-authority network with a pre-funded developer account, mining enabled",
		Category: flags.DevCategory,
	}
	DeveloperPeriodFlag = &cli.Uint64Flag{
		Name:     "dev.period",
		Usage:    "Block period to use in developer mode (0 = mine only if transaction pending)",
		Category: flags.DevCategory,
	}
	DeveloperGasLimitFlag = &cli.Uint64Flag{
		Name:     "dev.gaslimit",
		Usage:    "Initial block gas limit",
		Value:    11500000,
		Category: flags.DevCategory,
	}

	IdentityFlag = &cli.StringFlag{
		Name:     "identity",
		Usage:    "Custom node name",
		Category: flags.NetworkingCategory,
	}
	DocRootFlag = &flags.DirectoryFlag{
		Name:     "docroot",
		Usage:    "Document Root for HTTPClient file scheme",
		Value:    flags.DirectoryString(flags.HomeDir()),
		Category: flags.APICategory,
	}
	ExitWhenSyncedFlag = &cli.BoolFlag{
		Name:     "exitwhensynced",
		Usage:    "Exits after block synchronisation completes",
		Category: flags.EthCategory,
	}

	// Dump command options.
	IterativeOutputFlag = &cli.BoolFlag{
		Name:  "iterative",
		Usage: "Print streaming JSON iteratively, delimited by newlines",
		Value: true,
	}
	ExcludeStorageFlag = &cli.BoolFlag{
		Name:  "nostorage",
		Usage: "Exclude storage entries (save db lookups)",
	}
	IncludeIncompletesFlag = &cli.BoolFlag{
		Name:  "incompletes",
		Usage: "Include accounts for which we don't have the address (missing preimage)",
	}
	ExcludeCodeFlag = &cli.BoolFlag{
		Name:  "nocode",
		Usage: "Exclude contract code (save db lookups)",
	}
	StartKeyFlag = &cli.StringFlag{
		Name:  "start",
		Usage: "Start position. Either a hash or address",
		Value: "0x0000000000000000000000000000000000000000000000000000000000000000",
	}
	DumpLimitFlag = &cli.Uint64Flag{
		Name:  "limit",
		Usage: "Max number of elements (0 = no limit)",
		Value: 0,
	}

	defaultSyncMode = ethconfig.Defaults.SyncMode
	SnapshotFlag    = &cli.BoolFlag{
		Name:     "snapshot",
		Usage:    `Enables snapshot-database mode (default = enable)`,
		Value:    true,
		Category: flags.EthCategory,
	}
	LightKDFFlag = &cli.BoolFlag{
		Name:     "lightkdf",
		Usage:    "Reduce key-derivation RAM & CPU usage at some expense of KDF strength",
		Category: flags.AccountCategory,
	}
	EthRequiredBlocksFlag = &cli.StringFlag{
		Name:     "eth.requiredblocks",
		Usage:    "Comma separated block number-to-hash mappings to require for peering (<number>=<hash>)",
		Category: flags.EthCategory,
	}
	BloomFilterSizeFlag = &cli.Uint64Flag{
		Name:     "bloomfilter.size",
		Usage:    "Megabytes of memory allocated to bloom-filter for pruning",
		Value:    2048,
		Category: flags.EthCategory,
	}
	OverrideCancun = &cli.Uint64Flag{
		Name:     "override.cancun",
		Usage:    "Manually specify the Cancun fork timestamp, overriding the bundled setting",
		Category: flags.EthCategory,
	}
	OverrideVerkle = &cli.Uint64Flag{
		Name:     "override.verkle",
		Usage:    "Manually specify the Verkle fork timestamp, overriding the bundled setting",
		Category: flags.EthCategory,
	}
	SyncModeFlag = &flags.TextMarshalerFlag{
		Name:     "syncmode",
		Usage:    `Blockchain sync mode ("snap" or "full")`,
		Value:    &defaultSyncMode,
		Category: flags.StateCategory,
	}
	GCModeFlag = &cli.StringFlag{
		Name:     "gcmode",
		Usage:    `Blockchain garbage collection mode, only relevant in state.scheme=hash ("full", "archive")`,
		Value:    "full",
		Category: flags.StateCategory,
	}
	StateSchemeFlag = &cli.StringFlag{
		Name:     "state.scheme",
		Usage:    "Scheme to use for storing ethereum state ('hash' or 'path')",
		Category: flags.StateCategory,
	}
	StateHistoryFlag = &cli.Uint64Flag{
		Name:     "history.state",
		Usage:    "Number of recent blocks to retain state history for (default = 90,000 blocks, 0 = entire chain)",
		Value:    ethconfig.Defaults.StateHistory,
		Category: flags.StateCategory,
	}
	TransactionHistoryFlag = &cli.Uint64Flag{
		Name:     "history.transactions",
		Usage:    "Number of recent blocks to maintain transactions index for (default = about one year, 0 = entire chain)",
		Value:    ethconfig.Defaults.TransactionHistory,
		Category: flags.StateCategory,
	}
	// Beacon client light sync settings
	BeaconApiFlag = &cli.StringSliceFlag{
		Name:     "beacon.api",
		Usage:    "Beacon node (CL) light client API URL. This flag can be given multiple times.",
		Category: flags.BeaconCategory,
	}
	BeaconApiHeaderFlag = &cli.StringSliceFlag{
		Name:     "beacon.api.header",
		Usage:    "Pass custom HTTP header fields to the remote beacon node API in \"key:value\" format. This flag can be given multiple times.",
		Category: flags.BeaconCategory,
	}
	BeaconThresholdFlag = &cli.IntFlag{
		Name:     "beacon.threshold",
		Usage:    "Beacon sync committee participation threshold",
		Value:    bparams.SyncCommitteeSupermajority,
		Category: flags.BeaconCategory,
	}
	BeaconNoFilterFlag = &cli.BoolFlag{
		Name:     "beacon.nofilter",
		Usage:    "Disable future slot signature filter",
		Category: flags.BeaconCategory,
	}
	BeaconConfigFlag = &cli.StringFlag{
		Name:     "beacon.config",
		Usage:    "Beacon chain config YAML file",
		Category: flags.BeaconCategory,
	}
	BeaconGenesisRootFlag = &cli.StringFlag{
		Name:     "beacon.genesis.gvroot",
		Usage:    "Beacon chain genesis validators root",
		Category: flags.BeaconCategory,
	}
	BeaconGenesisTimeFlag = &cli.Uint64Flag{
		Name:     "beacon.genesis.time",
		Usage:    "Beacon chain genesis time",
		Category: flags.BeaconCategory,
	}
	BeaconCheckpointFlag = &cli.StringFlag{
		Name:     "beacon.checkpoint",
		Usage:    "Beacon chain weak subjectivity checkpoint block hash",
		Category: flags.BeaconCategory,
	}
	BlsyncApiFlag = &cli.StringFlag{
		Name:     "blsync.engine.api",
		Usage:    "Target EL engine API URL",
		Category: flags.BeaconCategory,
	}
	BlsyncJWTSecretFlag = &cli.StringFlag{
		Name:     "blsync.jwtsecret",
		Usage:    "Path to a JWT secret to use for target engine API endpoint",
		Category: flags.BeaconCategory,
	}
	// Transaction pool settings
	TxPoolLocalsFlag = &cli.StringFlag{
		Name:     "txpool.locals",
		Usage:    "Comma separated accounts to treat as locals (no flush, priority inclusion)",
		Category: flags.TxPoolCategory,
	}
	TxPoolNoLocalsFlag = &cli.BoolFlag{
		Name:     "txpool.nolocals",
		Usage:    "Disables price exemptions for locally submitted transactions",
		Category: flags.TxPoolCategory,
	}
	TxPoolJournalFlag = &cli.StringFlag{
		Name:     "txpool.journal",
		Usage:    "Disk journal for local transaction to survive node restarts",
		Value:    ethconfig.Defaults.TxPool.Journal,
		Category: flags.TxPoolCategory,
	}
	TxPoolRejournalFlag = &cli.DurationFlag{
		Name:     "txpool.rejournal",
		Usage:    "Time interval to regenerate the local transaction journal",
		Value:    ethconfig.Defaults.TxPool.Rejournal,
		Category: flags.TxPoolCategory,
	}
	TxPoolPriceLimitFlag = &cli.Uint64Flag{
		Name:     "txpool.pricelimit",
		Usage:    "Minimum gas price tip to enforce for acceptance into the pool",
		Value:    ethconfig.Defaults.TxPool.PriceLimit,
		Category: flags.TxPoolCategory,
	}
	TxPoolPriceBumpFlag = &cli.Uint64Flag{
		Name:     "txpool.pricebump",
		Usage:    "Price bump percentage to replace an already existing transaction",
		Value:    ethconfig.Defaults.TxPool.PriceBump,
		Category: flags.TxPoolCategory,
	}
	TxPoolAccountSlotsFlag = &cli.Uint64Flag{
		Name:     "txpool.accountslots",
		Usage:    "Minimum number of executable transaction slots guaranteed per account",
		Value:    ethconfig.Defaults.TxPool.AccountSlots,
		Category: flags.TxPoolCategory,
	}
	TxPoolGlobalSlotsFlag = &cli.Uint64Flag{
		Name:     "txpool.globalslots",
		Usage:    "Maximum number of executable transaction slots for all accounts",
		Value:    ethconfig.Defaults.TxPool.GlobalSlots,
		Category: flags.TxPoolCategory,
	}
	TxPoolAccountQueueFlag = &cli.Uint64Flag{
		Name:     "txpool.accountqueue",
		Usage:    "Maximum number of non-executable transaction slots permitted per account",
		Value:    ethconfig.Defaults.TxPool.AccountQueue,
		Category: flags.TxPoolCategory,
	}
	TxPoolGlobalQueueFlag = &cli.Uint64Flag{
		Name:     "txpool.globalqueue",
		Usage:    "Maximum number of non-executable transaction slots for all accounts",
		Value:    ethconfig.Defaults.TxPool.GlobalQueue,
		Category: flags.TxPoolCategory,
	}
	TxPoolLifetimeFlag = &cli.DurationFlag{
		Name:     "txpool.lifetime",
		Usage:    "Maximum amount of time non-executable transaction are queued",
		Value:    ethconfig.Defaults.TxPool.Lifetime,
		Category: flags.TxPoolCategory,
	}
	// Blob transaction pool settings
	BlobPoolDataDirFlag = &cli.StringFlag{
		Name:     "blobpool.datadir",
		Usage:    "Data directory to store blob transactions in",
		Value:    ethconfig.Defaults.BlobPool.Datadir,
		Category: flags.BlobPoolCategory,
	}
	BlobPoolDataCapFlag = &cli.Uint64Flag{
		Name:     "blobpool.datacap",
		Usage:    "Disk space to allocate for pending blob transactions (soft limit)",
		Value:    ethconfig.Defaults.BlobPool.Datacap,
		Category: flags.BlobPoolCategory,
	}
	BlobPoolPriceBumpFlag = &cli.Uint64Flag{
		Name:     "blobpool.pricebump",
		Usage:    "Price bump percentage to replace an already existing blob transaction",
		Value:    ethconfig.Defaults.BlobPool.PriceBump,
		Category: flags.BlobPoolCategory,
	}
	// Performance tuning settings
	CacheFlag = &cli.IntFlag{
		Name:     "cache",
		Usage:    "Megabytes of memory allocated to internal caching (default = 4096 mainnet full node, 128 light mode)",
		Value:    1024,
		Category: flags.PerfCategory,
	}
	CacheDatabaseFlag = &cli.IntFlag{
		Name:     "cache.database",
		Usage:    "Percentage of cache memory allowance to use for database io",
		Value:    50,
		Category: flags.PerfCategory,
	}
	CacheTrieFlag = &cli.IntFlag{
		Name:     "cache.trie",
		Usage:    "Percentage of cache memory allowance to use for trie caching (default = 15% full mode, 30% archive mode)",
		Value:    15,
		Category: flags.PerfCategory,
	}
	CacheGCFlag = &cli.IntFlag{
		Name:     "cache.gc",
		Usage:    "Percentage of cache memory allowance to use for trie pruning (default = 25% full mode, 0% archive mode)",
		Value:    25,
		Category: flags.PerfCategory,
	}
	CacheSnapshotFlag = &cli.IntFlag{
		Name:     "cache.snapshot",
		Usage:    "Percentage of cache memory allowance to use for snapshot caching (default = 10% full mode, 20% archive mode)",
		Value:    10,
		Category: flags.PerfCategory,
	}
	CacheNoPrefetchFlag = &cli.BoolFlag{
		Name:     "cache.noprefetch",
		Usage:    "Disable heuristic state prefetch during block import (less CPU and disk IO, more time waiting for data)",
		Category: flags.PerfCategory,
	}
	CachePreimagesFlag = &cli.BoolFlag{
		Name:     "cache.preimages",
		Usage:    "Enable recording the SHA3/keccak preimages of trie keys",
		Category: flags.PerfCategory,
	}
	CacheLogSizeFlag = &cli.IntFlag{
		Name:     "cache.blocklogs",
		Usage:    "Size (in number of blocks) of the log cache for filtering",
		Category: flags.PerfCategory,
		Value:    ethconfig.Defaults.FilterLogCacheSize,
	}
	FDLimitFlag = &cli.IntFlag{
		Name:     "fdlimit",
		Usage:    "Raise the open file descriptor resource limit (default = system fd limit)",
		Category: flags.PerfCategory,
	}
	CryptoKZGFlag = &cli.StringFlag{
		Name:     "crypto.kzg",
		Usage:    "KZG library implementation to use; gokzg (recommended) or ckzg",
		Value:    "gokzg",
		Category: flags.PerfCategory,
	}

	// Miner settings
	MinerGasLimitFlag = &cli.Uint64Flag{
		Name:     "miner.gaslimit",
		Usage:    "Target gas ceiling for mined blocks",
		Value:    ethconfig.Defaults.Miner.GasCeil,
		Category: flags.MinerCategory,
	}
	MinerGasPriceFlag = &flags.BigFlag{
		Name:     "miner.gasprice",
		Usage:    "Minimum gas price for mining a transaction",
		Value:    ethconfig.Defaults.Miner.GasPrice,
		Category: flags.MinerCategory,
	}
	MinerExtraDataFlag = &cli.StringFlag{
		Name:     "miner.extradata",
		Usage:    "Block extra data set by the miner (default = client version)",
		Category: flags.MinerCategory,
	}
	MinerRecommitIntervalFlag = &cli.DurationFlag{
		Name:     "miner.recommit",
		Usage:    "Time interval to recreate the block being mined",
		Value:    ethconfig.Defaults.Miner.Recommit,
		Category: flags.MinerCategory,
	}
	MinerPendingFeeRecipientFlag = &cli.StringFlag{
		Name:     "miner.pending.feeRecipient",
		Usage:    "0x prefixed public address for the pending block producer (not used for actual block production)",
		Category: flags.MinerCategory,
	}

	// Account settings
	UnlockedAccountFlag = &cli.StringFlag{
		Name:     "unlock",
		Usage:    "Comma separated list of accounts to unlock",
		Value:    "",
		Category: flags.AccountCategory,
	}
	PasswordFileFlag = &cli.PathFlag{
		Name:      "password",
		Usage:     "Password file to use for non-interactive password input",
		TakesFile: true,
		Category:  flags.AccountCategory,
	}
	ExternalSignerFlag = &cli.StringFlag{
		Name:     "signer",
		Usage:    "External signer (url or path to ipc file)",
		Value:    "",
		Category: flags.AccountCategory,
	}
	InsecureUnlockAllowedFlag = &cli.BoolFlag{
		Name:     "allow-insecure-unlock",
		Usage:    "Allow insecure account unlocking when account-related RPCs are exposed by http",
		Category: flags.AccountCategory,
	}

	// EVM settings
	VMEnableDebugFlag = &cli.BoolFlag{
		Name:     "vmdebug",
		Usage:    "Record information useful for VM and contract debugging",
		Category: flags.VMCategory,
	}
	VMTraceFlag = &cli.StringFlag{
		Name:     "vmtrace",
		Usage:    "Name of tracer which should record internal VM operations (costly)",
		Category: flags.VMCategory,
	}
	VMTraceJsonConfigFlag = &cli.StringFlag{
		Name:     "vmtrace.jsonconfig",
		Usage:    "Tracer configuration (JSON)",
		Value:    "{}",
		Category: flags.VMCategory,
	}
	// API options.
	RPCGlobalGasCapFlag = &cli.Uint64Flag{
		Name:     "rpc.gascap",
		Usage:    "Sets a cap on gas that can be used in eth_call/estimateGas (0=infinite)",
		Value:    ethconfig.Defaults.RPCGasCap,
		Category: flags.APICategory,
	}
	RPCGlobalEVMTimeoutFlag = &cli.DurationFlag{
		Name:     "rpc.evmtimeout",
		Usage:    "Sets a timeout used for eth_call (0=infinite)",
		Value:    ethconfig.Defaults.RPCEVMTimeout,
		Category: flags.APICategory,
	}
	RPCGlobalTxFeeCapFlag = &cli.Float64Flag{
		Name:     "rpc.txfeecap",
		Usage:    "Sets a cap on transaction fee (in ether) that can be sent via the RPC APIs (0 = no cap)",
		Value:    ethconfig.Defaults.RPCTxFeeCap,
		Category: flags.APICategory,
	}
	// Authenticated RPC HTTP settings
	AuthListenFlag = &cli.StringFlag{
		Name:     "authrpc.addr",
		Usage:    "Listening address for authenticated APIs",
		Value:    node.DefaultConfig.AuthAddr,
		Category: flags.APICategory,
	}
	AuthPortFlag = &cli.IntFlag{
		Name:     "authrpc.port",
		Usage:    "Listening port for authenticated APIs",
		Value:    node.DefaultConfig.AuthPort,
		Category: flags.APICategory,
	}
	AuthVirtualHostsFlag = &cli.StringFlag{
		Name:     "authrpc.vhosts",
		Usage:    "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
		Value:    strings.Join(node.DefaultConfig.AuthVirtualHosts, ","),
		Category: flags.APICategory,
	}
	JWTSecretFlag = &flags.DirectoryFlag{
		Name:     "authrpc.jwtsecret",
		Usage:    "Path to a JWT secret to use for authenticated RPC endpoints",
		Category: flags.APICategory,
	}

	// Logging and debug settings
	EthStatsURLFlag = &cli.StringFlag{
		Name:     "ethstats",
		Usage:    "Reporting URL of a ethstats service (nodename:secret@host:port)",
		Category: flags.MetricsCategory,
	}
	NoCompactionFlag = &cli.BoolFlag{
		Name:     "nocompaction",
		Usage:    "Disables db compaction after import",
		Category: flags.LoggingCategory,
	}

	// MISC settings
	SyncTargetFlag = &cli.StringFlag{
		Name:      "synctarget",
		Usage:     `Hash of the block to full sync to (dev testing feature)`,
		TakesFile: true,
		Category:  flags.MiscCategory,
	}

	// RPC settings
	IPCDisabledFlag = &cli.BoolFlag{
		Name:     "ipcdisable",
		Usage:    "Disable the IPC-RPC server",
		Category: flags.APICategory,
	}
	IPCPathFlag = &flags.DirectoryFlag{
		Name:     "ipcpath",
		Usage:    "Filename for IPC socket/pipe within the datadir (explicit paths escape it)",
		Category: flags.APICategory,
	}
	HTTPEnabledFlag = &cli.BoolFlag{
		Name:     "http",
		Usage:    "Enable the HTTP-RPC server",
		Category: flags.APICategory,
	}
	HTTPListenAddrFlag = &cli.StringFlag{
		Name:     "http.addr",
		Usage:    "HTTP-RPC server listening interface",
		Value:    node.DefaultHTTPHost,
		Category: flags.APICategory,
	}
	HTTPPortFlag = &cli.IntFlag{
		Name:     "http.port",
		Usage:    "HTTP-RPC server listening port",
		Value:    node.DefaultHTTPPort,
		Category: flags.APICategory,
	}
	HTTPCORSDomainFlag = &cli.StringFlag{
		Name:     "http.corsdomain",
		Usage:    "Comma separated list of domains from which to accept cross origin requests (browser enforced)",
		Value:    "",
		Category: flags.APICategory,
	}
	HTTPVirtualHostsFlag = &cli.StringFlag{
		Name:     "http.vhosts",
		Usage:    "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
		Value:    strings.Join(node.DefaultConfig.HTTPVirtualHosts, ","),
		Category: flags.APICategory,
	}
	HTTPApiFlag = &cli.StringFlag{
		Name:     "http.api",
		Usage:    "API's offered over the HTTP-RPC interface",
		Value:    "",
		Category: flags.APICategory,
	}
	HTTPPathPrefixFlag = &cli.StringFlag{
		Name:     "http.rpcprefix",
		Usage:    "HTTP path prefix on which JSON-RPC is served. Use '/' to serve on all paths.",
		Value:    "",
		Category: flags.APICategory,
	}
	GraphQLEnabledFlag = &cli.BoolFlag{
		Name:     "graphql",
		Usage:    "Enable GraphQL on the HTTP-RPC server. Note that GraphQL can only be started if an HTTP server is started as well.",
		Category: flags.APICategory,
	}
	GraphQLCORSDomainFlag = &cli.StringFlag{
		Name:     "graphql.corsdomain",
		Usage:    "Comma separated list of domains from which to accept cross origin requests (browser enforced)",
		Value:    "",
		Category: flags.APICategory,
	}
	GraphQLVirtualHostsFlag = &cli.StringFlag{
		Name:     "graphql.vhosts",
		Usage:    "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
		Value:    strings.Join(node.DefaultConfig.GraphQLVirtualHosts, ","),
		Category: flags.APICategory,
	}
	WSEnabledFlag = &cli.BoolFlag{
		Name:     "ws",
		Usage:    "Enable the WS-RPC server",
		Category: flags.APICategory,
	}
	WSListenAddrFlag = &cli.StringFlag{
		Name:     "ws.addr",
		Usage:    "WS-RPC server listening interface",
		Value:    node.DefaultWSHost,
		Category: flags.APICategory,
	}
	WSPortFlag = &cli.IntFlag{
		Name:     "ws.port",
		Usage:    "WS-RPC server listening port",
		Value:    node.DefaultWSPort,
		Category: flags.APICategory,
	}
	WSApiFlag = &cli.StringFlag{
		Name:     "ws.api",
		Usage:    "API's offered over the WS-RPC interface",
		Value:    "",
		Category: flags.APICategory,
	}
	WSAllowedOriginsFlag = &cli.StringFlag{
		Name:     "ws.origins",
		Usage:    "Origins from which to accept websockets requests",
		Value:    "",
		Category: flags.APICategory,
	}
	WSPathPrefixFlag = &cli.StringFlag{
		Name:     "ws.rpcprefix",
		Usage:    "HTTP path prefix on which JSON-RPC is served. Use '/' to serve on all paths.",
		Value:    "",
		Category: flags.APICategory,
	}
	ExecFlag = &cli.StringFlag{
		Name:     "exec",
		Usage:    "Execute JavaScript statement",
		Category: flags.APICategory,
	}
	PreloadJSFlag = &cli.StringFlag{
		Name:     "preload",
		Usage:    "Comma separated list of JavaScript files to preload into the console",
		Category: flags.APICategory,
	}
	AllowUnprotectedTxs = &cli.BoolFlag{
		Name:     "rpc.allow-unprotected-txs",
		Usage:    "Allow for unprotected (non EIP155 signed) transactions to be submitted via RPC",
		Category: flags.APICategory,
	}
	BatchRequestLimit = &cli.IntFlag{
		Name:     "rpc.batch-request-limit",
		Usage:    "Maximum number of requests in a batch",
		Value:    node.DefaultConfig.BatchRequestLimit,
		Category: flags.APICategory,
	}
	BatchResponseMaxSize = &cli.IntFlag{
		Name:     "rpc.batch-response-max-size",
		Usage:    "Maximum number of bytes returned from a batched call",
		Value:    node.DefaultConfig.BatchResponseMaxSize,
		Category: flags.APICategory,
	}
	EnablePersonal = &cli.BoolFlag{
		Name:     "rpc.enabledeprecatedpersonal",
		Usage:    "Enables the (deprecated) personal namespace",
		Category: flags.APICategory,
	}

	// Network Settings
	MaxPeersFlag = &cli.IntFlag{
		Name:     "maxpeers",
		Usage:    "Maximum number of network peers (network disabled if set to 0)",
		Value:    node.DefaultConfig.P2P.MaxPeers,
		Category: flags.NetworkingCategory,
	}
	MaxPendingPeersFlag = &cli.IntFlag{
		Name:     "maxpendpeers",
		Usage:    "Maximum number of pending connection attempts (defaults used if set to 0)",
		Value:    node.DefaultConfig.P2P.MaxPendingPeers,
		Category: flags.NetworkingCategory,
	}
	ListenPortFlag = &cli.IntFlag{
		Name:     "port",
		Usage:    "Network listening port",
		Value:    30303,
		Category: flags.NetworkingCategory,
	}
	BootnodesFlag = &cli.StringFlag{
		Name:     "bootnodes",
		Usage:    "Comma separated enode URLs for P2P discovery bootstrap",
		Value:    "",
		Category: flags.NetworkingCategory,
	}
	NodeKeyFileFlag = &cli.StringFlag{
		Name:     "nodekey",
		Usage:    "P2P node key file",
		Category: flags.NetworkingCategory,
	}
	NodeKeyHexFlag = &cli.StringFlag{
		Name:     "nodekeyhex",
		Usage:    "P2P node key as hex (for testing)",
		Category: flags.NetworkingCategory,
	}
	NATFlag = &cli.StringFlag{
		Name:     "nat",
		Usage:    "NAT port mapping mechanism (any|none|upnp|pmp|pmp:<IP>|extip:<IP>)",
		Value:    "any",
		Category: flags.NetworkingCategory,
	}
	NoDiscoverFlag = &cli.BoolFlag{
		Name:     "nodiscover",
		Usage:    "Disables the peer discovery mechanism (manual peer addition)",
		Category: flags.NetworkingCategory,
	}
	DiscoveryV4Flag = &cli.BoolFlag{
		Name:     "discovery.v4",
		Aliases:  []string{"discv4"},
		Usage:    "Enables the V4 discovery mechanism",
		Category: flags.NetworkingCategory,
		Value:    true,
	}
	DiscoveryV5Flag = &cli.BoolFlag{
		Name:     "discovery.v5",
		Aliases:  []string{"discv5"},
		Usage:    "Enables the V5 discovery mechanism",
		Category: flags.NetworkingCategory,
		Value:    true,
	}
	NetrestrictFlag = &cli.StringFlag{
		Name:     "netrestrict",
		Usage:    "Restricts network communication to the given IP networks (CIDR masks)",
		Category: flags.NetworkingCategory,
	}
	DNSDiscoveryFlag = &cli.StringFlag{
		Name:     "discovery.dns",
		Usage:    "Sets DNS discovery entry points (use \"\" to disable DNS)",
		Category: flags.NetworkingCategory,
	}
	DiscoveryPortFlag = &cli.IntFlag{
		Name:     "discovery.port",
		Usage:    "Use a custom UDP port for P2P discovery",
		Value:    30303,
		Category: flags.NetworkingCategory,
	}

	// Console
	JSpathFlag = &flags.DirectoryFlag{
		Name:     "jspath",
		Usage:    "JavaScript root path for `loadScript`",
		Value:    flags.DirectoryString("."),
		Category: flags.APICategory,
	}
	HttpHeaderFlag = &cli.StringSliceFlag{
		Name:     "header",
		Aliases:  []string{"H"},
		Usage:    "Pass custom headers to the RPC server when using --" + RemoteDBFlag.Name + " or the geth attach console. This flag can be given multiple times.",
		Category: flags.APICategory,
	}

	// Gas price oracle settings
	GpoBlocksFlag = &cli.IntFlag{
		Name:     "gpo.blocks",
		Usage:    "Number of recent blocks to check for gas prices",
		Value:    ethconfig.Defaults.GPO.Blocks,
		Category: flags.GasPriceCategory,
	}
	GpoPercentileFlag = &cli.IntFlag{
		Name:     "gpo.percentile",
		Usage:    "Suggested gas price is the given percentile of a set of recent transaction gas prices",
		Value:    ethconfig.Defaults.GPO.Percentile,
		Category: flags.GasPriceCategory,
	}
	GpoMaxGasPriceFlag = &cli.Int64Flag{
		Name:     "gpo.maxprice",
		Usage:    "Maximum transaction priority fee (or gasprice before London fork) to be recommended by gpo",
		Value:    ethconfig.Defaults.GPO.MaxPrice.Int64(),
		Category: flags.GasPriceCategory,
	}
	GpoIgnoreGasPriceFlag = &cli.Int64Flag{
		Name:     "gpo.ignoreprice",
		Usage:    "Gas price below which gpo will ignore transactions",
		Value:    ethconfig.Defaults.GPO.IgnorePrice.Int64(),
		Category: flags.GasPriceCategory,
	}

	// Metrics flags
	MetricsEnabledFlag = &cli.BoolFlag{
		Name:     "metrics",
		Usage:    "Enable metrics collection and reporting",
		Category: flags.MetricsCategory,
	}
	// MetricsHTTPFlag defines the endpoint for a stand-alone metrics HTTP endpoint.
	// Since the pprof service enables sensitive/vulnerable behavior, this allows a user
	// to enable a public-OK metrics endpoint without having to worry about ALSO exposing
	// other profiling behavior or information.
	MetricsHTTPFlag = &cli.StringFlag{
		Name:     "metrics.addr",
		Usage:    `Enable stand-alone metrics HTTP server listening interface.`,
		Category: flags.MetricsCategory,
	}
	MetricsPortFlag = &cli.IntFlag{
		Name: "metrics.port",
		Usage: `Metrics HTTP server listening port.
Please note that --` + MetricsHTTPFlag.Name + ` must be set to start the server.`,
		Value:    metrics.DefaultConfig.Port,
		Category: flags.MetricsCategory,
	}
	MetricsEnableInfluxDBFlag = &cli.BoolFlag{
		Name:     "metrics.influxdb",
		Usage:    "Enable metrics export/push to an external InfluxDB database",
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBEndpointFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.endpoint",
		Usage:    "InfluxDB API endpoint to report metrics to",
		Value:    metrics.DefaultConfig.InfluxDBEndpoint,
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBDatabaseFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.database",
		Usage:    "InfluxDB database name to push reported metrics to",
		Value:    metrics.DefaultConfig.InfluxDBDatabase,
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBUsernameFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.username",
		Usage:    "Username to authorize access to the database",
		Value:    metrics.DefaultConfig.InfluxDBUsername,
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBPasswordFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.password",
		Usage:    "Password to authorize access to the database",
		Value:    metrics.DefaultConfig.InfluxDBPassword,
		Category: flags.MetricsCategory,
	}
	// Tags are part of every measurement sent to InfluxDB. Queries on tags are faster in InfluxDB.
	// For example `host` tag could be used so that we can group all nodes and average a measurement
	// across all of them, but also so that we can select a specific node and inspect its measurements.
	// https://docs.influxdata.com/influxdb/v1.4/concepts/key_concepts/#tag-key
	MetricsInfluxDBTagsFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.tags",
		Usage:    "Comma-separated InfluxDB tags (key/values) attached to all measurements",
		Value:    metrics.DefaultConfig.InfluxDBTags,
		Category: flags.MetricsCategory,
	}

	MetricsEnableInfluxDBV2Flag = &cli.BoolFlag{
		Name:     "metrics.influxdbv2",
		Usage:    "Enable metrics export/push to an external InfluxDB v2 database",
		Category: flags.MetricsCategory,
	}

	MetricsInfluxDBTokenFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.token",
		Usage:    "Token to authorize access to the database (v2 only)",
		Value:    metrics.DefaultConfig.InfluxDBToken,
		Category: flags.MetricsCategory,
	}

	MetricsInfluxDBBucketFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.bucket",
		Usage:    "InfluxDB bucket name to push reported metrics to (v2 only)",
		Value:    metrics.DefaultConfig.InfluxDBBucket,
		Category: flags.MetricsCategory,
	}

	MetricsInfluxDBOrganizationFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.organization",
		Usage:    "InfluxDB organization name (v2 only)",
		Value:    metrics.DefaultConfig.InfluxDBOrganization,
		Category: flags.MetricsCategory,
	}
)

var (
	// TestnetFlags is the flag group of all built-in supported testnets.
	TestnetFlags = []cli.Flag{
		SepoliaFlag,
		HoleskyFlag,
	}
	// NetworkFlags is the flag group of all built-in supported networks.
	NetworkFlags = append([]cli.Flag{MainnetFlag}, TestnetFlags...)

	// DatabaseFlags is the flag group of all database flags.
	DatabaseFlags = []cli.Flag{
		DataDirFlag,
		AncientFlag,
		RemoteDBFlag,
		DBEngineFlag,
		StateSchemeFlag,
		HttpHeaderFlag,
	}
)
