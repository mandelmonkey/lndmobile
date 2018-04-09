// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2017 The Lightning Network Developers

package lnd

import (
	"log"
	"net"
	"time"
	"net/http"
	"os" 
	"path/filepath"
	"runtime"
	"strings"
    "github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightninglabs/neutrino"
	"github.com/roasbeef/btcwallet/chain"
	"github.com/roasbeef/btcwallet/walletdb"
	 "github.com/lightningnetwork/lnd/autopilot"
	"runtime/pprof"
	"github.com/lightningnetwork/lnd/keychain"
	"google.golang.org/grpc"
	"github.com/lightningnetwork/lnd/channeldb"
	"fmt"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet" 
	"github.com/lightningnetwork/lnd/lnwallet" 
	"github.com/roasbeef/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"crypto/rand" 
	"sync" 
	"github.com/lightningnetwork/lnd/chainntnfs/neutrinonotify"
	"github.com/lightningnetwork/lnd/routing/chainview"

)

var (

	//Commit stores the current commit hash of this build. This should be
	//set using -ldflags during compilation.
	Commit string

	cfg              *config
	shutdownChannel  = make(chan struct{})
	registeredChains = newChainRegistry()

	macaroonDatabaseDir string
	 


)

// Controls access to lightningRpcServer.
var rpcServerMutex = &sync.Mutex{}

var lndGrpcServer *grpc.Server 

var LndRpcServer * rpcServer;
 
// Start, analogous to lndMain
func Start(seed []byte, dataDir string) error {

	// Use all processor cores.
	// TODO(roasbeef): remove this if required version # is > 1.6?
	runtime.GOMAXPROCS(runtime.NumCPU())

// Load the configuration, and parse any command line options. This
	// function will also set up logging properly.
	loadedConfig, err := loadConfig(dataDir)
	if err != nil {
		return err
	}
	cfg = loadedConfig
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	// Show version at startup.
	ltndLog.Infof("Version %s", version())

	var network string
	switch {
	case cfg.Bitcoin.TestNet3 || cfg.Litecoin.TestNet3:
		network = "testnet"

	case cfg.Bitcoin.MainNet || cfg.Litecoin.MainNet:
		network = "mainnet"

	case cfg.Bitcoin.SimNet:
		network = "simmnet"

	case cfg.Bitcoin.RegTest:
		network = "regtest"
	}

	ltndLog.Infof("Active chain: %v (network=%v)",
		strings.Title(registeredChains.PrimaryChain().String()),
		network,
	)

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", cfg.Profile)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			fmt.Println(http.ListenAndServe(listenAddr, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			ltndLog.Errorf("Unable to create cpu profile: %v", err)
			return err
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	// Create the network-segmented directory for the channel database.
	graphDir := filepath.Join(cfg.DataDir,
		defaultGraphSubDirname,
		normalizeNetwork(activeNetParams.Name))

	// Open the channeldb, which is dedicated to storing channel, and
	// network related metadata.
	chanDB, err := channeldb.Open(graphDir)
	if err != nil {
		ltndLog.Errorf("unable to open channeldb: %v", err)
		return err
	}
	//defer chanDB.Close() //this was closed for ios specific

	
	 
	// We wait until the user provides a password over RPC. In case lnd is
	// started with the --noencryptwallet flag, we use the default password
	// "hello" for wallet encryption.
	privateWalletPw := []byte("hello")
	publicWalletPw := []byte("public")
	 

	// With the information parsed from the configuration, create valid
	// instances of the pertinent interfaces required to operate the
	// Lightning Network Daemon.
	activeChainControl, _, err := newChainControlFromConfigCustom(cfg,
		chanDB, privateWalletPw, publicWalletPw,seed)
	if err != nil {
		fmt.Printf("unable to create chain control: %v\n", err)
		return err
	}
	 
	 
	// Finally before we start the server, we'll register the "holy
	// trinity" of interface for our current "home chain" with the active
	// chainRegistry interface.
	primaryChain := registeredChains.PrimaryChain()
	registeredChains.RegisterChain(primaryChain, activeChainControl)


	// Select the configuration and furnding parameters for Bitcoin or
	// Litecoin, depending on the primary registered chain.
	chainCfg := cfg.Bitcoin
	minRemoteDelay := minBtcRemoteDelay
	maxRemoteDelay := maxBtcRemoteDelay
	if primaryChain == litecoinChain {
		chainCfg = cfg.Litecoin
		minRemoteDelay = minLtcRemoteDelay
		maxRemoteDelay = maxLtcRemoteDelay
	}


	idPrivKey, err := activeChainControl.wallet.DerivePrivKey(keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamilyNodeKey,
			Index:  0,
		},
	})
	if err != nil {
		ltndLog.Info("privkey error %v",err)
		return err
	}
	
	idPrivKey.Curve = btcec.S256()

	if cfg.Tor.Socks != "" && cfg.Tor.DNS != "" {
		srvrLog.Infof("Proxying all network traffic via Tor "+
			"(stream_isolation=%v)! NOTE: If running with a full-node "+
			"backend, ensure that is proxying over Tor as well",
			cfg.Tor.StreamIsolation)
	}

	

	// Set up the core server which will listen for incoming peer
	// connections.
	server, err := newServer(
		cfg.Listeners, chanDB, activeChainControl, idPrivKey,
	)
	if err != nil {
		srvrLog.Errorf("unable to create server: %v\n", err)
		return err
	}

	// Next, we'll initialize the funding manager itself so it can answer
	// queries while the wallet+chain are still syncing.
	nodeSigner := newNodeSigner(idPrivKey)
	var chanIDSeed [32]byte
	if _, err := rand.Read(chanIDSeed[:]); err != nil {
		return err
	}
	fundingMgr, err := newFundingManager(fundingConfig{
		IDKey:              idPrivKey.PubKey(),
		Wallet:             activeChainControl.wallet,
		PublishTransaction: activeChainControl.wallet.PublishTransaction,
		Notifier:           activeChainControl.chainNotifier,
		FeeEstimator:       activeChainControl.feeEstimator,
		SignMessage: func(pubKey *btcec.PublicKey,
			msg []byte) (*btcec.Signature, error) {

			if pubKey.IsEqual(idPrivKey.PubKey()) {
				return nodeSigner.SignMessage(pubKey, msg)
			}

			return activeChainControl.msgSigner.SignMessage(
				pubKey, msg,
			)
		},
		CurrentNodeAnnouncement: func() (lnwire.NodeAnnouncement, error) {
			return server.genNodeAnnouncement(true)
		},
		SendAnnouncement: func(msg lnwire.Message) error {
			errChan := server.authGossiper.ProcessLocalAnnouncement(msg,
				idPrivKey.PubKey())
			return <-errChan
		},
		ArbiterChan:      server.breachArbiter.newContracts,
		SendToPeer:       server.SendToPeer,
		NotifyWhenOnline: server.NotifyWhenOnline,
		FindPeer:         server.FindPeer,
		TempChanIDSeed:   chanIDSeed,
		FindChannel: func(chanID lnwire.ChannelID) (*lnwallet.LightningChannel, error) {
			dbChannels, err := chanDB.FetchAllChannels()
			if err != nil {
				return nil, err
			}

			for _, channel := range dbChannels {
				if chanID.IsChanPoint(&channel.FundingOutpoint) {
					// TODO(roasbeef): populate beacon
					return lnwallet.NewLightningChannel(
						activeChainControl.signer,
						server.witnessBeacon,
						channel)
				}
			}

			return nil, fmt.Errorf("unable to find channel")
		},
		DefaultRoutingPolicy: activeChainControl.routingPolicy,
		NumRequiredConfs: func(chanAmt btcutil.Amount,
			pushAmt lnwire.MilliSatoshi) uint16 {
			// For large channels we increase the number
			// of confirmations we require for the
			// channel to be considered open. As it is
			// always the responder that gets to choose
			// value, the pushAmt is value being pushed
			// to us. This means we have more to lose
			// in the case this gets re-orged out, and
			// we will require more confirmations before
			// we consider it open.
			// TODO(halseth): Use Litecoin params in case
			// of LTC channels.

			// In case the user has explicitly specified
			// a default value for the number of
			// confirmations, we use it.
			defaultConf := uint16(chainCfg.DefaultNumChanConfs)
			if defaultConf != 0 {
				return defaultConf
			}

			// If not we return a value scaled linearly
			// between 3 and 6, depending on channel size.
			// TODO(halseth): Use 1 as minimum?
			minConf := uint64(3)
			maxConf := uint64(6)
			maxChannelSize := uint64(
				lnwire.NewMSatFromSatoshis(maxFundingAmount))
			stake := lnwire.NewMSatFromSatoshis(chanAmt) + pushAmt
			conf := maxConf * uint64(stake) / maxChannelSize
			if conf < minConf {
				conf = minConf
			}
			if conf > maxConf {
				conf = maxConf
			}
			return uint16(conf)
		},
		RequiredRemoteDelay: func(chanAmt btcutil.Amount) uint16 {
			// We scale the remote CSV delay (the time the
			// remote have to claim funds in case of a unilateral
			// close) linearly from minRemoteDelay blocks
			// for small channels, to maxRemoteDelay blocks
			// for channels of size maxFundingAmount.
			// TODO(halseth): Litecoin parameter for LTC.

			// In case the user has explicitly specified
			// a default value for the remote delay, we
			// use it.
			defaultDelay := uint16(chainCfg.DefaultRemoteDelay)
			if defaultDelay > 0 {
				return defaultDelay
			}

			// If not we scale according to channel size.
			delay := uint16(btcutil.Amount(maxRemoteDelay) *
				chanAmt / maxFundingAmount)
			if delay < minRemoteDelay {
				delay = minRemoteDelay
			}
			if delay > maxRemoteDelay {
				delay = maxRemoteDelay
			}
			return delay
		},
		WatchNewChannel: func(channel *channeldb.OpenChannel,
			addr *lnwire.NetAddress) error {

			// First, we'll mark this new peer as a persistent peer
			// for re-connection purposes.
			server.mu.Lock()
			pubStr := string(addr.IdentityKey.SerializeCompressed())
			server.persistentPeers[pubStr] = struct{}{}
			server.mu.Unlock()

			// With that taken care of, we'll send this channel to
			// the chain arb so it can react to on-chain events.
			return server.chainArb.WatchNewChannel(channel)
		},
		ReportShortChanID: func(chanPoint wire.OutPoint,
			sid lnwire.ShortChannelID) error {

			cid := lnwire.NewChanIDFromOutPoint(&chanPoint)
			return server.htlcSwitch.UpdateShortChanID(cid, sid)
		},
		RequiredRemoteChanReserve: func(chanAmt btcutil.Amount) btcutil.Amount {
			// By default, we'll require the remote peer to maintain
			// at least 1% of the total channel capacity at all
			// times.
			return chanAmt / 100
		},
		RequiredRemoteMaxValue: func(chanAmt btcutil.Amount) lnwire.MilliSatoshi {
			// By default, we'll allow the remote peer to fully
			// utilize the full bandwidth of the channel, minus our
			// required reserve.
			reserve := lnwire.NewMSatFromSatoshis(chanAmt / 100)
			return lnwire.NewMSatFromSatoshis(chanAmt) - reserve
		},
		RequiredRemoteMaxHTLCs: func(chanAmt btcutil.Amount) uint16 {
			// By default, we'll permit them to utilize the full
			// channel bandwidth.
			return uint16(lnwallet.MaxHTLCNumber / 2)
		},
		ZombieSweeperInterval: 1 * time.Minute,
		ReservationTimeout:    10 * time.Minute,
	})
	if err != nil {
		return err
	}
	if err := fundingMgr.Start(); err != nil {
		return err
	}
	server.fundingMgr = fundingMgr
	 
	// Initialize, and register our implementation of the gRPC interface
	// exported by the rpcServer.
	
	rpcServer := newRPCServer(server)
	if err := rpcServer.Start(); err != nil {
		return err
	}
	LndRpcServer = rpcServer;
	 

 
	go func() error {
 
		_, bestHeight, err := activeChainControl.chainIO.GetBestBlock()
		if err != nil {
 		 srvrLog.Errorf("unable to sync: %v\n", err)
			return err
		}

		ltndLog.Infof("Waiting for chain backend to finish sync, "+
			"start_height=%v", bestHeight)

		for {
			synced, _, err := activeChainControl.wallet.IsSynced()
			if err != nil {
				return err
			}

			if synced {
				break
			}

			time.Sleep(time.Second * 1)
		}

		_, bestHeight, err = activeChainControl.chainIO.GetBestBlock()
		if err != nil {
			return err
		}

		ltndLog.Infof("Chain backend is fully synced (end_height=%v)!",
			bestHeight)
	 

	// With all the relevant chains initialized, we can finally start the
	// server itself.
	if err := server.Start(); err != nil {
		srvrLog.Errorf("unable to start server: %v\n", err)
		return err
	}


	// Now that the server has started, if the autopilot mode is currently
	// active, then we'll initialize a fresh instance of it and start it.
 var pilot *autopilot.Agent
	if cfg.Autopilot.Active {
		pilot, err := initAutoPilot(server, cfg.Autopilot)
		if err != nil {
			ltndLog.Errorf("unable to create autopilot agent: %v",
				err)
			return err
		}
		if err := pilot.Start(); err != nil {
			ltndLog.Errorf("unable to start autopilot agent: %v",
				err)
			return err
		}
	} 


	addInterruptHandler(func() {
		ltndLog.Infof("Gracefully shutting down the server...")
		rpcServer.Stop()
		fundingMgr.Stop()
		server.Stop()

		if pilot != nil {
			pilot.Stop()
		}

		server.WaitForShutdown()
	})


	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	<-shutdownChannel
	ltndLog.Info("Shutdown complete")

	 
return nil

	}()
 

	log.Print("Returning from Start")

	return nil

	 
	
}

// fileExists reports whether the named file or directory exists.
// This function is taken from https://github.com/btcsuite/btcd
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}


 func newChainControlFromConfigCustom(cfg *config, chanDB *channeldb.DB,
	privateWalletPw, publicWalletPw []byte, seed []byte) (*chainControl, func(), error) {

	// Set the RPC config from the "home" chain. Multi-chain isn't yet
	// active, so we'll restrict usage to a particular chain for now.
	homeChainConfig := cfg.Bitcoin
	if registeredChains.PrimaryChain() == litecoinChain {
		homeChainConfig = cfg.Litecoin
	}
	ltndLog.Infof("Primary chain is set to: %v",
		registeredChains.PrimaryChain())

	cc := &chainControl{}
 

		cc.routingPolicy = htlcswitch.ForwardingPolicy{
			MinHTLC:       cfg.Bitcoin.MinHTLC,
			BaseFee:       cfg.Bitcoin.BaseFee,
			FeeRate:       cfg.Bitcoin.FeeRate,
			TimeLockDelta: cfg.Bitcoin.TimeLockDelta,
		}
		cc.feeEstimator = lnwallet.StaticFeeEstimator{
			FeeRate: defaultBitcoinStaticFeeRate,
		}
	 

	walletConfig := &btcwallet.Config{
		PrivatePass:  privateWalletPw,
		PublicPass:   publicWalletPw,
		DataDir:      homeChainConfig.ChainDir,
		NetParams:    activeNetParams.Params,
		FeeEstimator: cc.feeEstimator,
		CoinType:     activeNetParams.CoinType,
		HdSeed:       seed,
	}

	var (
		err          error
		cleanUp      func() 
	)
 
		// First we'll open the database file for neutrino, creating
		// the database if needed. We append the normalized network name
		// here to match the behavior of btcwallet.
		neutrinoDbPath := filepath.Join(homeChainConfig.ChainDir,
			normalizeNetwork(activeNetParams.Name))

		// Ensure that the neutrino db path exists.
		if err := os.MkdirAll(neutrinoDbPath, 0700); err != nil {
			return nil, nil, err
		}

		dbName := filepath.Join(neutrinoDbPath, "neutrino.db")
		nodeDatabase, err := walletdb.Create("bdb", dbName)
		if err != nil {
			return nil, nil, err
		}



 
		// With the database open, we can now create an instance of the
		// neutrino light client. We pass in relevant configuration
		// parameters required.
		config := neutrino.Config{
			DataDir:      neutrinoDbPath,
			Database:     nodeDatabase,
			ChainParams:  *activeNetParams.Params,
			AddPeers:     cfg.NeutrinoMode.AddPeers,
			ConnectPeers: cfg.NeutrinoMode.ConnectPeers,
			Dialer: func(addr net.Addr) (net.Conn, error) {
				return cfg.net.Dial(addr.Network(), addr.String())
			},
			NameResolver: func(host string) ([]net.IP, error) {
				addrs, err := cfg.net.LookupHost(host)
				if err != nil {
					return nil, err
				}

				ips := make([]net.IP, 0, len(addrs))
				for _, strIP := range addrs {
					ip := net.ParseIP(strIP)
					if ip == nil {
						continue
					}

					ips = append(ips, ip)
				}

				return ips, nil
			},
		}
		neutrino.WaitForMoreCFHeaders = time.Second * 1
		neutrino.MaxPeers = 8
		neutrino.BanDuration = 5 * time.Second
		svc, err := neutrino.NewChainService(config)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to create neutrino: %v", err)
		}
		svc.Start()

		// Next we'll create the instances of the ChainNotifier and
		// FilteredChainView interface which is backed by the neutrino
		// light client.
		cc.chainNotifier, err = neutrinonotify.New(svc)
		if err != nil {
			return nil, nil, err
		}
		cc.chainView, err = chainview.NewCfFilteredChainView(svc)
		if err != nil {
			return nil, nil, err
		}

		// Finally, we'll set the chain source for btcwallet, and
		// create our clean up function which simply closes the
		// database.
		walletConfig.ChainSource = chain.NewNeutrinoClient(svc)
		cleanUp = func() {
			svc.Stop()
			nodeDatabase.Close()
		}
	 

	wc, err := btcwallet.New(*walletConfig)
	if err != nil {
		fmt.Printf("unable to create wallet controller: %v\n", err)
		return nil, nil, err
	}

	cc.msgSigner = wc
	cc.signer = wc
	cc.chainIO = wc

	// Select the default channel constraints for the primary chain.
	channelConstraints := defaultBtcChannelConstraints
	if registeredChains.PrimaryChain() == litecoinChain {
		channelConstraints = defaultLtcChannelConstraints
	}

	keyRing := keychain.NewBtcWalletKeyRing(
		wc.InternalWallet(), activeNetParams.CoinType,
	)

	// Create, and start the lnwallet, which handles the core payment
	// channel logic, and exposes control via proxy state machines.
	walletCfg := lnwallet.Config{
		Database:           chanDB,
		Notifier:           cc.chainNotifier,
		WalletController:   wc,
		Signer:             cc.signer,
		FeeEstimator:       cc.feeEstimator,
		SecretKeyRing:      keyRing,
		ChainIO:            cc.chainIO,
		DefaultConstraints: channelConstraints,
		NetParams:          *activeNetParams.Params,
	}
	wallet, err := lnwallet.NewLightningWallet(walletCfg)
	if err != nil {
		fmt.Printf("unable to create wallet: %v\n", err)
		return nil, nil, err
	}
	if err := wallet.Startup(); err != nil {
		fmt.Printf("unable to start wallet: %v\n", err)
		return nil, nil, err
	}

	ltndLog.Info("LightningWallet opened")

	cc.wallet = wallet
 

	return cc, cleanUp, nil
}


