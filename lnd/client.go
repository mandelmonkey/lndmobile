// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2017 The Lightning Network Developers

package lnd

import (
	"bytes"
	"crypto/rsa" 
	//"crypto/ecdsa"
	//"crypto/elliptic"
	"encoding/hex"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
    "google.golang.org/grpc/credentials"
	"io/ioutil"
	"math/big"
 
	"log"
	"net"
	"time"
	"net/http"
	"os"
	//"golang.org/x/net/context"
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
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/lnwallet"
	base "github.com/roasbeef/btcwallet/wallet"   
	//proxy "github.com/grpc-ecosystem/grpc-gateway/runtime" 
 	//"github.com/urfave/cli"
	"github.com/roasbeef/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"github.com/lightningnetwork/lnd/lnrpc"
	"crypto/rand" 
	"sync" 
	"github.com/lightningnetwork/lnd/chainntnfs/neutrinonotify"
	"github.com/lightningnetwork/lnd/routing/chainview"

)

const (
	// Make certificate valid for 14 months.
	autogenCertValidity = 14 /*months*/ * 30 /*days*/ * 24 * time.Hour

)

var (

	//Commit stores the current commit hash of this build. This should be
	//set using -ldflags during compilation.
	Commit string

	cfg              *config
	shutdownChannel  = make(chan struct{})
	registeredChains = newChainRegistry()

	macaroonDatabaseDir string
	
	// End of ASN.1 time.
	endOfTime = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)

	// Max serial number.
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)


	/*
	 * These cipher suites fit the following criteria:
	 * - Don't use outdated algorithms like SHA-1 and 3DES
	 * - Don't use ECB mode or other insecure symmetric methods
	 * - Included in the TLS v1.2 suite
	 * - Are available in the Go 1.7.6 standard library (more are
	 *   available in 1.8.3 and will be added after lnd no longer
	 *   supports 1.7, including suites that support CBC mode)
	**/
	/*tlsCipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}*/

	tlsCipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

)

// Controls access to lightningRpcServer.
var rpcServerMutex = &sync.Mutex{}

var lndGrpcServer *grpc.Server 
var lndRpcServer * rpcServer;
 
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

	// Only process macaroons if --no-macaroons isn't set.
	/*ctx := context.Background()
	//ctx, cancel := context.WithCancel(ctx)
	//defer cancel() //this was closed for ios specific


	// Ensure we create TLS key and certificate if they don't exist
	if !fileExists(cfg.TLSCertPath) && !fileExists(cfg.TLSKeyPath) {
		if err := genCertPair(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
			return err
		}
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		CipherSuites: tlsCipherSuites,
		MinVersion:   tls.VersionTLS12,
	}
	sCreds := credentials.NewTLS(tlsConf)
	serverOpts := []grpc.ServerOption{grpc.Creds(sCreds)}
	cCreds, err := credentials.NewClientTLSFromFile(cfg.TLSCertPath, "")
	if err != nil {
		return err
	}
	proxyOpts := []grpc.DialOption{grpc.WithTransportCredentials(cCreds)}
*/
	 
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
	lndRpcServer = rpcServer;
	 /*

	grpcServer := grpc.NewServer(serverOpts...)
	lnrpc.RegisterLightningServer(grpcServer, lndRpcServer)

	// Next, Start the gRPC server listening for HTTP/2 connections.
	for _, listener := range cfg.RPCListeners {
		lis, err := net.Listen("tcp", listener)
		if err != nil {
			ltndLog.Errorf("RPC server unable to listen on %s", listener)
			return err
		}
		//defer lis.Close()
		go func() {
			rpcsLog.Infof("RPC server listening on %s", lis.Addr())
			grpcServer.Serve(lis)
		}()
	}

	// Finally, start the REST proxy for our gRPC server above.
	mux := proxy.NewServeMux()
	err = lnrpc.RegisterLightningHandlerFromEndpoint(ctx, mux,
		cfg.RPCListeners[0], proxyOpts)
	if err != nil {
		return err
	}
	for _, restEndpoint := range cfg.RESTListeners {
		listener, err := tls.Listen("tcp", restEndpoint, tlsConf)
		if err != nil {
			ltndLog.Errorf("gRPC proxy unable to listen on %s", restEndpoint)
			return err
		}
		//defer listener.Close()
		go func() {
			rpcsLog.Infof("gRPC proxy started at %s", listener.Addr())
			http.Serve(listener, mux)
		}()
	}
*/
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

	 /*
 
	return nil
*/



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

func genCertPair(certFile, keyFile string) error {
	rpcsLog.Infof("Generating TLS certificates...")

	org := "lnd autogenerated cert"
	now := time.Now()
	validUntil := now.Add(autogenCertValidity)

	// Check that the certificate validity isn't past the ASN.1 end of time.
	if validUntil.After(endOfTime) {
		validUntil = endOfTime
	}

	// Generate a serial number that's below the serialNumberLimit.
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %s", err)
	}

	// Collect the host's IP addresses, including loopback, in a slice.
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	// addIP appends an IP address only if it isn't already in the slice.
	addIP := func(ipAddr net.IP) {
		for _, ip := range ipAddresses {
			if bytes.Equal(ip, ipAddr) {
				return
			}
		}
		ipAddresses = append(ipAddresses, ipAddr)
	}

	// Add all the interface IPs that aren't already in the slice.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		ipAddr, _, err := net.ParseCIDR(a.String())
		if err == nil {
			addIP(ipAddr)
		}
	}

	// Add extra IP to the slice.
	ipAddr := net.ParseIP(cfg.TLSExtraIP)
	if ipAddr != nil {
		addIP(ipAddr)
	}

	// Collect the host's names into a slice.
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	dnsNames := []string{host}
	if host != "localhost" {
		dnsNames = append(dnsNames, "localhost")
	}
	if cfg.TLSExtraDomain != "" {
		dnsNames = append(dnsNames, cfg.TLSExtraDomain)
	}

	// Generate a private key for the certificate.
	/*priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}*/

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// Construct the certificate template.
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   host,
		},
		NotBefore: now.Add(-time.Hour * 24),
		NotAfter:  validUntil,

		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA: true, // so can sign self.
		BasicConstraintsValid: true,

		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template,
		&template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	certBuf := &bytes.Buffer{}
	err = pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE",
		Bytes: derBytes})
	if err != nil {
		return fmt.Errorf("failed to encode certificate: %v", err)
	}

	/*keybytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("unable to encode privkey: %v", err)
	}
	keyBuf := &bytes.Buffer{}
	err = pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY",
		Bytes: keybytes})
	if err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}*/

	keybytes := x509.MarshalPKCS1PrivateKey(priv)
	keyBuf := &bytes.Buffer{}
	err = pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: keybytes})
	if err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}

	// Write cert and key files.
	if err = ioutil.WriteFile(certFile, certBuf.Bytes(), 0644); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyFile, keyBuf.Bytes(), 0600); err != nil {
		os.Remove(certFile)
		return err
	}

	rpcsLog.Infof("Done generating TLS certificates")
	return nil
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


 
func WalletExists(dataDir string) bool {
	network := chaincfg.TestNet3Params

	netDir := btcwallet.NetworkDir(dataDir, &network)

	loader := base.NewLoader(&network, netDir)
	walletExists, err := loader.WalletExists()
	if err != nil {
		log.Printf("Failed to read wallet: %v", err)
		return true
	}

	return walletExists
}

func Pause() {
	ltndLog.Errorf("stopping grpc")
	// Kills the gRPC server and any tcp connections.
	lndGrpcServer.GracefulStop();
	 
	lndGrpcServer = nil 
}

func Resume() {

//	ctx := context.Background()
	//ctx, cancel := context.WithCancel(ctx)
	//defer cancel() //this was closed for ios specific


	// Ensure we create TLS key and certificate if they don't exist
	if !fileExists(cfg.TLSCertPath) && !fileExists(cfg.TLSKeyPath) {
		if err := genCertPair(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
			//return err
		}
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		ltndLog.Errorf("grpc resume error %s", err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		CipherSuites: tlsCipherSuites,
		MinVersion:   tls.VersionTLS12,
	}
	sCreds := credentials.NewTLS(tlsConf)
	serverOpts := []grpc.ServerOption{grpc.Creds(sCreds)}
	 
	 

	ltndLog.Errorf("resuming grpc")

	 
	grpcServer := grpc.NewServer(serverOpts...)
	lnrpc.RegisterLightningServer(grpcServer, lndRpcServer)
	ltndLog.Errorf("resuming grpc4")


	// Next, Start the gRPC server listening for HTTP/2 connections.
	for _, listener := range cfg.RPCListeners {
		lis, err := net.Listen("tcp", listener)
		if err != nil {
			ltndLog.Errorf("RPC server unable to listen on %s", listener)
			 
		}
		//defer lis.Close()
		go func() {
			rpcsLog.Infof("RPC server listening on %s", lis.Addr())
			grpcServer.Serve(lis)
		}()
	}
	lndGrpcServer = grpcServer;


 }

func GetInfo()(*lnrpc.GetInfoResponse, error){

	req := &lnrpc.GetInfoRequest{}
	resp, err := lndRpcServer.GetInfo(nil, req)
	if err != nil {
		return nil, err
	}

	return resp,nil

}

func NewAddress(addressType int32)(*lnrpc.NewAddressResponse, error){

	req := &lnrpc.NewAddressRequest{}
	req.Type = lnrpc.NewAddressRequest_AddressType(addressType)
	resp, err := lndRpcServer.NewAddress(nil, req)
	if err != nil {
		return nil, err
	}

	return resp,nil

}

func WalletBalance()(*lnrpc.WalletBalanceResponse, error){

	req := &lnrpc.WalletBalanceRequest{}
	resp, err := lndRpcServer.WalletBalance(nil, req)
	if err != nil {
		return nil, err
	}

	return resp,nil

}

func ChannelBalance()(*lnrpc.ChannelBalanceResponse, error){

	req := &lnrpc.ChannelBalanceRequest{}
	resp, err := lndRpcServer.ChannelBalance(nil, req)
	if err != nil {
		return nil, err
	}

	return resp,nil

}

func PendingChannels()(*lnrpc.PendingChannelsResponse, error){

	req := &lnrpc.PendingChannelsRequest{}
	resp, err := lndRpcServer.PendingChannels(nil, req)
	if err != nil {
		return nil, err
	}

	return resp,nil

}

func ListChannels()(*lnrpc.ListChannelsResponse, error){

	req := &lnrpc.ListChannelsRequest{}
	resp, err := lndRpcServer.ListChannels(nil, req)
	if err != nil {
		return nil, err
	}

	return resp,nil

}

func ListPayments()(*lnrpc.ListPaymentsResponse, error){

	req := &lnrpc.ListPaymentsRequest{}
	resp, err := lndRpcServer.ListPayments(nil, req)
	if err != nil {
		return nil, err
	}

	return resp,nil

}

func GetTransactions()(*lnrpc.TransactionDetails, error){

	req := &lnrpc.GetTransactionsRequest{}
	resp, err := lndRpcServer.GetTransactions(nil, req)
	if err != nil {
		return nil, err
	}

	return resp,nil

}

func ConnectPeer(targetAdd string)(*lnrpc.ConnectPeerResponse, error){
	//ctx :=  context.Background()
	//ctxb := context.Background()
	targetAddress := targetAdd
	splitAddr := strings.Split(targetAddress, "@")
	if len(splitAddr) != 2 {
		return nil, fmt.Errorf("target address expected in format: " +
			"pubkey@host:port")
	}

	addr := &lnrpc.LightningAddress{
		Pubkey: splitAddr[0],
		Host:   splitAddr[1],
	}
	req := &lnrpc.ConnectPeerRequest{
		Addr: addr,
		Perm:false,
	}

	resp, err := lndRpcServer.ConnectPeer(nil, req)
	if err != nil {
		return nil, err
	}

	return resp,nil

}
 
func OpenChannelSync(nodePubKeyHex string,localAmount int64)(*lnrpc.ChannelPoint, error){
	// TODO(roasbeef): add deadline to context
	//ctxb := context.Background()
	 
	var err error
 

	req := &lnrpc.OpenChannelRequest{}

	nodePubHex, err := hex.DecodeString(nodePubKeyHex)
	
	if err != nil {
		return nil,fmt.Errorf("unable to decode node public key: %v", err)
	}
		 
	req.NodePubkey = nodePubHex;
	 

	// As soon as we can confirm that the node's node_key was set, rather
	// than the peer_id, we can check if the host:port was also set to
	// connect to it before opening the channel.
	if req.NodePubkey != nil  {
		addr := &lnrpc.LightningAddress{
			Pubkey: hex.EncodeToString(req.NodePubkey),
			//Host:   ctx.String("connect"),
		}

		req := &lnrpc.ConnectPeerRequest{
			Addr: addr,
			Perm: false,
		}

		// Check if connecting to the node was successful.
		// We discard the peer id returned as it is not needed.
		_, err := lndRpcServer.ConnectPeer(nil, req)
		if err != nil &&
			!strings.Contains(err.Error(), "already connected") {
			return nil,err
		}
	}
 
	req.LocalFundingAmount = localAmount
	if err != nil {
		return nil,fmt.Errorf("unable to decode local amt: %v", err)
	}
		 
	/*look at later

	if ctx.IsSet("push_amt") {
		req.PushSat = int64(ctx.Int("push_amt"))
	} else if args.Present() {
		req.PushSat, err = strconv.ParseInt(args.First(), 10, 64)
		if err != nil {
			return fmt.Errorf("unable to decode push amt: %v", err)
		}
	}
	*/

	req.Private = false;//ctx.Bool("private")
	 
	resp, err := lndRpcServer.OpenChannelSync(nil, req)
	if err != nil {
		return nil,err
	}

	return resp,nil

		
	
}

func SendPaymentSync(paymentRequest string)(*lnrpc.SendResponse, error){
	// TODO(roasbeef): add deadline to context
	//ctxb := context.Background()
	
	req := &lnrpc.SendRequest{
			PaymentRequest: paymentRequest, 
		} 
	
	resp, err := lndRpcServer.SendPaymentSync(nil, req)
	if err != nil {
		return nil,err
	}

	return resp,nil

		
	
}

