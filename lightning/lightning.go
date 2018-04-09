package lightning

import (
	"github.com/mandelmonkey/lndmobile/lnd"  
	"strings"
	"log"
	b39 "github.com/tyler-smith/go-bip39"
	"github.com/roasbeef/btcutil/hdkeychain"
	"github.com/roasbeef/btcutil" 
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/jsonpb"
	"fmt"
	"github.com/lightningnetwork/lnd/lnrpc"
)

 
var started = false

func Start(dir, mnemonic string) error {


	btcutil.SetDir(dir);


	if started {
		log.Print("LND already started")
		return nil
	}

	started = true 

	var seed []byte = nil
	var err error

	if mnemonic != "" {
		seed, err = b39.NewSeedWithErrorChecking(mnemonic, "")
		if err != nil {
			return err
		}
	}

	err = lnd.Start(seed,dir)
	if err != nil {
		log.Printf("lnd.Start failed: %v\n", err)
		return err
	}
 	 

	return nil
}
 
func CreateBip39Seed() (string, error) {
	// Using 32 bytes of entropy gives us a 24 word seed phrase. Here we use
	// half of that to obtain a 12 word phrase.
	entropy, err := hdkeychain.GenerateSeed(16)
	if err != nil {
		return "", err
	}

	mnemonic, err := b39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}

 
func convertToJSON(resp proto.Message) (string,error) {
	jsonMarshaler := &jsonpb.Marshaler{
		EmitDefaults: true,
		Indent:       "    ",
	}

	jsonStr, err := jsonMarshaler.MarshalToString(resp)
	if err != nil {
		fmt.Println("unable to decode response: ", err)
		return "",err
	}

	return jsonStr,nil;
}

func GetInfo() (string, error){
	req := &lnrpc.GetInfoRequest{}
	resp, err := lnd.LndRpcServer.GetInfo(nil, req)
	
	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

 

func NewAddress(addressType int32) (string, error){

	req := &lnrpc.NewAddressRequest{}
	req.Type = lnrpc.NewAddressRequest_AddressType(addressType)
	resp, err := lnd.LndRpcServer.NewAddress(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func WalletBalance() (string, error){


	req := &lnrpc.WalletBalanceRequest{}
	resp, err := lnd.LndRpcServer.WalletBalance(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func ChannelBalance() (string, error){

	req := &lnrpc.ChannelBalanceRequest{}
	resp, err := lnd.LndRpcServer.ChannelBalance(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func PendingChannels() (string, error){

	req := &lnrpc.PendingChannelsRequest{}
	resp, err := lnd.LndRpcServer.PendingChannels(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func ListChannels() (string, error){

	req := &lnrpc.ListChannelsRequest{}
	resp, err := lnd.LndRpcServer.ListChannels(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func ListPayments() (string, error){

	req := &lnrpc.ListPaymentsRequest{}
	resp, err := lnd.LndRpcServer.ListPayments(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func ListPeers() (string, error){

	req := &lnrpc.ListPeersRequest{}
	resp, err := lnd.LndRpcServer.ListPeers(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func GetTransactions() (string, error){

	req := &lnrpc.GetTransactionsRequest{}
	resp, err := lnd.LndRpcServer.GetTransactions(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func ConnectPeer(targetAddress string) (string, error){

	splitAddr := strings.Split(targetAddress, "@")
	if len(splitAddr) != 2 {
		return "", fmt.Errorf("target address expected in format: " +
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

	resp, err := lnd.LndRpcServer.ConnectPeer(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func OpenChannelSync(nodePubKeyHex string,localAmount int64) (string, error){

	req := &lnrpc.OpenChannelRequest{}	 
		 
	req.NodePubkeyString = nodePubKeyHex;
	   
	req.LocalFundingAmount = localAmount
		 
	req.Private = false; 
	  
	resp, err := lnd.LndRpcServer.OpenChannelSync(nil, req)
	if err != nil {
		return "", err
	} 
	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

func SendPaymentSync(paymentRequest string) (string, error){

	req := &lnrpc.SendRequest{
			PaymentRequest: paymentRequest, 
		} 
	
	resp, err := lnd.LndRpcServer.SendPaymentSync(nil, req)

	if err != nil {
		return "", err
	}

	jsonString,err := convertToJSON(resp);
 	
 	if err != nil {
		return "", err
	}

	return jsonString, nil
}

 
