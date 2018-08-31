package btc

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type multiSigWallet struct {
	Network        string
	Mnemonic       string
	DerivationPath []uint32
	M              int
	N              int
	RedeemScript   string
	PublicKeys     []string
}

func pathMultiSigWallet(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "wallet/multisig/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"network": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Btc network type: mainnet | testnet",
			},
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Wallet name",
			},
			"pubkeys": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: "List of public keys for multisig wallet",
			},
			"m": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Description: "Threshold signature",
			},
			"n": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Description: "Total number of signatures",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathMultiSigWalletRead,
			logical.UpdateOperation: b.pathMultiSigWalletWrite,
		},

		HelpSynopsis:    pathMultiSigWalletsHelpSyn,
		HelpDescription: pathMultiSigWalletsHelpDesc,
	}
}

func (b *backend) pathMultiSigWalletWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	network := d.Get("network").(string)
	if network == "" {
		return nil, errors.New("missing network")
	}

	walletName := d.Get("name").(string)
	if walletName == "" {
		return nil, errors.New("missing wallet name")
	}

	pubkeys := d.Get("pubkeys").([]string)
	if len(pubkeys) == 0 {
		return nil, errors.New("missing public keys")
	}

	m := d.Get("m").(int)
	if m <= 0 {
		return nil, errors.New("Missing or invalid m param: it must be a positive number)")
	}

	n := d.Get("n").(int)
	if n <= 0 {
		return nil, errors.New("Missing or invalid n param: it must be a positive number)")
	}

	// check valid params:
	// # of public keys should be equal to n - 1
	// m should be minor or equal to n
	// TODO: check valid public keys
	if l := len(pubkeys); l != (n - 1) {
		return nil, errors.New("Invalid list of public keys: provided " + string(l) + " expected " + string(n))
	}
	if m > n {
		return nil, errors.New("Invalid m param: it must be minor or equal to n")
	}

	// return error if a wallet with same name has already been created
	walletName = "multisig_" + walletName
	w, err := b.GetMultiSigWallet(ctx, req.Storage, walletName)
	if err != nil {
		return nil, err
	}
	if w != nil {
		return nil, errors.New("MultiSig wallet with name '" + walletName + "' already exists")
	}

	// create multisig wallet with params
	wallet, err := createMultiSigWallet(network, pubkeys, m, n)
	if err != nil {
		return nil, err
	}

	// create storage entry
	entry, err := logical.StorageEntryJSON("wallet/"+walletName, wallet)
	if err != nil {
		return nil, err
	}

	// save in local storage
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathMultiSigWalletRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	walletName := d.Get("name").(string)
	walletName = "multisig_" + walletName

	// get wallet from storage
	w, err := b.GetMultiSigWallet(ctx, req.Storage, walletName)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"m":            w.M,
			"n":            w.N,
			"pubkeys":      w.PublicKeys,
			"redeemScript": w.RedeemScript,
		},
	}, nil
}

func (b *backend) GetMultiSigWallet(ctx context.Context, store logical.Storage, walletName string) (*multiSigWallet, error) {
	entry, err := store.Get(ctx, "wallet/"+walletName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var w multiSigWallet
	if err := entry.DecodeJSON(&w); err != nil {
		return nil, err
	}

	return &w, nil
}

const pathMultiSigWalletsHelpSyn = ""
const pathMultiSigWalletsHelpDesc = ""
