package btc

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathTransaction(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "transaction/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Wallet name",
			},
			"rawTx": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Raw transaction to be signed",
			},
			"multisig": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: "Multisig transaction",
				Default:     false,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathTransactionWrite,
		},

		HelpSynopsis:    PathTransactionHelpSyn,
		HelpDescription: PathTransactionHelpDesc,
	}
}

func (b *backend) pathTransactionWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	walletName := d.Get("name").(string)
	if walletName == "" {
		return nil, errors.New(MissingWalletNameError)
	}
	multisig := d.Get("multisig").(bool)
	if multisig {
		walletName = MultiSigPrefix + walletName
	}

	w, err := b.GetWallet(ctx, req.Storage, walletName)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return nil, errors.New("Wallet " + walletName + " not found")
	}

	rawTx := d.Get("rawTx").(string)
	if rawTx == "" {
		return nil, errors.New(MissingRawTxError)
	}

	seed := seedFromMnemonic(w.Mnemonic)

	masterKey, err := getMasterKey(seed, w.Network)
	if err != nil {
		return nil, err
	}

	// derive key of last used address (for multisig is 0)
	childnum, err := b.GetLastUsedAddressIndex(ctx, req.Storage, walletName)
	if err != nil {
		return nil, err
	}

	derivedPrivKey, err := derivePrivKey(masterKey, append(w.DerivationPath, childnum))
	privateKey, err := derivedPrivKey.ECPrivKey()
	if err != nil {
		return nil, err
	}

	// convert tx string to raw bytes
	rawTxBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		return nil, err
	}

	// double sha256 before signing
	hashedRawTx := chainhash.DoubleHashB(rawTxBytes)
	signatureBytes, err := privateKey.Sign(hashedRawTx)
	if err != nil {
		return nil, err
	}

	// convert signature raw bytes to string
	signature := hex.EncodeToString(signatureBytes.Serialize())

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": signature,
		},
	}, nil
}
