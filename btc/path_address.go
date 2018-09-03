package btc

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type address struct {
	Childnum    uint32
	LastAddress string
}

func pathAddress(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: PathAddress + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Wallet name",
			},
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Auth token",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathAddressWrite,
		},

		HelpSynopsis:    PathAddressHelpSyn,
		HelpDescription: PathAddressHelpDesc,
	}
}

func (b *backend) pathAddressWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	t := d.Get("token").(string)
	if t == "" {
		return nil, errors.New(MissingTokenError)
	}

	// check if auth token is valid
	token, err := b.GetToken(ctx, req.Storage, t)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New(InvalidTokenError)
	}

	walletName := token.WalletName

	// get wallet from storage
	w, err := b.GetWallet(ctx, req.Storage, walletName)

	// get last address and address index from storage
	childnum, err := b.GetLastUsedAddressIndex(ctx, req.Storage, walletName)
	if err != nil {
		return nil, err
	}

	// increment childnum to derive next address
	childnum = childnum + 1
	a, err := deriveAddress(w, childnum)
	if err != nil {
		return nil, err
	}

	// override the storage with new generated address
	entry, err := logical.StorageEntryJSON(PathAddress+walletName, a)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": a.LastAddress,
		},
	}, nil
}

// retrieves last derived address from storage and returns its index
func (b *backend) GetLastUsedAddressIndex(ctx context.Context, store logical.Storage, walletName string) (uint32, error) {
	var childnum uint32

	addressEntry, err := store.Get(ctx, PathAddress+walletName)
	if err != nil {
		return 0, err
	}
	if addressEntry != nil {
		var a address
		if err := addressEntry.DecodeJSON(&a); err != nil {
			return 0, err
		}
		childnum = a.Childnum
	}

	return childnum, nil
}
