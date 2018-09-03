package btc

import (
	"context"
	"errors"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type credential struct {
	WalletName string
}

func pathCredentials(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: PathCreds + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Wallet name",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredsRead,
		},

		HelpSynopsis:    PathCredsHelpSyn,
		HelpDescription: PathCredsHelpDesc,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	walletName := d.Get("name").(string)
	if walletName == "" {
		return nil, errors.New(MissingWalletNameError)
	}

	w, err := b.GetWallet(ctx, req.Storage, walletName)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return nil, errors.New("Failed to create credentials for '" + walletName + "': wallet does not exist")
	}

	cred := &credential{
		WalletName: walletName,
	}

	token, err := b.NewToken(ctx, req.Storage, cred, walletName)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(SecretCredsType).Response(
		map[string]interface{}{"token": token},
		map[string]interface{}{"token": token},
	)

	return resp, nil
}

func newSaltedToken(ctx context.Context, s logical.Storage, config *salt.Config) (string, string, error) {
	token, err := uuid.GenerateUUID()
	if err != nil {
		return "", "", err
	}

	newSalt, err := salt.NewSalt(ctx, s, config)
	if err != nil {
		return "", "", err
	}

	return token, newSalt.SaltID(token), nil
}

func (b *backend) NewToken(ctx context.Context, store logical.Storage, cred *credential, walletName string) (string, error) {
	token, saltedToken, err := newSaltedToken(ctx, store, nil)
	if err != nil {
		return "", err
	}

	entry, err := logical.StorageEntryJSON(PathCreds+saltedToken, cred)
	if err != nil {
		return "", err
	}

	if err := store.Put(ctx, entry); err != nil {
		return "", err
	}

	return token, nil
}

func (b *backend) GetToken(ctx context.Context, s logical.Storage, token string) (*credential, error) {
	newSalt, err := salt.NewSalt(ctx, s, nil)
	if err != nil {
		return nil, err
	}

	saltedToken := newSalt.SaltID(token)

	entry, err := s.Get(ctx, PathCreds+saltedToken)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var cred credential
	if err := entry.DecodeJSON(&cred); err != nil {
		return nil, err
	}

	return &cred, nil
}
