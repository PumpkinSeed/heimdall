package token

import (
	"context"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/vault"
	"sync"
)

// tokenSubPath is the sub-path used for the token store
// view. This is nested under the system view.
var (
	tokenSubPath = "token/"

	// idPrefix is the prefix used to store tokens for their
	// primary ID based index
	idPrefix = "id/"

	// accessorPrefix is the prefix used to store the index from
	// Accessor to Token ID
	accessorPrefix = "accessor/"

	// parentPrefix is the prefix used to store tokens for their
	// secondary parent based index
	parentPrefix = "parent/"

	// rolesPrefix is the prefix used to store role information
	//rolesPrefix = "roles/"
)

type Request struct {
	ID string `json:"id,omitempty"`
}

type Response struct {
	ID string `json:"id"`
}

type TokenStore struct {
	salts               map[string]*salt.Salt
	baseBarrierView     *vault.BarrierView
	idBarrierView       *vault.BarrierView
	accessorBarrierView *vault.BarrierView
	parentBarrierView   *vault.BarrierView
	//rolesBarrierView    *vault.BarrierView

	saltLock   sync.RWMutex
	tokenLocks []*locksutil.LockEntry
}

func NewTokenStore(u *unseal.Unseal) *TokenStore {
	view := vault.NewBarrierView(u.SecurityBarrier, "sys/"+tokenSubPath)
	return &TokenStore{
		salts:               make(map[string]*salt.Salt),
		baseBarrierView:     view,
		idBarrierView:       view.SubView(idPrefix),
		accessorBarrierView: view.SubView(accessorPrefix),
		parentBarrierView:   view.SubView(parentPrefix),
		saltLock:            sync.RWMutex{},
		tokenLocks:          locksutil.CreateLocks(),
	}
}

func (ts *TokenStore) CheckToken(ctx context.Context, id string) (bool, error) {
	tokenNS, err := ts.NamespaceByID(ctx, namespace.RootNamespaceID)
	if err != nil {
		return false, err
	}
	if tokenNS == nil {
		return false, namespace.ErrNoNamespace
	}
	ctx = namespace.ContextWithNamespace(ctx, tokenNS)
	ret, err := ts.lookupInternal(ctx, id, false, false)
	if err != nil {
		return false, err
	}
	return ret != nil, nil
}
