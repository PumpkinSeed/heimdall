package init

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rootTokenEntryPath = "auth/token/root"
	rootTokenPolicy    = "root"
)

func (init *Init) getRootToken(ctx context.Context) (*logical.TokenEntry, error) {
	ctx = namespace.ContextWithNamespace(ctx, namespace.RootNamespace)
	te := &logical.TokenEntry{
		Policies:     []string{rootTokenPolicy},
		Path:         rootTokenEntryPath,
		DisplayName:  rootTokenPolicy,
		CreationTime: time.Now().Unix(),
		NamespaceID:  namespace.RootNamespaceID,
		Type:         logical.TokenTypeService,
	}
	tokenNS, err := init.NamespaceByID(ctx, te.NamespaceID)
	if err != nil {
		return nil, err
	}
	if tokenNS == nil {
		return nil, errors.New("missing token")
	}

	te.Policies = policyutil.SanitizePolicies(te.Policies, policyutil.DoNotAddDefaultPolicy)
	//
	//var createRootTokenFlag bool
	//if len(te.Policies) == 1 && te.Policies[0] == "root" {
	//	createRootTokenFlag = true
	//}

	// In case it was default, force to service
	te.Type = logical.TokenTypeService

	// Generate an ID if necessary
	//userSelectedID := true
	//if te.ID == "" {
	//	userSelectedID = false
	te.ID, err = base62.RandomWithReader(TokenLength, rand.Reader)

	if err != nil {
		return nil, err
	}
	//}

	//if !userSelectedID {
	te.ID = fmt.Sprintf("s.%s", te.ID)
	//}

	// Attach namespace ID for tokens that are not belonging to the root
	// namespace
	if tokenNS.ID != namespace.RootNamespaceID {
		te.ID = fmt.Sprintf("%s.%s", te.ID, tokenNS.ID)
	}

	if tokenNS.ID != namespace.RootNamespaceID || strings.HasPrefix(te.ID, "s.") {
		if te.CubbyholeID == "" {
			cubbyholeID, err := base62.Random(TokenLength)
			if err != nil {
				return nil, err
			}
			te.CubbyholeID = cubbyholeID
		}
	}

	// If the user didn't specifically pick the ID, e.g. because they were
	// sudo/root, check for collision; otherwise trust the process
	//if userSelectedID {
	//	exist, _ := init.lookupInternal(ctx, te.ID, false, true)
	//	if exist != nil {
	//		return fmt.Errorf("cannot create a token with a duplicate ID")
	//	}
	//}

	err = init.createAccessor(ctx, te)
	if err != nil {
		return nil, err
	}

	if err := init.storeCommon(ctx, te, true); err != nil {
		return nil, err
	}
	return te, nil
}

func (init *Init) NamespaceByID(ctx context.Context, id string) (*namespace.Namespace, error) {
	if id == namespace.RootNamespaceID {
		return namespace.RootNamespace, nil
	}
	return nil, namespace.ErrNoNamespace
}

func (init *Init) createAccessor(ctx context.Context, entry *logical.TokenEntry) error {
	var err error
	// Create a random accessor
	entry.Accessor, err = base62.Random(TokenLength)
	if err != nil {
		return err
	}

	tokenNS, err := init.NamespaceByID(ctx, entry.NamespaceID)
	if err != nil {
		return err
	}
	if tokenNS == nil {
		return namespace.ErrNoNamespace
	}

	if tokenNS.ID != namespace.RootNamespaceID {
		entry.Accessor = fmt.Sprintf("%s.%s", entry.Accessor, tokenNS.ID)
	}

	// Create index entry, mapping the accessor to the token ID
	saltCtx := namespace.ContextWithNamespace(ctx, tokenNS)
	saltID, err := init.SaltID(saltCtx, entry.Accessor)
	if err != nil {
		return err
	}

	aEntry := &accessorEntry{
		TokenID:     entry.ID,
		AccessorID:  entry.Accessor,
		NamespaceID: entry.NamespaceID,
	}

	aEntryBytes, err := jsonutil.EncodeJSON(aEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal accessor index entry: %v", err)
	}

	le := &logical.StorageEntry{Key: saltID, Value: aEntryBytes}
	if err := init.accessorBarrierView.Put(ctx, le); err != nil {
		return fmt.Errorf("failed to persist accessor index entry: %v", err)
	}
	return nil

}

func (init *Init) lookupInternal(ctx context.Context, id string, salted, tainted bool) (*logical.TokenEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, errwrap.Wrapf("failed to find namespace in context: {{err}}", err)
	}

	// If it starts with "b." it's a batch token
	if len(id) > 2 && strings.HasPrefix(id, "b.") {
		return nil, err
	}

	var raw *logical.StorageEntry
	lookupID := id

	if !salted {
		// If possible, always use the token's namespace. If it doesn't match
		// the request namespace, ensure the request namespace is a child
		_, nsID := namespace.SplitIDFromString(id)
		if nsID != "" {
			tokenNS, err := init.NamespaceByID(ctx, nsID)
			if err != nil {
				return nil, errwrap.Wrapf("failed to look up namespace from the token: {{err}}", err)
			}
			if tokenNS != nil {
				if tokenNS.ID != ns.ID {
					ns = tokenNS
					ctx = namespace.ContextWithNamespace(ctx, tokenNS)
				}
			}
		} else {
			// Any non-root-ns token should have an accessor and child
			// namespaces cannot have custom IDs. If someone omits or tampers
			// with it, the lookup in the root namespace simply won't work.
			ns = namespace.RootNamespace
			ctx = namespace.ContextWithNamespace(ctx, ns)
		}

		lookupID, err = init.SaltID(ctx, id)
		if err != nil {
			return nil, err
		}
	}

	raw, err = init.idBarrierView.Get(ctx, lookupID)
	if err != nil {
		return nil, errwrap.Wrapf("failed to read entry: {{err}}", err)
	}

	// Bail if not found
	if raw == nil {
		return nil, nil
	}

	// Unmarshal the token
	entry := new(logical.TokenEntry)
	if err := jsonutil.DecodeJSON(raw.Value, entry); err != nil {
		return nil, errwrap.Wrapf("failed to decode entry: {{err}}", err)
	}

	// This is a token that is awaiting deferred revocation or tainted
	if entry.NumUses < 0 && !tainted {
		return nil, nil
	}

	if entry.NamespaceID == "" {
		entry.NamespaceID = namespace.RootNamespaceID
	}

	// This will be the upgrade case
	if entry.Type == logical.TokenTypeDefault {
		entry.Type = logical.TokenTypeService
	}

	persistNeeded := false

	// Upgrade the deprecated fields
	if entry.DisplayNameDeprecated != "" {
		if entry.DisplayName == "" {
			entry.DisplayName = entry.DisplayNameDeprecated
		}
		entry.DisplayNameDeprecated = ""
		persistNeeded = true
	}

	if entry.CreationTimeDeprecated != 0 {
		if entry.CreationTime == 0 {
			entry.CreationTime = entry.CreationTimeDeprecated
		}
		entry.CreationTimeDeprecated = 0
		persistNeeded = true
	}

	if entry.ExplicitMaxTTLDeprecated != 0 {
		if entry.ExplicitMaxTTL == 0 {
			entry.ExplicitMaxTTL = entry.ExplicitMaxTTLDeprecated
		}
		entry.ExplicitMaxTTLDeprecated = 0
		persistNeeded = true
	}

	if entry.NumUsesDeprecated != 0 {
		if entry.NumUses == 0 || entry.NumUsesDeprecated < entry.NumUses {
			entry.NumUses = entry.NumUsesDeprecated
		}
		entry.NumUsesDeprecated = 0
		persistNeeded = true
	}

	// It's a root token with unlimited creation TTL (so never had an
	// expiration); this may or may not have a lease (based on when it was
	// generated, for later revocation purposes) but it doesn't matter, it's
	// allowed. Fast-path this.
	if len(entry.Policies) == 1 && entry.Policies[0] == "root" && entry.TTL == 0 {
		// If fields are getting upgraded, store the changes
		if persistNeeded {
			if err := init.store(ctx, entry); err != nil {
				return nil, errwrap.Wrapf("failed to persist token upgrade: {{err}}", err)
			}
		}
		return entry, nil
	}

	var ret *logical.TokenEntry

	// If fields are getting upgraded, store the changes
	if persistNeeded {
		if err := init.store(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to persist token upgrade: %v", err)
		}
	}

	return ret, nil
}

func (init *Init) SaltID(ctx context.Context, id string) (string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return "", namespace.ErrNoNamespace
	}

	s, err := init.Salt(ctx)
	if err != nil {
		return "", err
	}

	// For tokens of older format and belonging to the root namespace, use SHA1
	// hash for salting.
	if ns.ID == namespace.RootNamespaceID && !strings.Contains(id, ".") {
		return s.SaltID(id), nil
	}

	// For all other tokens, use SHA2-256 HMAC for salting. This includes
	// tokens of older format, but belonging to a namespace other than the root
	// namespace.
	return "h" + s.GetHMAC(id), nil
}

func (init *Init) Salt(ctx context.Context) (*salt.Salt, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	init.saltLock.RLock()
	if salt, ok := init.salts[ns.ID]; ok {
		defer init.saltLock.RUnlock()
		return salt, nil
	}
	init.saltLock.RUnlock()
	init.saltLock.Lock()
	defer init.saltLock.Unlock()
	if salt, ok := init.salts[ns.ID]; ok {
		return salt, nil
	}

	salt, err := salt.NewSalt(ctx, init.baseBarrierView, &salt.Config{
		HashFunc: salt.SHA1Hash,
		Location: salt.DefaultLocation,
	})
	if err != nil {
		return nil, err
	}
	init.salts[ns.ID] = salt
	return salt, nil
}

func (init *Init) store(ctx context.Context, entry *logical.TokenEntry) error {
	return init.storeCommon(ctx, entry, false)
}

func (init *Init) storeCommon(ctx context.Context, entry *logical.TokenEntry, writeSecondary bool) error {
	tokenNS, err := init.NamespaceByID(ctx, entry.NamespaceID)
	if err != nil {
		return err
	}
	if tokenNS == nil {
		return namespace.ErrNoNamespace
	}

	saltCtx := namespace.ContextWithNamespace(ctx, tokenNS)
	saltedID, err := init.SaltID(saltCtx, entry.ID)
	if err != nil {
		return err
	}

	// Marshal the entry
	enc, err := json.Marshal(entry)
	if err != nil {
		return errwrap.Wrapf("failed to encode entry: {{err}}", err)
	}

	if writeSecondary {
		// Write the secondary index if necessary. This is done before the
		// primary index because we'd rather have a dangling pointer with
		// a missing primary instead of missing the parent index and potentially
		// escaping the revocation chain.
		if entry.Parent != "" {
			// Ensure the parent exists
			parent, err := init.Lookup(ctx, entry.Parent)
			if err != nil {
				return errwrap.Wrapf("failed to lookup parent: {{err}}", err)
			}
			if parent == nil {
				return fmt.Errorf("parent token not found")
			}

			parentNS, err := init.NamespaceByID(ctx, parent.NamespaceID)
			if err != nil {
				return err
			}
			if parentNS == nil {
				return namespace.ErrNoNamespace
			}

			parentCtx := namespace.ContextWithNamespace(ctx, parentNS)

			// Create the index entry
			parentSaltedID, err := init.SaltID(parentCtx, entry.Parent)
			if err != nil {
				return err
			}

			path := parentSaltedID + "/" + saltedID
			if tokenNS.ID != namespace.RootNamespaceID {
				path = fmt.Sprintf("%s.%s", path, tokenNS.ID)
			}

			le := &logical.StorageEntry{Key: path}
			if err := init.parentBarrierView.Put(ctx, le); err != nil {
				return errwrap.Wrapf("failed to persist entry: {{err}}", err)
			}
		}
	}

	// Write the primary ID
	le := &logical.StorageEntry{Key: saltedID, Value: enc}
	if len(entry.Policies) == 1 && entry.Policies[0] == "root" {
		le.SealWrap = true
	}
	if err := init.idBarrierView.Put(ctx, le); err != nil {
		return errwrap.Wrapf("failed to persist entry: {{err}}", err)
	}
	return nil
}

func (init *Init) Lookup(ctx context.Context, id string) (*logical.TokenEntry, error) {
	if id == "" {
		return nil, fmt.Errorf("cannot lookup blank token")
	}

	// If it starts with "b." it's a batch token
	if len(id) > 2 && strings.HasPrefix(id, "b.") {
		return nil, nil
	}

	lock := locksutil.LockForKey(init.tokenLocks, id)
	lock.RLock()
	defer lock.RUnlock()

	return init.lookupInternal(ctx, id, false, false)
}

type accessorEntry struct {
	TokenID     string `json:"token_id"`
	AccessorID  string `json:"accessor_id"`
	NamespaceID string `json:"namespace_id"`
}
