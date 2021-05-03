package token

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	tokenLength = 24

	rootTokenEntryPath = "auth/token/root"
	rootTokenPolicy    = "root"
)

func (ts *TokenStore) GenRootToken(ctx context.Context, id string) (*logical.TokenEntry, error) {
	ctx = namespace.ContextWithNamespace(ctx, namespace.RootNamespace)
	te := &logical.TokenEntry{
		Policies:     []string{rootTokenPolicy},
		Path:         rootTokenEntryPath,
		DisplayName:  rootTokenPolicy,
		CreationTime: time.Now().Unix(),
		NamespaceID:  namespace.RootNamespaceID,
		Type:         logical.TokenTypeService,
	}
	tokenNS, err := ts.NamespaceByID(ctx, te.NamespaceID)
	if err != nil {
		return nil, err
	}
	if tokenNS == nil {
		return nil, errors.New("missing token")
	}

	te.Policies = policyutil.SanitizePolicies(te.Policies, policyutil.DoNotAddDefaultPolicy)

	// In case it was default, force to service
	te.Type = logical.TokenTypeService

	if id != "" {
		te.ID, err = base62.RandomWithReader(tokenLength, rand.Reader)
	} else {
		te.ID = id
	}

	if err != nil {
		return nil, err
	}

	te.ID = fmt.Sprintf("s.%s", te.ID)

	// Attach namespace ID for tokens that are not belonging to the root
	// namespace
	if tokenNS.ID != namespace.RootNamespaceID {
		te.ID = fmt.Sprintf("%s.%s", te.ID, tokenNS.ID)
	}

	if tokenNS.ID != namespace.RootNamespaceID || strings.HasPrefix(te.ID, "s.") {
		if te.CubbyholeID == "" {
			cubbyholeID, err := base62.Random(tokenLength)
			if err != nil {
				return nil, err
			}
			te.CubbyholeID = cubbyholeID
		}
	}

	err = ts.createAccessor(ctx, te)
	if err != nil {
		return nil, err
	}

	if err := ts.storeCommon(ctx, te, true); err != nil {
		return nil, err
	}
	return te, nil
}

func (ts *TokenStore) NamespaceByID(ctx context.Context, id string) (*namespace.Namespace, error) {
	if id == namespace.RootNamespaceID {
		return namespace.RootNamespace, nil
	}
	return nil, namespace.ErrNoNamespace
}

func (ts *TokenStore) createAccessor(ctx context.Context, entry *logical.TokenEntry) error {
	var err error
	// Create a random accessor
	entry.Accessor, err = base62.Random(tokenLength)
	if err != nil {
		return err
	}

	tokenNS, err := ts.NamespaceByID(ctx, entry.NamespaceID)
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
	saltID, err := ts.SaltID(saltCtx, entry.Accessor)
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
		return fmt.Errorf("failed to marshal accessor index entry: %w", err)
	}

	le := &logical.StorageEntry{Key: saltID, Value: aEntryBytes}
	if err := ts.accessorBarrierView.Put(ctx, le); err != nil {
		return fmt.Errorf("failed to persist accessor index entry: %w", err)
	}
	return nil

}

func (ts *TokenStore) lookupInternal(ctx context.Context, id string, salted, tainted bool) (*logical.TokenEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to find namespace in context: %w", err)
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
			tokenNS, err := ts.NamespaceByID(ctx, nsID)
			if err != nil {
				return nil, fmt.Errorf("failed to look up namespace from the token: %w", err)
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

		lookupID, err = ts.SaltID(ctx, id)
		if err != nil {
			return nil, err
		}
	}

	raw, err = ts.idBarrierView.Get(ctx, lookupID)
	if err != nil {
		return nil, fmt.Errorf("failed to read entry: %w", err)
	}

	// Bail if not found
	if raw == nil {
		return nil, nil
	}

	// Unmarshal the token
	entry := new(logical.TokenEntry)
	if err := jsonutil.DecodeJSON(raw.Value, entry); err != nil {
		return nil, fmt.Errorf("failed to decode entry: %w", err)
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
			if err := ts.store(ctx, entry); err != nil {
				return nil, fmt.Errorf("failed to persist token upgrade: %w", err)
			}
		}
		return entry, nil
	}

	var ret *logical.TokenEntry

	// If fields are getting upgraded, store the changes
	if persistNeeded {
		if err := ts.store(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to persist token upgrade: %w", err)
		}
	}

	return ret, nil
}

func (ts *TokenStore) SaltID(ctx context.Context, id string) (string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return "", namespace.ErrNoNamespace
	}

	s, err := ts.Salt(ctx)
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

func (ts *TokenStore) Salt(ctx context.Context) (*salt.Salt, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	ts.saltLock.RLock()
	if salt, ok := ts.salts[ns.ID]; ok {
		defer ts.saltLock.RUnlock()
		return salt, nil
	}
	ts.saltLock.RUnlock()
	ts.saltLock.Lock()
	defer ts.saltLock.Unlock()
	if salt, ok := ts.salts[ns.ID]; ok {
		return salt, nil
	}

	salt, err := salt.NewSalt(ctx, ts.baseBarrierView, &salt.Config{
		HashFunc: salt.SHA1Hash,
		Location: salt.DefaultLocation,
	})
	if err != nil {
		return nil, err
	}
	ts.salts[ns.ID] = salt
	return salt, nil
}

func (ts *TokenStore) store(ctx context.Context, entry *logical.TokenEntry) error {
	return ts.storeCommon(ctx, entry, false)
}

func (ts *TokenStore) storeCommon(ctx context.Context, entry *logical.TokenEntry, writeSecondary bool) error {
	tokenNS, err := ts.NamespaceByID(ctx, entry.NamespaceID)
	if err != nil {
		return err
	}
	if tokenNS == nil {
		return namespace.ErrNoNamespace
	}

	saltCtx := namespace.ContextWithNamespace(ctx, tokenNS)
	saltedID, err := ts.SaltID(saltCtx, entry.ID)
	if err != nil {
		return err
	}

	// Marshal the entry
	enc, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to encode entry: %w", err)
	}

	if writeSecondary {
		// Write the secondary index if necessary. This is done before the
		// primary index because we'd rather have a dangling pointer with
		// a missing primary instead of missing the parent index and potentially
		// escaping the revocation chain.
		if entry.Parent != "" {
			// Ensure the parent exists
			parent, err := ts.Lookup(ctx, entry.Parent)
			if err != nil {
				return fmt.Errorf("failed to lookup parent: %w", err)
			}
			if parent == nil {
				return errors.New("parent token not found")
			}

			parentNS, err := ts.NamespaceByID(ctx, parent.NamespaceID)
			if err != nil {
				return err
			}
			if parentNS == nil {
				return namespace.ErrNoNamespace
			}

			parentCtx := namespace.ContextWithNamespace(ctx, parentNS)

			// Create the index entry
			parentSaltedID, err := ts.SaltID(parentCtx, entry.Parent)
			if err != nil {
				return err
			}

			path := parentSaltedID + "/" + saltedID
			if tokenNS.ID != namespace.RootNamespaceID {
				path = fmt.Sprintf("%s.%s", path, tokenNS.ID)
			}

			le := &logical.StorageEntry{Key: path}
			if err := ts.parentBarrierView.Put(ctx, le); err != nil {
				return fmt.Errorf("failed to persist entry: %w", err)
			}
		}
	}

	// Write the primary ID
	le := &logical.StorageEntry{Key: saltedID, Value: enc}
	if len(entry.Policies) == 1 && entry.Policies[0] == "root" {
		le.SealWrap = true
	}
	if err := ts.idBarrierView.Put(ctx, le); err != nil {
		return fmt.Errorf("failed to persist entry: %w", err)
	}
	return nil
}

func (ts *TokenStore) Lookup(ctx context.Context, id string) (*logical.TokenEntry, error) {
	if id == "" {
		return nil, errors.New("cannot lookup blank token")
	}

	// If it starts with "b." it's a batch token
	if len(id) > 2 && strings.HasPrefix(id, "b.") {
		return nil, nil
	}

	lock := locksutil.LockForKey(ts.tokenLocks, id)
	lock.RLock()
	defer lock.RUnlock()

	return ts.lookupInternal(ctx, id, false, false)
}

type accessorEntry struct {
	TokenID     string `json:"token_id"`
	AccessorID  string `json:"accessor_id"`
	NamespaceID string `json:"namespace_id"`
}
