//
// (C) Copyright 2018-2024 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package main

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"time"
	"crypto"
	"net/http"
	"net/url"
	"io"
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/daos-stack/daos/src/control/drpc"
	"github.com/daos-stack/daos/src/control/lib/cache"
	"github.com/daos-stack/daos/src/control/lib/daos"
	"github.com/daos-stack/daos/src/control/logging"
	"github.com/daos-stack/daos/src/control/security"
	"github.com/daos-stack/daos/src/control/security/auth"
)

type (
	// credSignerFn defines the function signature for signing credentials.
	credSignerFn func(context.Context, *auth.CredentialRequest) (*auth.Credential, error)
	credSignerAMFn func(context.Context, *auth.Info, crypto.PrivateKey) (*auth.Credential, error)

	// credentialCache implements a cache for signed credentials.
	credentialCache struct {
		log          logging.Logger
		cache        *cache.ItemCache
		credLifetime time.Duration
		cacheMissFn  credSignerFn
	}

	// cachedCredential wraps a cached credential and implements the cache.ExpirableItem interface.
	cachedCredential struct {
		cacheItem
		key       string
		expiredAt time.Time
		cred      *auth.Credential
	}

	// securityConfig defines configuration parameters for SecurityModule.
	securityConfig struct {
		credentials *security.CredentialConfig
		transport   *security.TransportConfig
	}

	// SecurityModule is the security drpc module struct
	SecurityModule struct {
		log            logging.Logger
		signCredential credSignerFn
		signCredentialAM credSignerAMFn
		credCache      *credentialCache

		config *securityConfig
	}

	amErr struct {
		ResponseCode int `json:"error"`
		Message string `json:"message"`
	}

	Resp struct {
		Error    amErr             `json:"error"`
		Info     string            `json:"info"`
	}
)

var _ cache.ExpirableItem = (*cachedCredential)(nil)

// NewSecurityModule creates a new module with the given initialized TransportConfig.
func NewSecurityModule(log logging.Logger, cfg *securityConfig) *SecurityModule {
	var credCache *credentialCache
	credSigner := auth.GetSignedCredential
	credSignerAM := auth.GetSignedCredentialAM
	if cfg.credentials.CacheExpiration > 0 {
		credCache = &credentialCache{
			log:          log,
			cache:        cache.NewItemCache(log),
			credLifetime: cfg.credentials.CacheExpiration,
			cacheMissFn:  auth.GetSignedCredential,
		}
		credSigner = credCache.getSignedCredential
		log.Noticef("credential cache enabled (entry lifetime: %s)", cfg.credentials.CacheExpiration)
	}

	return &SecurityModule{
		log:            log,
		signCredential: credSigner,
		signCredentialAM: credSignerAM,
		credCache:      credCache,
		config:         cfg,
	}
}

func credReqKey(req *auth.CredentialRequest) string {
	return fmt.Sprintf("%d:%d:%s", req.DomainInfo.Uid(), req.DomainInfo.Gid(), req.DomainInfo.Ctx())
}

// Key returns the key for the cached credential.
func (cred *cachedCredential) Key() string {
	if cred == nil {
		return ""
	}

	return cred.key
}

// IsExpired returns true if the cached credential is expired.
func (cred *cachedCredential) IsExpired() bool {
	if cred == nil || cred.cred == nil || cred.expiredAt.IsZero() {
		return true
	}

	return time.Now().After(cred.expiredAt)
}

func (cc *credentialCache) getSignedCredential(ctx context.Context, req *auth.CredentialRequest) (*auth.Credential, error) {
	key := credReqKey(req)

	createItem := func() (cache.Item, error) {
		cc.log.Tracef("cache miss for %s", key)
		cred, err := cc.cacheMissFn(ctx, req)
		if err != nil {
			return nil, err
		}
		cc.log.Tracef("getting credential for %s", key)
		return newCachedCredential(key, cred, cc.credLifetime)
	}

	item, release, err := cc.cache.GetOrCreate(ctx, key, createItem)
	if err != nil {
		return nil, errors.Wrap(err, "getting cached credential from cache")
	}
	defer release()

	cachedCred, ok := item.(*cachedCredential)
	if !ok {
		return nil, errors.New("invalid cached credential")
	}

	return cachedCred.cred, nil
}

func newCachedCredential(key string, cred *auth.Credential, lifetime time.Duration) (*cachedCredential, error) {
	if cred == nil {
		return nil, errors.New("credential is nil")
	}

	return &cachedCredential{
		key:       key,
		cred:      cred,
		expiredAt: time.Now().Add(lifetime),
	}, nil
}

// HandleCall is the handler for calls to the SecurityModule
func (m *SecurityModule) HandleCall(ctx context.Context, session *drpc.Session, method drpc.Method, body []byte) ([]byte, error) {
	switch method {
		case drpc.MethodRequestCredentials:
			return m.getCredential(ctx, session)
		case drpc.MethodRequestCredentialsAM:
			return m.getCredentialAM(ctx, body)
	}

	return nil, drpc.UnknownMethodFailure();
}

// getCredentials generates a signed user credential based on the data attached to
// the Unix Domain Socket.
func (m *SecurityModule) getCredential(ctx context.Context, session *drpc.Session) ([]byte, error) {
	if session == nil {
		return nil, drpc.NewFailureWithMessage("session is nil")
	}

	uConn, ok := session.Conn.(*net.UnixConn)
	if !ok {
		return nil, drpc.NewFailureWithMessage("connection is not a unix socket")
	}

	info, err := security.DomainInfoFromUnixConn(m.log, uConn)
	if err != nil {
		m.log.Errorf("Unable to get credentials for client socket: %s", err)
		return m.credRespWithStatus(daos.MiscError)
	}

	signingKey, err := m.config.transport.PrivateKey()
	if err != nil {
		m.log.Errorf("%s: failed to get signing key: %s", info, err)
		// something is wrong with the cert config
		return m.credRespWithStatus(daos.BadCert)
	}

	req := auth.NewCredentialRequest(info, signingKey)
	cred, err := m.signCredential(ctx, req)
	if err != nil {
		if err := func() error {
			if !errors.Is(err, user.UnknownUserIdError(info.Uid())) {
				return err
			}

			mu := m.config.credentials.ClientUserMap.Lookup(info.Uid())
			if mu == nil {
				return user.UnknownUserIdError(info.Uid())
			}

			req.WithUserAndGroup(mu.User, mu.Group, mu.Groups...)
			cred, err = m.signCredential(ctx, req)
			if err != nil {
				return err
			}

			return nil
		}(); err != nil {
			m.log.Errorf("%s: failed to get user credential: %s", info, err)
			return m.credRespWithStatus(daos.MiscError)
		}
	}

	resp := &auth.GetCredResp{Cred: cred}
	return drpc.Marshal(resp)
}


var callerID string = "hdp://user/the-operator"
var baseURL string = "http://am-1.labs.hpecorp.net:8080"

func request(ctx context.Context, apiPath string, method string, kv ...string) ([]byte, error) {
	u, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return nil, fmt.Errorf("can't happen: %w", err)
	}
	u.Path = apiPath
	params := url.Values{}
	if len(kv)%2 != 0 {
		return nil, fmt.Errorf("must have an even number of key/value pairs")
	}
	for i := 0; i < len(kv); i += 2 {
		params.Set(kv[i], kv[i+1])
	}

	params.Set("caller_id", callerID)
	u.RawQuery = params.Encode()

	request, err := http.NewRequestWithContext(
		ctx,
		method,
		u.String(),
		http.NoBody,
	)
	if err != nil {
		return nil, fmt.Errorf(`cannot create request for "%s": %w`, u.String(), err)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf(`cannot access "%s": %w`, u.String(), err)
	}

	//goland:noinspection GoUnhandledErrorResult
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(`unexpected status code "%d"`, response.StatusCode)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf(`error reading response from %s: %w`, u.String(), err)
	}
	return responseBody, err
}

// getCredentials generates a signed user credential based on the data attached to
// the Unix Domain Socket.
func (m *SecurityModule) getCredentialAM(ctx context.Context, delegationCred []byte) ([]byte, error) {
	var amResp Resp
	var authInfo auth.Info

	resp, err := request(context.Background(), "/validate", http.MethodGet, "credential", string(delegationCred))
	if err != nil {
		m.log.Errorf("%s: failed to get signing key: %s", string(delegationCred), err)
		return nil, err;
	}
	
    err = json.Unmarshal(resp, &amResp)
    if err != nil {
        m.log.Errorf("%s: failed to get signing key: %s", string(delegationCred), err)
		return nil, err;
    }

	if amResp.Error.ResponseCode != 0 {
		m.log.Errorf("%s: failed to get signing key: %s", string(delegationCred), amResp.Error.Message)
		return nil, errors.New(amResp.Error.Message);
	}

	err = json.Unmarshal([]byte(amResp.Info), &authInfo)
    if err != nil {
        m.log.Errorf("%s: failed to get signing key: %s", string(delegationCred), err)
		return nil, err;
    }

	signingKey, err := m.config.transport.PrivateKey()
	if err != nil {
		m.log.Errorf("%s: failed to get signing key: %s", string(delegationCred), err)
		// something is wrong with the cert config
		return m.credRespWithStatus(daos.BadCert)
	}

	cred, err := m.signCredentialAM(ctx, &authInfo, signingKey)
	if err != nil {
		m.log.Errorf("%s: failed to get user credential: %s", string(delegationCred), err)
		return m.credRespWithStatus(daos.MiscError)
	}

	cred_resp := &auth.GetCredResp{Cred: cred}
	return drpc.Marshal(cred_resp)
}

func (m *SecurityModule) credRespWithStatus(status daos.Status) ([]byte, error) {
	resp := &auth.GetCredResp{Status: int32(status)}
	return drpc.Marshal(resp)
}

// ID will return Security module ID
func (m *SecurityModule) ID() drpc.ModuleID {
	return drpc.ModuleSecurityAgent
}
