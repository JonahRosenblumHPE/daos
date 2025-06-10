//
// (C) Copyright 2018-2024 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package auth

import (
	"bytes"
	"context"
	"crypto"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"

	"github.com/daos-stack/daos/src/control/logging"
	"github.com/daos-stack/daos/src/control/security"
)

// VerifierFromToken will return a SHA512 hash of the token data. If a signing key
// is passed in it will additionally sign the hash of the token.
func VerifierFromToken(key crypto.PublicKey, token *Token) ([]byte, error) {
	var sig []byte
	tokenBytes, err := proto.Marshal(token)
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal Token")
	}

	signer := security.DefaultTokenSigner()

	if key == nil {
		return signer.Hash(tokenBytes)
	}
	sig, err = signer.Sign(key, tokenBytes)
	return sig, errors.Wrap(err, "signing verifier failed")
}

// VerifyToken takes the auth token and the signature bytes in the verifier and
// verifies it against the public key provided for the agent who claims to have
// provided the token.
func VerifyToken(key crypto.PublicKey, token *Token, sig []byte) error {
	tokenBytes, err := proto.Marshal(token)
	if err != nil {
		return errors.Wrap(err, "unable to marshal Token")
	}

	signer := security.DefaultTokenSigner()

	if key == nil {
		digest, err := signer.Hash(tokenBytes)
		if err != nil {
			return err
		}
		if bytes.Equal(digest, sig) {
			return nil
		}
		return errors.Errorf("unsigned hash failed to verify.")
	}

	err = signer.Verify(key, tokenBytes, sig)
	return errors.Wrap(err, "token verification Failed")
}

func sysNameToPrincipalName(name string) string {
	return name + "@"
}

func stripHostName(name string) string {
	return strings.Split(name, ".")[0]
}

// GetMachineName returns the "short" hostname by stripping the domain from the FQDN.
func GetMachineName() (string, error) {
	name, err := os.Hostname()
	if err != nil {
		return "", err
	}

	return stripHostName(name), nil
}

type (
	getHostnameFn   func() (string, error)
	getUserFn       func(string) (*user.User, error)
	getGroupFn      func(string) (*user.Group, error)
	getGroupIdsFn   func(*CredentialRequest) ([]string, error)
	getGroupNamesFn func(*CredentialRequest) ([]string, error)

	// CredentialRequest defines the request parameters for GetSignedCredential.
	CredentialRequest struct {
		DomainInfo    *security.DomainInfo
		SigningKey    crypto.PrivateKey
		getHostname   getHostnameFn
		getUser       getUserFn
		getGroup      getGroupFn
		getGroupIds   getGroupIdsFn
		getGroupNames getGroupNamesFn
	}

	Info struct {
		Identity string  `json:"id"`
		Roles []string  `json:"roles"`
	}
)

func getGroupIds(req *CredentialRequest) ([]string, error) {
	u, err := req.user()
	if err != nil {
		return nil, err
	}
	return u.GroupIds()
}

func getGroupNames(req *CredentialRequest) ([]string, error) {
	groupIds, err := req.getGroupIds(req)
	if err != nil {
		return nil, err
	}

	groupNames := make([]string, len(groupIds))
	for i, gID := range groupIds {
		g, err := req.getGroup(gID)
		if err != nil {
			return nil, err
		}
		groupNames[i] = g.Name
	}

	return groupNames, nil
}

// NewCredentialRequest returns a properly initialized CredentialRequest.
func NewCredentialRequest(info *security.DomainInfo, key crypto.PrivateKey) *CredentialRequest {
	return &CredentialRequest{
		DomainInfo:    info,
		SigningKey:    key,
		getHostname:   GetMachineName,
		getUser:       user.LookupId,
		getGroup:      user.LookupGroupId,
		getGroupIds:   getGroupIds,
		getGroupNames: getGroupNames,
	}
}

func (r *CredentialRequest) hostname() (string, error) {
	if r.getHostname == nil {
		return "", errors.New("hostname lookup function not set")
	}

	hostname, err := r.getHostname()
	if err != nil {
		return "", errors.Wrap(err, "failed to get hostname")
	}
	return stripHostName(hostname), nil
}

func (r *CredentialRequest) user() (*user.User, error) {
	if r.getUser == nil {
		return nil, errors.New("user lookup function not set")
	}
	return r.getUser(strconv.Itoa(int(r.DomainInfo.Uid())))
}

func (r *CredentialRequest) userPrincipal() (string, error) {
	u, err := r.user()
	if err != nil {
		return "", err
	}
	return sysNameToPrincipalName(u.Username), nil
}

func (r *CredentialRequest) group() (*user.Group, error) {
	if r.getGroup == nil {
		return nil, errors.New("group lookup function not set")
	}
	return r.getGroup(strconv.Itoa(int(r.DomainInfo.Gid())))
}

func (r *CredentialRequest) groupPrincipal() (string, error) {
	g, err := r.group()
	if err != nil {
		return "", err
	}
	return sysNameToPrincipalName(g.Name), nil
}

func (r *CredentialRequest) groupPrincipals() ([]string, error) {
	if r.getGroupNames == nil {
		return nil, errors.New("groupNames function not set")
	}

	groupNames, err := r.getGroupNames(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get group names")
	}

	for i, g := range groupNames {
		groupNames[i] = sysNameToPrincipalName(g)
	}
	return groupNames, nil
}

// WithUserAndGroup provides an override to set the user, group, and optional list
// of group names to be used for the request.
func (r *CredentialRequest) WithUserAndGroup(userStr, groupStr string, groupStrs ...string) {
	r.getUser = func(id string) (*user.User, error) {
		return &user.User{
			Uid:      id,
			Gid:      id,
			Username: userStr,
		}, nil
	}
	r.getGroup = func(id string) (*user.Group, error) {
		return &user.Group{
			Gid:  id,
			Name: groupStr,
		}, nil
	}
	r.getGroupNames = func(*CredentialRequest) ([]string, error) {
		return groupStrs, nil
	}
}

// GetSignedCredential returns a credential based on the provided domain info and
// signing key.
func GetSignedCredential(ctx context.Context, req *CredentialRequest) (*Credential, error) {
	if req == nil {
		return nil, errors.Errorf("%T is nil", req)
	}

	if req.DomainInfo == nil {
		return nil, errors.New("No domain info supplied")
	}

	hostname, err := req.hostname()
	if err != nil {
		return nil, err
	}

	userPrinc, err := req.userPrincipal()
	if err != nil {
		return nil, err
	}

	groupPrinc, err := req.groupPrincipal()
	if err != nil {
		return nil, err
	}

	groupPrincs, err := req.groupPrincipals()
	if err != nil {
		return nil, err
	}

	// Craft AuthToken
	sys := Sys{
		Stamp:       0,
		Machinename: hostname,
		User:        userPrinc,
		Group:       groupPrinc,
		Groups:      groupPrincs,
		Secctx:      req.DomainInfo.Ctx()}

	// Marshal our AuthSys token into a byte array
	tokenBytes, err := proto.Marshal(&sys)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to marshal AuthSys token")
	}
	token := Token{
		Flavor: Flavor_AUTH_SYS,
		Data:   tokenBytes}

	verifier, err := VerifierFromToken(req.SigningKey, &token)
	if err != nil {
		return nil, errors.WithMessage(err, "Unable to generate verifier")
	}

	verifierToken := Token{
		Flavor: Flavor_AUTH_SYS,
		Data:   verifier}

	credential := Credential{
		Token:    &token,
		Verifier: &verifierToken,
		Origin:   "agent"}

	logging.FromContext(ctx).Tracef("%s: successfully signed credential", req.DomainInfo)
	return &credential, nil
}

// GetSignedCredential returns a credential based on the provided domain info and
// signing key.
func GetSignedCredentialAM(ctx context.Context, credInfo *Info, signingKey crypto.PrivateKey) (*Credential, error) { // I can rip out CredentialRequest with my own info.
	// DAOS is built with UNIX groups in mind. We cannot use the AM-style URLS as they contain colons, and do not end with an '@'.
	// This function helps parse out the path.
	seperate := func(url string) (string, string, error) {
		var split_url = strings.Split(url, "://")
		if len(split_url) != 2 {
			return "", "", errors.New("Access manager url does not follow expected format 'foo://bar'")
		}
		split_url[0] += "://"
		split_url[1] += "@am"
		return split_url[0], split_url[1], nil
	}

	var machine_name, identity, err = seperate(credInfo.Identity)

	if (err != nil) {
		return nil, err
	}
	
	groups := make([]string, len(credInfo.Roles))
	for i := range groups {
		var _, role, err = seperate(credInfo.Roles[i])
		if (err != nil) {
			return nil, err
		}
		groups[i] = role
	}

	// Craft AuthToken
	sys := Sys{
		Stamp:       0,
		Machinename: machine_name,
		User:        identity,
		Group:       "",
		Groups:      groups,
		Secctx:      ""}

	// Marshal our AuthSys token into a byte array
	tokenBytes, err := proto.Marshal(&sys)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to marshal AuthSys token")
	}

	token := Token{
		Flavor: Flavor_AUTH_SYS,
		Data:   tokenBytes}

	verifier, err := VerifierFromToken(signingKey, &token)
	if err != nil {
		return nil, errors.WithMessage(err, "Unable to generate verifier")
	}

	verifierToken := Token{
		Flavor: Flavor_AUTH_SYS,
		Data:   verifier}

	credential := Credential{
		Token:    &token,
		Verifier: &verifierToken,
		Origin:   "agent"}

	logging.FromContext(ctx).Tracef("%s: successfully signed credential", credInfo)

	return &credential, nil
}

// AuthSysFromAuthToken takes an opaque AuthToken and turns it into a
// concrete AuthSys data structure.
func AuthSysFromAuthToken(authToken *Token) (*Sys, error) {
	if authToken.GetFlavor() != Flavor_AUTH_SYS {
		return nil, errors.New("Attempting to convert an invalid AuthSys Token")
	}

	sysToken := &Sys{}
	err := proto.Unmarshal(authToken.GetData(), sysToken)
	if err != nil {
		return nil, errors.Wrapf(err, "unmarshaling %s", authToken.GetFlavor())
	}
	return sysToken, nil
}
