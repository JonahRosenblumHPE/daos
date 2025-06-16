//
// (C) Copyright 2018-2024 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package auth

import (
	"context"
	"crypto"
	"os"
	"os/user"
	"strconv"
	"strings"
	"net"
	"fmt"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"

	"github.com/daos-stack/daos/src/control/drpc"
	"github.com/daos-stack/daos/src/control/logging"
	"github.com/daos-stack/daos/src/control/security"
)

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
	getGroupIdsFn   func(*CredentialRequestUnix) ([]string, error)
	getGroupNamesFn func(*CredentialRequestUnix) ([]string, error)

	// CredentialRequest defines the request parameters for GetSignedCredential.
	CredentialRequestUnix struct {
		DomainInfo    *security.DomainInfo
		SigningKey    crypto.PrivateKey
		getHostname   getHostnameFn
		getUser       getUserFn
		getGroup      getGroupFn
		getGroupIds   getGroupIdsFn
		getGroupNames getGroupNamesFn
		ClientMap     *security.ClientUserMap
	}
)

func getGroupIds(req *CredentialRequestUnix) ([]string, error) {
	u, err := req.user()
	if err != nil {
		return nil, err
	}
	return u.GroupIds()
}

func getGroupNames(req *CredentialRequestUnix) ([]string, error) {
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

func (r *CredentialRequestUnix) hostname() (string, error) {
	if r.getHostname == nil {
		return "", errors.New("hostname lookup function not set")
	}

	hostname, err := r.getHostname()
	if err != nil {
		return "", errors.Wrap(err, "failed to get hostname")
	}
	return stripHostName(hostname), nil
}

func (r *CredentialRequestUnix) user() (*user.User, error) {
	if r.getUser == nil {
		return nil, errors.New("user lookup function not set")
	}
	return r.getUser(strconv.Itoa(int(r.DomainInfo.Uid())))
}

func (r *CredentialRequestUnix) userPrincipal() (string, error) {
	u, err := r.user()
	if err != nil {
		return "", err
	}
	return sysNameToPrincipalName(u.Username), nil
}

func (r *CredentialRequestUnix) group() (*user.Group, error) {
	if r.getGroup == nil {
		return nil, errors.New("group lookup function not set")
	}
	return r.getGroup(strconv.Itoa(int(r.DomainInfo.Gid())))
}

func (r *CredentialRequestUnix) groupPrincipal() (string, error) {
	g, err := r.group()
	if err != nil {
		return "", err
	}
	return sysNameToPrincipalName(g.Name), nil
}

func (r *CredentialRequestUnix) groupPrincipals() ([]string, error) {
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
func (r *CredentialRequestUnix) WithUserAndGroup(userStr, groupStr string, groupStrs ...string) {
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
	r.getGroupNames = func(*CredentialRequestUnix) ([]string, error) {
		return groupStrs, nil
	}
}

func (req *CredentialRequestUnix) InitCredentialRequest(log logging.Logger, session *drpc.Session, req_body []byte, key crypto.PrivateKey) (error) {
	if session == nil {
		return drpc.NewFailureWithMessage("session is nil")
	}

	uConn, ok := session.Conn.(*net.UnixConn)
	if !ok {
		return drpc.NewFailureWithMessage("connection is not a unix socket")
	}

	info, err := security.DomainInfoFromUnixConn(log, uConn)
	if (err != nil) {
		return err
	}

	req.DomainInfo = info
	req.SigningKey = key
	req.getHostname = GetMachineName
	req.getUser = user.LookupId
	req.getGroup = user.LookupGroupId
	req.getGroupIds = getGroupIds
	req.getGroupNames = getGroupNames

	return nil
}

// GetSignedCredential returns a credential based on the provided domain info and
// signing key.
func (req *CredentialRequestUnix) getSignedCredentialInternal(ctx context.Context) (*Credential, error) {
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

// Unix auth has custom error handling logic for UnknownUserIDError. To solve this we
// use a helper function - getSignedCredentialInternal - and hide 
func (req *CredentialRequestUnix) GetSignedCredential(log logging.Logger, ctx context.Context) (*Credential, error) {
	cred, err := req.getSignedCredentialInternal(ctx)
	if err != nil {
		if err := func() error {
			if !errors.Is(err, user.UnknownUserIdError(req.DomainInfo.Uid())) {
				return err
			}

			mu := req.ClientMap.Lookup(req.DomainInfo.Uid())
			if mu == nil {
				return user.UnknownUserIdError(req.DomainInfo.Uid())
			}

			req.WithUserAndGroup(mu.User, mu.Group, mu.Groups...)
			cred, err = req.getSignedCredentialInternal(ctx)
			if err != nil {
				return err
			}

			return nil
		}(); err != nil {
			log.Errorf("%s: failed to get user credential: %s", req.DomainInfo, err)
			return nil, err
		}
	}
	return cred, nil
}

func (req *CredentialRequestUnix) CredReqKey() string {
	return fmt.Sprintf("%d:%d:%s", req.DomainInfo.Uid(), req.DomainInfo.Gid(), req.DomainInfo.Ctx())
}