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
	"reflect"
	"fmt"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"

	"github.com/daos-stack/daos/src/control/drpc"
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

func CredentialRequestGetSigned(ctx context.Context, log logging.Logger, req CredentialRequest) (*Credential, error) {
	return req.GetSignedCredential(log, ctx)
}

func StrToAuthTag(str string) (AuthTag, error) {
	var authNameBuffer AuthTag
	if len(str) != AuthTagSize {
		return authNameBuffer, fmt.Errorf("auth string '%s' is the wrong length. Expected %d, got %d", str, AuthTagSize, len(str))
	}
	copy(authNameBuffer[:], str)
	return authNameBuffer, nil
}

func getAuthName(authNameStr string) AuthTag {
	tag, err := StrToAuthTag(authNameStr)
	if (err != nil) {
		panic(errors.Wrap(err, "Check your interface implementation of 'GetAuthName' to ensure name is proper length"))
	}
	return tag
}

func registerAllAuthenticationMethods() AuthMap {
	var ar = make(map[AuthTag]reflect.Type)
	for _, req := range CredentialRequests {
		authName := req.GetAuthName()
		_, found := ar[authName]
		if (found) {
			panic(fmt.Errorf("multiple authentication methods with the name `%s` were found - confirm that all implementations of `GetAuthName` are unique", authName))
		}
		ar[authName] = reflect.TypeOf(req)
	}
	return ar
}

const (
   AuthTagSize = 4
)

type (
	AuthTag [AuthTagSize]byte

	AuthMap map[AuthTag]reflect.Type

	CredentialRequest interface {
		InitCredentialRequest(log logging.Logger, sec_cfg *security.CredentialConfig, session *drpc.Session, req_body []byte, key crypto.PrivateKey) (error)
		GetSignedCredential(log logging.Logger, ctx context.Context) (*Credential, error)
		CredReqKey() string
		GetAuthName() AuthTag
	}
)

// CredentialRequests is a list of request types that can be used for authentication.
// To add a new type of authentication simply implement the CredentialRequest interface and add
// an instance to the CredentialRequests list.
// The agent must be configured to allow an authentication method when it is initalized.
// By default, only Unix authentication is enabled.
var CredentialRequests = []CredentialRequest{&CredentialRequestUnix{}, &CredentialRequestAM{}}
var AuthRegister = registerAllAuthenticationMethods()