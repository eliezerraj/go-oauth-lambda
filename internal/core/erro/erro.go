package erro

import (
	"errors"
)

var (
	ErrParseCert 	= errors.New("unable to parse x509 cert")
	ErrDecodeCert 	= errors.New("failed to decode pem-encoded cert")
	ErrDecodeKey 	= errors.New("error decode rsa key")
	ErrTokenExpired	= errors.New("token expired")
	ErrStatusUnauthorized 	= errors.New("invalid Token")
	ErrBearTokenFormad 		= errors.New("unauthorized token not informed")
	ErrPreparedQuery  		= errors.New("erro prepare query for dynamo")
	ErrNotFound 	= errors.New("data not found")
	ErrQuery 		= errors.New("query table error")
	ErrUnmarshal 	= errors.New("erro unmarshall")
	ErrSignatureInvalid = errors.New("signature error")
	ErrMethodNotAllowed	= errors.New("method not allowed")
	ErrQueryEmpty	= errors.New("query parameters missing")
	ErrCertRevoked	= errors.New("error cert revoke")
	ErrCredentials	= errors.New("credential informed is invalid (user or password) ")
)