package service

import (
	"context"
	"fmt"
	"time"
	"encoding/base64"
    "encoding/pem"
	"crypto/x509"

	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v4"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"

	"github.com/go-oauth-lambda/internal/core/model"
	"github.com/go-oauth-lambda/internal/core/erro"

	go_core_cert "github.com/eliezerraj/go-core/cert"
	go_core_observ "github.com/eliezerraj/go-core/observability"
)

var tracerProvider go_core_observ.TracerProvider
var coreCert go_core_cert.CertCore

type MessageService struct {
	ValidStatus		bool  	`json:"valid"`
	Msg				string	`json:"msg"`
}

// About check token HS256 expired/signature and claims
func TokenValidationHS256(bearerToken string, hs256Key interface{}) ( *model.JwtData, error){
	childLogger.Debug().Msg("TokenValidationHS256")

	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(fmt.Sprint(hs256Key)), nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	return claims, nil
}

// About check token RSA expired/signature and claims
func TokenValidationRSA(bearerToken string, rsaPubKey interface{})( *model.JwtData, error){
	childLogger.Debug().Msg("TokenValidationRSA")

	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		return rsaPubKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	return claims, nil
}

// About create token HS256
func CreatedTokenHS256(Hs256Key interface{}, expirationTime time.Time, jwtData model.JwtData) (*model.Authentication, error){
	childLogger.Debug().Msg("CreatedTokenHS256")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtData)
	tokenString, err := token.SignedString([]byte(fmt.Sprint(Hs256Key)))
	if err != nil {
		return nil, err
	}

	authentication := model.Authentication{Token: tokenString, 
								ExpirationTime: expirationTime}

	return &authentication ,nil
}

// About create token RSA
func CreatedTokenRSA(keyRsaPriv interface{}, expirationTime time.Time, jwtData model.JwtData) (*model.Authentication, error){
	childLogger.Debug().Msg("CreatedTokenRSA")

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtData)
	tokenString, err := token.SignedString(keyRsaPriv)
	if err != nil {
		return nil, err
	}

	authentication := model.Authentication{Token: tokenString, 
								ExpirationTime: expirationTime}

	return &authentication ,nil
}

// About Login
func (w *WorkerService) OAUTHCredential(ctx context.Context, credential model.Credential) (*model.Authentication, error){
	childLogger.Debug().Msg("OAUTHCredential")
	childLogger.Debug().Interface("credential: ", credential).Msg("")

	// Trace
	span := tracerProvider.Span(ctx, "service.OAUTHCredential")
	span.End()

	// Prepare ID and SK
	id := fmt.Sprintf("USER-%s", credential.User)
	sk := fmt.Sprintf("USER-%s", credential.User)

	// Get credentials for dynamo
	res_credential, err := w.coreDynamoDB.QueryInput(ctx, &w.awsService.DynamoTableName, id, sk)
	if err != nil {
		return nil, err
	}
	if len(res_credential) == 0 {
		return nil, erro.ErrNotFound
	}

	// Prepare ID and SK
	id = fmt.Sprintf("USER-%s", credential.User)
	sk = "SCOPE-001"

	// get scopes associated with a credential
	res_credential_scope, err := w.coreDynamoDB.QueryInput(ctx, &w.awsService.DynamoTableName, id, sk)
	if err != nil {
		return nil, err
	}
	if len(res_credential_scope) == 0 {
		return nil, erro.ErrNotFound
	}
	
	credential_scope := []model.CredentialScope{}
	err = attributevalue.UnmarshalListOfMaps(res_credential_scope, &credential_scope)
	if err != nil {
		return nil, err
	}

	// Set a JWT expiration date 
	expirationTime := time.Now().Add(720 * time.Minute)

	newUUID := uuid.New()
	uuidString := newUUID.String()

	// Create a JWT Oauth 2.0 with all scopes and expiration date
	jwtData := &model.JwtData{	Username: credential.User,
								Scope: credential_scope[0].Scope,
								ISS: "go-oauth-lambda",
								Version: "3",
								JwtId: uuidString,
								TokenUse: "access",
								RegisteredClaims: jwt.RegisteredClaims{
									ExpiresAt: jwt.NewNumericDate(expirationTime), 	// JWT expiry time is unix milliseconds
								},
	}

	// Create token Function via parameter (see router decision)
	authentication, err := w.CreatedToken(credential.JwtKeyCreation, expirationTime, *jwtData)
	if err != nil {
		return nil, err
	}

	return authentication, nil
}

// About check a token expitation date
func (w *WorkerService) TokenValidation(ctx context.Context, credential model.Credential) (MessageService, error){
	childLogger.Debug().Msg("TokenValidation")
	//childLogger.Debug().Interface("credential: ", credential).Msg("")

	// Trace
	span := tracerProvider.Span(ctx, "service.TokenValidation")
	span.End()
	
	// Validate token - Function via parameter (see router decision)
	_, err := w.TokenSignedValidation(credential.Token, credential.JwtKeySign)
	if err != nil {
		return MessageService{ValidStatus: false, Msg: err.Error()}, err
	}

	return MessageService{ValidStatus: true, Msg: "success"}, nil
}

// About refresh token
func (w *WorkerService) RefreshToken(ctx context.Context, credential model.Credential) (*model.Authentication, error){
	childLogger.Debug().Msg("RefreshToken")
	//childLogger.Debug().Interface("credential: ", credential).Msg("")

	// Trace
	span := tracerProvider.Span(ctx, "service.RefreshToken")
	span.End()

	// Validate token and extract claims
	jwtData := &model.JwtData{}

	// Validate token
	jwtData, err := w.TokenSignedValidation(credential.Token, credential.JwtKeySign)
	if err != nil {
		return nil, err
	}
	// Set a new tokens claims
	expirationTime := time.Now().Add(60 * time.Minute)
	jwtData.ExpiresAt = jwt.NewNumericDate(expirationTime)
	jwtData.ISS = "go-oauth-lambda-refreshed"

	// Create token Function via parameter (see router decision)
	authentication, err := w.CreatedToken(credential.JwtKeyCreation, expirationTime, *jwtData)
	if err != nil {
		return nil, err
	}

	return authentication ,nil
}

// About wellKnown
func (w *WorkerService) WellKnown(ctx context.Context) (*model.Jwks, error){
	childLogger.Debug().Msg("WellKnown")

	// Trace
	span := tracerProvider.Span(ctx, "service.WellKnown")
	span.End()

	// Convert B64 pub key
	nBase64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(w.Keys.Key_rsa_pub_pem))

	// prepate jkws
	jKey := model.JKey{
		Type: "RSA",
		Algorithm: "RS256",
		JwtId: "1",
		NBase64: nBase64,
	}
	
	// set all jkws (in this example we hava just one)
	var arr_jKey []model.JKey
	arr_jKey = append(arr_jKey, jKey)

	jwks := model.Jwks{Keys: arr_jKey}
	
	return &jwks ,nil
}

// About valid token was signed with pub key
func (w *WorkerService) ValidationTokenSignedPubKey(ctx context.Context, jwksData model.JwksData) (MessageService, error){
	childLogger.Debug().Msg("ValidationTokenSignedPubKey")

	// Trace
	span := tracerProvider.Span(ctx, "service.ValidationTokenSignedPubKey")
	span.End()

	// Decode b64 pubkey to pem pubkey
	rsa_pub_key_pem, err := base64.RawStdEncoding.DecodeString(jwksData.RSAPublicKeyB64)
	if err != nil {
		return MessageService{ValidStatus: false, Msg: err.Error()}, err
	}	
	str_rsa_pub_key_pem := string(rsa_pub_key_pem)
	// Validate pem pubkey 
	rsa_pub_key, err := coreCert.ParsePemToRSAPub(&str_rsa_pub_key_pem)
	if err != nil {
		return MessageService{ValidStatus: false, Msg: err.Error()}, err
	}

	// Check with token is signed 
	_ , err = TokenValidationRSA(jwksData.Token, rsa_pub_key)
	if err != nil {
		return MessageService{ValidStatus: false, Msg: err.Error()}, err
	}
	
	return MessageService{ValidStatus: true, Msg: "success"}, nil
}

// About valid a crl list
func (w *WorkerService) VerifyCertCRL(ctx context.Context, certX509PemEncoded string) (bool, error){
	childLogger.Debug().Msg("VerifyCertCRL")

	// Trace
	span := tracerProvider.Span(ctx, "service.VerifyCertCRL")
	span.End()

	// The cert must be informed
	if certX509PemEncoded == ""{
		return false, erro.ErrCertRevoked
	}

	// decode b64 cert
	certX509PemDecoded, err := base64.StdEncoding.DecodeString(certX509PemEncoded)
	if err != nil {
		return false, err
	}
	
	// convert in x509
	str_certX509PemDecoded := string(certX509PemDecoded)
	certX509, err := coreCert.ParsePemToCertx509(&str_certX509PemDecoded)
	if err != nil {
		return false, erro.ErrParseCert
	}

	// check cert information
	certSerialNumber := certX509.SerialNumber
	childLogger.Debug().Interface("certSerialNumber : ", certSerialNumber).Msg("")

	block, _ := pem.Decode([]byte(w.Keys.Crl_pem))
	if block == nil || block.Type != "X509 CRL" {
		return false, err
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return false, err
	}

	fmt.Printf("Issuer: %s\n", crl.Issuer)
	fmt.Printf("ThisUpdate: %s\n", crl.ThisUpdate)
	fmt.Printf("NextUpdate: %s\n", crl.NextUpdate)
	fmt.Printf("Number of Revoked Cert: %d\n", len(crl.RevokedCertificates))

	// Iterate over revoked certificates
	for i, revokedCert := range crl.RevokedCertificateEntries {
		fmt.Printf("Revoked Certificate %d:\n", i+1)
		fmt.Printf("Serial Number: %s\n", revokedCert.SerialNumber)
		fmt.Printf("Revocation Time: %s\n", revokedCert.RevocationTime)
		if revokedCert.SerialNumber.Cmp(certSerialNumber) == 0 {
			return true, nil
		}
		return true, nil
	}

	return false, nil
}