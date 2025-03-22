package service

import (
	"fmt"
	"time"
	"context"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/go-oauth-lambda/internal/core/model"
	"github.com/go-oauth-lambda/internal/core/erro"
)

// About create a new credential
func (w *WorkerService) SignIn(ctx context.Context, credential model.Credential) (*model.Credential, error){
	childLogger.Info().Str("func","SignIn").Interface("trace-resquest-id", ctx.Value("trace-request-id")).Interface("credential", credential).Send()

	// Trace
	span := tracerProvider.Span(ctx, "service.SignIn")
	span.End()

	// Prepare ID and SK
	credential.ID = fmt.Sprintf("USER-%s", credential.User)
	credential.SK = fmt.Sprintf("USER-%s", credential.User)
	credential.Updated_at 	= time.Now()

	// Put item dynamo
	err := w.coreDynamoDB.PutItem(ctx, &w.awsService.DynamoTableName, credential)
	if err != nil {
		return nil, err
	}

	return &credential, nil
}

// About add a scope
func (w *WorkerService) AddScope(ctx context.Context, credential_scope model.CredentialScope) (*model.CredentialScope, error){
	childLogger.Info().Str("func","AddScope").Interface("trace-resquest-id", ctx.Value("trace-request-id")).Interface("credential_scope", credential_scope).Send()

	// Trace
	span := tracerProvider.Span(ctx, "service.AddScope")
	span.End()

	// Prepare ID and SK
	credential_scope.ID = fmt.Sprintf("USER-%s", credential_scope.User)
	credential_scope.SK = "SCOPE-001"
	credential_scope.Updated_at = time.Now()

	// Put item dynamo
	err := w.coreDynamoDB.PutItem(ctx, &w.awsService.DynamoTableName, credential_scope)
	if err != nil {
		return nil, err
	}

	return &credential_scope, nil
}

// About get credential
func (w *WorkerService) GetCredential(ctx context.Context, credential model.Credential) (*model.Credential, error){
	childLogger.Info().Str("func","GetCredential").Interface("trace-resquest-id", ctx.Value("trace-request-id")).Interface("credential", credential).Send()

	// Trace
	span := tracerProvider.Span(ctx, "service.GetCredential")
	span.End()

	// Prepare ID and SK
	id := fmt.Sprintf("USER-%s", credential.User)
	sk := fmt.Sprintf("USER-%s", credential.User)

	// Get user from dynamo
	res_credential, err := w.coreDynamoDB.QueryInput(ctx, &w.awsService.DynamoTableName, id, sk)
	if err != nil {
		return nil, err
	}
	if len(res_credential) == 0 {
		return nil, erro.ErrNotFound
	}

	un_credential := []model.Credential{}
	err = attributevalue.UnmarshalListOfMaps(res_credential, &un_credential)
    if err != nil {
		return nil, err
	}
	// Prepare SK
	sk = "SCOPE-001"
	// Get credential from dynamo
	res_credential_scope, err := w.coreDynamoDB.QueryInput(ctx, &w.awsService.DynamoTableName, id, sk)
	if err != nil {
		return nil, err
	}
	credential_scope := []model.CredentialScope{}
	if len(res_credential_scope) > 0 {
		err = attributevalue.UnmarshalListOfMaps(res_credential_scope, &credential_scope)
		if err != nil {
			return nil, err
		}
		un_credential[0].CredentialScope = &credential_scope[0]
	}
	
	return &un_credential[0], nil
}