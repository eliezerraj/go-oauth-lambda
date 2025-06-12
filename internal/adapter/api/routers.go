package api

import(	
	"context"
	"net/http"
	"encoding/json"

	"github.com/rs/zerolog/log"
	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/go-oauth-lambda/internal/core/model"
	"github.com/go-oauth-lambda/internal/core/erro"
	"github.com/go-oauth-lambda/internal/core/service"

	"github.com/aws/aws-lambda-go/events"

	go_core_observ "github.com/eliezerraj/go-core/observability"
)

var childLogger = log.With().Str("component", "go-oauth-lambda").Str("package", "internal.adapter.api").Logger()

var tracerProvider go_core_observ.TracerProvider
var response		*events.APIGatewayProxyResponse

type LambdaRouters struct {
	workerService 	*service.WorkerService
	model			string
}

func NewLambdaRouters(workerService *service.WorkerService, model string) LambdaRouters {
	childLogger.Info().Str("func","NewLambdaRouters").Send()

	return LambdaRouters{
		workerService: workerService,
		model: model,
	}
}

func ApiHandlerResponse(statusCode int, body interface{}) (*events.APIGatewayProxyResponse, error){
	childLogger.Info().Str("func","ApiHandlerResponse").Send()

	stringBody, err := json.Marshal(&body)
	if err != nil {
		return nil, erro.ErrUnmarshal
	}

	return &events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(stringBody),
	}, nil
}

func (l *LambdaRouters) UnhandledMethod() (*events.APIGatewayProxyResponse, error){
	childLogger.Info().Str("func","UnhandledMethod").Send()

	return ApiHandlerResponse(http.StatusMethodNotAllowed, MessageBody{ErrorMsg: aws.String(erro.ErrMethodNotAllowed.Error())})
}

type MessageBody struct {
	ErrorMsg 	*string `json:"error,omitempty"`
	Msg 		*string `json:"message,omitempty"`
}

// Above setup the type model of jwt key signature
func (l *LambdaRouters) setSignModel(model string, credential *model.Credential){
	childLogger.Info().Str("func","setSignModel").Send()

	if model == "HS256" {
		credential.JwtKeySign = l.workerService.Keys.JwtKey
		credential.JwtKeyCreation = l.workerService.Keys.JwtKey
		l.workerService.TokenSignedValidation = service.TokenValidationHS256
		l.workerService.CreatedToken = service.CreatedTokenHS256
	} else {
		credential.JwtKeySign = l.workerService.Keys.Key_rsa_pub
		credential.JwtKeyCreation = l.workerService.Keys.Key_rsa_priv
		l.workerService.TokenSignedValidation = service.TokenValidationRSA
		l.workerService.CreatedToken = service.CreatedTokenRSA
	}
}

// About get into
func (l *LambdaRouters) GetInfo(ctx context.Context) (*events.APIGatewayProxyResponse, error) {
	childLogger.Info().Str("func","GetInfo").Send()
	
	//trace
	span := tracerProvider.Span(ctx, "adapter.api.GetInfo")
	defer span.End()

	msg := "ok from lambda"

	handlerResponse, err := ApiHandlerResponse(http.StatusOK,  MessageBody{Msg: &msg })
	if err != nil {
		return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
	}

	return handlerResponse, nil
}

// About sign-in
func (l *LambdaRouters) OAUTHCredential(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	childLogger.Info().Str("func","OAUTHCredential").Send()
	
	//trace
	span := tracerProvider.Span(ctx, "adapter.api.OAUTHCredential")
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return ApiHandlerResponse(http.StatusBadRequest, MessageBody{ErrorMsg: aws.String(err.Error())})
    }

	// Check which type of authentication method 
	if l.model == "HS256" {
		l.setSignModel("HS256", &credential)
	} else {
		l.setSignModel("RSA", &credential)
	}

	//call service
	response, err := l.workerService.OAUTHCredential(ctx, credential)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			return ApiHandlerResponse(http.StatusNotFound, MessageBody{ErrorMsg: aws.String(err.Error())})
		default:
			return ApiHandlerResponse(http.StatusBadRequest, MessageBody{ErrorMsg: aws.String(err.Error())})
		}
	}
	
	handlerResponse, err := ApiHandlerResponse(http.StatusOK, response)
	if err != nil {
		return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
	}

	return handlerResponse, nil
}

// About refresh
func (l *LambdaRouters) RefreshToken(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	childLogger.Info().Str("func","RefreshToken").Send()
	
	//trace
	span := tracerProvider.Span(ctx, "adapter.api.RefreshToken")
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return ApiHandlerResponse(http.StatusBadRequest, MessageBody{ErrorMsg: aws.String(err.Error())})
    }

	// Check which type of authentication method 
	if l.model == "HS256" {
		l.setSignModel("HS256", &credential)
	} else {
		l.setSignModel("RSA", &credential)
	}

	//call service
	response, err := l.workerService.RefreshToken(ctx, credential)
	if err != nil {
		switch err {
		case erro.ErrTokenExpired:
			return ApiHandlerResponse(http.StatusUnauthorized, MessageBody{ErrorMsg: aws.String(err.Error())})
		case erro.ErrStatusUnauthorized:
			return ApiHandlerResponse(http.StatusUnauthorized, MessageBody{ErrorMsg: aws.String(err.Error())})
		default:
			return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
		}
	}
	
	handlerResponse, err := ApiHandlerResponse(http.StatusOK, response)
	if err != nil {
		return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
	}

	return handlerResponse, nil
}

// About TokenValidation
func (l *LambdaRouters) TokenValidation(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	childLogger.Info().Str("func","TokenValidation").Send()
	
	//trace
	span := tracerProvider.Span(ctx, "adapter.api.TokenValidation")
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return ApiHandlerResponse(http.StatusBadRequest, MessageBody{ErrorMsg: aws.String(err.Error())})
    }

	// Check which type of authentication method 
	if l.model == "HS256" {
		l.setSignModel("HS256", &credential)
	} else {
		l.setSignModel("RSA", &credential)
	}

	//call service
	response, err := l.workerService.TokenValidation(ctx, credential)
	if err != nil {
		switch err {
		case erro.ErrTokenExpired:
			return ApiHandlerResponse(http.StatusUnauthorized, MessageBody{ErrorMsg: aws.String(err.Error())})
		case erro.ErrStatusUnauthorized:
			return ApiHandlerResponse(http.StatusUnauthorized, MessageBody{ErrorMsg: aws.String(err.Error())})
		default:
			return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
		}
	}
	
	handlerResponse, err := ApiHandlerResponse(http.StatusOK, response)
	if err != nil {
		return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
	}

	return handlerResponse, nil
}

// About SignIn
func (l *LambdaRouters) SignIn(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	childLogger.Info().Str("func","SignIn").Send()
	
	//trace
	span := tracerProvider.Span(ctx, "adapter.api.SignIn")
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return ApiHandlerResponse(http.StatusBadRequest, MessageBody{ErrorMsg: aws.String(err.Error())})
    }

	//call service
	response, err := l.workerService.SignIn(ctx, credential)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			return ApiHandlerResponse(http.StatusNotFound, MessageBody{ErrorMsg: aws.String(err.Error())})
		default:
			return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
		}
	}
	
	handlerResponse, err := ApiHandlerResponse(http.StatusOK, response)
	if err != nil {
		return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
	}

	return handlerResponse, nil
}

// About GetCredential
func (l *LambdaRouters) GetCredential(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	childLogger.Info().Str("func","LambdaRouters").Send()

	//trace
	span := tracerProvider.Span(ctx, "adapter.api.GetCredential")
	defer span.End()

	// prepare
	id := req.PathParameters["id"]
	if len(id) == 0 {
		return ApiHandlerResponse(http.StatusBadRequest, MessageBody{ErrorMsg: aws.String(erro.ErrQueryEmpty.Error())})
	}

	credential := model.Credential{User: id}
	
	//call service
	response, err := l.workerService.GetCredential(ctx, credential)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			return ApiHandlerResponse(http.StatusNotFound, MessageBody{ErrorMsg: aws.String(err.Error())})
		default:
			return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
		}
	}
	
	handlerResponse, err := ApiHandlerResponse(http.StatusOK, response)
	if err != nil {
		return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
	}

	return handlerResponse, nil
}

// About AddScope
func (l *LambdaRouters) AddScope(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	childLogger.Info().Str("func","AddScope").Send()
	
	//trace
	span := tracerProvider.Span(ctx, "adapter.api.AddScope")
	defer span.End()

	// prepare
	credential_scope := model.CredentialScope{}
    if err := json.Unmarshal([]byte(req.Body), &credential_scope); err != nil {
		return ApiHandlerResponse(http.StatusBadRequest, MessageBody{ErrorMsg: aws.String(err.Error())})
    }

	//call service
	response, err := l.workerService.AddScope(ctx, credential_scope)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			return ApiHandlerResponse(http.StatusNotFound, MessageBody{ErrorMsg: aws.String(err.Error())})
		default:
			return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
		}
	}
	
	handlerResponse, err := ApiHandlerResponse(http.StatusOK, response)
	if err != nil {
		return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
	}

	return handlerResponse, nil
}

// About GetCredential
func (l *LambdaRouters) WellKnown(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	childLogger.Info().Str("func","LambdaRouters").Send()

	//trace
	span := tracerProvider.Span(ctx, "adapter.api.WellKnown")
	defer span.End()

	//call service
	response, err := l.workerService.WellKnown(ctx)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			return ApiHandlerResponse(http.StatusNotFound, MessageBody{ErrorMsg: aws.String(err.Error())})
		default:
			return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
		}
	}
	
	handlerResponse, err := ApiHandlerResponse(http.StatusOK, response)
	if err != nil {
		return ApiHandlerResponse(http.StatusInternalServerError, MessageBody{ErrorMsg: aws.String(err.Error())})
	}

	return handlerResponse, nil
}
