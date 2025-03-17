package lambdaHandler

import(
	"context"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/go-oauth-lambda/internal/adapter/api"

	go_core_observ "github.com/eliezerraj/go-core/observability"	
)

var childLogger = log.With().Str("adapter", "api.lambdaHandler").Logger()

var tracerProvider go_core_observ.TracerProvider
var response		*events.APIGatewayProxyResponse

type LambdaHandler struct {
	lambdaRouters	*api.LambdaRouters
}

// About inicialize handler
func InitializeLambdaHandler( lambdaRouters *api.LambdaRouters) *LambdaHandler {
	childLogger.Debug().Msg("InitializeLambdaHandler")

    return &LambdaHandler{
		lambdaRouters: lambdaRouters,
    }
}

// About handle the request
func (l *LambdaHandler) LambdaHandlerRequest(ctx context.Context,
											request events.APIGatewayProxyRequest ) (*events.APIGatewayProxyResponse, error) {
	childLogger.Debug().Msg("LambdaHandlerRequest")
	childLogger.Debug().Interface("request: ", request).Msg("")

	//trace
	span := tracerProvider.Span(ctx, "adapter.lambdaHandler.LambdaHandlerRequest")
	defer span.End()
	
	// Check the http method and path
	switch request.HTTPMethod {
		case "GET":
			if strings.Contains(request.Path, "/credential/{id}"){  
				response, _ = l.lambdaRouters.GetCredential(ctx, request) // Query the scopes associated with credential
			}else if strings.Contains(request.Path , "/info"){
				response, _ = l.lambdaRouters.GetInfo(ctx)
			}else {
				response, _ = l.lambdaRouters.UnhandledMethod()
			}
		case "POST":
			if strings.Contains(request.Path, "/oauth_credential"){  
				response, _ = l.lambdaRouters.OAUTHCredential(ctx, request) // Login
			}else if strings.Contains(request.Path, "/refreshToken") {
				response, _ = l.lambdaRouters.RefreshToken(ctx, request) // Refresh Token
			}else if strings.Contains(request.Path, "/tokenValidation") {
				response, _ = l.lambdaRouters.TokenValidation(ctx, request) // Do a JWT validation (signature and expiration date)
			}else if strings.Contains(request.Path, "/signIn") {
				response, _ = l.lambdaRouters.SignIn(ctx, request) // Create a new credentials
			}else if strings.Contains(request.Path,"/addScope") {
				response, _ =  l.lambdaRouters.AddScope(ctx, request) // Add scopes to the credential
			}else {
				response, _ = l.lambdaRouters.UnhandledMethod()
			}
		case "DELETE":
			response, _ = l.lambdaRouters.UnhandledMethod()
		case "PUT":
			response, _ = l.lambdaRouters.UnhandledMethod()
		default:
			response, _ = l.lambdaRouters.UnhandledMethod()
	}	

	childLogger.Debug().Interface("===== > response.Resource: ", response).Msg("")

	return response, nil												
}