package lambdaHandler

import(
	"context"

	"github.com/rs/zerolog/log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/go-oauth-lambda/internal/adapter/api"

	go_core_observ "github.com/eliezerraj/go-core/observability"	
)

var childLogger = log.With().Str("component", "go-oauth-lambda").Str("package", "internal.adapter.lambdaHandler").Logger()

var tracerProvider go_core_observ.TracerProvider
var response		*events.APIGatewayProxyResponse

type LambdaHandler struct {
	lambdaRouters	*api.LambdaRouters
}

// About inicialize handler
func InitializeLambdaHandler( lambdaRouters *api.LambdaRouters) *LambdaHandler {
	childLogger.Info().Str("func","InitializeLambdaHandler").Send()

    return &LambdaHandler{
		lambdaRouters: lambdaRouters,
    }
}

// About handle the request
func (l *LambdaHandler) LambdaHandlerRequest(ctx context.Context,
											request events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	childLogger.Info().Str("func","LambdaHandlerRequest").Interface("request", request).Send()

	//trace
	span := tracerProvider.Span(ctx, "adapter.lambdaHandler.LambdaHandlerRequest")
	defer span.End()
	
	// get the resquest-id and put in inside the 
	ctx = context.WithValue(ctx, "trace-request-id", request.RequestContext.RequestID)

	// Check the http method and path
	switch request.HTTPMethod {
		case "GET":
			if request.Resource == "/credential/{id}" {  
				response, _ = l.lambdaRouters.GetCredential(ctx, request) // Query the scopes associated with credential
			}else if request.Resource == "/info"{
				response, _ = l.lambdaRouters.GetInfo(ctx)
			}else if request.Resource == "/wellKnown/1" {
				response, _ =  l.lambdaRouters.WellKnown(ctx, request) // Add scopes to the credential
			}else {
				response, _ = l.lambdaRouters.UnhandledMethod()
			}
		case "POST":
			if request.Resource == "/oauth_credential"{  
				response, _ = l.lambdaRouters.OAUTHCredential(ctx, request) // Login
			}else if request.Resource == "/refreshToken" {
				response, _ = l.lambdaRouters.RefreshToken(ctx, request) // Refresh Token
			}else if request.Resource == "/tokenValidation" {
				response, _ = l.lambdaRouters.TokenValidation(ctx, request) // Do a JWT validation (signature and expiration date)
			}else if request.Resource == "/signIn" {
				response, _ = l.lambdaRouters.SignIn(ctx, request) // Create a new credentials
			}else if request.Resource == "/addScope" {
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

	childLogger.Info().Interface("response", response).Send()

	return response, nil												
}