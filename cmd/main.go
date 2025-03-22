package main

import(
	"context"
	"encoding/json"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-oauth-lambda/internal/infra/configuration"
	"github.com/go-oauth-lambda/internal/core/model"
	"github.com/go-oauth-lambda/internal/core/service"
	"github.com/go-oauth-lambda/internal/adapter/api"
	"github.com/go-oauth-lambda/internal/adapter/lambdaHandler"

	//"github.com/aws/aws-lambda-go/events" // use it for a mock local
	"github.com/aws/aws-lambda-go/lambda"

	go_core_observ "github.com/eliezerraj/go-core/observability"
	go_core_bucket_s3 "github.com/eliezerraj/go-core/aws/bucket_s3"
	go_core_cert "github.com/eliezerraj/go-core/cert"
	go_core_aws_config "github.com/eliezerraj/go-core/aws/aws_config"
	go_core_aws_dynamo "github.com/eliezerraj/go-core/aws/dynamo"
	go_core_aws_secret_manager "github.com/eliezerraj/go-core/aws/secret_manager" 

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/contrib/propagators/aws/xray"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda/xrayconfig"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
)

var(
	logLevel = 	zerolog.InfoLevel // zerolog.InfoLevel zerolog.DebugLevel
	
	appServer	model.AppServer
	awsConfig 	go_core_aws_config.AwsConfig
	databaseDynamo		go_core_aws_dynamo.DatabaseDynamo
	awsSecretManager	go_core_aws_secret_manager.AwsSecretManager
	awsBucketS3			go_core_bucket_s3.AwsBucketS3

	infoTrace go_core_observ.InfoTrace
	tracer 			trace.Tracer
	tracerProvider go_core_observ.TracerProvider

	childLogger = log.With().Str("component","go-oauth-lambda").Str("package", "main").Logger()
)

// About initialize the enviroment var
func init(){
	childLogger.Info().Str("func","init").Send()
	
	zerolog.SetGlobalLevel(logLevel)

	infoPod := configuration.GetInfoPod()
	configOTEL 	:= configuration.GetOtelEnv()
	awsService 	:= configuration.GetAwsServiceEnv() 

	appServer.InfoPod = &infoPod
	appServer.ConfigOTEL = &configOTEL
	appServer.AwsService = &awsService
}

// About loads all key (HS256 and RSA)
func loadKey(	ctx context.Context, 
				awsService model.AwsService, 
				coreSecretManager 	*go_core_aws_secret_manager.AwsSecretManager,
				coreBucketS3 		*go_core_bucket_s3.AwsBucketS3) (*model.RsaKey, error){
	childLogger.Info().Str("func","loadKey").Send()

	//trace
	span := tracerProvider.Span(ctx, "main.loadKey")
	defer span.End()

	// Load symetric key from secret manager
	var certCore go_core_cert.CertCore

	keys := model.RsaKey{}
	secret, err := coreSecretManager.GetSecret(ctx, awsService.SecretName)
	if err != nil {
		return nil, err
	}
	var secretData map[string]string
	if err := json.Unmarshal([]byte(*secret), &secretData); err != nil {
		return nil, err
	}
	keys.JwtKey = secretData["JWT_KEY"]

	// Load the private key
	private_key, err := coreBucketS3.GetObject(ctx, 
												awsService.BucketNameRSAKey,
												awsService.FilePathRSA,
												awsService.FileNameRSAPrivKey )
	if err != nil{
		return nil, err
	}
	// Convert private key
	key_rsa_priv, err := certCore.ParsePemToRSAPriv(private_key)
	if err != nil{
		return nil, err
	}
	keys.Key_rsa_priv = key_rsa_priv

	// Load the private key
	public_key, err := coreBucketS3.GetObject(ctx, 
												awsService.BucketNameRSAKey,
												awsService.FilePathRSA,
												awsService.FileNameRSAPubKey )
	if err != nil{
		return nil, err
	}
	key_rsa_pub, err := certCore.ParsePemToRSAPub(public_key)
	if err != nil{
		return nil, err
	}
	keys.Key_rsa_pub = key_rsa_pub

	// Load the crl
	crl_pem, err := coreBucketS3.GetObject(ctx, 
												awsService.BucketNameRSAKey,
												awsService.FilePathRSA,
												awsService.FileNameCrlKey )
	if err != nil{
		return nil, err
	}
	keys.Crl_pem = *crl_pem

	return &keys, nil
}

// About main
func main (){
	childLogger.Info().Str("func","main").Interface("appServer :",appServer).Send()

	ctx := context.Background()

	// otel
	infoTrace.PodName = appServer.InfoPod.PodName
	infoTrace.PodVersion = appServer.InfoPod.ApiVersion
	infoTrace.ServiceType = "k8-workload"
	infoTrace.Env = appServer.InfoPod.Env

	tp := tracerProvider.NewTracerProvider(	ctx, 
											appServer.ConfigOTEL, 
											&infoTrace)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(xray.Propagator{})
	tracer = tp.Tracer(appServer.InfoPod.PodName)

	// Start the root tracer
	ctx, span := tracer.Start(ctx, "lambda-main-span")
	defer span.End()

	defer func(ctx context.Context) {
			err := tp.Shutdown(ctx)
			if err != nil {
				log.Error().Err(err).Msg("error shutting down tracer provider")
			}
	}(ctx)

	// Prepare aws services
	awsConfig, err := awsConfig.NewAWSConfig(ctx, appServer.AwsService.AwsRegion)
	if err != nil {
		panic("error create new aws session " + err.Error())
	}
	otelaws.AppendMiddlewares(&awsConfig.APIOptions)
	
	// Prepare AWS services
	coreDynamoDB := databaseDynamo.NewDatabaseDynamo(awsConfig)
	coreSecretManager := awsSecretManager.NewAwsSecretManager(awsConfig)
	coreBucketS3 := awsBucketS3.NewAwsS3Bucket(awsConfig)

	// Load all keys
	appServer.RsaKey, err = loadKey(ctx, 
									*appServer.AwsService, 
									coreSecretManager, 
									coreBucketS3)
	if err != nil {
		panic("error get keys" + err.Error())
	}

	// wire	
	workerService, err := service.NewWorkerService(	coreDynamoDB, 
													appServer.AwsService, 
													appServer.RsaKey,
													service.TokenValidationRSA,
													service.CreatedTokenRSA)
	if err != nil {
		panic("error create a workerservice " + err.Error())
	}

	// prepare routers
	lambdaRouters := api.NewLambdaRouters(workerService, appServer.InfoPod.ModelSign)

	handler := lambdaHandler.InitializeLambdaHandler(&lambdaRouters)

	/*mockEvent := events.APIGatewayProxyRequest{
		HTTPMethod: "POST",
		Path:       "/test",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: `{"message": "Hello, Lambda!"}`,
	}
	mockEvent = events.APIGatewayProxyRequest{
		HTTPMethod: "POST",
		Resource:    "/oauth_credential",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: `{"user": "admin", "password":"admin"}`,
	}
	mockEvent = events.APIGatewayProxyRequest{
		HTTPMethod: "GET",
		Resource:    "/credential/{id}",
		RequestContext: events.APIGatewayProxyRequestContext{
			RequestID: "mock-request-id-12345",
		},
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		PathParameters: map[string]string{"id": "admin-03"},
	}
	
	handler.LambdaHandlerRequest(ctx, mockEvent)*/

	lambda.Start(otellambda.InstrumentHandler(handler.LambdaHandlerRequest, xrayconfig.WithRecommendedOptions(tp)... ))
}