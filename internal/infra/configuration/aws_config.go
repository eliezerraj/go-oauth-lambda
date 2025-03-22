package configuration

import(
	"os"
	"github.com/go-oauth-lambda/internal/core/model"
)

// About get AWS service env ver
func GetAwsServiceEnv() model.AwsService {
	childLogger.Info().Str("func","GetAwsServiceEnv").Send()

	var awsService	model.AwsService

	if os.Getenv("REGION") !=  "" {
		awsService.AwsRegion = os.Getenv("REGION")
	}
	if os.Getenv("SECRET_NAME") !=  "" {
		awsService.SecretName = os.Getenv("SECRET_NAME")
	}
	if os.Getenv("DYNAMO_TABLE_NAME") !=  "" {
		awsService.DynamoTableName = os.Getenv("DYNAMO_TABLE_NAME")
	}

	if os.Getenv("RSA_BUCKET_NAME_KEY") !=  "" {
		awsService.BucketNameRSAKey = os.Getenv("RSA_BUCKET_NAME_KEY")
	}
	if os.Getenv("RSA_FILE_PATH") !=  "" {
		awsService.FilePathRSA = os.Getenv("RSA_FILE_PATH")
	}
	if os.Getenv("RSA_PRIV_FILE_KEY") !=  "" {
		awsService.FileNameRSAPrivKey = os.Getenv("RSA_PRIV_FILE_KEY")
	}
	if os.Getenv("RSA_PUB_FILE_KEY") !=  "" {
		awsService.FileNameRSAPubKey = os.Getenv("RSA_PUB_FILE_KEY")
	}
	if os.Getenv("CRL_FILE_KEY") !=  "" {
		awsService.FileNameCrlKey = os.Getenv("CRL_FILE_KEY")
	}
	
	return awsService
}