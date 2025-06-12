# go-oauth-lambda

POC Lambda for technical purposes

Lambda mock a login and return a JWT/Scope Oath using a HS256 (symetric key) The JWT token is 60 minutes duration

It saves the credentials and scopes in a DynamoDB table

![Alt text](/assets/image.png)

See: lambda-go-auth-apigw (extend example)

## Enviroment variable

+ tablename: DynamoDB table

+ jwtKey: The KEY used for encrypt Hs256

## Compile lambda

   Manually compile the function

      Old Version 
      GOOD=linux GOARCH=amd64 go build -o ../build/main main.go
      zip -jrm ../build/main.zip ../build/main

      Convert
      aws lambda update-function-configuration --function-name lambda-go-autentication --runtime provided.al2

      New Version
      GOARCH=amd64 GOOS=linux go build -o ../build/bootstrap main.go
      zip -jrm ../build/main.zip ../build/bootstrap

      aws lambda update-function-code \
        --region us-east-2 \
        --function-name lambda-go-autentication \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/lambda-go-autentication/build/main.zip \
        --publish

## Install a LambdaLayer (OTEL)

arn:aws:lambda:us-east-2:901920570463:layer:aws-otel-collector-amd64-ver-0-90-1:1

## Endpoints

+ POST /signIn

      {
         "user":"admin",
         "password":"admin",
         "tier":"tier1"
      }

+ POST /oauth_credential

      {
         "user": "007",
         "password": "MrBeam"
      }

+ POST /tokenValidation

      {
         "token": "ABC123",
      }

+ POST /refreshToken

      {
         "token": "ABC123",
      }

+ POST /addScope

      {
         "user": "user-01",
         "scope": ["test.read","test.write"]
      }

      or

      {
         "user": "user-01",
         "scope": ["admin"]
      }

      or

      {
         "user": "user-01",
         "scope": ["info"]
      }

+ GET /credential/user-01

      {
         "id": "USER-user-02",
         "sk": "SCOPE-001",
         "scope": [
            "header.read",
            "version.read",
            "info.read"
         ],
         "updated_at": "2023-09-11T01:29:54.7366791Z"
      }

## Lambda Env Variables

      POD_NAME: go-oauth-lambda
      OTEL_EXPORTER_OTLP_ENDPOINT: localhost:4317
      REGION:us-east-2
      RSA_BUCKET_NAME_KEY:eliezerraj-908671954593-mtls-truststore
      RSA_FILE_PATH:/
      RSA_PRIV_FILE_KEY:private_key.pem
      RSA_PUB_FILE_KEY:public_key.pem
      CRL_FILE_KEY: crl-ca.crl
      SECRET_NAME: 'key-jwt-auth'
      DYNAMO_TABLE_NAME:user_login_2
      API_VERSION: !Ref ApiVersion
      MODEL_SIGN: "RSA"

## Running locally

+ Create a docker image

      docker build -t lambda-go-autentication .

+ Setup the docker compose
+ Download the lambda aws-lambda-rie

      mkdir -p .aws-lambda-rie && curl -Lo .aws-lambda-rie/aws-lambda-rie https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie && chmod +x .aws-lambda-rie/aws-lambda-rie

+ start the docker compose
   /deployment-locally/start.sh

+ Test

      curl --location 'http://localhost:9000/2015-03-31/functions/function/invocations' --header 'Content-Type: application/json' --data '{"httpMethod":"GET","resource":"/info","pathParameters": {"id":"1"}}'

+ Test APIGW

      {
         "httpMethod": "GET",
         "resource": "/info"
      }

      {
         "httpMethod": "POST",
         "resource": "/login",
         "body": "{\"user\":\"admin\", \"password\":\"admin\"}"
      }

      {
         "httpMethod": "GET",
         "resource": "/credential/{id}",
         "pathParameters": {"id":"admin"}
      }

      {
         "httpMethod": "POST",
         "resource": "/refreshToken",
         "body": "{\"token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MtcnNhIiwiaXNzIjoibGFtYmRhLWdvLWF1dGVudGljYXRpb24iLCJ2ZXJzaW9uIjoiMiIsImp3dF9pZCI6IjkxNTNkNGU3LTljZWItNDRjMC1iZGRjLTM3ZWUyMzM0NzgzOCIsInVzZXJuYW1lIjoiYWRtaW4iLCJzY29wZSI6WyJhZG1pbiJdLCJleHAiOjE3MzM4MTgxNzF9.X_vKruOsgZZEBHJsz5OEzSIPDtpR6xW_824zJDWYsiZ8FMKHsGwWpsbYbqwJgOCnPlqX2_cDbNg89BCOXBiaP8oE_H97Z-PMAQhnX8NPel4rR893NvFkBbQwRI-IHu4oU7Jw-pQd7gbjsaz_b-HYPdsBH1xXe2GZpRcAOVSYJOAx6S47QK2F0Vy6xExKQcFEEvLJdf4uXLL5XzMlIrguC8SM6ObsDWiWr8iJa5bh9fYN4GjZ_n2ssjYrFnX-C3Q9ewCdquBZcSKoDYkR0Hjo98KHJpxylLByW9osiXbFdP4jhGj1eMvTYK6POg5Qfnz1LpGO3g30q7vxBN9fhn4NDQ\"}"
      }

      {
         "httpMethod": "POST",
         "resource": "/tokenValidation",
         "body": "{\"token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MtcnNhIiwiaXNzIjoibGFtYmRhLWdvLWF1dGVudGljYXRpb24iLCJ2ZXJzaW9uIjoiMiIsImp3dF9pZCI6IjRlMjFmYmJjLWNhOGYtNDczMi05YjJlLTE0Nzc3NTIwMDViYyIsInVzZXJuYW1lIjoiYWRtaW4iLCJzY29wZSI6WyJhZG1pbiJdLCJleHAiOjE3MzM4MTU4MTl9.AZXgxpidbeTRoLLFQCIZW16izopIWsUuO7EYu4V4JZ_byqHKftbfrockSh820u4DOwmnRufCjoe_t7akB9RPUyrXYBCunQipQy9TQhyvBDRX0qmv4krM7C_zXCyh8gdeaJG67p1bOctItJp6KCfANqd_TgITwB86luuzHHqpv5FMfg5AIQS15jXzSClb6D3_0hurooWT9WR2nIY1eByYl-QrcRvgem_RyGmSwja_ZiZd31j0MCoueRZnUltAhXsNKgtqZGq2uaU_i0GDlDme707kIk8QJLPZqOSmbYRnBFA5bWtIXQPtGRkMZlNknxS1yKN92pGsZlj4ORJFuiZ1Bg\"}"
      }
