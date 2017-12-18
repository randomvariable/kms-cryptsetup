package main

import (
	"log"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/kms"
)

func HandleError(err error) {
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeNotFoundException:
				log.Fatal(kms.ErrCodeNotFoundException, aerr.Error())
			case kms.ErrCodeDisabledException:
				log.Fatal(kms.ErrCodeDisabledException, aerr.Error())
			case kms.ErrCodeInvalidCiphertextException:
				log.Fatal(kms.ErrCodeInvalidCiphertextException, aerr.Error())
			case kms.ErrCodeKeyUnavailableException:
				log.Fatal(kms.ErrCodeKeyUnavailableException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				log.Fatal(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInvalidGrantTokenException:
				log.Fatal(kms.ErrCodeInvalidGrantTokenException, aerr.Error())
			case kms.ErrCodeInternalException:
				log.Fatal(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeInvalidStateException:
				log.Fatal(kms.ErrCodeInvalidStateException, aerr.Error())
			case kms.ErrCodeInvalidKeyUsageException:
				log.Fatal(kms.ErrCodeInvalidKeyUsageException, aerr.Error())
			case kms.ErrCodeAlreadyExistsException:
				log.Fatal(kms.ErrCodeAlreadyExistsException, aerr.Error())
			case kms.ErrCodeLimitExceededException:
				log.Fatal(kms.ErrCodeLimitExceededException, aerr.Error())
			case kms.ErrCodeMalformedPolicyDocumentException:
				log.Fatal(kms.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case kms.ErrCodeInvalidArnException:
				log.Fatal(kms.ErrCodeInvalidArnException, aerr.Error())
			case kms.ErrCodeUnsupportedOperationException:
				log.Fatal(kms.ErrCodeUnsupportedOperationException, aerr.Error())
			case kms.ErrCodeTagException:
				log.Fatal(kms.ErrCodeTagException, aerr.Error())

			case iam.ErrCodeServiceFailureException:
				log.Fatal(iam.ErrCodeServiceFailureException, aerr.Error())
			case iam.ErrCodeNoSuchEntityException:
				log.Fatal(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				log.Fatal(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeMalformedPolicyDocumentException:
				log.Fatal(iam.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case iam.ErrCodeEntityAlreadyExistsException:
				log.Fatal(iam.ErrCodeEntityAlreadyExistsException, aerr.Error())

			case dynamodb.ErrCodeResourceInUseException:
				log.Fatal(dynamodb.ErrCodeResourceInUseException, aerr.Error())
			case dynamodb.ErrCodeInternalServerError:
				log.Fatal(dynamodb.ErrCodeInternalServerError, aerr.Error())
			case dynamodb.ErrCodeProvisionedThroughputExceededException:
				log.Fatal(dynamodb.ErrCodeProvisionedThroughputExceededException, aerr.Error())
			case dynamodb.ErrCodeResourceNotFoundException:
				log.Fatal(dynamodb.ErrCodeResourceNotFoundException, aerr.Error())

			case dynamodb.ErrCodeConditionalCheckFailedException:
				log.Fatal(dynamodb.ErrCodeConditionalCheckFailedException, aerr.Error())
			case dynamodb.ErrCodeItemCollectionSizeLimitExceededException:
				log.Fatal(dynamodb.ErrCodeItemCollectionSizeLimitExceededException, aerr.Error())

			default:
				log.Fatal(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Fatal(err.Error())
		}
	}
}

func HandleErrorWithMatch(err error, errorType string) bool {
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == errorType {
				return true
			} else {
				HandleError(err)
			}
		} else {
			HandleError(err)
		}
	}
	return false
}
