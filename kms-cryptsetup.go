package main

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"encoding/base64"
	"encoding/json"
	"path/filepath"

	"os/exec"

	"github.com/alecthomas/kingpin"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/kms"
)

var (
	computerContextCommand    = kingpin.Command("computer-context", "Print the computer context")
	grantComputerCommand      = kingpin.Command("grant-computer", "Grant a computer access")
	storeEncryptionKeyCommand = kingpin.Command("store-encryption-key", "store an encryption key for a disk")
	encryptDiskCommand        = kingpin.Command("encrypt-disk", "Encrypt a disk")
	createTableCommand        = kingpin.Command("create-table", "Create DynamoDB Table")
	device                    = kingpin.Flag("device", "Device to encrypt").Short('d').String()
	computerContext           = kingpin.Flag("computer-context", "Supply Computer Context up-front").Short('c').String()
)

func main() {
	switch kingpin.Parse() {
	case "computer-context":
		fmt.Println(ComputerContext())
	case "grant-computer":
		GrantComputer()
	case "store-encryption-key":
		GetEncryptedDiskKey()
	case "create-table":
		DynamoTable()
	case "encrypt-disk":
		EncryptDisk()
	}

}

type KeyRecord struct {
	Computer string
	Disk     string
	KeyData  string
}

func SaveEncryptedDiskKey() []byte {
	data := GenerateDataKey()
	str := base64.StdEncoding.EncodeToString(data)
	svc := dynamodb.New(session.New())
	input := &dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			"Computer": {
				S: aws.String(ComputerContext()),
			},
			"Disk": {
				S: aws.String(DiskContext(*device)),
			},
			"KeyData": {
				S: aws.String(str),
			},
		},
		ReturnConsumedCapacity: aws.String("TOTAL"),
		TableName:              aws.String("kms-cryptsetup"),
	}

	_, err := svc.PutItem(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				fmt.Println(dynamodb.ErrCodeConditionalCheckFailedException, aerr.Error())
			case dynamodb.ErrCodeProvisionedThroughputExceededException:
				fmt.Println(dynamodb.ErrCodeProvisionedThroughputExceededException, aerr.Error())
			case dynamodb.ErrCodeResourceNotFoundException:
				fmt.Println(dynamodb.ErrCodeResourceNotFoundException, aerr.Error())
			case dynamodb.ErrCodeItemCollectionSizeLimitExceededException:
				fmt.Println(dynamodb.ErrCodeItemCollectionSizeLimitExceededException, aerr.Error())
			case dynamodb.ErrCodeInternalServerError:
				fmt.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}
	return data
}

func DynamoKey() map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"Computer": {
			S: aws.String(ComputerContext()),
		},
		"Disk": {
			S: aws.String(DiskContext(*device)),
		},
	}
}

func EncryptDisk() {
	cmd := exec.Command("cryptsetup", "--allow-discards", "--cipher", "aes-xts-plain64", "--key-file", "-", "--key-size=256", "open", "--type", "plain", *device, EncryptedDM())
	cmd.Stdin = bytes.NewReader(DecryptDataKey())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func GetEncryptedDiskKey() []byte {
	svc := dynamodb.New(session.New())
	input := &dynamodb.GetItemInput{
		Key:       DynamoKey(),
		TableName: aws.String("kms-cryptsetup"),
	}

	result, err := svc.GetItem(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeProvisionedThroughputExceededException:
				fmt.Println(dynamodb.ErrCodeProvisionedThroughputExceededException, aerr.Error())
			case dynamodb.ErrCodeResourceNotFoundException:
				return SaveEncryptedDiskKey()
			case dynamodb.ErrCodeInternalServerError:
				fmt.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}
	record := KeyRecord{}
	err = dynamodbattribute.UnmarshalMap(result.Item, &record)
	if record.KeyData == "" {
		return SaveEncryptedDiskKey()
	}
	data, err := base64.StdEncoding.DecodeString(record.KeyData)
	if err != nil {
		fmt.Println("error:", err)
	}
	return data
}

func DynamoTable() string {
	svc := dynamodb.New(session.New())
	input := &dynamodb.DescribeTableInput{
		TableName: aws.String("kms-cryptsetup"),
	}

	result, err := svc.DescribeTable(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeResourceNotFoundException:
				return CreateTable()
			case dynamodb.ErrCodeInternalServerError:
				fmt.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}

	return *result.Table.TableArn
}

func CreateTable() string {
	svc := dynamodb.New(session.New())
	input := &dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("Computer"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("Disk"),
				AttributeType: aws.String("S"),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("Computer"),
				KeyType:       aws.String("HASH"),
			},
			{
				AttributeName: aws.String("Disk"),
				KeyType:       aws.String("RANGE"),
			},
		},
		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(1),
			WriteCapacityUnits: aws.Int64(1),
		},
		TableName: aws.String("kms-cryptsetup"),
	}

	result, err := svc.CreateTable(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeResourceInUseException:
				fmt.Println(dynamodb.ErrCodeResourceInUseException, aerr.Error())
			case dynamodb.ErrCodeLimitExceededException:
				fmt.Println(dynamodb.ErrCodeLimitExceededException, aerr.Error())
			case dynamodb.ErrCodeInternalServerError:
				fmt.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}

	return *result.TableDescription.TableArn
}

func ComputerUserName() string {
	sum := sha1.Sum([]byte(ComputerContext()))
	truncated := fmt.Sprintf("%.59x", sum)
	return strings.Join([]string{"crypt", truncated}, "-")
}

func CreateComputerUser() string {
	svc := iam.New(session.New())
	fmt.Println(ComputerUserName())
	input := &iam.CreateUserInput{
		UserName: aws.String(ComputerUserName()),
	}

	result, err := svc.CreateUser(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeLimitExceededException:
				fmt.Println(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeEntityAlreadyExistsException:
				fmt.Println(iam.ErrCodeEntityAlreadyExistsException, aerr.Error())
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}
	input2 := &iam.PutUserPolicyInput{
		PolicyDocument: aws.String(DynamoPolicy()),
		PolicyName:     aws.String("kms-cryptsetup"),
		UserName:       aws.String(ComputerUserName()),
	}

	_, err2 := svc.PutUserPolicy(input2)
	if err2 != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeLimitExceededException:
				fmt.Println(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeMalformedPolicyDocumentException:
				fmt.Println(iam.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}

	CreateAccessKey()
	return *result.User.Arn
}

func DynamoPolicy() string {
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Sid":    "VisualEditor0",
				"Effect": "Allow",
				"Action": []interface{}{
					"dynamodb:PutItem",
					"dynamodb:GetItem",
				},
				"Resource": DynamoTable(),
				"Condition": map[string]interface{}{
					"ForAllValues:StringLike": map[string]interface{}{
						"dynamodb:LeadingKeys": fmt.Sprintf("%s*", ComputerContext()),
					},
				},
			},
		},
	}
	str, err := json.Marshal(policy)
	if err != nil {
		fmt.Println(err)
	}
	return string(str)
}

func CreateAccessKey() {
	svc := iam.New(session.New())
	input := &iam.CreateAccessKeyInput{
		UserName: aws.String(ComputerUserName()),
	}

	result, err := svc.CreateAccessKey(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				fmt.Println(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	fmt.Println(result)
}

func ComputerUser() string {
	svc := iam.New(session.New())
	input := &iam.GetUserInput{
		UserName: aws.String(ComputerUserName()),
	}

	result, err := svc.GetUser(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				return CreateComputerUser()
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}
	return *result.User.Arn
}

func KeyARN() string {
	svc := kms.New(session.New())
	input := &kms.DescribeKeyInput{
		KeyId: aws.String("alias/kms-cryptsetup"),
	}
	result, err := svc.DescribeKey(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeNotFoundException:
				return CreateKey()
			case kms.ErrCodeInvalidArnException:
				fmt.Println(kms.ErrCodeInvalidArnException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInternalException:
				fmt.Println(kms.ErrCodeInternalException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}
	return *result.KeyMetadata.Arn
}

func EncryptionContext() map[string]*string {
	return map[string]*string{
		"Computer": aws.String(ComputerContext()),
	}
}

func GrantComputer() {
	svc := kms.New(session.New())
	params := &kms.CreateGrantInput{
		Constraints: &kms.GrantConstraints{
			EncryptionContextSubset: EncryptionContext(),
		},
		GranteePrincipal: aws.String(ComputerUser()),
		KeyId:            aws.String(KeyARN()),
		Name:             aws.String(ComputerContext()),
		Operations: []*string{
			aws.String("Encrypt"),
			aws.String("Decrypt"),
			aws.String("GenerateDataKey"),
			aws.String("DescribeKey"),
		},
	}

	result, err := svc.CreateGrant(params)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeNotFoundException:
				fmt.Println(kms.ErrCodeNotFoundException, aerr.Error())
			case kms.ErrCodeDisabledException:
				fmt.Println(kms.ErrCodeDisabledException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInvalidArnException:
				fmt.Println(kms.ErrCodeInvalidArnException, aerr.Error())
			case kms.ErrCodeInternalException:
				fmt.Println(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeInvalidGrantTokenException:
				fmt.Println(kms.ErrCodeInvalidGrantTokenException, aerr.Error())
			case kms.ErrCodeLimitExceededException:
				fmt.Println(kms.ErrCodeLimitExceededException, aerr.Error())
			case kms.ErrCodeInvalidStateException:
				fmt.Println(kms.ErrCodeInvalidStateException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	fmt.Println(result)
}

func CreateKey() string {
	svc := kms.New(session.New())
	params := &kms.CreateKeyInput{
		Description: aws.String("kms-cryptsetup"),
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("Name"),
				TagValue: aws.String("kms-cryptsetup"),
			},
		},
	}
	result, err := svc.CreateKey(params)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeMalformedPolicyDocumentException:
				fmt.Println(kms.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInvalidArnException:
				fmt.Println(kms.ErrCodeInvalidArnException, aerr.Error())
			case kms.ErrCodeUnsupportedOperationException:
				fmt.Println(kms.ErrCodeUnsupportedOperationException, aerr.Error())
			case kms.ErrCodeInternalException:
				fmt.Println(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeLimitExceededException:
				fmt.Println(kms.ErrCodeLimitExceededException, aerr.Error())
			case kms.ErrCodeTagException:
				fmt.Println(kms.ErrCodeTagException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}
	arn := *result.KeyMetadata.Arn
	aliasInput := &kms.CreateAliasInput{
		AliasName:   aws.String("alias/kms-cryptsetup"),
		TargetKeyId: aws.String(arn),
	}

	_, err2 := svc.CreateAlias(aliasInput)
	if err2 != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeDependencyTimeoutException:
				fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeAlreadyExistsException:
				fmt.Println(kms.ErrCodeAlreadyExistsException, aerr.Error())
			case kms.ErrCodeNotFoundException:
				fmt.Println(kms.ErrCodeNotFoundException, aerr.Error())
			case kms.ErrCodeInvalidAliasNameException:
				fmt.Println(kms.ErrCodeInvalidAliasNameException, aerr.Error())
			case kms.ErrCodeInternalException:
				fmt.Println(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeLimitExceededException:
				fmt.Println(kms.ErrCodeLimitExceededException, aerr.Error())
			case kms.ErrCodeInvalidStateException:
				fmt.Println(kms.ErrCodeInvalidStateException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}
	return arn
}

func HandleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func DmiString(name string) string {
	val, err := ioutil.ReadFile(fmt.Sprintf("/sys/devices/virtual/dmi/id/%s", name))
	HandleError(err)
	return strings.TrimSpace(string(val))
}

func DecryptDataKey() []byte {
	svc := kms.New(session.New())
	data := GetEncryptedDiskKey()
	input := &kms.DecryptInput{
		CiphertextBlob:    data,
		EncryptionContext: EncryptionContext(),
	}

	result, err := svc.Decrypt(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeNotFoundException:
				fmt.Println(kms.ErrCodeNotFoundException, aerr.Error())
			case kms.ErrCodeDisabledException:
				fmt.Println(kms.ErrCodeDisabledException, aerr.Error())
			case kms.ErrCodeInvalidCiphertextException:
				fmt.Println(kms.ErrCodeInvalidCiphertextException, aerr.Error())
			case kms.ErrCodeKeyUnavailableException:
				fmt.Println(kms.ErrCodeKeyUnavailableException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInvalidGrantTokenException:
				fmt.Println(kms.ErrCodeInvalidGrantTokenException, aerr.Error())
			case kms.ErrCodeInternalException:
				fmt.Println(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeInvalidStateException:
				fmt.Println(kms.ErrCodeInvalidStateException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}

	return result.Plaintext
}

func GenerateDataKey() []byte {
	svc := kms.New(session.New())
	input := &kms.GenerateDataKeyInput{
		KeyId:             aws.String("alias/kms-cryptsetup"),
		KeySpec:           aws.String("AES_256"),
		EncryptionContext: EncryptionContext(),
	}

	result, err := svc.GenerateDataKey(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeNotFoundException:
				fmt.Println(kms.ErrCodeNotFoundException, aerr.Error())
			case kms.ErrCodeDisabledException:
				fmt.Println(kms.ErrCodeDisabledException, aerr.Error())
			case kms.ErrCodeKeyUnavailableException:
				fmt.Println(kms.ErrCodeKeyUnavailableException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInvalidKeyUsageException:
				fmt.Println(kms.ErrCodeInvalidKeyUsageException, aerr.Error())
			case kms.ErrCodeInvalidGrantTokenException:
				fmt.Println(kms.ErrCodeInvalidGrantTokenException, aerr.Error())
			case kms.ErrCodeInternalException:
				fmt.Println(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeInvalidStateException:
				fmt.Println(kms.ErrCodeInvalidStateException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}
	return result.CiphertextBlob
}

func Contextify(str string) string {
	return strings.ToLower(strings.Replace(strings.Replace(strings.Replace(str, "-", "", -1), " ", "", -1), ".", "", -1))
}

func ComputerContext() string {
	if *computerContext != "" {
		return *computerContext
	}
	context := []string{DmiString("board_vendor"), DmiString("board_serial"), DmiString("product_uuid")}
	return Contextify(strings.Join(context, ""))
}

func DiskContext(device string) string {
	sysfs := fmt.Sprintf("/sys/block/%s/device/wwid", RealDiskDevice(device))
	blockInfo, err := ioutil.ReadFile(sysfs)
	if err != nil {
		log.Fatal(err)
	}
	fields := strings.Fields(string(blockInfo))
	return Contextify(strings.Join(fields, ""))
}

func EncryptedDM() string {
	return fmt.Sprintf("dmcrypt-%s", RealDiskDevice(*device))
}

func RealDiskDevice(device string) string {
	deviceInfo, err := filepath.EvalSymlinks(device)
	if err != nil {
		log.Fatal(err)
	}
	return filepath.Base(deviceInfo)
}
