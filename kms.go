package main

import (
	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/kms"
)

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
	HandleError(err)
	arn := *result.KeyMetadata.Arn
	aliasInput := &kms.CreateAliasInput{
		AliasName:   aws.String("alias/kms-cryptsetup"),
		TargetKeyId: aws.String(arn),
	}

	_, err2 := svc.CreateAlias(aliasInput)
	HandleError(err2)
	return arn
}

func DecryptDataKey() []byte {
	svc := kms.New(session.New())
	data := GetEncryptedDiskKey()
	input := &kms.DecryptInput{
		CiphertextBlob:    data,
		EncryptionContext: EncryptionContext(),
	}

	result, err := svc.Decrypt(input)
	HandleError(err)
	return result.Plaintext
}

func KeyARN() string {
	svc := kms.New(session.New())
	input := &kms.DescribeKeyInput{
		KeyId: aws.String("alias/kms-cryptsetup"),
	}
	result, err := svc.DescribeKey(input)
	if HandleErrorWithMatch(err, kms.ErrCodeNotFoundException) {
		return CreateKey()
	}
	return *result.KeyMetadata.Arn
}

func EncryptionContext() map[string]*string {
	return map[string]*string{
		"Computer": aws.String(ComputerContext()),
	}
}

func GenerateDataKey() []byte {
	svc := kms.New(session.New())
	input := &kms.GenerateDataKeyInput{
		KeyId:             aws.String("alias/kms-cryptsetup"),
		KeySpec:           aws.String("AES_256"),
		EncryptionContext: EncryptionContext(),
	}

	result, err := svc.GenerateDataKey(input)
	HandleError(err)
	return result.CiphertextBlob
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
	HandleError(err)
	return data
}

func GetEncryptedDiskKey() []byte {
	record := GetDynamoRecord(DiskDynamoKey())
	if record.KeyData == "" {
		return SaveEncryptedDiskKey()
	}
	data, err := base64.StdEncoding.DecodeString(record.KeyData)
	HandleError(err)
	return data
}

func DiskDynamoKey() map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"Computer": {
			S: aws.String(ComputerContext()),
		},
		"Disk": {
			S: aws.String(DiskContext(*device)),
		},
	}
}
