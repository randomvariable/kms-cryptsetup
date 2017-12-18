package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/kms"
)

func ComputerGrant() KeyRecord {
	record := GetDynamoRecord(GrantDynamoKey())
	if record.KeyData == "" {
		return CreateComputerGrant()
	}
	return record
}

func CreateComputerGrant() KeyRecord {
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
	HandleError(err)
	record := KeyRecord{
		GrantID:    *result.GrantId,
		GrantToken: *result.GrantToken,
	}
	StoreGrant(record)
	return record
}

func RevokeGrant() {
	record := ComputerGrant()
	svc := kms.New(session.New())
	params := &kms.RevokeGrantInput{
		GrantId: aws.String(record.GrantID),
		KeyId:   aws.String(KeyARN()),
	}
	_, err := svc.RevokeGrant(params)
	HandleError(err)
	DeleteGrant(record)
}

func DeleteGrant(record KeyRecord) {
	svc := dynamodb.New(session.New())
	input := &dynamodb.DeleteItemInput{
		Key: GrantDynamoKey(),
		ReturnConsumedCapacity: aws.String("TOTAL"),
		TableName:              aws.String("kms-cryptsetup"),
	}
	_, err := svc.DeleteItem(input)
	HandleError(err)
}

func StoreGrant(record KeyRecord) {
	svc := dynamodb.New(session.New())
	input := &dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			"Computer": {
				S: aws.String(ComputerContext()),
			},
			"Disk": {
				S: aws.String("KeyGrant"),
			},
			"GrantID": {
				S: aws.String(record.GrantID),
			},
			"GrantToken": {
				S: aws.String(record.GrantToken),
			},
		},
		ReturnConsumedCapacity: aws.String("TOTAL"),
		TableName:              aws.String("kms-cryptsetup"),
	}

	_, err := svc.PutItem(input)
	HandleError(err)
}

func GrantDynamoKey() map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"Computer": {
			S: aws.String(ComputerContext()),
		},
		"Disk": {
			S: aws.String("KeyGrant"),
		},
	}
}
