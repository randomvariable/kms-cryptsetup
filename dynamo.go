package main

import (
	"fmt"

	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

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
	HandleError(err)
	return string(str)
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
	HandleError(err)

	return *result.TableDescription.TableArn
}

func GetDynamoRecord(key map[string]*dynamodb.AttributeValue) KeyRecord {
	svc := dynamodb.New(session.New())
	input := &dynamodb.GetItemInput{
		Key:       key,
		TableName: aws.String("kms-cryptsetup"),
	}

	result, err := svc.GetItem(input)
	HandleError(err)
	record := KeyRecord{}
	err = dynamodbattribute.UnmarshalMap(result.Item, &record)
	return record
}

func DynamoTable() string {
	svc := dynamodb.New(session.New())
	input := &dynamodb.DescribeTableInput{
		TableName: aws.String("kms-cryptsetup"),
	}

	result, err := svc.DescribeTable(input)
	if HandleErrorWithMatch(err, dynamodb.ErrCodeResourceNotFoundException) {
		return CreateTable()
	}
	return *result.Table.TableArn
}

type KeyRecord struct {
	Computer   string
	Disk       string
	KeyData    string
	GrantID    string
	GrantToken string
}
