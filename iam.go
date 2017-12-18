package main

import (
	"crypto/sha1"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

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
	HandleError(err)
	input2 := &iam.PutUserPolicyInput{
		PolicyDocument: aws.String(DynamoPolicy()),
		PolicyName:     aws.String("kms-cryptsetup"),
		UserName:       aws.String(ComputerUserName()),
	}

	_, err2 := svc.PutUserPolicy(input2)
	HandleError(err2)

	CreateAccessKey()
	return *result.User.Arn
}

func CreateAccessKey() {
	svc := iam.New(session.New())
	input := &iam.CreateAccessKeyInput{
		UserName: aws.String(ComputerUserName()),
	}

	result, err := svc.CreateAccessKey(input)
	HandleError(err)
	fmt.Println(result)
}

func ComputerUser() string {
	svc := iam.New(session.New())
	input := &iam.GetUserInput{
		UserName: aws.String(ComputerUserName()),
	}

	result, err := svc.GetUser(input)
	if HandleErrorWithMatch(err, iam.ErrCodeNoSuchEntityException) {
		return CreateComputerUser()
	}
	return *result.User.Arn
}
