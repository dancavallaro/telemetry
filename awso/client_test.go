package awso

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func p(s string) *string {
	return &s
}

func TestClientCaching(t *testing.T) {
	buildClientInvocations := 0
	cp := NewClientProvider(context.TODO(), func(cfg aws.Config) *string {
		buildClientInvocations++
		return p("dummy client")
	})

	for i := 0; i < 5; i++ {
		client := cp.Client()
		assert.Equal(t, "dummy client", *client)
	}

	assert.Equal(t, 1, buildClientInvocations)
}

func TestCallsToSts(t *testing.T) {
	sts := NewClientProvider(context.TODO(), func(cfg aws.Config) *awssts.Client {
		fmt.Println("constructing new client")
		cfg.Region = "us-east-1"
		return awssts.NewFromConfig(cfg)
	})

	for i := 0; i < 5; i++ {
		resp, err := sts.Client().GetCallerIdentity(context.TODO(), nil)
		if err != nil {
			if errors.Is(err, ClientInvalidated) {
				fmt.Println("Credentials expired! Client will be reloaded on next invocation")
			} else {
				fmt.Printf("Error: %v\n", err)
			}
		}
		fmt.Println(resp)
		//fmt.Println(*resp.Arn)
		time.Sleep(1 * time.Second)
	}
}
