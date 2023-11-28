package awso

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"testing"
	"time"
)

func TestClientCaching(t *testing.T) {
	sts := NewClientProvider(func(cfg aws.Config) *awssts.Client {
		fmt.Println("constructing new client") // TODO: remove this, do real test
		return awssts.NewFromConfig(cfg)
	})

	for i := 0; i < 10; i++ {
		resp, err := sts.Client().GetCallerIdentity(context.TODO(), nil)
		if err != nil {
			panic(err)
		}
		fmt.Println(*resp.Arn)
		time.Sleep(1 * time.Second)
	}
}
