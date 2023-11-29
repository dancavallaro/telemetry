package awso

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// TODO: need to figure out how to actually handle expiration. can i inject a middleware?
// TODO: is it possible to use a credential provider instead?

type ClientProvider[T any] struct {
	buildClient func(cfg aws.Config) *T
	client      *T
}

func NewClientProvider[T any](buildClient func(cfg aws.Config) *T) ClientProvider[T] {
	return ClientProvider[T]{buildClient: buildClient}
}

func (cp *ClientProvider[T]) Client() *T {
	if cp.client == nil {
		cfg, err := config.LoadDefaultConfig(context.TODO()) // TODO: should accept context as parameter

		if err != nil {
			panic(err)
		}

		cfg.Region = "us-east-1" // TODO: make this configurable
		cp.client = cp.buildClient(cfg)
	}
	return cp.client
}
