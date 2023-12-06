package awso

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"log"
)

type ClientProvider[T any] struct {
	Context     context.Context
	buildClient func(cfg aws.Config) *T
	client      *T
}

func NewClientProvider[T any](buildClient func(cfg aws.Config) *T) ClientProvider[T] {
	return ClientProvider[T]{
		buildClient: buildClient,
		Context:     context.TODO(),
	}
}

var ClientInvalidated = errors.New("client invalidated")

type deserializeMiddlewareFunc func(
	context.Context, middleware.DeserializeInput, middleware.DeserializeHandler,
) (
	middleware.DeserializeOutput, middleware.Metadata, error,
)

func clientInvalidatorMiddleware[T any](cp *ClientProvider[T]) deserializeMiddlewareFunc {
	return func(
		ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler,
	) (
		middleware.DeserializeOutput, middleware.Metadata, error,
	) {
		out, metadata, err := next.HandleDeserialize(ctx, in)

		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) && ae.ErrorCode() == "ExpiredToken" {
				log.Println("credentials are expired! invalidating cached client")
				cp.client = nil

				return out, metadata, ClientInvalidated
			}
		}

		return out, metadata, err
	}
}

func (cp *ClientProvider[T]) Client() *T {
	client, err := cp.ClientSafe()
	if err != nil {
		// Not great to panic here, but awkward for the caller to have to handle an
		// error return value when using this method.
		panic(err)
	}
	return client
}

func (cp *ClientProvider[T]) ClientSafe() (*T, error) {
	if cp.client == nil {
		cfg, err := config.LoadDefaultConfig(cp.Context)
		if err != nil {
			return nil, err
		}

		cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
			m := middleware.DeserializeMiddlewareFunc("ClientInvalidatorMiddleware", clientInvalidatorMiddleware(cp))
			return stack.Deserialize.Add(m, middleware.Before)
		})

		cp.client = cp.buildClient(cfg)
	}
	return cp.client, nil
}
