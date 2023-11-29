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

// TODO: is it possible to use a credential provider instead?

type ClientProvider[T any] struct {
	ctx         context.Context
	buildClient func(cfg aws.Config) *T
	client      *T
}

func NewClientProvider[T any](ctx context.Context, buildClient func(cfg aws.Config) *T) ClientProvider[T] {
	return ClientProvider[T]{
		ctx:         ctx,
		buildClient: buildClient,
	}
}

var ClientInvalidated = errors.New("client invalidated after credential expiration")

type DeserializeMiddlewareFunc func(
	context.Context, middleware.DeserializeInput, middleware.DeserializeHandler,
) (
	middleware.DeserializeOutput, middleware.Metadata, error,
)

func clientInvalidatorMiddleware[T any](cp *ClientProvider[T]) DeserializeMiddlewareFunc {
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
	if cp.client == nil {
		cfg, err := config.LoadDefaultConfig(cp.ctx)

		if err != nil {
			panic(err)
		}

		cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
			m := middleware.DeserializeMiddlewareFunc("ClientInvalidatorMiddleware", clientInvalidatorMiddleware(cp))
			return stack.Deserialize.Add(m, middleware.Before)
		})

		cp.client = cp.buildClient(cfg)
	}
	return cp.client
}
