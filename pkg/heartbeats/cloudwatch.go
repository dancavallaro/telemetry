package heartbeats

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/dancavallaro/telemetry/pkg/awso"
	"log"
	"time"
)

type CloudwatchPublisher struct {
	cw              CloudwatchClientProvider
	metricNamespace string
	metricName      string
	deviceDimension string
}

type CloudwatchClientProvider interface {
	Client() *cloudwatch.Client
}

func NewCloudwatchPublisher(
	cw CloudwatchClientProvider, metricNamespace string, metricName string, deviceDimension string,
) CloudwatchPublisher {
	return CloudwatchPublisher{cw, metricNamespace, metricName, deviceDimension}
}

func (pub CloudwatchPublisher) PublishHeartbeat(device string) error {
	return pub.PublishValue(device, 1)
}

func (pub CloudwatchPublisher) PublishValue(device string, value float64) error {
	if err := pub.publishValue(device, value); err != nil {
		if !errors.Is(err, awso.ClientInvalidated) {
			return err
		}

		log.Println("IAM creds are expired, sleeping for 5 seconds then retrying")
		time.Sleep(5 * time.Second)

		if err := pub.publishValue(device, value); err != nil {
			return err
		}
	}
	return nil
}

func (pub CloudwatchPublisher) publishValue(device string, value float64) error {
	_, err := pub.cw.Client().PutMetricData(context.TODO(), &cloudwatch.PutMetricDataInput{
		Namespace: aws.String(pub.metricNamespace),
		MetricData: []types.MetricDatum{
			{
				MetricName: aws.String(pub.metricName),
				Dimensions: []types.Dimension{
					{
						Name:  aws.String(pub.deviceDimension),
						Value: &device,
					},
				},
				Value: aws.Float64(value),
			},
		},
	})

	if err == nil {
		log.Printf("Published heartbeat metric for device %s\n", device)
	}
	return err
}
