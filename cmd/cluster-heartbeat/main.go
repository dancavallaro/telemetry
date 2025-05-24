package main

import (
	"flag"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/dancavallaro/telemetry/pkg/awso"
	"github.com/dancavallaro/telemetry/pkg/heartbeats"
	"github.com/prometheus/alertmanager/api/v2/client"
	"github.com/prometheus/alertmanager/api/v2/client/alert"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// This app continuously publishes a metric to CloudWatch with the number of Alertmanager alerts
// currently in alarm. This is meant to be used as a single backstop monitor in AWS, it should
// be 0 most of the time but we'll alarm 1) if data disappears entirely or 2) if the metric
// is non-zero for an extended period of time (e.g. > 24 hours). Either of these conditions could
// indicate that monitoring is broken or that there is a serious issue with the cluster.

const alertmanagerHost = "alertmanager.monitoring.svc.cluster.local"
const clusterName = "talos-prod"

type MetricPublisher interface {
	PublishValue(device string, value float64) error
}

type noopPublisher struct{}

func (p noopPublisher) PublishValue(_ string, _ float64) error {
	return nil
}

func printConfigSummary() {
	log.Println("============= Configuration =============")
	log.Printf("AWS region: %s\n", *region)
	log.Printf("Cloudwatch namespace: %s\n", *metricNamespace)
	log.Printf("Cloudwatch metric name: %s\n", *metricName)
	log.Printf("Cloudwatch metric dimension: %s\n", *metricDimension)
	log.Println("=========================================")
}

var (
	region          = flag.String("region", "us-east-1", "Cloudwatch region to use")
	metricNamespace = flag.String("metricNamespace", "Testing", "Metric namespace to publish in")
	metricName      = flag.String("metricName", "Heartbeat", "Metric name to use for heartbeats")
	metricDimension = flag.String("metricDimension", "Device", "Dimension name to use for identifying devices")
	logOnly         = flag.Bool("logOnly", false, "Log heartbeats, but don't publish metrics to Cloudwatch")
)

func monitorAlertmanager(publisher MetricPublisher, client *client.AlertmanagerAPI) {
	for {
		alerts, err := client.Alert.GetAlerts(&alert.GetAlertsParams{})
		if err != nil {
			log.Printf("Error getting alerts: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(alerts.Payload) == 0 {
			log.Println("No alerts currently firing")
		} else {
			var alertTitles []string
			for _, a := range alerts.Payload {
				alertTitles = append(alertTitles, a.Labels["alertname"])
			}
			log.Printf("Found %d alerts firing: %v", len(alerts.Payload), alertTitles)
		}

		if err := publisher.PublishValue(clusterName, float64(len(alerts.Payload))); err != nil {
			log.Panic(err)
		}

		time.Sleep(30 * time.Second)
	}
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[cluster-heartbeat] ")

	flag.Parse()
	printConfigSummary()

	var publisher MetricPublisher = noopPublisher{}
	if !*logOnly {
		cw := awso.NewClientProvider(func(cfg aws.Config) *cloudwatch.Client {
			cfg.Region = *region
			log.Println("Creating new Cloudwatch client")
			return cloudwatch.NewFromConfig(cfg)
		})
		publisher = heartbeats.NewCloudwatchPublisher(&cw, *metricNamespace, *metricName, *metricDimension)
	}

	alertClient := client.NewHTTPClientWithConfig(nil,
		client.DefaultTransportConfig().WithHost(alertmanagerHost))

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Monitoring Alertmanager alert status...")
	go monitorAlertmanager(publisher, alertClient)
	<-done
}
