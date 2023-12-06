package main

import (
	"dancavallaro.com/telemetry/pkg/awso"
	"dancavallaro.com/telemetry/pkg/heartbeats"
	"flag"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"log"
	"os"
	"os/signal"
	"regexp"
	"syscall"
)

const mqttTopic = "device/+/heartbeat"

var mqttTopicRegex = regexp.MustCompile(`device/(.+)/heartbeat`)

type heartbeatHandler struct {
	publisher heartbeats.CloudwatchPublisher
}

func (handler heartbeatHandler) Heartbeat(topic string) {
	device := mqttTopicRegex.FindStringSubmatch(topic)[1]
	log.Printf("Received heartbeat message for device %s\n", device)
	if err := handler.publisher.PublishHeartbeat(device); err != nil {
		log.Panic(err)
	}
}

func (handler heartbeatHandler) Invalid(topic string, message string) {
	log.Printf("Received invalid heartbeat message on topic '%s': %s\n", topic, message)
}

var (
	region          = flag.String("region", "us-east-1", "Cloudwatch region to use")
	metricNamespace = flag.String("metricNamespace", "Testing", "Metric namespace to publish in")
	metricName      = flag.String("metricName", "Heartbeat", "Metric name to use for heartbeats")
	metricDimension = flag.String("metricDimension", "Device", "Dimension name to use for identifying devices")
	mqttAddress     = flag.String("mqttAddress", "localhost:1883", "Address:port of MQTT broker")
	mqttUsername    = flag.String("mqttUsername", "<none>", "MQTT username")
	mqttPassword    = flag.String("mqttPassword", "<none>", "MQTT password")
)

func main() {
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("[heartbeats] ")

	cw := awso.NewClientProvider(func(cfg aws.Config) *cloudwatch.Client {
		cfg.Region = *region
		log.Println("Creating new Cloudwatch client")
		return cloudwatch.NewFromConfig(cfg)
	})
	publisher := heartbeats.NewCloudwatchPublisher(&cw, *metricNamespace, *metricName, *metricDimension)

	listener, err := heartbeats.NewMQTTListener(heartbeats.MQTTListenerConfig{
		BrokerAddress: *mqttAddress,
		Username:      *mqttUsername,
		Password:      *mqttPassword,
		Logger:        log.New(os.Stdout, "[mqtt] ", 0),
	})
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		log.Println("Shutting down MQTT listener now...")
		listener.Close()
	}()
	if err := listener.RegisterHandler(mqttTopic, heartbeatHandler{publisher}); err != nil {
		log.Panic(err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	<-done
}
