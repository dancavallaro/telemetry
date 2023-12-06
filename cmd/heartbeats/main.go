package main

import (
	"dancavallaro.com/telemetry/pkg/awso"
	"dancavallaro.com/telemetry/pkg/heartbeats"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/eclipse/paho.mqtt.golang"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"
)

// TODO: refactor all this mess, break it up into separate packages/files

var topicRegex = regexp.MustCompile(`device/(.+)/heartbeat`)

func parseDevice(message string) string {
	matches := topicRegex.FindStringSubmatch(message)
	return matches[1]
}

func heartbeatHandler(publisher heartbeats.CloudwatchPublisher) func(_ mqtt.Client, msg mqtt.Message) {
	return func(_ mqtt.Client, msg mqtt.Message) {
		device := parseDevice(msg.Topic())

		if string(msg.Payload()) == "OK" {
			log.Printf("Received heartbeat message for device %s\n", device)
			if err := publisher.PublishHeartbeat(device); err != nil {
				log.Panic(err)
			}
		} else {
			log.Printf("Received invalid heartbeat message for device %s: %s\n", device, msg.Payload())
		}
	}
}

func generateClientId() string {
	now := time.Now().Unix()
	random := rand.Intn(100)
	return fmt.Sprintf("heartbeatmetrics-%v-%v", now, random)
}

func shutdown(mqttClient mqtt.Client) {
	log.Println("Shutting down now...")
	mqttClient.Disconnect(1000)
}

const brokerAddress string = "localhost:1883"
const heartbeatTopic string = "device/+/heartbeat"

var (
	region          = flag.String("region", "us-east-1", "Cloudwatch region to use")
	metricNamespace = flag.String("metricNamespace", "Testing", "Metric namespace to publish in")
	metricName      = flag.String("metricName", "Heartbeat", "Metric name to use for heartbeats")
	metricDimension = flag.String("metricDimension", "Device", "Dimension name to use for identifying devices")
)

func main() {
	flag.Parse()

	log.SetFlags(0)

	mqtt.ERROR = log.New(os.Stdout, "[ERROR] ", 0)
	mqtt.CRITICAL = log.New(os.Stdout, "[CRIT] ", 0)
	mqtt.WARN = log.New(os.Stdout, "[WARN]  ", 0)
	//mqtt.DEBUG = log.New(os.Stdout, "[DEBUG] ", 0)

	opts := mqtt.NewClientOptions()
	opts.AddBroker(brokerAddress)
	opts.SetClientID(generateClientId())
	// TODO: Get this out of source control
	opts.SetUsername("rpi")
	opts.SetPassword("DHV6x48uBtYI83Ppu0tEWBmH")
	opts.SetKeepAlive(2 * time.Second)
	opts.SetPingTimeout(1 * time.Second)
	opts.SetOrderMatters(false)

	mqttClient := mqtt.NewClient(opts)
	defer shutdown(mqttClient)

	caughtSignal := make(chan os.Signal, 1)
	shutdownSignal := make(chan bool, 1)
	signal.Notify(caughtSignal, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-caughtSignal
		shutdownSignal <- true
	}()

	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		log.Panicln(token.Error())
	}

	cw := awso.NewClientProvider(func(cfg aws.Config) *cloudwatch.Client {
		cfg.Region = *region
		log.Println("Creating new Cloudwatch client")
		return cloudwatch.NewFromConfig(cfg)
	})
	publisher := heartbeats.NewCloudwatchPublisher(&cw, *metricNamespace, *metricName, *metricDimension)
	handler := heartbeatHandler(publisher)

	if token := mqttClient.Subscribe(heartbeatTopic, 0, handler); token.Wait() && token.Error() != nil {
		log.Fatalln(token.Error())
	}

	<-shutdownSignal
}
