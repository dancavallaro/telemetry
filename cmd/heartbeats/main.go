package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
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

func publishHeartbeat(device string) {
	_, err := cwClient.PutMetricData(context.TODO(), &cloudwatch.PutMetricDataInput{
		Namespace: aws.String(metricNamespace),
		MetricData: []types.MetricDatum{
			{
				MetricName: aws.String(metricName),
				Dimensions: []types.Dimension{
					{
						Name:  aws.String(metricDimension),
						Value: &device,
					},
				},
				Value: aws.Float64(1),
			},
		},
	})

	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("Published heartbeat metric for device %s\n", device)
}

func heartbeatHandler(_ mqtt.Client, msg mqtt.Message) {
	device := parseDevice(msg.Topic())

	if string(msg.Payload()) == "OK" {
		fmt.Printf("Received heartbeat message for device %s\n", device)
		// Publish metric to CloudWatch in a goroutine so we don't block MQTT client
		go publishHeartbeat(device)
	} else {
		fmt.Printf("Received invalid heartbeat message for device %s: %s\n", device, msg.Payload())
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

// const mqttBroker string = "rpi.local:1883"
const brokerAddress string = "localhost:1883"
const heartbeatTopic string = "device/+/heartbeat"

const metricNamespace = "RPiMonitoring"
const metricName = "Heartbeat"
const metricDimension = "Device"

var cwClient *cloudwatch.Client

func main() {
	log.SetPrefix("[heartbeats] ")
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

	mqttClient := mqtt.NewClient(opts)
	defer shutdown(mqttClient)

	caughtSignal := make(chan os.Signal, 1)
	shutdownSignal := make(chan bool, 1)
	signal.Notify(caughtSignal, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-caughtSignal
		shutdownSignal <- true
	}()

	cfg, err := config.LoadDefaultConfig(context.TODO())

	if err != nil {
		log.Panic(err)
	}

	cfg.Region = "us-east-1"
	cwClient = cloudwatch.NewFromConfig(cfg)

	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		log.Panicln(token.Error())
	}

	if token := mqttClient.Subscribe(heartbeatTopic, 0, heartbeatHandler); token.Wait() && token.Error() != nil {
		log.Fatalln(token.Error())
	}

	<-shutdownSignal
}
