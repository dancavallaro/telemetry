package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/smithy-go"
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

func publishHeartbeat(device string) error {
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
		return err
	}

	fmt.Printf("Published heartbeat metric for device %s\n", device)
	return nil
}

func heartbeatHandler(_ mqtt.Client, msg mqtt.Message) {
	device := parseDevice(msg.Topic())

	if string(msg.Payload()) == "OK" {
		fmt.Printf("Received heartbeat message for device %s\n", device)

		if err := publishHeartbeat(device); err != nil {
			var ae smithy.APIError
			if !errors.As(err, &ae) || ae.ErrorCode() != "ExpiredToken" {
				log.Panic(err)
			}

			log.Println("IAM creds are expired, sleeping for 5 seconds then retrying")
			time.Sleep(5 * time.Second)
			cwClient = getCwClient()

			if err := publishHeartbeat(device); err != nil {
				log.Panic(err) // Just give up if the retry fails
			}
		}
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

func getCwClient() *cloudwatch.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO())

	if err != nil {
		log.Panic(err)
	}

	cfg.Region = "us-east-1"
	return cloudwatch.NewFromConfig(cfg)
}

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

	cwClient = getCwClient()

	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		log.Panicln(token.Error())
	}

	if token := mqttClient.Subscribe(heartbeatTopic, 0, heartbeatHandler); token.Wait() && token.Error() != nil {
		log.Fatalln(token.Error())
	}

	<-shutdownSignal
}
