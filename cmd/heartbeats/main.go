package main

import (
	"fmt"
	"github.com/eclipse/paho.mqtt.golang"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"
)

var heartbeatTopicRegex = regexp.MustCompile(`device/(.+)/heartbeat`)

func parseDevice(message string) string {
	matches := heartbeatTopicRegex.FindStringSubmatch(message)
	return matches[1]
}

func heartbeatHandler(_ mqtt.Client, msg mqtt.Message) {
	device := parseDevice(msg.Topic())

	if string(msg.Payload()) == "OK" {
		fmt.Printf("Received heartbeat for device %s\n", device)
		// TODO: publish to CloudWatch (in a goroutine; don't block here)
	} else {
		fmt.Printf("Received invalid heartbeat message for device %s: %s\n", device, msg.Payload())
	}
}

func generateClientId() string {
	currentTime := time.Now().Unix()
	randomNum := rand.Intn(100)
	return fmt.Sprintf("heartbeatmetrics-%v-%v", currentTime, randomNum)
}

func shutdown(mqttClient mqtt.Client) {
	log.Println("Shutting down now...")
	mqttClient.Disconnect(1000)
}

// const mqttBroker string = "rpi.local:1883"
const mqttBroker string = "localhost:1883"
const mqttHeartbeatTopic string = "device/+/heartbeat"

func main() {
	log.SetPrefix("[heartbeats] ")
	log.SetFlags(0)

	mqtt.ERROR = log.New(os.Stdout, "[ERROR] ", 0)
	mqtt.CRITICAL = log.New(os.Stdout, "[CRIT] ", 0)
	mqtt.WARN = log.New(os.Stdout, "[WARN]  ", 0)
	//mqtt.DEBUG = log.New(os.Stdout, "[DEBUG] ", 0)

	opts := mqtt.NewClientOptions()
	opts.AddBroker(mqttBroker)
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

	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		log.Panicln(token.Error())
	}

	if token := mqttClient.Subscribe(mqttHeartbeatTopic, 0, heartbeatHandler); token.Wait() && token.Error() != nil {
		log.Fatalln(token.Error())
	}

	<-shutdownSignal
}
