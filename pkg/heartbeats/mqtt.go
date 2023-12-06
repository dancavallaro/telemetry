package heartbeats

import (
	"fmt"
	"github.com/eclipse/paho.mqtt.golang"
	"math/rand"
	"time"
)

type MQTTListener struct {
	client mqtt.Client
}

type Logger interface {
	Println(v ...interface{})
	Printf(format string, v ...interface{})
}

type MQTTListenerConfig struct {
	Username      string
	Password      string
	BrokerAddress string
	Logger        Logger
	DebugLogger   Logger
}

func NewMQTTListener(cfg MQTTListenerConfig) (*MQTTListener, error) {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(cfg.BrokerAddress)
	opts.SetClientID(generateClientId())
	opts.SetUsername(cfg.Username)
	opts.SetPassword(cfg.Password)
	opts.SetKeepAlive(2 * time.Second)
	opts.SetPingTimeout(1 * time.Second)
	opts.SetOrderMatters(false)

	if cfg.Logger != nil {
		mqtt.ERROR = cfg.Logger
		mqtt.CRITICAL = cfg.Logger
		mqtt.WARN = cfg.Logger
	}
	if cfg.DebugLogger != nil {
		mqtt.DEBUG = cfg.DebugLogger
	}

	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}

	return &MQTTListener{client}, nil
}

type MQTTMessageHandler interface {
	Heartbeat(topic string)
	Invalid(topic string, message string)
}

func (lis MQTTListener) RegisterHandler(topic string, handler MQTTMessageHandler) error {
	token := lis.client.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) {
		message := string(msg.Payload())
		if message == "OK" {
			handler.Heartbeat(msg.Topic())
		} else {
			handler.Invalid(msg.Topic(), message)
		}
	})
	token.Wait()
	return token.Error()
}

func (lis MQTTListener) Close() {
	lis.client.Disconnect(1000)
}

func generateClientId() string {
	now := time.Now().Unix()
	random := rand.Intn(1000000)
	return fmt.Sprintf("mqttclient-%v-%v", now, random)
}
