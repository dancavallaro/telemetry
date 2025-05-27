package main

import (
	"flag"
	"github.com/dancavallaro/telemetry/pkg/heartbeats"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"
)

const (
	heartbeatTTLSeconds = 24 * 60 * 60
	mqttTopic           = "device/+/heartbeat"
)

var (
	mqttTopicRegex      = regexp.MustCompile(`device/(.+)/heartbeat`)
	mqttAddress         = flag.String("mqttAddress", "localhost:1883", "Address:port of MQTT broker")
	mqttUsername        = flag.String("mqttUsername", "<none>", "MQTT username")
	mqttPassword        = flag.String("mqttPassword", "<none>", "MQTT password")
	heartbeatMetricDesc = prometheus.NewDesc(
		"iot_device_last_heartbeat_time",
		"Time of the last heartbeat received from the device",
		[]string{"device"}, nil,
	)
)

type heartbeatHandler struct {
	lastHeartbeats *sync.Map
}

func newHeartbeatHandler() heartbeatHandler {
	return heartbeatHandler{
		lastHeartbeats: &sync.Map{},
	}
}

func (handler heartbeatHandler) Heartbeat(topic string) {
	device := mqttTopicRegex.FindStringSubmatch(topic)[1]
	log.Printf("Received heartbeat message for device %s\n", device)
	handler.lastHeartbeats.Store(device, time.Now().Unix())
}

func (handler heartbeatHandler) Invalid(topic string, message string) {
	log.Printf("Received invalid heartbeat message on topic '%s': %s\n", topic, message)
}

type heartbeatCollector struct {
	lastHeartbeats *sync.Map
}

func (h heartbeatCollector) Describe(descs chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(h, descs)
}

func (h heartbeatCollector) Collect(metrics chan<- prometheus.Metric) {
	h.lastHeartbeats.Range(func(key, value any) bool {
		device := key.(string)
		lastHeartbeatTime := value.(int64)

		if time.Now().Unix()-lastHeartbeatTime > heartbeatTTLSeconds {
			log.Printf("Device %s has not sent a heartbeat in the last %d seconds, expiring...", device, heartbeatTTLSeconds)
			h.lastHeartbeats.Delete(device)
		} else {
			metrics <- prometheus.MustNewConstMetric(
				heartbeatMetricDesc, prometheus.CounterValue, float64(lastHeartbeatTime), device)
		}
		return true
	})
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[heartbeats] ")

	flag.Parse()

	log.Printf("Creating MQTT listener for topic '%s'\n", mqttTopic)
	mqttLogger := log.New(log.Default().Writer(), "[mqtt]", log.Default().Flags())
	listener, err := heartbeats.NewMQTTListener(heartbeats.MQTTListenerConfig{
		BrokerAddress: *mqttAddress,
		Username:      *mqttUsername,
		Password:      *mqttPassword,
		Logger:        mqttLogger,
	})
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		log.Println("Shutting down MQTT listener now...")
		listener.Close()
	}()
	handler := newHeartbeatHandler()
	if err := listener.RegisterHandler(mqttTopic, handler); err != nil {
		log.Panic(err)
	}
	log.Println("Listening for heartbeats...")

	prometheus.MustRegister(&heartbeatCollector{handler.lastHeartbeats})

	log.Println("Starting metrics server at :8080/metrics")
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":8080", nil))
}
