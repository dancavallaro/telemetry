package main

import (
	"flag"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/dancavallaro/telemetry/pkg/heartbeats"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	heartbeatTTLSeconds = 24 * 60 * 60
	// Telemetry samples expire after this long without an update, so a device that
	// stops reporting goes stale instead of flatlining at its last published value.
	telemetryTTLSeconds = 15 * 60

	heartbeatTopic = "device/+/heartbeat"
	telemetryTopic = "device/+/telemetry/+"
	versionTopic   = "device/+/version"
)

var (
	heartbeatTopicRegex = regexp.MustCompile(`device/(.+)/heartbeat`)
	telemetryTopicRegex = regexp.MustCompile(`device/(.+)/telemetry/(.+)`)
	versionTopicRegex   = regexp.MustCompile(`device/(.+)/version`)
	// Prometheus metric names may only contain [a-zA-Z0-9_:].
	invalidMetricNameChars = regexp.MustCompile(`[^a-zA-Z0-9_]`)

	mqttAddress  = flag.String("mqttAddress", "localhost:1883", "Address:port of MQTT broker")
	mqttUsername = flag.String("mqttUsername", "<none>", "MQTT username")
	mqttPassword = flag.String("mqttPassword", "<none>", "MQTT password")

	heartbeatMetricDesc = prometheus.NewDesc(
		"iot_device_last_heartbeat_time",
		"Time of the last heartbeat received from the device",
		[]string{"device"}, nil,
	)
	firmwareInfoDesc = prometheus.NewDesc(
		"iot_device_firmware_info",
		"Firmware version reported by the device (value is always 1; see the 'version' label)",
		[]string{"device", "version"}, nil,
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

func (handler heartbeatHandler) handle(topic string, message string) {
	if message != "OK" {
		log.Printf("Received invalid heartbeat message on topic '%s': %s\n", topic, message)
		return
	}
	device := heartbeatTopicRegex.FindStringSubmatch(topic)[1]
	log.Printf("Received heartbeat message for device %s\n", device)
	handler.lastHeartbeats.Store(device, time.Now().Unix())
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

type telemetryHandler struct {
	samples *sync.Map // seriesKey -> telemetrySample
}

func newTelemetryHandler() telemetryHandler {
	return telemetryHandler{
		samples: &sync.Map{},
	}
}

func (handler telemetryHandler) handle(topic string, message string) {
	match := telemetryTopicRegex.FindStringSubmatch(topic)
	if match == nil {
		log.Printf("Received telemetry message on unparseable topic '%s'\n", topic)
		return
	}
	device, metric := match[1], match[2]

	value, err := strconv.ParseFloat(message, 64)
	if err != nil {
		log.Printf("Received non-numeric telemetry message for %s/%s on topic '%s': %s\n", device, metric, topic, message)
		return
	}

	log.Printf("Received telemetry metric %s=%g for device %s\n", metric, value, device)
	handler.samples.Store(seriesKey{device, metric}, telemetrySample{value, time.Now().Unix()})
}

// seriesKey identifies a single (device, metric) telemetry time series.
type seriesKey struct {
	device string
	metric string
}

type telemetrySample struct {
	value     float64
	updatedAt int64
}

type telemetryCollector struct {
	samples *sync.Map
}

func (c telemetryCollector) Describe(descs chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, descs)
}

func (c telemetryCollector) Collect(metrics chan<- prometheus.Metric) {
	c.samples.Range(func(key, value any) bool {
		series := key.(seriesKey)
		sample := value.(telemetrySample)

		if time.Now().Unix()-sample.updatedAt > telemetryTTLSeconds {
			log.Printf("Metric %s for device %s is stale (no update in %d seconds), expiring...", series.metric, series.device, telemetryTTLSeconds)
			c.samples.Delete(key)
			return true
		}

		desc := prometheus.NewDesc(
			telemetryMetricName(series.metric),
			"Telemetry value published by the device over MQTT",
			[]string{"device"}, nil,
		)
		metrics <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, sample.value, series.device)
		return true
	})
}

// telemetryMetricName maps an MQTT telemetry metric to a Prometheus metric name,
// e.g. "battery_voltage" -> "iot_device_battery_voltage". The iot_ prefix matters:
// Alloy's heartbeat_metrics relabel keeps only iot_.* series.
func telemetryMetricName(metric string) string {
	return "iot_device_" + invalidMetricNameChars.ReplaceAllString(metric, "_")
}

type versionHandler struct {
	versions *sync.Map // device(string) -> version(string)
}

func newVersionHandler() versionHandler {
	return versionHandler{
		versions: &sync.Map{},
	}
}

func (handler versionHandler) handle(topic string, message string) {
	match := versionTopicRegex.FindStringSubmatch(topic)
	if match == nil {
		log.Printf("Received version message on unparseable topic '%s'\n", topic)
		return
	}
	device := match[1]

	if message == "" {
		// A cleared (empty) retained payload means the device was decommissioned; forget it.
		log.Printf("Cleared firmware version for device %s\n", device)
		handler.versions.Delete(device)
		return
	}

	log.Printf("Received firmware version %s for device %s\n", message, device)
	handler.versions.Store(device, message)
}

// versionCollector exports the firmware version each device reported, as an info-style
// gauge (value always 1; the version is carried as a label). Unlike the heartbeat and
// telemetry collectors it has no TTL: the version is published once per MQTT connection
// (retained), not on a periodic cadence, so entries persist until the daemon restarts
// (re-reading the broker's retained state) or an empty retained payload clears them.
type versionCollector struct {
	versions *sync.Map
}

func (c versionCollector) Describe(descs chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, descs)
}

func (c versionCollector) Collect(metrics chan<- prometheus.Metric) {
	c.versions.Range(func(key, value any) bool {
		device := key.(string)
		version := value.(string)
		metrics <- prometheus.MustNewConstMetric(
			firmwareInfoDesc, prometheus.GaugeValue, 1, device, version)
		return true
	})
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[heartbeats] ")

	flag.Parse()

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

	hbHandler := newHeartbeatHandler()
	log.Printf("Subscribing to heartbeat topic '%s'\n", heartbeatTopic)
	if err := listener.RegisterHandler(heartbeatTopic, hbHandler.handle); err != nil {
		log.Panic(err)
	}

	telHandler := newTelemetryHandler()
	log.Printf("Subscribing to telemetry topic '%s'\n", telemetryTopic)
	if err := listener.RegisterHandler(telemetryTopic, telHandler.handle); err != nil {
		log.Panic(err)
	}

	verHandler := newVersionHandler()
	log.Printf("Subscribing to version topic '%s'\n", versionTopic)
	if err := listener.RegisterHandler(versionTopic, verHandler.handle); err != nil {
		log.Panic(err)
	}

	prometheus.MustRegister(&heartbeatCollector{hbHandler.lastHeartbeats})
	prometheus.MustRegister(&telemetryCollector{telHandler.samples})
	prometheus.MustRegister(&versionCollector{verHandler.versions})

	log.Println("Starting metrics server at :8080/metrics")
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":8080", nil))
}
