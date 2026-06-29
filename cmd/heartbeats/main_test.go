package main

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestVersionHandlerStoresVersion(t *testing.T) {
	h := newVersionHandler()
	h.handle("device/starforge/version", "v1.2.3")

	got, ok := h.versions.Load("starforge")
	if !ok || got.(string) != "v1.2.3" {
		t.Fatalf("expected starforge=v1.2.3, got %v (ok=%v)", got, ok)
	}
}

func TestVersionHandlerOverwrites(t *testing.T) {
	h := newVersionHandler()
	h.handle("device/starforge/version", "v1.0.0")
	h.handle("device/starforge/version", "v2.0.0")

	got, _ := h.versions.Load("starforge")
	if got.(string) != "v2.0.0" {
		t.Fatalf("expected v2.0.0 after overwrite, got %v", got)
	}
}

func TestVersionHandlerEmptyPayloadDeletes(t *testing.T) {
	h := newVersionHandler()
	h.handle("device/starforge/version", "v1.2.3")
	h.handle("device/starforge/version", "")

	if _, ok := h.versions.Load("starforge"); ok {
		t.Fatalf("expected starforge to be deleted on empty payload")
	}
}

func TestVersionHandlerIgnoresUnparseableTopic(t *testing.T) {
	h := newVersionHandler()
	h.handle("device/version", "v1.2.3") // missing the device segment

	count := 0
	h.versions.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Fatalf("expected no entries for unparseable topic, got %d", count)
	}
}

func TestVersionCollectorEmitsInfoMetric(t *testing.T) {
	h := newVersionHandler()
	h.handle("device/starforge/version", "v1.2.3")
	h.handle("device/starlord/version", "v0.9")
	c := &versionCollector{h.versions}

	expected := `
# HELP iot_device_firmware_info Firmware version reported by the device (value is always 1; see the 'version' label)
# TYPE iot_device_firmware_info gauge
iot_device_firmware_info{device="starforge",version="v1.2.3"} 1
iot_device_firmware_info{device="starlord",version="v0.9"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}

func TestVersionCollectorOmitsClearedDevice(t *testing.T) {
	h := newVersionHandler()
	h.handle("device/starforge/version", "v1.2.3")
	h.handle("device/starforge/version", "")
	c := &versionCollector{h.versions}

	if n := testutil.CollectAndCount(c, "iot_device_firmware_info"); n != 0 {
		t.Fatalf("expected 0 series after clear, got %d", n)
	}
}
