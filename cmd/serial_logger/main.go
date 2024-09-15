package main

import (
	"flag"
	"github.com/albenik/go-serial/v2"
	"log"
)

const Required = "<REQUIRED>"

func openDevice(device string, baud int) *serial.Port {
	port, err := serial.Open(
		device,
		serial.WithBaudrate(baud),
		serial.WithReadTimeout(1000),
		serial.WithWriteTimeout(1000),
	)
	if err != nil {
		panic(err)
	}
	return port
}

func readAndPrint(port *serial.Port) {
	buff := make([]byte, 100)
	for {
		n, err := port.Read(buff)
		if err != nil {
			panic(err)
		}
		line := string(buff[:n])
		if line != "" {
			log.Printf("%v", line)
		}
	}
}

func main() {
	device := flag.String("device", Required, "serial device to read from")
	baud := flag.Int("baud", 115200, "baudrate to use")
	flag.Parse()

	if *device == Required {
		panic("must specify path to device!")
	}

	port := openDevice(*device, *baud)
	readAndPrint(port)
}
