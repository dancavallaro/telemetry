package main

import (
	"bufio"
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
	reader := bufio.NewReader(port)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[ERROR] Error reading from serial port: %v\n", err)
			continue
		}
		log.Print(line)
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
