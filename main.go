package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type pcapWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
	Close() error
}

type defaultPcapWriter struct {
	io.WriteCloser
	*Writer
}

type Packet struct {
	Ci   gopacket.CaptureInfo
	Data []byte
}

type Config struct {
	pcapReadFile  string
	pcapWriteFile string
	ssrcReplace   string
	packetStart   int
	packetStop    int
	buf           bytes.Buffer
	snapLen       int
}

var dumpChan = make(chan *Packet, 1000)
var logger *log.Logger
var buf bytes.Buffer
var config Config

func main() {
	var (
		pcapReadFile  = flag.String("input-pcap-file", "", "Pcap file to read from")
		pcapWriteFile = flag.String("output-pcap-file", "", "Pcap file to write to")
		ssrcReplace   = flag.String("ssrc", "", "SSRC to replace")
		packetStart   = flag.Int("start-packet", 0, "Packet to start")
		packetStop    = flag.Int("stop-packet", 0, "Packet to stop")
	)
	flag.Parse()

	logger = log.New(&buf, "logger: ", log.Lshortfile)

	if len(*pcapReadFile) < 1 {
		fmt.Println("Please provide the input-pcap-file param")
		os.Exit(1)
	}

	if len(*pcapWriteFile) < 1 {
		fmt.Println("Please provide the output-pcap-file param")
		os.Exit(1)
	}

	if len(*ssrcReplace) < 1 {
		fmt.Println("Please provide the ssrc param")
		os.Exit(1)
	}

	if *packetStart == 0 {
		fmt.Println("Please provide the start-packet param")
		os.Exit(1)
	}

	if *packetStop == 0 {
		fmt.Println("Please provide the stop-packet param")
		os.Exit(1)
	}

	config = Config{
		pcapReadFile:  *pcapReadFile,
		pcapWriteFile: *pcapWriteFile,
		ssrcReplace:   *ssrcReplace,
		packetStart:   *packetStart,
		packetStop:    *packetStop,
		snapLen:       65535,
	}

	pcapHandle, err := pcap.OpenOffline(config.pcapReadFile)
	if err != nil {
		fmt.Errorf("couldn't open file %v! %v", config.pcapReadFile, err)
	}

	dataSource := gopacket.PacketDataSource(pcapHandle)
	isAlive := true

	for isAlive {
		data, ci, err := dataSource.ReadPacketData()

		if err == pcap.NextErrorTimeoutExpired || err == syscall.EINTR {
			fmt.Errorf("pcap error %v", err)
			os.Exit(1)
		}

		if err == io.EOF {

			logger.Print("sniffer", "End of file")
			logger.Print("EOFExit enabled.Prepare exit...")
			logger.Print("Sent all packets, exiting...")
			isAlive = false
			os.Exit(0)
			continue
		}

		if err != nil {
			fmt.Println("sniffing error: %s", err)
			isAlive = false
			continue
		}

		if len(data) == 0 {
			continue
		}

		//worker.OnPacket(data, &ci)

		if config.pcapWriteFile != "" {
			dumpChan <- &Packet{Ci: ci, Data: data}
		}
	}
}

func Save(dc chan *Packet, lt layers.LinkType) {

	tmpName := config.pcapWriteFile + ".tmp"

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	w, err := createPcap(tmpName, lt)
	if err != nil {
		logger.Print("Error opening pcap: %v", err)
	}

	for {
		select {
		case packet := <-dc:
			err := w.WritePacket(packet.Ci, packet.Data)
			if err != nil {
				w.Close()
				logger.Print("Error writing output pcap: %v", err)
			}

		case <-signals:
			logger.Print("Received stop signal")
			err = w.Close()
			if err != nil {
				logger.Print("Error Closing: %v", err)
			}
			os.Exit(0)
		}
	}
}

func createPcap(baseFilename string, lt layers.LinkType) (pcapWriter, error) {

	logger.Print("opening new pcap file %s", baseFilename)
	f, err := os.Create(baseFilename)
	if err != nil {
		return nil, err
	}

	w := NewWriter(f)
	// It's a new file, so we need to create a new writer
	w.WriteFileHeader(uint32(config.snapLen), lt)
	return &defaultPcapWriter{f, w}, nil

}
