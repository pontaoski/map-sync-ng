package main

import (
	"bytes"
	"io"
	"log"
	"net"
)

func main() {
	l, err := net.Listen("tcp", "0.0.0.0:12312")
	if err != nil {
		log.Fatalf("failed to listen: %s\n", err)
	}

	defer l.Close()
	log.Printf("Listening on 0.0.0.0:12312")
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Error accepting a connection: %s\n", err)
		}

		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	log.Printf("Accepted new connection from %s\n", conn)
	defer conn.Close()

	var uuid *string

	for {
		packetSize, err := ru32(conn)
		if err != nil {
			log.Printf("Error reading packet type from %s: %s\n", conn, err)
			return
		}

		packetBuf := make([]byte, 0, packetSize)
		_, err = io.ReadFull(conn, packetBuf)
		if err != nil {
			log.Printf("Error reading packet from %s: %s\n", conn, err)
			return
		}

		packetReader := bytes.NewReader(packetBuf)
		packet, err := DecodePacket(packetReader)
		if err != nil {
			log.Printf("Error decoding packet from %s: %s\n", conn, err)
			return
		}

		if uuid == nil {
			switch p := packet.(type) {
			case HandshakePacket:
			case EncryptionResponse:
			default:
				log.Printf("Unexpected packet type from %s: %s\n", conn, p)
				return
			}
		} else {
			switch p := packet.(type) {
			case ChunkTilePacket:
			case CatchupRequestPacket:
			case RegionCatchupPacket:
			default:
				log.Printf("Unexpected packet type from %s: %s\n", conn, p)
				return
			}
		}
	}
}
