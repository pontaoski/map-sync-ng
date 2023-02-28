package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	kError = iota
	kHandshake
	kEncryptionRequest
	kEncryptionResponse
	kChunkTile
	kCatchup
	kCatchupRequest
	kRegionTimestamps
	kRegionCatchup
)

var b = binary.BigEndian

func ru8(r io.Reader) (uint8, error) {
	var buf [1]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, fmt.Errorf("failed to read uint8: %w", err)
	}
	return buf[0], nil
}

func ri32(r io.Reader) (int32, error) {
	var buf [4]byte
	_, err := io.ReadAtLeast(r, buf[:], 4)
	if err != nil {
		return 0, fmt.Errorf("failed to read int32: %w", err)
	}
	return int32(b.Uint32(buf[:])), nil
}

func ri16(r io.Reader) (int16, error) {
	var buf [2]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, fmt.Errorf("failed to read int16: %w", err)
	}
	return int16(b.Uint16(buf[:])), nil
}

func ru16(r io.Reader) (uint16, error) {
	var buf [2]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, fmt.Errorf("failed to read uint16: %w", err)
	}
	return b.Uint16(buf[:]), nil
}

func ru32(r io.Reader) (uint32, error) {
	var buf [4]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, fmt.Errorf("failed to read uint32: %w", err)
	}
	return b.Uint32(buf[:]), nil
}

func ru64(r io.Reader) (uint64, error) {
	var buf [8]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, fmt.Errorf("failed to read uint64: %w", err)
	}
	return b.Uint64(buf[:]), nil
}

func rstr(r io.Reader) (string, error) {
	length, err := ru32(r)
	if err != nil {
		return "", fmt.Errorf("failed to read string length: %w", err)
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return "", fmt.Errorf("failed to read string body: %w", err)
	}
	return string(buf), nil
}

func rbuf(r io.Reader) ([]byte, error) {
	length, err := ru32(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read buffer length: %w", err)
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read buffer body: %w", err)
	}
	return buf, nil
}

func DecodePacket(r io.Reader) (Packet, error) {
	kind, err := ru8(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read packet type: %w", err)
	}
	switch kind {
	case kChunkTile:
		pack, err := decodeChunkTilePacket(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk tile packet: %w", err)
		}
		return pack, nil
	case kHandshake:
		pack, err := decodeHandshakePacket(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read handshake packet: %w", err)
		}
		return pack, nil
	case kEncryptionResponse:
		pack, err := decodeEncryptionResponse(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read encryption packet: %w", err)
		}
		return pack, nil
	case kCatchupRequest:
		pack, err := decodeCatchupRequestPacket(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read encryption packet: %w", err)
		}
		return pack, nil
	case kRegionCatchup:
		pack, err := decodeRegionCatchupPacket(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read encryption packet: %w", err)
		}
		return pack, nil
	default:
		return nil, fmt.Errorf("unknown packet type %d", kind)
	}
}

type Packet interface {
	Encode(to io.Writer) error
}

type ChunkTilePacket struct {
	World     string
	ChunkX    int32
	ChunkZ    int32
	Timestamp uint64
	Version   uint16
	Hash      []byte
	Data      []byte
}

func (c ChunkTilePacket) Encode(to io.Writer) error {
	panic("not implemented")
}

func decodeChunkTilePacket(r io.Reader) (ChunkTilePacket, error) {
	world, err := rstr(r)
	if err != nil {
		return ChunkTilePacket{}, fmt.Errorf("failed to read world name: %w", err)
	}
	chunkX, err := ri32(r)
	if err != nil {
		return ChunkTilePacket{}, fmt.Errorf("failed to read chunk x: %w", err)
	}
	chunkZ, err := ri32(r)
	if err != nil {
		return ChunkTilePacket{}, fmt.Errorf("failed to read chunk z: %w", err)
	}
	timestamp, err := ru64(r)
	if err != nil {
		return ChunkTilePacket{}, fmt.Errorf("failed to read chunk timestamp: %w", err)
	}
	version, err := ru16(r)
	if err != nil {
		return ChunkTilePacket{}, fmt.Errorf("failed to read version: %w", err)
	}
	hash, err := rbuf(r)
	if err != nil {
		return ChunkTilePacket{}, fmt.Errorf("failed to read hash: %w", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return ChunkTilePacket{}, fmt.Errorf("failed to read data: %w", err)
	}

	return ChunkTilePacket{
		World:     world,
		ChunkX:    chunkX,
		ChunkZ:    chunkZ,
		Timestamp: timestamp,
		Version:   version,
		Hash:      hash,
		Data:      data,
	}, nil
}

type HandshakePacket struct {
	ModVersion  string
	MojangName  string
	GameAddress string
	World       string
}

func (h HandshakePacket) Encode(to io.Writer) error {
	panic("not implemented")
}

func decodeHandshakePacket(r io.Reader) (HandshakePacket, error) {
	modVersion, err := rstr(r)
	if err != nil {
		return HandshakePacket{}, fmt.Errorf("failed to read mod version: %w", err)
	}
	mojangName, err := rstr(r)
	if err != nil {
		return HandshakePacket{}, fmt.Errorf("failed to read mojang name: %w", err)
	}
	gameAddress, err := rstr(r)
	if err != nil {
		return HandshakePacket{}, fmt.Errorf("failed to read game address: %w", err)
	}
	world, err := rstr(r)
	if err != nil {
		return HandshakePacket{}, fmt.Errorf("failed to read world: %w", err)
	}
	return HandshakePacket{
		ModVersion:  modVersion,
		MojangName:  mojangName,
		GameAddress: gameAddress,
		World:       world,
	}, err
}

type EncryptionResponse struct {
	SharedSecret []byte
	VerifyToken  []byte
}

func (e EncryptionResponse) Encode(to io.Writer) error {
	panic("you wouldn't need to encode this")
}

func decodeEncryptionResponse(r io.Reader) (EncryptionResponse, error) {
	sharedSecret, err := rbuf(r)
	if err != nil {
		return EncryptionResponse{}, fmt.Errorf("failed to read shared secret: %w", err)
	}
	verifyToken, err := rbuf(r)
	if err != nil {
		return EncryptionResponse{}, fmt.Errorf("failed to read verify token: %w", err)
	}
	return EncryptionResponse{
		SharedSecret: sharedSecret,
		VerifyToken:  verifyToken,
	}, nil
}

type CatchupRequestPacket struct {
	Chunks []CatchupChunk
}

type CatchupChunk struct {
	World     string
	ChunkX    int32
	ChunkZ    int32
	Timestamp uint64
}

func (c CatchupRequestPacket) Encode(to io.Writer) error {
	panic("you wouldn't need to encode this")
}

func decodeCatchupRequestPacket(r io.Reader) (CatchupRequestPacket, error) {
	world, err := rstr(r)
	if err != nil {
		return CatchupRequestPacket{}, fmt.Errorf("failed to read world name: %w", err)
	}
	numChunks, err := ru32(r)
	if err != nil {
		return CatchupRequestPacket{}, fmt.Errorf("failed to read the number of chunks: %w", err)
	}
	chunks := make([]CatchupChunk, 0, numChunks)
	for i := uint32(0); i < numChunks; i++ {
		chunkX, err := ri32(r)
		if err != nil {
			return CatchupRequestPacket{}, fmt.Errorf("failed to read chunk x: %w", err)
		}
		chunkZ, err := ri32(r)
		if err != nil {
			return CatchupRequestPacket{}, fmt.Errorf("failed to read chunk z: %w", err)
		}
		timestamp, err := ru64(r)
		if err != nil {
			return CatchupRequestPacket{}, fmt.Errorf("failed to read chunk timestamp: %w", err)
		}
		chunks = append(chunks, CatchupChunk{
			World:     world,
			ChunkX:    chunkX,
			ChunkZ:    chunkZ,
			Timestamp: timestamp,
		})
	}
	return CatchupRequestPacket{chunks}, nil
}

type RegionCatchupPacket struct {
	World   string
	Regions []RegionCoordinates
}

func (c RegionCatchupPacket) Encode(to io.Writer) error {
	panic("you wouldn't need to encode this")
}

func decodeRegionCatchupPacket(r io.Reader) (RegionCatchupPacket, error) {
	world, err := rstr(r)
	if err != nil {
		return RegionCatchupPacket{}, fmt.Errorf("failed to read world name: %w", err)
	}
	count, err := ri16(r)
	if err != nil {
		return RegionCatchupPacket{}, fmt.Errorf("failed to read region count: %w", err)
	}
	regions := make([]RegionCoordinates, 0, count)
	for i := int16(0); i < count; i++ {
		x, err := ri16(r)
		if err != nil {
			return RegionCatchupPacket{}, fmt.Errorf("failed to read region x: %w", err)
		}
		z, err := ri16(r)
		if err != nil {
			return RegionCatchupPacket{}, fmt.Errorf("failed to read region z: %w", err)
		}
		regions = append(regions, RegionCoordinates{
			ChunkX: x,
			ChunkZ: z,
		})
	}
	return RegionCatchupPacket{
		World:   world,
		Regions: regions,
	}, nil
}