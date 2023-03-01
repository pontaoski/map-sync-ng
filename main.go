package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	l, err := net.Listen("tcp", "0.0.0.0:12312")
	if err != nil {
		log.Fatalf("failed to listen: %s\n", err)
	}

	s, err := NewServer()
	if err != nil {
		log.Fatalf("Failed to initialise server: %s", err)
	}

	defer s.DB.Close()
	defer l.Close()
	log.Printf("Listening on 0.0.0.0:12312")
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Error accepting a connection: %s\n", err)
			conn.Close()
			continue
		}

		go s.HandleConnection(conn)
	}
}

type Server struct {
	Clients      map[int]Client
	ClientsNum   int
	ClientsMutex sync.RWMutex

	Config *Config

	DB DBWithMutex

	Key            *rsa.PrivateKey
	PublicKeyBytes []byte
}

func NewServer() (*Server, error) {
	s := &Server{
		Clients:      map[int]Client{},
		ClientsNum:   0,
		ClientsMutex: sync.RWMutex{},
	}

	conf, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	s.Config = conf

	privkey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	s.Key = privkey

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privkey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key bytes: %w", err)
	}

	// publicKeyBlock := &pem.Block{
	// 	Type:  "PUBLIC KEY",
	// 	Bytes: publicKeyBytes,
	// }

	db, err := sql.Open("sqlite3", "./db.sqlite")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	_, err = db.Exec(
		`
		CREATE TABLE IF NOT EXISTS "chunk_data" (
			"hash" blob PRIMARY KEY NOT NULL,
			"version" integer NOT NULL,
			"data" blob NOT NULL
		)
		`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create chunk_data table: %w", err)
	}
	_, err = db.Exec(
		`
		CREATE TABLE IF NOT EXISTS "player_chunk" (
			"world" text NOT NULL,
			"chunk_x" integer NOT NULL,
			"chunk_z" integer NOT NULL,
			"uuid" text NOT NULL,
			"ts" bigint NOT NULL,
			"hash" blob,
			CONSTRAINT "FK_e80a5d4eebceb40ccfb829850be" FOREIGN KEY ("hash") REFERENCES "chunk_data" ("hash") ON DELETE NO ACTION ON UPDATE NO ACTION,
			PRIMARY KEY ("world", "chunk_x", "chunk_z", "uuid")
		)
		`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create player_chunk table: %w", err)
	}

	s.DB = DBWithMutex{db, sync.RWMutex{}}

	// publicKeyPEM := pem.EncodeToMemory(publicKeyBlock)
	s.PublicKeyBytes = publicKeyBytes

	return s, nil
}

func (s *Server) HandleConnection(conn net.Conn) {
	s.ClientsMutex.Lock()

	s.ClientsNum++
	myNum := s.ClientsNum
	s.Clients[myNum] = Client{
		Conn:  conn,
		State: &UnauthenticatedClientState{},
	}

	s.ClientsMutex.Unlock()

	defer conn.Close()

	defer func() {
		s.ClientsMutex.Lock()
		delete(s.Clients, myNum)
		s.ClientsMutex.Unlock()
	}()

	for {
		s.ClientsMutex.RLock()
		client := s.Clients[myNum]
		s.ClientsMutex.RUnlock()

		reader := io.Reader(conn)
		if v, ok := client.State.(*AuthenticatedClientState); ok {
			reader = cipher.StreamReader{S: v.Decipher, R: reader}
		}

		packetSize, err := ru32(reader)
		if err != nil {
			log.Printf("Error reading packet size from %s: %s\n", client, err)
			return
		}

		packetBuf := make([]byte, packetSize)
		_, err = io.ReadFull(reader, packetBuf)
		if err != nil {
			log.Printf("Error reading packet from %s: %s\n", client, err)
			return
		}

		packetReader := bytes.NewReader(packetBuf)
		packet, err := DecodePacket(packetReader)
		if err != nil {
			log.Printf("Error decoding packet from %s: %s\n", client, err)
			return
		}

		nieu, err := client.State.Handle(s, client, packet)
		if err != nil {
			log.Printf("Error handling packet from %s: %s\n", client, err)
			return
		}

		if nieu != client.State {
			s.ClientsMutex.Lock()
			s.Clients[myNum] = Client{
				Conn:  conn,
				State: nieu,
			}
			s.ClientsMutex.Unlock()
		}
	}
}

type Client struct {
	Conn  net.Conn
	State ClientState
}

func (c Client) String() string {
	switch c.State.(type) {
	case *UnauthenticatedClientState:
		return "Unauthenticated Client"
	case *HandshakenClientState:
		return "Authenticating Client"
	case *AuthenticatedClientState:
		return "Authenticated Client"
	default:
		return "Unknown Client"
	}
}

func (c *Client) SendPacket(p Packet, doCrypto bool, state ClientState) error {
	pbuf := bytes.Buffer{}
	err := p.Encode(&pbuf)
	if err != nil {
		return fmt.Errorf("error encoding packet: %w", err)
	}

	tbuf := bytes.Buffer{}

	var buf [4]byte
	b.PutUint32(buf[:], uint32(pbuf.Len()))

	_, err = tbuf.Write(buf[:])
	if err != nil {
		return fmt.Errorf("error writing packet size: %w", err)
	}

	_, err = tbuf.Write(pbuf.Bytes())
	if err != nil {
		return fmt.Errorf("error writing packet body: %w", err)
	}

	if doCrypto {
		v, ok := state.(*AuthenticatedClientState)
		if !ok {
			return fmt.Errorf("cannot do crypto unless client is authenticated")
		}

		pbuf.Reset()

		writer := &cipher.StreamWriter{S: v.Cipher, W: &pbuf}

		if _, err = io.Copy(writer, &tbuf); err != nil {
			return fmt.Errorf("failed to copy packet to encrypted buffer: %w", err)
		}

		if _, err = c.Conn.Write(pbuf.Bytes()); err != nil {
			return fmt.Errorf("failed to write encrypted buffer to connection: %w", err)
		}
	} else {
		if _, err = c.Conn.Write(tbuf.Bytes()); err != nil {
			return fmt.Errorf("failed to write unencrypted buffer to connection: %w", err)
		}
	}

	return nil
}

type ClientState interface {
	Handle(s *Server, c Client, p Packet) (ClientState, error)
}

type UnauthenticatedClientState struct {
}

func (u *UnauthenticatedClientState) Handle(s *Server, c Client, packet Packet) (ClientState, error) {
	switch p := packet.(type) {
	case HandshakePacket:
		if s.Config.MainConfig.ServerAddressMustInclude != "" {
			if !strings.Contains(p.GameAddress, s.Config.MainConfig.ServerAddressMustInclude) {
				return nil, fmt.Errorf("client is not connecting for right server")
			}
		}
		var buf [4]byte
		_, err := rand.Read(buf[:])
		if err != nil {
			return nil, fmt.Errorf("failed to generate random token: %w", err)
		}
		newState := HandshakenClientState{
			ModVersion:  p.ModVersion,
			GameAddress: p.GameAddress,
			MojangName:  p.MojangName,
			World:       p.World,
			VerifyToken: buf[:],
		}
		err = c.SendPacket(EncryptionRequest{
			PublicKey:         s.PublicKeyBytes,
			VerificationToken: buf[:],
		}, false, u)
		if err != nil {
			return nil, fmt.Errorf("failed to send encryption request: %w", err)
		}
		return &newState, nil
	default:
		return nil, fmt.Errorf("unexpected packet type from %s: %s", c, p)
	}
}

type HandshakenClientState struct {
	ModVersion  string
	GameAddress string
	MojangName  string
	World       string

	VerifyToken []byte
}

var uuidRegex = regexp.MustCompile(`^(........)-?(....)-?(....)-?(....)-?(............)$`)

func fetchHasJoined(username string, hexSum string) (string, string, error) {
	url := fmt.Sprintf(`https://sessionserver.mojang.com/session/minecraft/hasJoined?username=%s&serverId=%s`, username, hexSum)
	res, err := http.Get(url)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch from session server: %w", err)
	}
	if res.StatusCode == 204 {
		println(204)
		return "", "", nil
	}

	var s struct {
		UUID string `json:"id"`
		Name string `json:"name"`
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read session server body: %w", err)
	}
	err = json.Unmarshal(data, &s)
	if err != nil {
		return "", "", fmt.Errorf("failed to unmarshal session server body: %w", err)
	}

	uuid := uuidRegex.ReplaceAllString(s.UUID, "$1-$2-$3-$4-$5")

	return s.Name, uuid, nil
}

func (h *HandshakenClientState) Handle(s *Server, c Client, packet Packet) (ClientState, error) {
	createCipher := func(secret []byte) (cipher.Stream, error) {
		block, err := aes.NewCipher(secret)
		if err != nil {
			return nil, err
		}
		return NewEncrypter(block, secret), nil
	}

	createDecipher := func(secret []byte) (cipher.Stream, error) {
		block, err := aes.NewCipher(secret)
		if err != nil {
			return nil, err
		}
		return NewDecrypter(block, secret), nil
	}

	switch p := packet.(type) {
	case EncryptionResponse:
		dec, err := rsa.DecryptPKCS1v15(rand.Reader, s.Key, p.VerifyToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt verification token: %w", err)
		}

		if !bytes.Equal(dec, h.VerifyToken) {
			return nil, fmt.Errorf("client sent invalid verification token")
		}

		sharedSecret, err := s.Key.Decrypt(rand.Reader, p.SharedSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt shared secret: %w", err)
		}

		sh := sha1.New()
		_, err = sh.Write(sharedSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to hash shared secret: %w", err)
		}

		_, err = sh.Write(s.PublicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to hash public key bytes: %w", err)
		}

		shaSum := sh.Sum(nil)
		hexSum := hex.EncodeToString(shaSum)

		username, uuid, err := fetchHasJoined(h.MojangName, hexSum)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch user from session server: %w", err)
		}
		if uuid == "" {
			return nil, fmt.Errorf("session server said client is not actually online")
		}

		cipher, err := createCipher(sharedSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}

		decipher, err := createDecipher(sharedSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to create decipher: %w", err)
		}

		nieu := &AuthenticatedClientState{
			Cipher:      cipher,
			Decipher:    decipher,
			Username:    username,
			UUID:        uuid,
			World:       h.World,
			GameAddress: h.GameAddress,
		}

		err = nieu.HandleAuthenticated(s, c)
		if err != nil {
			return nil, fmt.Errorf("failed to handle authenticated: %w", err)
		}

		return nieu, nil
	default:
		return nil, fmt.Errorf("unexpected packet type from %s: %s", c, p)
	}
}

type AuthenticatedClientState struct {
	Cipher      cipher.Stream
	Decipher    cipher.Stream
	Username    string
	UUID        string
	World       string
	GameAddress string
}

func (a *AuthenticatedClientState) HandleAuthenticated(s *Server, c Client) error {
	log.Printf("Client %s was authenticated\n", c)

	if s.Config.MainConfig.WhitelistEnabled {
		ok := false
		for _, plr := range s.Config.WhitelistConfig {
			if plr == a.UUID {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("client was not whitelisted")
		}
	}

	timestamps, err := GetRegionTimestamps(context.Background(), &s.DB)
	if err != nil {
		return fmt.Errorf("failed to get region timestamps: %w", err)
	}

	err = c.SendPacket(RegionTimestamps{
		World:      a.World,
		Timestamps: timestamps,
	}, true, a)
	if err != nil {
		return fmt.Errorf("failed to send timestamps to client: %w", err)
	}

	return nil
}

func (a *AuthenticatedClientState) Handle(s *Server, c Client, packet Packet) (ClientState, error) {
	switch p := packet.(type) {
	case ChunkTilePacket:
		err := a.HandleChunkTile(s, c, p)
		if err != nil {
			return nil, err
		}
		return a, nil
	case CatchupRequestPacket:
		err := a.HandleCatchup(s, c, p)
		if err != nil {
			return nil, err
		}
		return a, nil
	case RegionCatchupPacket:
		err := a.HandleRegionCatchup(s, c, p)
		if err != nil {
			return nil, err
		}
		return a, nil
	default:
		return nil, fmt.Errorf("unexpected packet type from %s: %s", c, packet)
	}
}

func (a *AuthenticatedClientState) HandleChunkTile(s *Server, c Client, p ChunkTilePacket) error {
	err := Store(
		context.TODO(),
		&s.DB,
		p.World,
		p.ChunkX,
		p.ChunkZ,
		a.UUID,
		p.Timestamp,
		p.Hash,
		p.Version,
		p.Data,
	)
	if err != nil {
		return fmt.Errorf("failed to write packet to database: %w", err)
	}

	s.ClientsMutex.RLock()
	for _, otherC := range s.Clients {
		if otherC.State == a {
			continue
		}
		err = otherC.SendPacket(p, true, otherC.State)
		if err != nil {
			log.Printf("failed to send packet to %s: %s\n", otherC, err)
		}
	}
	s.ClientsMutex.RUnlock()
	return nil
}

func (a *AuthenticatedClientState) HandleCatchup(s *Server, c Client, p CatchupRequestPacket) error {
	for _, chunk := range p.Chunks {
		data, err := GetChunkWithData(
			context.Background(),
			&s.DB,
			chunk.World,
			chunk.ChunkX,
			chunk.ChunkZ,
		)
		if err != nil {
			log.Printf("client %s requested unavailable chunk: %s", c, err)
			continue
		}
		if data.Timestamp > chunk.Timestamp {
			continue
		}
		if data.Timestamp < chunk.Timestamp {
			continue
		}
		err = c.SendPacket(ChunkTilePacket{
			World:     data.World,
			ChunkX:    data.ChunkX,
			ChunkZ:    data.ChunkZ,
			Timestamp: data.Timestamp,
			Version:   data.Version,
			Hash:      data.ChunkData.Hash,
			Data:      data.Data,
		}, true, a)
		if err != nil {
			return fmt.Errorf("failed to send chunk tile to client: %w", err)
		}
	}
	return nil
}

func (a *AuthenticatedClientState) HandleRegionCatchup(s *Server, c Client, p RegionCatchupPacket) error {
	data, err := GetCatchupData(
		context.Background(),
		&s.DB,
		p.World,
		p.Regions,
	)
	if err != nil {
		return fmt.Errorf("failed to get catchup data: %w", err)
	}
	ccs := make([]CatchupChunk, 0, len(data))
	for _, i := range data {
		ccs = append(ccs, CatchupChunk{
			World:     i.World,
			ChunkX:    i.ChunkX,
			ChunkZ:    i.ChunkZ,
			Timestamp: i.Timestamp,
		})
	}
	if len(ccs) == 0 {
		return nil
	}
	err = c.SendPacket(CatchupPacket{
		Chunks: ccs,
	}, true, a)
	if err != nil {
		return fmt.Errorf("failed to send catchup packet: %w", err)
	}
	return nil
}
