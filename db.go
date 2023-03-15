// SPDX-FileCopyrightText: 2023 Janet Blackquill <uhhadd@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
)

type ChunkData struct {
	Hash    []byte
	Version uint16
	Data    []byte
}

type PlayerChunk struct {
	World      string
	ChunkX     int32
	ChunkZ     int32
	PlayerUUID string

	Timestamp uint64

	Hash []byte
}

type RegionTimestamp struct {
	ChunkX    int16
	ChunkZ    int16
	Timestamp uint64
}

type RegionCoordinates struct {
	ChunkX int16
	ChunkZ int16
}

func (r RegionCoordinates) String() string {
	return fmt.Sprintf("%d_%d", r.ChunkX, r.ChunkZ)
}

func ToQueryList(r []RegionCoordinates) string {
	var s strings.Builder

	for idx := range r {
		if idx > 0 {
			s.WriteByte(',')
		}
		s.WriteByte('?')
	}

	return s.String()
}

type PlayerChunkAndData struct {
	ChunkData
	PlayerChunk
}

type DBWithMutex struct {
	*sql.DB
	sync.RWMutex
}

func Store(ctx context.Context, db *DBWithMutex,
	world string,
	chunkX int32,
	chunkZ int32,
	uuid string,
	ts uint64,
	hash []byte,
	version uint16,
	data []byte,
) error {
	const chunkDataQuery = `
		INSERT OR REPLACE INTO
			chunk_data (hash, version, data)
		VALUES
			($1, $2, $3)
	`
	const playerChunkQuery = `
		INSERT OR REPLACE INTO
			player_chunk (world, chunk_x, chunk_z, uuid, ts, hash)
		VALUES
			($1, $2, $3, $4, $5, $6)
	`

	db.Lock()
	defer db.Unlock()

	_, err := db.ExecContext(ctx, chunkDataQuery, hash, version, data)
	if err != nil {
		return fmt.Errorf("failed to insert into chunk data: %w", err)
	}

	_, err = db.ExecContext(ctx, playerChunkQuery, world, chunkX, chunkZ, uuid, ts, hash)
	if err != nil {
		return fmt.Errorf("failed to insert into player chunk data: %w", err)
	}

	return nil
}

func GetChunkWithData(ctx context.Context, db *DBWithMutex, world string, chunkX, chunkZ int32) (*PlayerChunkAndData, error) {
	const query = `
		SELECT player_chunk.world, player_chunk.chunk_x, player_chunk.chunk_x, player_chunk.uuid, player_chunk.ts, chunk_data.hash, chunk_data.version, chunk_data.data
		FROM player_chunk
		INNER JOIN chunk_data ON player_chunk.hash = chunk_data.hash
			WHERE world = ?
			AND   chunk_x = ?
			AND   chunk_z = ?
		ORDER BY ts DESC
	`

	db.RLock()
	defer db.RUnlock()

	rows, err := db.QueryContext(ctx, query, world, chunkX, chunkZ)
	if err != nil {
		return nil, fmt.Errorf("failed to query chunk with data: %w", err)
	}

	defer rows.Close()
	if rows.Next() {
		var (
			world          string
			chunkX, chunkZ int32
			uuid           string
			ts             uint64
			hash           []byte
			version        uint16
			data           []byte
		)
		if err := rows.Scan(&world, &chunkX, &chunkZ, &uuid, &ts, &hash, &version, &data); err != nil {
			return nil, fmt.Errorf("failed while scanning chunk data: %w", err)
		}

		return &PlayerChunkAndData{
			ChunkData: ChunkData{
				Hash:    hash,
				Version: version,
				Data:    data,
			},
			PlayerChunk: PlayerChunk{
				World:      world,
				ChunkX:     chunkX,
				ChunkZ:     chunkZ,
				PlayerUUID: uuid,
				Timestamp:  ts,
				Hash:       hash,
			},
		}, nil
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after scanning chunk data: %w", err)
	}

	return nil, fmt.Errorf("could not find %d/%d in %s", chunkX, chunkZ, world)
}

func GetCatchupData(ctx context.Context, db *DBWithMutex, world string, regions []RegionCoordinates) ([]PlayerChunk, error) {
	var query = `
		WITH region_real AS (SELECT
			chunk_x, chunk_z, world, uuid, ts, hash,
			chunk_x / 32.0 AS region_x_real,
			chunk_z / 32.0 AS region_z_real
			FROM player_chunk
		) SELECT
			(
				cast (region_x_real as int) - (region_x_real < cast (region_x_real as int))
			) || "_" || (
				cast (region_z_real as int) - (region_z_real < cast (region_z_real as int))
			) AS region,
			chunk_x, chunk_z, uuid, ts,
			hash AS data
		FROM region_real
		WHERE world = ? AND region IN (` + ToQueryList(regions) + `)
		ORDER BY ts DESC
	`

	db.RLock()
	defer db.RUnlock()

	args := []any{world}
	for _, r := range regions {
		args = append(args, r.String())
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query catchup data: %w", err)
	}

	ret := []PlayerChunk{}

	defer rows.Close()
	for rows.Next() {
		var region string
		var chunkX, chunkZ int32
		var uuid string
		var ts uint64
		var hash []byte
		if err := rows.Scan(&region, &chunkX, &chunkZ, &uuid, &ts, &hash); err != nil {
			return nil, fmt.Errorf("failed while scanning catchup data: %w", err)
		}

		ret = append(ret, PlayerChunk{
			World:      world,
			ChunkX:     chunkX,
			ChunkZ:     chunkZ,
			PlayerUUID: uuid,
			Timestamp:  ts,
			Hash:       hash,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after scanning catchup data: %w", err)
	}

	seen := map[struct {
		x int32
		z int32
	}]struct{}{}
	n := 0
	for _, val := range ret {
		if _, ok := seen[struct {
			x int32
			z int32
		}{val.ChunkX, val.ChunkZ}]; ok {
			continue
		}
		seen[struct {
			x int32
			z int32
		}{val.ChunkX, val.ChunkZ}] = struct{}{}
		ret[n] = val
		n++
	}

	return ret[:n], nil
}

func GetRegionTimestamps(ctx context.Context, db *DBWithMutex) ([]RegionTimestamp, error) {
	const query = `
		WITH region_real AS (SELECT
			chunk_x / 32.0 AS region_x_real,
			chunk_z / 32.0 AS region_z_real,
			ts
			FROM player_chunk
		) SELECT
			cast (region_x_real as int) - (region_x_real < cast (region_x_real as int)) AS region_x,
			cast (region_z_real as int) - (region_z_real < cast (region_z_real as int)) AS region_z,
			MAX(ts) AS ts
		FROM region_real
		GROUP BY region_x, region_z
		ORDER BY region_x DESC
	`

	db.RLock()
	defer db.RUnlock()

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query region timestamps: %w", err)
	}

	ret := []RegionTimestamp{}

	defer rows.Close()
	for rows.Next() {
		var regionX, regionZ int16
		var timestamp uint64
		if err := rows.Scan(&regionX, &regionZ, &timestamp); err != nil {
			return nil, fmt.Errorf("failed while scanning region timestamps: %w", err)
		}

		ret = append(ret, RegionTimestamp{regionX, regionZ, timestamp})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after scanning region timestamps: %w", err)
	}

	return ret, nil
}
