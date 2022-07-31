/*
Copyright (C) 2022 Jake Sanders

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package server

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	_ "modernc.org/sqlite"

	"github.com/jakexks/northfoot/api/mgmt/v1/mgmtv1connect"
	"github.com/jakexks/northfoot/api/sign/v1/signv1connect"
)

type Server struct {
	// options
	datastore string
	log       *zap.Logger

	// internal
	db          *sql.DB
	signerCache atomic.Value
	lock        sync.Mutex

	// interfaces
	signv1connect.UnimplementedSignServiceHandler
	mgmtv1connect.UnimplementedManagementServiceHandler
}

func (s *Server) Init() error {
	s.log.Info("initializing server", zap.String("datastore", s.datastore))
	db, err := sql.Open("sqlite", s.datastore)
	if err != nil {
		return err
	}
	s.db = db
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		s.log.Error("failed to ping database", zap.String("datastore", s.datastore))
		db.Close()
		return err
	}
	if err := s.initDB(); err != nil {
		s.log.Error("failed to init database", zap.String("datastore", s.datastore))
		return err
	}
	if err := s.initSigners(); err != nil {
		s.log.Error("failed to init signers", zap.String("datastore", s.datastore))
		return err
	}
	s.signerCache.Store(make(signerCache))
	return nil
}

func (s *Server) initDB() error {
	// ensure tables exist
	s.log.Info("ensuring signer table exists in DB")
	signerTable := `CREATE TABLE IF NOT EXISTS "signers" (
		"signer"	TEXT NOT NULL COLLATE BINARY
	);`
	_, err := s.db.Exec(signerTable)
	return err
}

func (s *Server) initSigners() error {
	// check if there are any signers in the DB
	q := `SELECT COUNT(*) FROM signers;`
	result, err := s.db.Query(q)
	if err != nil {
		s.log.Error("failed to query DB", zap.String("query", q))
		return err
	}
	defer result.Close()
	for result.Next() {
		var count int
		if err := result.Scan(&count); err != nil {
			s.log.Error("failed to scan result", zap.String("query", q))
			return err
		}
		if count == 0 {
			s.log.Warn("no signers found in DB. Consider adding one with the management API")
			return nil
		}
		s.log.Info("found signers in DB", zap.Int("count", count))
	}
	return result.Err()
}

func NewServer(options ...ServerOption) (*Server, error) {
	s := &Server{}
	for _, option := range options {
		err := option(s)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}
