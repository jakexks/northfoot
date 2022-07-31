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

package main

import (
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/jakexks/northfoot/api/mgmt/v1/mgmtv1connect"
	"github.com/jakexks/northfoot/api/sign/v1/signv1connect"
	"github.com/jakexks/northfoot/internal/server"
)

func main() {
	log, _ := zap.NewProduction()
	defer log.Sync()

	s, err := server.NewServer(server.WithLogger(log), server.WithDatastore("./northfoot.db"))
	if err != nil {
		log.Fatal("failed to create server", zap.Error(err))
	}

	if err := s.Init(); err != nil {
		log.Fatal("failed to init server", zap.Error(err))
	}

	mux := http.NewServeMux()
	mux.Handle(signv1connect.NewSignServiceHandler(s))
	mux.Handle(mgmtv1connect.NewManagementServiceHandler(s))
	log.Info("starting server", zap.String("bind", "localhost:8080"))
	err = http.ListenAndServe(
		"localhost:8080",
		// Use h2c so we can serve HTTP/2 without TLS.
		h2c.NewHandler(mux, &http2.Server{}),
	)
	log.Error("server stopped", zap.Error(err))
}
