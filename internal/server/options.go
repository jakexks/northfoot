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

import "go.uber.org/zap"

type ServerOption func(*Server) error

func WithDatastore(datastore string) ServerOption {
	return func(s *Server) error {
		s.datastore = datastore
		return nil
	}
}

func WithLogger(logger *zap.Logger) ServerOption {
	return func(s *Server) error {
		s.log = logger
		return nil
	}
}
