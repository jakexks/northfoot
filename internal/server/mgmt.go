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
	"errors"
	"strconv"

	"github.com/bufbuild/connect-go"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"

	mgmtv1 "github.com/jakexks/northfoot/api/mgmt/v1"
	"github.com/jakexks/northfoot/internal/server/validation"
)

func (s *Server) GetSigner(ctx context.Context, req *connect.Request[mgmtv1.GetSignerRequest]) (*connect.Response[mgmtv1.GetSignerResponse], error) {
	q, err := s.db.PrepareContext(ctx, "SELECT signers.signer FROM signers, json_each(signers.signer) WHERE json_each.key = 'id' AND json_each.value = ?")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer q.Close()
	rows, err := q.QueryContext(ctx, strconv.Itoa(int(req.Msg.Id)))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer rows.Close()
	var signers []*mgmtv1.Signer
	for rows.Next() {
		signer := &mgmtv1.Signer{}
		raw := ""
		if err := rows.Scan(&raw); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if err := protojson.Unmarshal([]byte(raw), signer); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		signers = append(signers, signer)
	}
	if err := rows.Err(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(signers) == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("signer with id "+strconv.Itoa(int(req.Msg.Id))+" not found"))
	}
	if len(signers) > 1 {
		return nil, connect.NewError(connect.CodeInternal, errors.New("multiple signers with id "+strconv.Itoa(int(req.Msg.Id))+" found"))
	}
	return connect.NewResponse(&mgmtv1.GetSignerResponse{
		Signer: signers[0],
	}), nil
}

func (s *Server) ListSigners(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[mgmtv1.ListSignersResponse], error) {
	q, err := s.db.PrepareContext(ctx, "SELECT signers.signer FROM signers")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer q.Close()
	rows, err := q.QueryContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer rows.Close()
	var signers []*mgmtv1.Signer
	for rows.Next() {
		signer := &mgmtv1.Signer{}
		raw := ""
		if err := rows.Scan(&raw); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if err := protojson.Unmarshal([]byte(raw), signer); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		signers = append(signers, signer)
	}
	if err := rows.Err(); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&mgmtv1.ListSignersResponse{
		Signers: &mgmtv1.SignerList{
			Signers: signers,
		},
	}), nil
}

func (s *Server) CreateSigner(ctx context.Context, req *connect.Request[mgmtv1.CreateSignerRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := validation.Signer(req.Msg.Signer); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	q, err := s.db.PrepareContext(ctx, "INSERT INTO signers (signer) VALUES (json(?))")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer q.Close()
	raw, err := protojson.Marshal(req.Msg.Signer)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if _, err := q.ExecContext(ctx, raw); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return &connect.Response[emptypb.Empty]{}, nil
}

func (s *Server) DeleteSigner(ctx context.Context, req *connect.Request[mgmtv1.DeleteSignerRequest]) (*connect.Response[emptypb.Empty], error) {
	q, err := s.db.PrepareContext(ctx, "DELETE FROM signers WHERE EXISTS (SELECT * FROM signers, json_each(signers.signer) WHERE json_each.key = 'id' AND json_each.value = ?)")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer q.Close()
	_, err = q.ExecContext(ctx, strconv.Itoa(int(req.Msg.Id)))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.lock.Lock()
	oldCache := s.signerCache.Load().(signerCache)
	newCache := make(signerCache)
	for k, v := range oldCache {
		if k != req.Msg.Id {
			newCache[k] = v
		}
	}
	s.signerCache.Store(newCache)
	s.lock.Unlock()
	return &connect.Response[emptypb.Empty]{}, nil
}
