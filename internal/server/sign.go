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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/bufbuild/connect-go"
	"google.golang.org/protobuf/encoding/protojson"

	mgmtv1 "github.com/jakexks/northfoot/api/mgmt/v1"
	signv1 "github.com/jakexks/northfoot/api/sign/v1"
	"github.com/jakexks/northfoot/internal/server/validation"
	"github.com/jakexks/northfoot/internal/util"
)

type signer interface {
	Sign(ctx context.Context, csr *x509.CertificateRequest, durationHint time.Duration) (*x509.Certificate, error)
	TrustBundle() []*x509.Certificate
}

type signerCache map[int64]signer

func (s *Server) Sign(ctx context.Context, req *connect.Request[signv1.SignRequest]) (*connect.Response[signv1.SignResponse], error) {
	cache := s.signerCache.Load().(signerCache)
	signer, found := cache[req.Msg.SignerId]
	if !found {
		si, err := s.loadSignerFromDataStore(ctx, req.Msg.SignerId)
		if err != nil {
			return nil, err
		}
		signer = si
	}
	csr, err := x509.ParseCertificateRequest(req.Msg.Csr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	cert, err := signer.Sign(ctx, csr, req.Msg.DurationHint.AsDuration())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&signv1.SignResponse{
		Cert: cert.Raw,
	}), nil
}

func (s *Server) loadSignerFromDataStore(ctx context.Context, signerID int64) (signer, error) {
	var signer signer
	q, err := s.db.PrepareContext(ctx, "SELECT signers.signer FROM signers, json_each(signers.signer) WHERE json_each.key = 'id' AND json_each.value = ?")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer q.Close()
	rows, err := q.QueryContext(ctx, strconv.Itoa(int(signerID)))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer rows.Close()
	resultCount := 0
	for rows.Next() {
		resultCount++
		signerJSON := ""
		if err := rows.Scan(&signerJSON); err != nil {
			return nil, fmt.Errorf("error scanning signer: %w", err)
		}
		signerPB := &mgmtv1.Signer{}
		if err := protojson.Unmarshal([]byte(signerJSON), signerPB); err != nil {
			return nil, fmt.Errorf("error unmarshalling signer: %w", err)
		}
		si, err := newSigner(signerPB)
		if err != nil {
			return nil, fmt.Errorf("error creating signer: %w", err)
		}
		s.lock.Lock()
		oldCache := s.signerCache.Load().(signerCache)
		newCache := make(signerCache)
		for k, v := range oldCache {
			newCache[k] = v
		}
		newCache[signerID] = si
		s.signerCache.Store(newCache)
		s.lock.Unlock()
		signer = si
		break
	}
	if resultCount == 0 {
		return nil, fmt.Errorf("signer not found")
	}
	return signer, nil
}

func (s *Server) TrustBundle(ctx context.Context, req *connect.Request[signv1.TrustBundleRequest]) (*connect.Response[signv1.TrustBundleResponse], error) {
	cache := s.signerCache.Load().(signerCache)
	signer, found := cache[req.Msg.SignerId]
	if !found {
		si, err := s.loadSignerFromDataStore(ctx, req.Msg.SignerId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		signer = si
	}
	certs := signer.TrustBundle()
	var resp [][]byte
	for _, cert := range certs {
		resp = append(resp, cert.Raw)
	}
	return connect.NewResponse(&signv1.TrustBundleResponse{
		Certs: resp,
	}), nil
}

func newSigner(s *mgmtv1.Signer) (signer, error) {
	if s == nil {
		return nil, validation.ErrNilSigner
	}
	switch s.Type {
	case mgmtv1.SignerType_SIGNER_TYPE_UNSPECIFIED:
		return nil, validation.ErrMissingType
	case mgmtv1.SignerType_SIGNER_TYPE_INMEM:
		return newInMemSigner(s.SignerConfig.(*mgmtv1.Signer_InMem))
	default:
		return nil, errors.New("signer type not implemented")
	}
}

func newInMemSigner(config *mgmtv1.Signer_InMem) (signer, error) {
	switch config.InMem.Key {
	case mgmtv1.PrivateKeyType_PRIVATE_KEY_TYPE_UNSPECIFIED:
		return nil, validation.ErrMissingKeyType
	case mgmtv1.PrivateKeyType_PRIVATE_KEY_TYPE_RSA:
		bits := 2048
		if config.InMem.KeySize != nil {
			bits = int(*config.InMem.KeySize)
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		cert, err := util.GenerateSelfSignedCA(key)
		if err != nil {
			return nil, err
		}
		return &inMemSigner{
			key:         key,
			cert:        cert,
			keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}, nil
	default:
		return nil, errors.New("key type not implemented")
	}
}

type inMemSigner struct {
	key  crypto.PrivateKey
	cert *x509.Certificate

	keyUsage    x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage
}

func (i *inMemSigner) Sign(ctx context.Context, csr *x509.CertificateRequest, durationHint time.Duration) (*x509.Certificate, error) {
	if csr == nil {
		return nil, errors.New("csr is nil")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR has invalid signature: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	if durationHint == 0 {
		durationHint = time.Hour
	}
	template := &x509.Certificate{
		Version:               2,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		IsCA:                  false,
		Subject:               csr.Subject,
		RawSubject:            csr.RawSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(durationHint),
		KeyUsage:              i.keyUsage,
		ExtKeyUsage:           i.extKeyUsage,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, csr.PublicKey, i.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

func (i *inMemSigner) TrustBundle() []*x509.Certificate {
	return []*x509.Certificate{i.cert}
}
