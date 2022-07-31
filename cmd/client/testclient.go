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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/bufbuild/connect-go"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"

	mgmtv1 "github.com/jakexks/northfoot/api/mgmt/v1"
	"github.com/jakexks/northfoot/api/mgmt/v1/mgmtv1connect"
	signv1 "github.com/jakexks/northfoot/api/sign/v1"
	"github.com/jakexks/northfoot/api/sign/v1/signv1connect"
)

func main() {
	client := mgmtv1connect.NewManagementServiceClient(newInsecureClient(), "http://localhost:8080", connect.WithGRPC())

	id := int64(1)
	keysize := int64(4096)
	name := "test"
	s := &mgmtv1.Signer{
		Id:          &id,
		Name:        &name,
		Description: nil,
		Type:        mgmtv1.SignerType_SIGNER_TYPE_INMEM,
		SignerConfig: &mgmtv1.Signer_InMem{
			InMem: &mgmtv1.SignerInMemConfig{
				Key:     mgmtv1.PrivateKeyType_PRIVATE_KEY_TYPE_RSA,
				KeySize: &keysize,
			},
		},
	}
	c := &mgmtv1.CreateSignerRequest{
		Signer: s,
	}

	fmt.Println("testing create signer")
	createResp, createErr := client.CreateSigner(context.Background(), connect.NewRequest(c))
	if createErr != nil {
		panic(createErr)
	}
	fmt.Printf("%s\n", createResp.Msg.String())

	fmt.Println("testing list signers")
	listResp, listErr := client.ListSigners(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	if listErr != nil {
		panic(listErr)
	}
	fmt.Printf("%s\n", listResp.Msg.String())

	fmt.Println("testing sign")
	signClient := signv1connect.NewSignServiceClient(newInsecureClient(), "http://localhost:8080", connect.WithGRPC())

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"GB"},
			Organization:       []string{"test"},
			OrganizationalUnit: []string{"testing"},
			CommonName:         "test",
		},
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		panic(err)
	}

	signReq := &signv1.SignRequest{
		SignerId:     1,
		Csr:          csr,
		DurationHint: durationpb.New(time.Hour),
	}

	signResp, signerr := signClient.Sign(context.Background(), connect.NewRequest(signReq))
	if signerr != nil {
		panic(signerr)
	}
	fmt.Printf("%s\n", signResp.Msg.String())

	fmt.Println("testing trust bundle")
	trustResp, trustErr := signClient.TrustBundle(context.Background(), connect.NewRequest(&signv1.TrustBundleRequest{
		SignerId: 1,
	}))
	if trustErr != nil {
		panic(trustErr)
	}
	fmt.Printf("%s\n", trustResp.Msg.String())

	fmt.Println("dumping in PEM format")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signResp.Msg.Cert,
	})
	bundlePem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: trustResp.Msg.Certs[0],
	})
	fmt.Printf("key:\n%s\n\ncert:\n%s\n\nbundle:\n%s\n\n", string(keyPem), string(certPem), string(bundlePem))

	fmt.Println("signing 10000 certs")
	start := time.Now()
	for i := 0; i < 10000; i++ {
		_, signerr := signClient.Sign(context.Background(), connect.NewRequest(signReq))
		if signerr != nil {
			panic(signerr)
		}
	}
	end := time.Now()
	timeTaken := end.Sub(start)
	fmt.Printf("took %s\n", timeTaken)

	fmt.Println("testing delete signer")
	deleteRequest, deleteErr := client.DeleteSigner(context.Background(), connect.NewRequest(&mgmtv1.DeleteSignerRequest{
		Id: 1,
	}))
	if deleteErr != nil {
		panic(deleteErr)
	}
	fmt.Printf("%s\n", deleteRequest.Msg.String())
}

func newInsecureClient() *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				// If you're also using this client for non-h2c traffic, you may want
				// to delegate to tls.Dial if the network isn't TCP or the addr isn't
				// in an allowlist.
				return net.Dial(network, addr)
			},
			// Don't forget timeouts!
		},
	}
}
