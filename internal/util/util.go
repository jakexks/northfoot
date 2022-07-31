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

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

func GenerateSelfSignedCA(key crypto.Signer) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	var keyAlgo x509.PublicKeyAlgorithm

	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyAlgo = x509.RSA
	case *ecdsa.PrivateKey:
		keyAlgo = x509.ECDSA
	case ed25519.PrivateKey:
		keyAlgo = x509.Ed25519
	default:
		return nil, fmt.Errorf("unsupported key type: %T", k)
	}
	spiffeID, err := url.Parse("spiffe://northfoot/ca")
	if err != nil {
		return nil, fmt.Errorf("failed to parse spiffeID: %w", err)
	}
	template := &x509.Certificate{
		Version:               2,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    keyAlgo,
		IsCA:                  true,
		Subject: pkix.Name{
			Country:            []string{"GB"},
			Organization:       []string{"Northfoot"},
			OrganizationalUnit: []string{"Development self-signed CA"},
			SerialNumber:       serialNumber.String(),
			CommonName:         "Northfoot Development Self-Signed CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 10),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageOCSPSigning},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		URIs:        []*url.URL{spiffeID},
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	return x509.ParseCertificate(cert)
}
