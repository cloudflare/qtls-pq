//go:build ignore
// +build ignore

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/qtls-go1-19"
)

func main() {
	tlsConf, err := generateQTLSConfig()
	if err != nil {
		log.Fatal(err)
	}
	tlsConf.ClientAuth = qtls.RequestClientCert
	tlsConf.InsecureSkipVerify = true
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	go connect(ln.Addr())
	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	c := qtls.Server(conn, tlsConf)
	if err := c.Handshake(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Received connection from", c.RemoteAddr())
	c.Write([]byte("foo"))
	select {}
}

func connect(addr net.Addr) {
	tlsConf, err := generateQTLSConfig()
	if err != nil {
		log.Fatal(err)
	}
	tlsConf.InsecureSkipVerify = true
	tlsConf.ClientSessionCache = qtls.NewLRUClientSessionCache(10)
	tlsConf.MinVersion = tls.VersionTLS13
	conn, err := qtls.Dial("tcp", addr.String(), tlsConf)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte("foobar")); err != nil {
		log.Fatal(err)
	}
	fmt.Println("dialed", conn.RemoteAddr())
}

func generateQTLSConfig() (*qtls.Config, error) {
	// Generate a new private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create a self-signed certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	// Create a new TLS certificate with the private key and self-signed certificate
	cert := qtls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privKey,
		OCSPStaple:  make([]byte, math.MaxUint16-372),
	}

	// Create a new TLS configuration with the self-signed certificate
	tlsConfig := &qtls.Config{
		Certificates: []qtls.Certificate{cert},
	}
	return tlsConfig, nil
}

func generateTLSConfig() (*tls.Config, error) {
	// Generate a new private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create a self-signed certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	// Create a new TLS certificate with the private key and self-signed certificate
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privKey,
	}

	// Create a new TLS configuration with the self-signed certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return tlsConfig, nil
}
