// Sourced from: https://gist.github.com/devtdeng/4f6adcb5a306f2ae035a2e7d9f724d17/raw/135ebcce649214b536222815a6c2a563a969351c/verify_certificate.go
//
// With modifications.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 4 {
		log.Printf("Usage: verify_certificate SERVER_NAME CERT.pem CHAIN.pem TRUST.pem")
		return
	}

	serverName := os.Args[1]

	certPEM, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	chainPEM, err := ioutil.ReadFile(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}

	rootPEM, err := ioutil.ReadFile(os.Args[4])
	if err != nil {
		log.Fatal(err)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}

	chain := x509.NewCertPool()
	ok = roots.AppendCertsFromPEM([]byte(chainPEM))
	if !ok {
		panic("failed to parse chain")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       serverName,
		Intermediates: chain,
	}

	if _, err := cert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}

	log.Printf("verification succeeds")
}
