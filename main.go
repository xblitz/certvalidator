package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	keyPtr := flag.String("key", "", "Private key file")
	intPtr := flag.String("int", "", "Intermediate certificates file")

	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Printf("Usage: %s [OPTIONS...] [Certificate File]\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Printf("\nExample: %s --key example.com.key --int intermediates.crt example.com.crt\n", os.Args[0])
		os.Exit(1)
	}

	certBlocks := pemFileToBlocks(flag.Arg(0))
	intCertBlocks := pemFileToBlocks(*intPtr)
	keyBlocks := pemFileToBlocks(*keyPtr)

	cert := parseCertificate(certBlocks[0].Bytes)

	intCertsPool := x509.NewCertPool()
	for _, block := range intCertBlocks {
		intCertsPool.AddCert(parseCertificate(block.Bytes))
	}

	opts := x509.VerifyOptions{
		Intermediates: intCertsPool,
	}

	if _, err := cert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	} else {
		fmt.Println("Certificate chain is valid!")
	}
	fmt.Printf("Certificate valid from: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	privateKeyCertificateMatch(keyBlocks[0], cert)

}

func privateKeyCertificateMatch(keyBlock *pem.Block, cert *x509.Certificate) bool {
	key := decodePrivateKey(keyBlock)

	if cert.PublicKey.(*rsa.PublicKey).N.Cmp(key.PublicKey.N) == 0 && key.PublicKey.E == cert.PublicKey.(*rsa.PublicKey).E {
		fmt.Println("Key and Certificate matches!")
	} else {
		panic("Key and Certificate does not match!")
	}
	return true
}

func decodePrivateKey(keyBlock *pem.Block) *rsa.PrivateKey {
	var b []byte
	if keyBlock != nil {
		b = keyBlock.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(b)
		if err != nil {
			panic("private key should be a PEM or plain PKSC1 or PKCS8; parse error: " + err.Error())
		}
	}
	rsa, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		panic("private key is invalid")
	}
	return rsa
}

func pemFileToBlocks(file string) (blocks []*pem.Block) {
	pemData, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	for {
		var derBlock *pem.Block
		derBlock, pemData = pem.Decode(pemData)
		if derBlock == nil {
			break
		}
		// fmt.Printf("Block type: %+v\n", derBlock.Type)
		blocks = append(blocks, derBlock)
	}
	if blocks == nil {
		panic("Failed to read PEM block from file " + file)
	}
	return
}

func parseCertificate(block []byte) (cert *x509.Certificate) {
	cert, err := x509.ParseCertificate(block)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	fmt.Printf("Certificate [Subject: %+v]\n            [Issuer:  %+v]\n", cert.Subject, cert.Issuer)
	return
}
