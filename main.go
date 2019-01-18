package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	certBlocks := pemFileToBlocks(os.Args[1])
	intCertBlocks := pemFileToBlocks(os.Args[2])
	keyBlocks := pemFileToBlocks(os.Args[3])

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

	fmt.Printf("%+v", privateKeyCertificateMatch(keyBlocks[0], cert))

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
