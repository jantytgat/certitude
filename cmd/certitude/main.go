package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	inputFileName  string
	inputType      string
	inputBytes     []byte
	inputFileMode  os.FileMode
	outputFileName string
	outputType     string
	outputBytes    []byte
)

func main() {
	parseFlags()
	validateFlags()

	inputFileInfo, err := os.Lstat(inputFileName)
	if err != nil {
		if !os.IsExist(err) {
			log.Fatal("Input filename ", inputFileName, " does not exist")
		}
	}

	inputBytes, err = os.ReadFile(inputFileName)
	if err != nil {
		log.Fatal(err)
	}
	inputFileMode = inputFileInfo.Mode()

	switch inputType {
	case "PEM":
		processPEM()
	case "DER":
		processDER()
	}
}

func parseFlags() {
	flag.StringVar(&inputFileName, "inFile", "", "Input file for conversion")
	flag.StringVar(&inputType, "inType", "", "Input file type (PEM,DER)")
	//flag.StringVar(&outputFileName, "outFile", "", "Output file name (without extension")
	flag.StringVar(&outputType, "outType", "", "Output file type (PEM,DER)")
	flag.Parse()
}

func validateFlags() {
	if len(strings.TrimSpace(inputFileName)) == 0 {
		log.Fatal("inFile is required")
	}

	//if len(strings.TrimSpace(outputFileName)) == 0 {
	//	log.Fatal("outFile is required")
	//}
}

func processPEM() {
	switch outputType {
	case "DER":
		convertPEMtoDER()
	}
}

func convertPEMtoDER() {
	fmt.Println("Converting PEM to DER")

	var block *pem.Block
	block, _ = pem.Decode([]byte(inputBytes))

	// just a single certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cert.Subject)
	fmt.Println(cert.DNSNames)

	outputFileName = inputFileName + ".der"
	os.WriteFile(outputFileName, cert.Raw, inputFileMode)
}

func processDER() {
	switch outputType {
	case "PEM":
		convertDERtoPEM()
	}
}

func convertDERtoPEM() {
	fmt.Println("Converting DER to PEM")

	cert, err := x509.ParseCertificate(inputBytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cert.Subject)
	fmt.Println(cert.DNSNames)

	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	outputBytes = pem.EncodeToMemory(&block)
	outputFileName = inputFileName + ".pem"
	os.WriteFile(outputFileName, outputBytes, inputFileMode)
}
