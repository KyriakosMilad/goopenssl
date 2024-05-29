package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

const (
	openSSLCommand           = "openssl"
	getParsedCertTextCommand = `x509 -text -noout"`
	getPublicKeyCommand      = `x509 -pubkey -noout`
	//getSignatureCommand = `x509 -text -noout" | grep -A 1000 "Signature Value:" | tail -n +2` // This is a hack to get the signature value, parse certificate | get the lines after "Signature Value" | remove the line contains "Signature Value"
	//getSignatureCommand = `x509 -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame"` // get only Signature Algorithm and Signature Value, more from https://www.openssl.org/docs/man1.1.1/man1/x509.html
	getSignatureCommand = `x509 -text -noout -certopt=ca_default,no_validity,no_serial,no_subject,no_extensions,no_signame"` // get only Signature Algorithm and Signature Value, more from https://www.openssl.org/docs/man1.1.1/man1/x509.html
	getStartDateCommand = `x509 -startdate -noout`
	getEndDateCommand   = `x509 -enddate -noout`
)

type Certificate struct {
	cert string
}

func LoadCertificateFromPEM(cert string) *Certificate {
	return &Certificate{cert}
}

func (c *Certificate) GetParsedCertText() (string, error) {
	argsSlice := strings.Split(getParsedCertTextCommand, " ")

	stderr := &bytes.Buffer{}
	stdout := &bytes.Buffer{}

	cmd := exec.Command(openSSLCommand, argsSlice...)
	cmd.Stdin = strings.NewReader(c.cert)
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil || stderr.Len() > 0 {
		return "", fmt.Errorf("failed to execute command: %v: %v", err, stderr.String())
	}

	parsedCert := stdout.String()
	// remove the unparsed certificate from the output
	parsedCertRaw := strings.ReplaceAll(parsedCert, c.cert, "")
	// remove last \n
	parsedCertRaw = strings.TrimRight(parsedCertRaw, "\n")

	return parsedCertRaw, nil
}

func (c *Certificate) GetPublicKeyPEM() (string, error) {
	argsSlice := strings.Split(getPublicKeyCommand, " ")

	stderr := &bytes.Buffer{}
	stdout := &bytes.Buffer{}

	cmd := exec.Command(openSSLCommand, argsSlice...)
	cmd.Stdin = strings.NewReader(c.cert)
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil || stderr.Len() > 0 {
		return "", fmt.Errorf("failed to execute command: %v: %v", err, stderr.String())
	}

	// remove last \n
	publicKey := stdout.String()
	publicKey = strings.TrimRight(publicKey, "\n")

	return publicKey, nil
}

func (c *Certificate) GetEndDate() (string, error) {
	argsSlice := strings.Split(getEndDateCommand, " ")

	stderr := &bytes.Buffer{}
	stdout := &bytes.Buffer{}

	cmd := exec.Command(openSSLCommand, argsSlice...)
	cmd.Stdin = strings.NewReader(c.cert)
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil || stderr.Len() > 0 {
		return "", fmt.Errorf("failed to execute command: %v: %v", err, stderr.String())
	}

	// remove last \n
	endDate := stdout.String()
	endDate = strings.TrimRight(endDate, "\n")

	return endDate, nil
}

func (c *Certificate) GetStartDate() (string, error) {
	argsSlice := strings.Split(getStartDateCommand, " ")

	stderr := &bytes.Buffer{}
	stdout := &bytes.Buffer{}

	cmd := exec.Command(openSSLCommand, argsSlice...)
	cmd.Stdin = strings.NewReader(c.cert)
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil || stderr.Len() > 0 {
		return "", fmt.Errorf("failed to execute command: %v: %v", err, stderr.String())
	}

	// remove last \n
	startDate := stdout.String()
	startDate = strings.TrimRight(startDate, "\n")

	return startDate, nil
}

func (c *Certificate) GetSignature() (string, error) {
	argsSlice := strings.Split(getSignatureCommand, " ")

	stderr := &bytes.Buffer{}
	stdout := &bytes.Buffer{}

	cmd := exec.Command(openSSLCommand, argsSlice...)
	cmd.Stdin = strings.NewReader(c.cert)
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil || stderr.Len() > 0 {
		return "", fmt.Errorf("failed to execute command: %v: %v", err, stderr.String())
	}

	// remove last \n
	signature := stdout.String()
	signature = strings.TrimRight(signature, "\n")

	return signature, nil
}

func main() {
	cert := ``

	c := LoadCertificateFromPEM(cert)
	pk, err := c.GetPublicKeyPEM()
	if err != nil {
		log.Fatal(err)
	}
	s := fmt.Sprintf("pk pem: %s", pk)
	fmt.Println(s)

	parsedCert, err := c.GetParsedCertText()
	if err != nil {
		log.Fatal(err)
	}
	s = fmt.Sprintf("parsed cert: %s", parsedCert)
	fmt.Println(s)

	endDate, err := c.GetEndDate()
	if err != nil {
		log.Fatal(err)
	}
	s = fmt.Sprintf("end date: %s", endDate)
	fmt.Println(s)

	startDate, err := c.GetStartDate()
	if err != nil {
		log.Fatal(err)
	}
	s = fmt.Sprintf("start date: %s", startDate)
	fmt.Println(s)

	signatureValue, err := c.GetSignature()
	if err != nil {
		log.Fatal(err)
	}
	s = fmt.Sprintf("signature value: %s", signatureValue)
	fmt.Println(s)
}
