package mtlsid

// to convert .12 files to .cer + .key file combination
// $ openssl pkcs12 -in client-id.p12 -clcerts -nokeys -out client-id.cer
// $ openssl pkcs12 -in client-id.p12 -clcerts -nodes -nocerts | openssl rsa > client-id.key

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"net/http"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"time"
)

type Self_Authority_API struct {
	TrustStore string
	Verbose bool
	Service string
	Identity_Dir string
	Device_Name string
	
	__client *http.Client
}

func (cli *Self_Authority_API) Invalidate(){
	cli.__client = nil
}

//
// just a set of wrappers around the methods
//
func (cli *Self_Authority_API) do_get(endpoint string, request_body string, certificate string, key string) (string, []byte) {
	return cli.do_call(endpoint, "GET", request_body, certificate, key)
}

func (cli *Self_Authority_API) do_put(endpoint string, request_body string, certificate string, key string) (string, []byte) {
	return cli.do_call(endpoint, "PUT", request_body, certificate, key)
}

func (cli *Self_Authority_API) do_post(endpoint string, request_body string, certificate string, key string) (string, []byte) {
	return cli.do_call(endpoint, "POST", request_body, certificate, key)
}

func (cli *Self_Authority_API) do_delete(endpoint string, request_body string, certificate string, key string) (string, []byte) {
	return cli.do_call(endpoint, "DELETE", request_body, certificate, key)
}

//
// returns 2 values int this order: the http response status (int) and the body of the answer ([]byte)
// - if the http response code is anything but 200, the body should be expected to contain
//   some error description
// - an error of 600 as response code means the call could not be made due to whatever reason
// - 5xx errors mean the request was made, but generated a server error
//
func (cli *Self_Authority_API) do_call(endpoint string, method string, request_body string, certificate string, key string) (string, []byte) {

	client, err := cli.client(certificate, key)

	if err != nil {
		return "Unable to create http client: " + err.Error(), nil
	}

	if cli.Verbose {
		fmt.Println(request_body)
	}

	// var body_reader io.Reader
	var jsonStr = []byte(request_body)
	client_request, err := http.NewRequest(method, endpoint, bytes.NewBuffer(jsonStr))
	client_request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(client_request)

	defer func() {
		// only close body if it exists to prevent nil reference
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	if err != nil {
		return "error during https call: " + err.Error(), nil
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "error decoding https answer: " + err.Error(), nil
	}

	return "", bodyBytes
}

func (cli *Self_Authority_API) client(certificate string, key string) (*http.Client, error) {

	// create the client if not yet created
	if cli.__client == nil {

		var client_certificates []tls.Certificate
		var trusted_authorities *x509.CertPool

		if cli.TrustStore != "" {
			root_cert, err := ioutil.ReadFile(cli.TrustStore)

			if err != nil {
				return nil, errors.New("error loading trust material: " + err.Error())
			}

			trusted_authorities = x509.NewCertPool()
			_ = trusted_authorities.AppendCertsFromPEM(root_cert)
		}

		if key != "" && certificate != "" {

			clientCert, err := tls.LoadX509KeyPair(certificate, key)

			if err != nil {
				return nil, errors.New("error loading key material: " + err.Error())
			}

			client_certificates = []tls.Certificate{clientCert}
		}

		tlsConfig := tls.Config{
			Certificates: client_certificates,
			RootCAs:      trusted_authorities,
		}

		transport := http.Transport{
			TLSClientConfig: &tlsConfig,
		}

		cli.__client = &http.Client{
			Transport: &transport,
			Timeout:   time.Second * 40,
		}
	}

	return cli.__client, nil
}

func (cli *Self_Authority_API) Interactive_enroll_user_agent() string {
	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"request_oob_unlock\", \"args\": {\"no-redundancy\":false}}", "", "")

	if err != "" {
		return "Failed requesting login intent: " + err
	}

	if cli.Verbose {
		fmt.Printf(string(ans))
	}

	var response Intent_Response
	json.Unmarshal(ans, &response)

	qr_code := strings.Split(response.Result.QR, ";")
	fmt.Println("")
	fmt.Println("")
	fmt.Print("      ")
	for i := 0; i < len(qr_code); i += 2 {
		for j := 0; j < len(qr_code[i]); j++ {

			if qr_code[i][j] == '1' && (i > len(qr_code)-3 || qr_code[i+1][j] == '0') {
				fmt.Printf("\u2580") // upper half block
			} else if qr_code[i][j] == '1' && i < len(qr_code)-2 && qr_code[i+1][j] == '1' {
				fmt.Printf("\u2588") // full block
			} else if qr_code[i][j] == '0' && i < len(qr_code)-2 && qr_code[i+1][j] == '1' {
				fmt.Printf("\u2584") // lower half block
			} else {
				fmt.Printf(" ")
			}
		}

		fmt.Println("")
		fmt.Print("      ")
	}
	fmt.Println("")
	fmt.Println("")
	fmt.Println("Please scan the above QR Code with your Identity Plus App.")
	fmt.Print("Waiting ...")

	for i := 0; i < 10; i++ {
		err, ans = cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"oob_unlock\", \"args\": {\"token\": \""+response.Result.Token+"\", \"intent\": \""+response.Result.Intent+"\", \"keep-alive\":10}}}", "", "")

		if err != "" {
			return string(err)
		}

		var response Auth_Response
		json.Unmarshal(ans, &response)

		if (response.Error != "" || response.Result.Outcome != "logged in") && cli.Verbose {
			fmt.Println(response.Error + ", trying again")
		} else {
			fmt.Printf(".")
		}

		if response.Result.Outcome == "logged in" {
			return "\n" + cli.do_enroll(response.Result.Token) + "\n"
		}

	}

	return "Login timed out"
}

func (cli *Self_Authority_API) do_enroll(token string) string {
	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"issue_certificate\", \"args\": {\"token\": \""+token+"\", \"device\": \""+cli.Device_Name+"\", \"protect\":true}}", "", "")

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".p12", p12_cert, 0644)
	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".password", []byte(agent_identity.Result.Password), 0644)

	pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".cer", pem_cert, 0644)

	pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".key", pem_key, 0644)

	return "success"
}

func (cli *Self_Authority_API) Enroll_user_agent(authorization string) string {
	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"qrc_unlock\", \"args\": {\"code\": \""+authorization+"\"}}", "", "")

	if err != "" {
		return "Login failed: " + err
	}

	if cli.Verbose {
		fmt.Printf(string(ans))
	}

	var response Auth_Response
	json.Unmarshal(ans, &response)

	if response.Error != "" {
		return "Login failed: " + response.Error
	}

	if response.Result.Outcome != "logged in" {
		return "Login failed: " + response.Result.Outcome
	}

	return cli.do_enroll(response.Result.Token)
}

func (cli *Self_Authority_API) Employ_service_agent(authorization string) string {

	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"issue_service_agent_identity\", \"args\": {\"authorization\": \""+authorization+"\", \"agent-name\": \""+cli.Device_Name+"\", \"protect\":true}}", "", "")

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if cli.Verbose {
		fmt.Printf(string(ans))
	}

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	path := cli.Identity_Dir
	if os.MkdirAll(path, os.ModePerm) != nil {
		log.Println(err)
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".p12", p12_cert, 0644)
	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".password", []byte(agent_identity.Result.Password), 0644)

	pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".cer", pem_cert, 0644)

	pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".key", pem_key, 0644)

	return "success"
}

func (cli *Self_Authority_API) Assist_enroll(managed_service string) string {
	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"assist\", \"args\": {\"managed-service\": \""+managed_service+"\"}}", cli.Identity_Dir+"/"+cli.Device_Name+".cer", cli.Identity_Dir+"/"+cli.Device_Name+".key")

	if err != "" {
		return "Failed generating autoprovisioning token: " + err
	}

	var response Autoprovisioning_Token_Response
	json.Unmarshal(ans, &response)

	if response.Error != "" {
		return "Failed generating autoprovisioning token: " + response.Error
	}

	return response.Result.Token
}

func (cli *Self_Authority_API) Enroll_unified(authorization string) string {

	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"enroll\", \"args\": {\"authorization\": \""+authorization+"\", \"agent-name\": \""+cli.Device_Name+"\", \"protect\":true}}", "", "")

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if cli.Verbose {
		fmt.Printf(string(ans))
	}

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	path := cli.Identity_Dir
	if os.MkdirAll(path, os.ModePerm) != nil {
		log.Println(err)
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".p12", p12_cert, 0644)
	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".password", []byte(agent_identity.Result.Password), 0644)

	pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".cer", pem_cert, 0644)

	pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".key", pem_key, 0644)

	return "success"
}

func (cli *Self_Authority_API) Renew(tentative bool) string {

	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"renew_certificate\", \"args\": {\"device\": \""+cli.Device_Name+"\", \"protect\":true, \"tentative\":"+strconv.FormatBool(tentative)+"}}", cli.Identity_Dir+"/"+cli.Device_Name+".cer", cli.Identity_Dir+"/"+cli.Device_Name+".key")

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	if agent_identity.Result.Outcome == "renewed" {

		p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".p12", p12_cert, 0644)
		ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".password", []byte(agent_identity.Result.Password), 0644)

		pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".cer", pem_cert, 0644)

		pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".key", pem_key, 0644)
	}

	return agent_identity.Result.Outcome
}

func (cli *Self_Authority_API) Issue_service_identity(force bool) string {
	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"issue_service_certificate\", \"args\": {\"force-renew\":"+strconv.FormatBool(force)+"}}", cli.Identity_Dir+"/"+cli.Device_Name+".cer", cli.Identity_Dir+"/"+cli.Device_Name+".key")

	if cli.Verbose {
		fmt.Printf(string(ans))
	}

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var service_identity X509_Identity_Response
	json.Unmarshal(ans, &service_identity)

	if service_identity.Error != "" {
		return "Failed issuing certificate: " + service_identity.Error
	}

	if service_identity.Result.Outcome == "renewed" {

		p12_cert, derr := base64.StdEncoding.DecodeString(service_identity.Result.P12)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		path := cli.Identity_Dir + "/service-id/"
		if os.MkdirAll(path, os.ModePerm) != nil {
			log.Println(err)
		}

		ioutil.WriteFile(cli.Identity_Dir+"/service-id/"+service_identity.Result.Name+".p12", p12_cert, 0644)
		ioutil.WriteFile(cli.Identity_Dir+"/service-id/"+service_identity.Result.Name+".password", []byte(service_identity.Result.Password), 0644)

		pem_cert, derr := base64.StdEncoding.DecodeString(service_identity.Result.Certificate)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/service-id/"+service_identity.Result.Name+".cer", pem_cert, 0644)

		pem_key, derr := base64.StdEncoding.DecodeString(service_identity.Result.PrivateKey)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/service-id/"+service_identity.Result.Name+".key", pem_key, 0644)
	}

	return service_identity.Result.Outcome
}

func (cli *Self_Authority_API) Get_trust_chain() string {
	err, ans := cli.do_get("https://platform."+cli.Service+"/download/trust-chain?format=pem", "", cli.Identity_Dir+"/"+cli.Device_Name+".cer", cli.Identity_Dir+"/"+cli.Device_Name+".key")

	if err != "" {
		return "unable to download trust chain: " + err
	}

	path := cli.Identity_Dir + "/service-id/"
	if os.MkdirAll(path, os.ModePerm) != nil {
		log.Println(err)
	}

	ioutil.WriteFile(cli.Identity_Dir+"/service-id/identity-plus-root-ca.cer", ans, 0644)
	
	return "trust chain saved: " + cli.Identity_Dir+"/service-id/identity-plus-root-ca.cer" 
}

func (cli *Self_Authority_API) List_devices() string {
	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"get_active_identities\", \"args\": {}}", cli.Identity_Dir+"/"+cli.Device_Name+".cer", cli.Identity_Dir+"/"+cli.Device_Name+".key")

	if err != "" {
		return "Failed to list active mTLS IDs for agent: " + err
	}

	// var agent_identity X509_Identity_Response
	// json.Unmarshal(ans, &agent_identity)

	return string(ans)
}

func (cli *Self_Authority_API) List_service_roles() string {
	err, ans := cli.do_post("https://signon."+cli.Service+"/api/v1", "{\"operation\": \"get_service_roles\", \"args\": {}}", cli.Identity_Dir+"/"+cli.Device_Name+".cer", cli.Identity_Dir+"/"+cli.Device_Name+".key")

	if err != "" {
		return "Failed to get service roles: " + err
	}

	// var agent_identity X509_Identity_Response
	// json.Unmarshal(ans, &agent_identity)

	return string(ans)
}

func (cli *Self_Authority_API) Call(url string) string {
	err, ans := cli.do_get(url, "", cli.Identity_Dir+"/"+cli.Device_Name+".cer", cli.Identity_Dir+"/"+cli.Device_Name+".key")

	if err != "" {
		return "Error Geting URL: " + err
	}

	return string(ans)
}
