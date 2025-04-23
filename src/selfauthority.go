package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"selfauthority/mtlsid"

	"gopkg.in/yaml.v2"
)

var command__ = "help"
var authorization__ = ""
var managed_service__ = ""
var url__ = ""
var body__ = ""

func get_self_authority() *mtlsid.Self_Authority_API {
	var sa mtlsid.Self_Authority_API
	yamlData, err := ioutil.ReadFile("./mtls-id.yaml")

	log.Println("----- reading -------\n" + string(yamlData) + "\n------------------")

	err = yaml.Unmarshal([]byte(yamlData), &sa)
	if err != nil {
		fmt.Printf("malformed identity file: %s\n", err.Error())
		os.Exit(1)
	}

	return &sa
}

func main() {
	var cli = get_self_authority()

	// attemp set default identity directory
	if cli.Identity_Dir == "" {
		home_dir, errh := os.UserHomeDir()

		if errh == nil {
			cli.Identity_Dir = home_dir + "/.identityplus"
		}
	}

	// attempt set default the host as device name if not set
	if cli.Device_Name == "" {
		device_name, err := os.Hostname()
		if err == nil {
			cli.Device_Name = device_name
		}
	}

	if cli.Service == "" {
		cli.Service = "identity.plus"
	}

	for i := 1; i < len(os.Args); i++ {

		if os.Args[i] == "-v" {
			cli.Verbose = true
		} else if os.Args[i] == "-h" {
			command__ = "help"

		} else if os.Args[i] == "-d" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: selfauthority [ flags ] -d device_name")
				os.Exit(1)
			} else {
				cli.Device_Name = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "-f" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: selfauthority [ flags ] -f directory/to/store/identity")
				os.Exit(1)
			} else {
				cli.Identity_Dir = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "-t" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: selfauthority [ flags ] -t path/to/trusted-root.cer")
				os.Exit(1)
			} else {
				cli.TrustStore[0] = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "-s" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: selfauthority [ flags ] -s identity.plus.service.domain")
				os.Exit(1)

			} else {
				cli.Service = os.Args[i+1]
				i = i + 1
			}
		} else if os.Args[i] == "enroll" {
			command__ = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: selfauthority [ flags ] enroll auto-provisioning-token")
				os.Exit(1)

			} else {
				authorization__ = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "assist-enroll" {
			command__ = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: selfauthority [ flags ] assist-enroll service")
				os.Exit(1)
			} else {
				managed_service__ = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "renew" {
			command__ = os.Args[i]

		} else if os.Args[i] == "issue-service-identity" {
			command__ = os.Args[i]

		} else if os.Args[i] == "update" {
			command__ = os.Args[i]

		} else if os.Args[i] == "update-service" {
			command__ = os.Args[i]

		} else if os.Args[i] == "list-devices" {
			command__ = os.Args[i]

		} else if os.Args[i] == "list-service-roles" {
			command__ = os.Args[i]

		} else if os.Args[i] == "get-trust-chain" {
			command__ = os.Args[i]

		} else if os.Args[i] == "get" {
			command__ = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: selfauthority [ flags ] get url")
				os.Exit(1)
			} else {
				url__ = os.Args[i+1]
				i = i + 1
			}
		} else if os.Args[i] == "post" {
			command__ = os.Args[i]

			if len(os.Args) <= i+2 {
				fmt.Println("Usage: selfauthority [ flags ] post url body")
				os.Exit(1)
			} else {
				url__ = os.Args[i+1]
				body__ = os.Args[i+2]
				i = i + 2
			}
		} else {
			command__ = "help"
		}
	}

	if cli.Verbose {
		fmt.Println("Identity directory: " + cli.Identity_Dir)
		fmt.Println("Device name: \"" + cli.Device_Name + "\"")
		fmt.Println("Identity Broker: \"" + cli.Service + "\"")
		fmt.Println("Trusted CA: System Default")

		for _, ca := range cli.TrustStore {
			fmt.Println("Trusted CA: " + ca)
		}

		fmt.Println("Operation: " + command__)
		fmt.Println("")
	}

	// configure logging
	err := os.MkdirAll(cli.Identity_Dir, os.ModePerm)
	if err != nil {
		log.Panic(err)
	}

	LOG_FILE := cli.Identity_Dir + "/activity.log"
	logFile, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Panic(err)
	}
	defer logFile.Close()

	// Set log out to file
	// log.SetOutput(logFile)

	// ensure identity directory exists and it is writable
	os.Mkdir(cli.Identity_Dir, 0700)
	_, err = os.OpenFile(cli.Identity_Dir+"/test.tmp", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error: directory " + cli.Identity_Dir + " does not exist or it is not writable")
	} else {
		os.Remove(cli.Identity_Dir + "/test.tmp")
	}

	if command__ == "enroll" {
		var ans = ""

		log.Println("attempting enrollement")
		if authorization__ == "" {
			ans = cli.Interactive_enroll_user_agent()
		} else {
			ans = cli.Enroll_unified(authorization__)
		}

		fmt.Print(ans)
	}

	if command__ == "assist-enroll" {
		log.Println("Assisting " + managed_service__ + " with autoprovisioning...")
		ans := cli.Assist_enroll(managed_service__)
		fmt.Print(ans)
	}

	if command__ == "renew" {
		log.Println("renewing service identity...")
		ans := cli.Renew(false)
		fmt.Print(ans)
	}

	if command__ == "issue-service-identity" {
		log.Println("issuing service identity...")
		ans := cli.Issue_service_identity(true)
		fmt.Print(ans)
	}

	if command__ == "update" {
		ans := cli.Renew(true)
		fmt.Print(ans)
		log.Println(ans)
	}

	if command__ == "update-service" {
		os.Mkdir(cli.Identity_Dir+"/service", 0700)
		log.Println("updating service identity...")
		ans := cli.Issue_service_identity(false)
		fmt.Print(ans)
	}

	if command__ == "list-devices" {
		ans := cli.List_devices()
		fmt.Print(ans)
	}

	if command__ == "list-service-roles" {
		ans := cli.List_service_roles()
		fmt.Print(ans)
	}

	if command__ == "get" {
		ans := cli.Call(url__, "GET", "")
		fmt.Print(ans)
	}

	if command__ == "post" {
		ans := cli.Call(url__, "POST", body__)
		fmt.Print(ans)
	}

	if command__ == "get-trust-chain" {
		ans := cli.Get_trust_chain()
		fmt.Print(ans)
	}

	if command__ == "help" {
		fmt.Println("\nIdentity Plus Command Line Interface")
		fmt.Println("Version: 1.0")
		fmt.Println("Copyright: Identity Plus (https://identity.plus)")
		fmt.Println("License: To be used with the Identity Plus service/platform. Do not distribute.")
		fmt.Println("\n---------\n")
		fmt.Println("Usage: selfauthority [flags] command arguments")
		fmt.Println("\n\n-- flags --\n")
		fmt.Println("-h prints this message")
		fmt.Println("-v verbose")
		fmt.Println("-f identity/directory [HOMEDIR/.selfauthority]: specify the directory where the identity material will be stored")
		fmt.Println("-d device-name [HOST NAME]: specify the device name to be used for this device")
		fmt.Println("-s api-service [identity.plus]: specify an alternative path for Identity Plus API service")
		fmt.Println("-t trusted-CAs [SYSTEM TRUST STORE]: specify Certificate Authority to trust. It will default to the authorities trusted by the OS")
		fmt.Println("\n\n-- commands --\n")
		fmt.Println("enroll AUTHORIZATION-TOKEN:\nEnroll current device as one of your end user devices. Requires an authorization token that can be obtained from https://my.identity.plus. If the authorization token is issued as part of a service agent in https://platform.identity.plus/organization/xyz.../service/qpr.../agents the identity will be issued as a service agent. You must have the correct role in the service to issue service agent identities.\n")
		fmt.Println("assist-enroll:\nIssues an autoprovisioning token for a service__ to help kickstart its provisioning. The requesting identity must be a manager or administrator of the assisted services)\n")
		fmt.Println("renew:\nRenewes the current identity (user device or service agent)\n")
		fmt.Println("update:\nRenewes the current identity (user device or service agent) if approaching expiration (3/4 of lifetime)\n")
		fmt.Println("issue-service-identity:\nGenerates a server certificate for your service, signed by the Idnetity Plus CA. The call must be made with a valid agent enrolled by the service. To work with Identity Plus issued server certificates we recommend explicitly trusting the Identity Plus Root CA\n")
		fmt.Println("update-service:\nrenewes the server certificate for the serviceif necessary (reached 3/4 of its lifetime or the domain name has changed). The call must be made with a valid agent employed by the service.\n")
		fmt.Println("list-agents:\nLists all devices you own\n")
		fmt.Println("list-service-roles:\nLists all roles in all service__s you are assigned\n")
		fmt.Println("get-trust-chain:\nDownloads the Identity Plus authority chain needed to accept and authenticate with Identity Plus issued client certificates\n")
		fmt.Println("get url:\nmakes an https get call using the mtls ID as client certificate authentication\n")
		fmt.Println("help:\nprints this message\n")
		fmt.Println("\n---\n\n")
	}
}
