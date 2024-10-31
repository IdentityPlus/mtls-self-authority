package main

import (
	"fmt"
	"log"
	"os"
	"selfauthority/mtlsid"
)

var verbose__ = false
var command__ = "help"
var service__ = "identity.plus"
var authorization__ = ""
var managed_service__ = ""
var identity_dir__ = "."
var trust_store__ = ""
var url__ = ""

func main() {
	home_dir, errh := os.UserHomeDir()
	if errh != nil {
		fmt.Println(errh.Error())
		os.Exit(1)
	}

	identity_dir__ = home_dir + "/.identityplus"

	var device_name = ""
	device_name, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for i := 1; i < len(os.Args); i++ {

		if os.Args[i] == "-v" {
			verbose__ = true
		} else if os.Args[i] == "-h" {
			command__ = "help"

		} else if os.Args[i] == "-d" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] -d device_name")
			} else {
				device_name = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "-f" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] -f directory/to/store/identity")
			} else {
				identity_dir__ = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "-t" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] -t path/to/trusted-root.cer")
			} else {
				trust_store__ = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "-s" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] -s identity.plus.service__.domain")
			} else {
				service__ = os.Args[i+1]
				i = i + 1
			}
		} else if os.Args[i] == "enroll" {
			command__ = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] enroll auto-provisioning-token")
			} else {
				authorization__ = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "assist-enroll" {
			command__ = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] assist-enroll service__")
			} else {
				managed_service__ = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "renew" {
			command__ = os.Args[i]

		} else if os.Args[i] == "issue-service__-identity" {
			command__ = os.Args[i]

		} else if os.Args[i] == "update" {
			command__ = os.Args[i]

		} else if os.Args[i] == "update-service__" {
			command__ = os.Args[i]

		} else if os.Args[i] == "list-devices" {
			command__ = os.Args[i]

		} else if os.Args[i] == "list-service__-roles" {
			command__ = os.Args[i]

		} else if os.Args[i] == "get-trust-chain" {
			command__ = os.Args[i]

		} else if os.Args[i] == "get" {
			command__ = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] get url__")
			} else {
				url__ = os.Args[i + 1]
				i = i + 1
			}
		} else {
			command__ = "help"
		}
	}

	var cli = mtlsid.Self_Authority_API{
		Verbose : verbose__,
		TrustStore : trust_store__,
		Service: service__,
		Identity_Dir : identity_dir__,
		Device_Name : device_name,
	}

	if verbose__ {
		fmt.Println("Identity directory: -f " + identity_dir__)
		fmt.Println("Device name: -d \"" + device_name + "\"")
		fmt.Println("Identity Plus service__: -s \"" + service__ + "\"")

		if trust_store__ == "" {
			fmt.Println("Trusted CAs: System Deafult")
		} else {
			fmt.Println("Trusted CAs: " + trust_store__)
		}
		fmt.Println("Operation: " + command__)
		fmt.Println("")
	}

	// configure logging
	path := identity_dir__
	if os.MkdirAll(path, os.ModePerm) != nil {
		log.Panic(err)
	}

	LOG_FILE := identity_dir__ + "/activity.log"
	logFile, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Panic(err)
	}
	defer logFile.Close()

	// Set log out to file
	// log.SetOutput(logFile)

	// ensure identity directory exists and it is writable
	os.Mkdir(identity_dir__, 0700)
	_, err = os.OpenFile(identity_dir__+"/test.tmp", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error: directory " + identity_dir__ + " does not exist or it is not writable")
	} else {
		os.Remove(identity_dir__ + "/test.tmp")
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
		log.Println("renewing service__ identity...")
		ans := cli.Renew(false)
		fmt.Print(ans)
	}

	if command__ == "issue-service__-identity" {
		log.Println("issuing service__ identity...")
		ans := cli.Issue_service_identity(true)
		fmt.Print(ans)
	}

	if command__ == "update" {
		ans := cli.Renew(true)
		fmt.Print(ans)
		log.Println(ans)
	}

	if command__ == "update-service__" {
		os.Mkdir(identity_dir__+"/service__", 0700)
		log.Println("updating service__ identity...")
		ans := cli.Issue_service_identity(false)
		fmt.Print(ans)
	}

	if command__ == "list-devices" {
		ans := cli.List_devices()
		fmt.Print(ans)
	}

	if command__ == "list-service__-roles" {
		ans := cli.List_service_roles()
		fmt.Print(ans)
	}

	if command__ == "get" {
		ans := cli.Call(url__, )
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
		fmt.Println("License: To be used with the Identity Plus service__/platform. Do not distribute.")
		fmt.Println("\n---------\n")
		fmt.Println("Usage: selfauthority [flags] command__ arguments")
		fmt.Println("\n\n-- flags --\n")
		fmt.Println("-h prints this message")
		fmt.Println("-v verbose__")
		fmt.Println("-f identity/directory [HOMEDIR/.selfauthority]: specify the directory where the identity material will be stored")
		fmt.Println("-d device-name [HOST NAME]: specify the device name to be used for this device")
		fmt.Println("-s api-service__ [identity.plus]: specify an alternative path for Identity Plus API service__")
		fmt.Println("-t trusted-CAs [SYSTEM TRUST STORE]: specify Certificate Authority to trust. It will default to the authorities trusted by the OS")
		fmt.Println("\n\n-- command__s --\n")
		fmt.Println("enroll AUTHORIZATION-TOKEN:\nEnroll current device as one of your end user devices. Requires an authorization__ token that can be obtained from https://my.identity.plus. If the authorization__ token is issued as part of a service__ agent in https://platform.identity.plus/organization/xyz.../service__/qpr.../agents the identity will be issued as a service__ agent. You must have the correct role in the service__ to issue service__ agent identities.\n")
		fmt.Println("assist-enroll:\nIssues an autoprovisioning token for a service__ to help kickstart its provisioning. The requesting identity must be a manager or administrator of the assisted service__s)\n")
		fmt.Println("renew:\nRenewes the current identity (user device or service__ agent)\n")
		fmt.Println("update:\nRenewes the current identity (user device or service__ agent) if approaching expiration (3/4 of lifetime)\n")
		fmt.Println("issue-service__-identity:\nGenerates a server certificate for your service__, signed by the Idnetity Plus CA. The call must be made with a valid agent enrolled by the service__. To work with Identity Plus issued server certificates we recommend explicitly trusting the Identity Plus Root CA\n")
		fmt.Println("update-service__:\nrenewes the server certificate for the service__ if necessary (reached 3/4 of its lifetime or the domain name has changed). The call must be made with a valid agent employed by the service__.\n")
		fmt.Println("list-agents:\nLists all devices you own\n")
		fmt.Println("list-service__-roles:\nLists all roles in all service__s you are assigned\n")
		fmt.Println("get-trust-chain:\nDownloads the Identity Plus authority chain needed to accept and authenticate with Identity Plus issued client certificates\n")			
		fmt.Println("get url__:\nmakes an https get call using the mtls ID as client certificate authentication\n")			
		fmt.Println("help:\nprints this message\n")			
		fmt.Println("\n---\n\n")
	}

	/* deprecated
	if command__ == "enroll-service__-device" {
		ans := enroll_unified(authorization__, )
		fmt.Print(ans)
		log.Println(ans)
	}

	// deprecated
	if command__ == "enroll-user-device" {
		var ans = ""

		if authorization__ == "" {
			ans = interactive_enroll_user_agent()
		} else {
			ans = enroll_unified(authorization__, )
		}

		fmt.Print(ans)
		log.Println(ans)
	}
	*/

}
