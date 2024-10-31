# Identity Plus - mTLS Self Authority Command Line Interface

The Indentity Plus CLI is a simple, command line tool for all identity plus basic functions. While these functions are available as API and can be perfomed from within applications, the CLI can come in handy to automate deployments and maintenance using an automation suite.

### Definitions 

Identity Plus is a device identity suite built upon the TLS communication stack. In this documentation we will assume you are already familiar with the following technologies and concepts:

#### TLS

Transport Layer Security, the successor of SSL, is a communication layer built upon the TCP stack to ensure confientiality of the communication and the identity of one or both the communicating parties. The term is also used denote the simple form of TLS communication, when only one of the parties presents identity information, the minimum necessary for TLS to work.

#### MATLS

Mutually Authenticated TLS, is the full version of TLS, when both parties present identity information

#### X.509 Certificate

Colloquially known as a TLS Certificate or SSL Certificate, the X.509 Certificate is a Criptographic instrument that gives a computer software the ability to prove identity by means of a private key. The public part of the certificate, contains identity information, verifying (public) key and various other information. Structurally all X.509 Certificates are the same, they only difer in their purpose which is documented in the cerificate: authority (certificates that sign other certificates), sever (certificates that prove server identity), client certificates (certificates that prove client identity)

## Running & Building

The Identity Plus command line interface is built in GoLang. We recomment that you build the application for your own specific platform. To do so, please follow the stepts:

**1.** Install the GoLang development platform  
**2.** Check out this project from the repository  
**3.** Open a terminal window and change direcory into the Identity Plus CLI directory you just checked out  
**4.** Build the application:  

        $ go mod init selfauthority  
        $ go build
  
**5.** You are done, the "selfauthority" file in the current folder is your executable  
**6.** You can also run the selfauthority CLI without building it  

        $ go run selfauthority.go ...  


## User Manual

./selfauthority [flags] command arguments

### Flags
**-h** prints the help message  
**-v** enables verbose mode  
**-f identity/directory [HOMEDIR/.selfauthority]**: specify the directory where the identity material will be stored  
**-d device-name [\"Default Go Test\"]**: specify the device name to be used for this device

#### Debug Flags
These flags are only need to be specified in case of debugging, otherwise they should stay default

**-s api-service [identity.plus]**: specify an alternative path for Identity Plus API service  
**-t trusted-CAs [SYSTEM TRUST STORE]**: specify Certificate Authority to trust. It will default to the authorities trusted by the OS  

### Operations

#### enroll AUTOPROVISIONING-TOKEN. 
Enroll current device as one of your end user devices. Requires an autoprovisioning token that can be obtained from https://my.identity.plus/devices. If the self autoprovisinong token is obtained at https://platform.identity.plus/organization/xyz.../service/qpr.../agents, the identity will be issued as an agent of the named service. You must have rights to issue agents to the service for this to succeede.

#### renew
Renewes the current identity (user device or service agent)

#### update
Renewes the current identity (user device or service agent) if approaching expiration (3/4 of lifetime)

#### issue-service-identity
Generates a server certificate for your service, signed by the Idnetity Plus CA. The call must be made with a valid agent enrolled by the service. To work with Identity Plus issued server certificates we recommend explicitly trusting the Identity Plus Root CA

#### update-service
Renewes the server certificate for the service if necessary (reached 3/4 of its lifetime or the domain name has changed). The called must be made with a valid agent employed by the service.

#### list-devices
Lists all devices you own)

#### assist-enroll managed-service.org.mtls.app
Generates an autoprovisioning token for the manged service. The managed service can use the resulting token within 5 minutes to perform an enroll operation.
The mTLS ID this operation is executed with must belong to an entity (person or service) that has management role (manager or administrator) in the managed-service.org.mtls.app service.
This has to be configured in the https://platform.identity.plus/organization/org-id/service/service-id/access-management/[services | people]

## Certificate Continuity
One of the biggest problems in certificate distribution and management is certificate expiry. Expired certificates can not be used to establish TLS connection and thus can cause server outages similarly as a network outages do. Identity Plus makes it simple to not run into this problem as the certificates are managed by the owners not by the issures. A simple client side automation using the Identity Plus command line tool will ensure continuity, in a set-and-forget manner, so you no longer have to worry about certificate expiry and the resulting communication outages.

There are potentially two automations required, depending on the nature of the deployment on the device in scope: client automation if the device is client only and both client and service automation if the device is running a service or a service gateway using Identity Plus issued server server certificates. If the server component is not running on Identity Plus issued server certificates, then the sever certificate conitnuity needs to be addressed separately, as it is neither dependant on, or in control of Identity Plus.

### Agent Continuity
After provisioning the agent (client) certificate either by using enroll (provision a personal certificate for a personal computer) or using (employ) to provision a service agent for a service worker, run the agent-update.sh shell script using the inputs (agent directory and agent name) you provided during provision:

        $ ./agent-update.sh /agent/directory AgentName

The certificate will be verified for validity and if approching expiry (75% of its lifetime) it will be automatically renewed. The command will also auto-provision a cron job, which will run the command itself, so that going forward the agent-update will be executed every day at 4AM in the morning.

### Service Continuity
Should your service run using an Identity Plus server certificate, the renewal of the certificate is done similarly, by running the command

        $ ./agent-update.sh /agent/directory AgentName

The agent renewal script also takes care of reloading nginx should the certificate be renewed. Load balancer restart is not necessary. Similarly to the agent update script, the service update script will also auto provision a cron job which will run the script on its own going forward so that you never don't have to manually manage this. This way you will not suffer certificate expiry related outages. This is particularly important for large service to service (micro-services for example) evironments, where you could potentially have hundreds of services, with thousands of interconnections among them.
