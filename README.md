# Whisper
***Openly announce secret files as whispers on blockchain***

Whisper provides server client functionality for both generating eth based contracts, and managing underlying file based transactions using ipfs.

* It's secure - reliant on blockchain for maintaining trust in contracts
* It's massively distributed - reliant on IPFS, giving it all the functionality that comes with a distrbuted system, with...
* It's industry grade encrypted (RSA) -  None of the security risks that follow.

The documentation outlines the package dependencies, basic server/client functionalities, and a how-to on integrating it with existing systems. 

---


### Whisper-Server

This [repository](https://github.com/shkr/whisper/tree/master/whisper_server) contains the Whisper server daemon which handles the file, encryption and transmission through ipfs, and the Web UI. 

Built in GO, the server leverages a local ipfs daemon, provides file searching, hashing and encryption, and a command line interface for easy deployment. If you are looking for the server user interface code see [here](server.html)



***Install***

The server daemon is available is a go src file which can be installed with the standard "go install" command. 

```sh
$ go install main.go
```
 

***Dependencies***

* [bytes](https://golang.org/pkg/bytes/) - go package for byte manipulation
* [crypto/rand](https://golang.org/pkg/crypto/rand/) - Random number generator for encryption
* [crypto/rsa](https://golang.org/pkg/crypto/rsa/) - RSA encryption as specified in PKCS#1
* [crypto/x509](https://golang.org/pkg/crypto/x509/)- parses X.509-encoded keys and certificates
* [encoding/base64](https://golang.org/pkg/encoding/base64/)- base64 encoding as specified by RFC 4648
* [encoding/pem](https://golang.org/pkg/encoding/pem/) - PEM data encoding
* [errors](https://golang.org/pkg/errors/)- error module in go
* [fmt](https://golang.org/pkg/fmt/)- standard file management module for go
* [go-ipfs-api](https://github.com/ipfs/go-ipfs-api) - unofficial go interface to ipfs's HTTP API
* [cors](https://github.com/rs/cors) - handle CORS requests
* [cli](https://github.com/urfave/cli)- building CLI apps in go 
* [io/util](https://golang.org/pkg/io/ioutil/)
* [log](https://golang.org/pkg/log/) - error logging
* [net/http](https://golang.org/pkg/net/http/)- http requests


***IPFS Dependency***

The server requires an ipfs server to be listening for API calls. Whisper relies on the go-ipfs-api standard release, to handle file hashing.

For 101's on how cool ipfs is, running a daemon and detailed user documentation, the best place is to go is the source itself at [Protocol Labs](https://ipfs.io/)

```sh
$ ipfs daemon
Initializing daemon...
Adjusting current ulimit to 2048...
Successfully raised file descriptor limit to 2048.
Swarm listening on /ip4/10.0.1.46/tcp/4001
Swarm listening on /ip4/127.0.0.1/tcp/4001
Swarm listening on /ip4/136.25.179.164/tcp/10530
Swarm listening on /ip6/2604:5500:b:1f3:6c2c:690d:b6e1:cbf0/tcp/4001
Swarm listening on /ip6/2604:5500:b:1f3:f65c:89ff:fec3:5107/tcp/4001
Swarm listening on /ip6/::1/tcp/4001
API server listening on /ip4/127.0.0.1/tcp/5001
Gateway (readonly) server listening on /ip4/127.0.0.1/tcp/8080
Daemon is ready
```

***Usage***

After installation, the command to start the server quite simply is "server":

```sh
$ server
server started on http://localhost:9090
```

Whisper uses the GO [http](https://golang.org/pkg/net/http/) API to provide the servlet routines. The [cli api](https://github.com/urfave/cli) is then used to provide elegant command line interfacing in a neat package. 

The WebUI provides the following functionality:

* [http://localhost:9090/inventory](http://localhost:9090/inventory) - Generates the current file inventory
	
* [http://localhost:9090/sell](http://localhost:9090/sell) - Locate files, encrypt, release hash.

 


***Options***


```sh
Usage:
  server [OPTIONS]

The start command starts the Whisper-Server

Application Options:
  -d, --dir                   Print the path for whispering files
```
