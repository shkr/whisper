package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ipfs/go-ipfs-api"
	"github.com/rs/cors"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

/*

Generate public and private keys

openssl genrsa -out key.pem
openssl rsa -in key.pem  -pubout > key-pub.pem

echo polaris@studygolang.com | openssl rsautl \
     -encrypt \
     -pubin -inkey key-pub.pem \
 > cipher.txt

cat cipher.txt | openssl rsautl \
    -decrypt \
    -inkey key.pem
*/

// Shell connection to ipfs
var sh *shell.Shell

// dirPath which contains the files to whisper
var dirPath string

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to ipwhisp")
}

type ClientConfig struct {
	host string
	port int
}

type WhisperConfiguration struct {
	eth     ClientConfig
	ipfs    ClientConfig
	whisper ClientConfig
}

type Whisper struct {
	PublicKey string
	FileName  string
}

func encode(b []byte) string {
  return base64.StdEncoding.EncodeToString(b)
}


func requestSecretStorage(w http.ResponseWriter, r *http.Request) {

	var whisperObject Whisper

	err := json.NewDecoder(r.Body).Decode(&whisperObject)
	if err != nil {
		panic(err)
	}

	encryptedHashAddress, err := storeSecret(whisperObject)
	// encode []byte encrypted hash address to string
	fmt.Fprintf(w, encode(encryptedHashAddress))
}


func storeSecret(whisperObject Whisper) ([] byte, error) {

	// transform filePath to local client side address
	filePath := fmt.Sprintf("%s/%s", dirPath, whisperObject.FileName)
	// Read data
	fileContent := loadFile(filePath)

	/**
	 * Encrypt the insecure payload
	 *
	 */
	// Encrypt file
	data, err := RsaEncrypt(fileContent, whisperObject.PublicKey)
	if err != nil {
		panic(err)
	}

	// Write file
	f := bytes.NewReader([]byte(encode(data)))

	// Save to ipfs
	hashAddress, err := sh.Add(f)
	if err != nil {
		panic(err)
	}	
	
	encryptedHashAddress, err := RsaEncrypt([]byte(hashAddress), whisperObject.PublicKey)

	return encryptedHashAddress, err
}

func loadFile(fileName string) []byte {

	// TODO: validation pubkey path
	if fileName == "" {
		fmt.Fprintf(os.Stderr, "Path parse failure: %s\n", fileName)
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(fileName)

	if err != nil {
		fmt.Fprintf(os.Stderr, "file parse failure: %s\n", data)
		os.Exit(1)
	}

	return data
}

// RSA Encrypt Function
func RsaEncrypt(origData []byte, pubKey string) ([]byte, error) {

	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

func main() {

	app := cli.NewApp()
	app.Name = "ipwhisp"
	app.Usage = "openly announce secret files as whispers on blockchain"
	app.Version = "0.1.0"

	// define server function
	serverFn := func(c *cli.Context) error {

		// connect shell to ipfs
		ipfsAddress := fmt.Sprintf("%s:%s", "localhost", "5001")
		sh = shell.NewShell(ipfsAddress)

		// set the dirPath
		dirPath = c.String("dir")

		// start http server
		mux := http.NewServeMux()

		// Print Instructions
		mux.HandleFunc("/", homePage)

		/**
		 * POST /buy
		 *
		 * All buy requests will come through the /buy route
		 * Each request should have a public key and a fileName value
		 */
		mux.HandleFunc("/buy", requestSecretStorage)

		// cors.Default() setup the middleware with default options being
		// all origins accepted with simple methods (GET, POST). See
		// documentation below for more options.
		handler := cors.Default().Handler(mux)
		err := http.ListenAndServe(":9090", handler) // set listen port
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}

		return nil
	}

	// commands
	app.Commands = []cli.Command{
		cli.Command {
			Name:   "server",
			Usage:  "start whisper server",
			Action: serverFn,
			Before: func(c *cli.Context) error {
				fmt.Fprintf(c.App.Writer, "server started on http://localhost:9090\n")
				return nil
			},
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "dir, d",
					Value: "./",
					Usage: "Path for whispering files",
				},
			},
		},
	}

	// Catch interrupt signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		os.Exit(1)
	}()

	app.Run(os.Args)
}
