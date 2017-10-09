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
var ipfsShell *shell.Shell

// inventoryPath
var inventoryPath string

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "WASP: Server Application for managing and selling inventory on InventoryRef Network")
}

type Address struct {
	host string
	port int
}

type ConnectionMap struct {
	eth     Address
	ipfs    Address
	whisper Address
}

type InventoryRef struct {
	PublicKey string
	FileType  string
	FileName  string
}

func encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func fetchByName(fileName string) []byte {
	// transform filePath to local client side address
	filePath := fmt.Sprintf("%s/%s", inventoryPath, fileName)
	// Read data
	fileContent := loadFile(filePath)

	return fileContent;
}

func fetchStoreThenReturn(w http.ResponseWriter, r *http.Request) {

	var item InventoryRef

	err := json.NewDecoder(r.Body).Decode(&item)
	if err != nil {
		panic(err)
	}

	// Only fetch type by fileName supported
	if item.FileName == "" {
		panic("fileName not specified in a store call")
	}

	fileContent := fetchByName(item.FileName)

	/**
	 * Encrypt the insecure payload
	 *
	 */
	// Encrypt file
	data, err := RsaEncrypt(fileContent, item.PublicKey)
	if err != nil {
		panic(err)
	}

	// Write file
	f := bytes.NewReader([]byte(encode(data)))

	// Save to ipfs
	hashAddress, err := ipfsShell.Add(f)
	if err != nil {
		panic(err)
	}

	encryptedHashAddress, err := RsaEncrypt([]byte(hashAddress), item.PublicKey)

	// encode []byte encrypted haipfsShell address to string
	fmt.Fprintf(w, encode(encryptedHashAddress))
}

func listInventory(inventoryPath string, w http.ResponseWriter) {
	files, _ := ioutil.ReadDir(inventoryPath)
	var filePaths []string
	for _, f := range files {
		filePaths = append(filePaths, f.Name())
	}

	listInventory, _ := json.Marshal(filePaths)
	fmt.Fprintf(w, string(listInventory))
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
	app.Name = "WASP"
	app.Usage = "SERVER INVENTORY MANAGER FOR WHISPER"
	app.Version = "0.1.0"

	// define server function
	serverFn := func(c *cli.Context) error {

		// connect shell to ipfs
		ipfsAddress := fmt.Sprintf("%s:%s", "localhost", "5001")
		ipfsShell = shell.NewShell(ipfsAddress)

		// set the inventoryPath
		inventoryPath = c.String("dir")

		// start http server
		mux := http.NewServeMux()

		// Print Instructions
		mux.HandleFunc("/", homePage)

		/**
		 * GET /inventory
		 *
		 * All the files in the inventory are returned
		 */
		mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
			listInventory(inventoryPath, w)
		})

		/**
		 * POST /buy
		 *
		 * All buy requests will come through the /buy route
		 * Each request should have a public key and a fileName value
		 */
		mux.HandleFunc("/store", fetchStoreThenReturn)

		// cors.Default() setup the middleware with default options being
		// all origins accepted with simple methods (GET, POST). See
		// documentation below for more options.
		handler := cors.Default().Handler(mux)
		err := http.ListenAndServe(":9090", handler) // set listen port
		if err != nil {
			log.Fatal("[ERROR] ", err)
		}

		return nil
	}

	// commands
	app.Commands = []cli.Command{
		cli.Command{
			Name:   "server",
			Usage:  "wasp server",
			Action: serverFn,
			Before: func(c *cli.Context) error {
				fmt.Fprintf(c.App.Writer, "server started on http://localhost:9090\n")
				return nil
			},
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "dir, d",
					Value: "./",
					Usage: "path for inventory files",
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
