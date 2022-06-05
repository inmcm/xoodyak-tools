package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/inmcm/xoodoo/xoodyak"
	"github.com/inmcm/xoodyak-tools/xoodyak-crypt/console"
	"github.com/inmcm/xoodyak-tools/xoodyak-crypt/parsing"
)

var (
	quiet      bool
	useStdOut  bool
	outputFile string
	cfgFile    string

	cfgShouldExist bool = false

	cryptoKey parsing.Component = parsing.Component{
		Name:      "key",
		Length:    xoodyak.KeyLen,
		Generated: false,
	}
	cryptoAD parsing.Component = parsing.Component{
		Name:      "metadata",
		Length:    -1,
		Generated: false,
	}
	cryptoNonce parsing.Component = parsing.Component{
		Name:      "nonce",
		Length:    xoodyak.NonceLen,
		Generated: false,
	}
)

func main() {

	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)

	// Add all common argument flags to sub-commands - see printHelp() for per argument docstrings
	for _, sub := range []*flag.FlagSet{encryptCmd, decryptCmd} {
		sub.StringVar(&cryptoKey.Encoded, "k", "", "")
		sub.StringVar(&cryptoKey.Encoded, "key", "", "")

		sub.StringVar(&cryptoKey.File, "K", "", "")
		sub.StringVar(&cryptoKey.File, "key-file", "", "")

		sub.StringVar(&cryptoAD.Encoded, "m", "", "")
		sub.StringVar(&cryptoAD.Encoded, "metadata", "", "")

		sub.StringVar(&cryptoAD.File, "M", "", "")
		sub.StringVar(&cryptoAD.File, "metadata-file", "", "")

		sub.StringVar(&cryptoNonce.Encoded, "n", "", "")
		sub.StringVar(&cryptoNonce.Encoded, "nonce", "", "")

		sub.StringVar(&cryptoNonce.File, "N", "", "")
		sub.StringVar(&cryptoNonce.File, "nonce-file", "", "")

		sub.StringVar(&outputFile, "o", "", "")
		sub.StringVar(&outputFile, "output-file", "", "")

		sub.BoolVar(&useStdOut, "p", false, "")
		sub.BoolVar(&useStdOut, "pipe-output", false, "")

		sub.BoolVar(&quiet, "q", false, "")
		sub.BoolVar(&quiet, "quiet", false, "")

		sub.StringVar(&cfgFile, "C", "", "")
		sub.StringVar(&cfgFile, "cfg-file", "", "")

		sub.Usage = printHelp
	}

	if len(os.Args) < 2 {
		console.Println("expected 'encrypt' or 'encrypt' subcommands")
		printHelp()
		os.Exit(1)
	}

	var command *flag.FlagSet
	switch os.Args[1] {
	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
		command = encryptCmd
	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
		command = decryptCmd
		cfgShouldExist = true
	default:
		console.Println("expected 'encrypt' or 'encrypt' subcommands")
		printHelp()
		os.Exit(1)
	}
	command.Usage = printHelp

	var err error
	cfgDataEmpty := parsing.Configuration{}
	cfgData := &cfgDataEmpty
	if cfgFile != "" {
		cfgData, err = parsing.ReadConfig(cfgFile, cfgShouldExist)
		if err != nil {
			console.Printf("xoodyak config file parsing: %s", err)
		}
	}

	err = cryptoKey.Parse(cfgData.Key)
	if err != nil {
		console.Printf("xoodyak key error: %s\n", err)
		os.Exit(1)
	}
	err = cryptoAD.Parse(cfgData.Metadata)
	if err != nil {
		console.Printf("xoodyak metadata error: %s\n", err)
		os.Exit(1)
	}
	err = cryptoNonce.Parse(cfgData.Nonce)
	if err != nil {
		console.Printf("xoodyak nonce error: %s\n", err)
		os.Exit(1)
	}

	if (cryptoKey.Generated || cryptoNonce.Generated) && cfgFile == "" {
		console.Printf("xoodyak nonce error: %s\n", err)
		os.Exit(1)
	}

	useStdIn := len(command.Args()) == 0

	// Setup output file names: specified file, alternate extension file, STDOUT
	defaultExt := ".plain"
	if command.Name() == "encrypt" {
		defaultExt = ".xdyk"
	}
	if outputFile == "" {
		if useStdIn {
			outputFile = "stdin" + defaultExt
		} else {
			inputFile := command.Arg(0)
			outputFile = inputFile[:len(inputFile)-len(path.Ext(inputFile))] + defaultExt
		}
	}
	outputFileTmp := outputFile + ".tmp"
	defer os.Remove(outputFileTmp)

	// Setup Output writer - file or STDOUT
	var outputFd io.WriteCloser
	if useStdOut {
		_, err := os.Stdout.Stat()
		if err != nil {
			console.Printf("xoodyak-crypt: cannot stat STDOUT - %s", err)
			os.Exit(1)
		}
		outputFd = os.Stdout
	} else {
		outputFd, err = os.Create(outputFileTmp)
		if err != nil {
			console.Printf("xoodyak encrypt: %s", err)
			os.Exit(1)
		}
		defer outputFd.Close()
	}
	outputFdBuf := bufio.NewWriter(outputFd)

	// Setup input reader; STDIN or file
	var inputFd io.Reader
	if useStdIn {
		info, err := os.Stdin.Stat()
		if err != nil {
			console.Printf("xoodyak-crypt: cannot stat STDIN - %s", err)
			os.Exit(1)
		}
		if info.Mode()&os.ModeNamedPipe == 0 && info.Mode()&os.ModeCharDevice == 0 {
			console.Println("xoodyak-crypt: STDIN not a valid pipe")
			os.Exit(1)
		}
		inputFd = bufio.NewReader(os.Stdin)

	} else {
		inputFd, err = os.Open(command.Arg(0))
		if err != nil {
			console.Printf("xoodyak encrypt: %s", err)
			os.Exit(1)
		}
	}
	// Use Buffered IO for Reads
	inputFdBuf := bufio.NewReader(inputFd)

	// Perform encryption or decryption
	switch command.Name() {
	case "encrypt":
		err = encryptStream(cryptoKey.Raw, cryptoAD.Raw, cryptoNonce.Raw, inputFdBuf, outputFdBuf)
		if cfgFile != "" {
			cfgData.Key = cryptoKey.Encoded
			cfgData.Nonce = cryptoNonce.Encoded
			cfgData.Metadata = cryptoAD.Encoded
			if err = parsing.SaveConfig(cfgData, cfgFile); err != nil {
				console.Printf("xoodyak config file save error: %s", err)
				os.Exit(1)
			}
		}
	case "decrypt":
		err = decryptStream(cryptoKey.Raw, cryptoAD.Raw, cryptoNonce.Raw, inputFdBuf, outputFdBuf)
	default:
		err = fmt.Errorf("invalid crypt command: %s", command.Name())
	}
	if err != nil {
		console.Printf("xoodyak crypt error: %s", err)
		os.Exit(1)
	}
	outputFdBuf.Flush()
	outputFd.Close()

	if !useStdOut {
		err = os.Rename(outputFileTmp, outputFile)
		if err != nil {
			console.Printf("xoodyak rename: %s", err)
			os.Exit(1)
		}
	}
	console.Printf("%s operation successful\n", command.Name())
}

func printHelp() {
	console.Printf(`Usage: %s encrypt|decrypt [OPTIONS]... [FILE]
Encrypt or Decrypt provided bytes using a provided (or generated) key, nonce and optional metadata
Encryption generates ciphertext bytes and an appended authentication tag
Decryption returns the original plaintext input

When no FILE is provided, read from STDIN
	-q, -quiet            only print the calculated checksum
	-h, -help             print this message
	-C, -cfg-file         encryption/decryption configuration parameters (key,nonce,metadata) are provided
	                      via a JSON encoded configuration file
	                      for encryption operations, parameters are written to config file
	                      following processing, including generated key/nonce data
	                      Config format: '{"key":"<KEY>","nonce":"<NONCE>","ad":"<METADATA>"}'
	-k, -key              encrypt/decrypt key is provided as base64 encoded string
	-K, -key-file         encryption key is first 16 bytes read from file at the provided path
	-m, -metadata         optional associated metadata is provided as base64 encoded string
	-M, -metadata-file    optional associated metadata is all bytes read from file at provided path
	-n, -nonce            nonce is provided as base64 encoded string
	-N, -nonce-file       nonce is first 16 bytes read from file at provided path
	-o, -output-file      output file path: ciphertext for encryption, plaintext for decryption
	                      filename will be generated from input file name if not provided
	-p, -pipe-output      encryption/decryption result will be passed to STDOUT instead of a file
`, os.Args[0])
}

func encryptStream(key, ad, nonce []byte, plaintext io.Reader, ciphertext io.Writer) (err error) {
	encOut, err := xoodyak.NewEncryptStream(ciphertext, key, nonce, ad)
	if err != nil {
		err = fmt.Errorf("xoodyak encrypt: %w", err)
		return
	}

	io.Copy(encOut, plaintext)
	if err != nil {
		err = fmt.Errorf("xoodyak encrypt: %w", err)
		return
	}

	err = encOut.Close()
	if err != nil {
		err = fmt.Errorf("xoodyak encrypt: %w", err)
	}
	return
}

func decryptStream(key, ad, nonce []byte, ciphertext io.Reader, plaintext io.Writer) (err error) {
	decIn, err := xoodyak.NewDecryptStream(ciphertext, key, nonce, ad)
	if err != nil {
		err = fmt.Errorf("xoodyak decrypt: %w", err)
		return err
	}
	_, err = io.Copy(plaintext, decIn)
	if err != nil {
		err = fmt.Errorf("xoodyak decrypt: %w", err)
		return err
	}
	return nil
}
