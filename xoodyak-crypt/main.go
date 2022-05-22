package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/inmcm/xoodoo/xoodyak"
)

var (
	quiet      bool
	outputFile string

	key component = component{
		name:   "key",
		length: xoodyak.KeyLen,
	}
	ad component = component{
		name:   "metadata",
		length: -1,
	}
	tag component = component{
		name:   "tag",
		length: xoodyak.TagLen,
	}
	nonce component = component{
		name:   "nonce",
		length: xoodyak.NonceLen,
	}
)

type component struct {
	name      string // component name
	raw       []byte // bytes read/decoded
	file      string // absolute path to file containing bytes
	encoded   string // Base64 encoded version
	length    int    // Required/populated length, -1 if unlimited
	generated bool
}

func main() {

	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)

	// Add all common argument flags to sub-commands
	for _, sub := range []*flag.FlagSet{encryptCmd, decryptCmd} {
		sub.StringVar(&key.encoded, "k", "", "encrypt/decrypt key is provided base64 encoded string")
		sub.StringVar(&key.encoded, "key-string", "", "encryption key input is a base64 encoded string")

		sub.StringVar(&key.file, "K", "", "encryption key is first 16 bytes read from provided path")
		sub.StringVar(&key.file, "key-file", "", "encryption key is first 16 bytes read from provided path")

		sub.StringVar(&ad.encoded, "m", "", "optional associated metadata is provided base64 encoded string")
		sub.StringVar(&ad.encoded, "metadata", "", "optional associated metadata is provided base64 encoded string")

		sub.StringVar(&ad.file, "M", "", "optional associated metadata is all bytes read from provided path")
		sub.StringVar(&ad.file, "metadata-file", "", "optional associated metadata is all bytes read from provided path")

		sub.StringVar(&nonce.encoded, "n", "", "nonce is provided as base64 encoded string")
		sub.StringVar(&nonce.encoded, "nonce", "", "nonce is provided as base64 encoded string")

		sub.StringVar(&nonce.file, "N", "", "nonce is first 16 bytes read from provided path")
		sub.StringVar(&nonce.file, "nonce-file", "", "nonce is first 16 bytes read from provided path")

		sub.StringVar(&outputFile, "o", "", "output file path: ciphertext for encryption, plaintext for decryption")
		sub.StringVar(&outputFile, "output-file", "", "output file path: ciphertext for encryption, plaintext for decryption")

		sub.BoolVar(&quiet, "q", false, "quiet mode - only the checksum is printed out")
		sub.BoolVar(&quiet, "quiet", false, "quiet mode - only the checksum is printed out")

	}

	if len(os.Args) < 2 {
		fmt.Println("expected 'encrypt' or 'decrypt' subcommands")
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
	default:
		fmt.Println("expected 'encrypt' or 'encrypt' subcommands")
		os.Exit(1)
	}

	// flag.Parse()
	var err error
	err = key.ParseInputs()
	err = ad.ParseInputs()
	err = nonce.ParseInputs()

	fmt.Printf("Key: %x\n", key.raw)
	fmt.Printf("Length: %d(%d)\n", len(key.raw), key.length)
	fmt.Printf("Key (Encoded): %s\n", key.encoded)
	fmt.Printf("Key (File): %s\n", key.file)

	fmt.Printf("Metadata: %x\n", ad.raw)
	fmt.Printf("Length: %d(%d)\n", len(ad.raw), ad.length)
	fmt.Printf("Metadata (Encoded): %s\n", ad.encoded)
	fmt.Printf("Metadata (File): %s\n", ad.file)

	fmt.Printf("Nonce: %x\n", nonce.raw)
	fmt.Printf("Length: %d(%d)\n", len(nonce.raw), nonce.length)
	fmt.Printf("Nonce (Encoded): %s\n", nonce.encoded)
	fmt.Printf("Nonce (File): %s\n", nonce.file)

	outputFileTmp := outputFile + ".tmp"
	defer os.Remove(outputFileTmp)

	if command.Name() == "encrypt" {
		if len(command.Args()) == 0 {
			if outputFile == "" {
				outputFile = "stdin.xdyk"
				outputFileTmp = outputFile + ".tmp"
			}

			err = encryptStdIn(key.raw, ad.raw, nonce.raw, outputFileTmp)
			if err != nil {
				fmt.Printf("%s", err)
				os.Exit(1)
			}
		} else {
			inputFile := command.Arg(0)
			if outputFile == "" {
				outputFile = inputFile[:len(inputFile)-len(path.Ext(inputFile))] + ".xdyk"
				outputFileTmp = outputFile + ".tmp"
			}
			err = encryptFile(key.raw, ad.raw, nonce.raw, inputFile, outputFileTmp)
			if err != nil {
				fmt.Printf("%s", err)
				os.Exit(1)
			}
		}
	} else if command.Name() == "decrypt" {
		if len(command.Args()) == 0 {
			if outputFile == "" {
				outputFile = "stdin.plain"
				outputFileTmp = outputFile + ".tmp"
			}
			err = decryptStdIn(key.raw, ad.raw, nonce.raw, outputFileTmp)
			if err != nil {
				fmt.Printf("%s", err)
				os.Exit(1)
			}
		} else {
			inputFile := command.Arg(0)
			if outputFile == "" {
				outputFile = inputFile[:len(inputFile)-len(path.Ext(inputFile))] + ".plain"
				outputFileTmp = outputFile + ".tmp"
			}
			err = decryptFile(key.raw, ad.raw, nonce.raw, inputFile, outputFileTmp)
			if err != nil {
				fmt.Printf("%s", err)
				os.Exit(1)
			}
		}
		fmt.Println("decrypt successful")
	}
	err = os.Rename(outputFileTmp, outputFile)
	if err != nil {
		fmt.Printf("xoodyak rename: %s", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf(`Usage: %s [OPTION]... [FILE].. 
Calculate and print the Xoodyak hash and number of bytes processed

When no FILE is provided, read from STDIN
	-q, --quiet         only print the calculated checksum 
	-h, --help          print this message
`, os.Args[0])
}

func printOutput(hash []byte, size int64, name string) {
	if quiet {
		fmt.Printf("%x\n", hash)
	} else {
		printName := name
		if name != "" {
			printName = name + " "
		}
		fmt.Printf("%x %s(%d bytes) \n", hash, printName, size)
	}

}

func encryptStdIn(key, ad, nonce []byte, ciphertext string) (err error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		err = fmt.Errorf("xoodyak encrypt: cannot stat STDIN - %w", err)
		return
	}
	if info.Mode()&os.ModeNamedPipe == 0 && info.Mode()&os.ModeCharDevice == 0 {
		err = fmt.Errorf("xoodyak encrypt: STDIN not a valid pipe")
		return
	}
	plaintextReader := bufio.NewReader(os.Stdin)

	out, err := os.Create(ciphertext)
	if err != nil {
		err = fmt.Errorf("xoodyak encrypt: %w", err)
		return
	}
	defer out.Close()

	return encryptStream(key, ad, nonce, plaintextReader, out)

}

func encryptFile(key, ad, nonce []byte, plaintext, ciphertext string) (err error) {
	in, err := os.Open(plaintext)
	if err != nil {
		err = fmt.Errorf("xoodyak encrypt: %w", err)
		return
	}
	fmt.Printf("\tKEY:%x\n\tNONCE:%x\n\tAD:%x\n", key, nonce, ad)

	out, err := os.Create(ciphertext)
	if err != nil {
		err = fmt.Errorf("xoodyak encrypt: %w", err)
		return
	}
	defer out.Close()

	return encryptStream(key, ad, nonce, in, out)

}

func decryptStdIn(key, ad, nonce []byte, plaintext string) (err error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		err = fmt.Errorf("xoodyak decrypt: cannot stat STDIN - %w", err)
		return
	}
	if info.Mode()&os.ModeNamedPipe == 0 && info.Mode()&os.ModeCharDevice == 0 {
		err = fmt.Errorf("xoodyak decrypt: STDIN not a valid pipe")
		return
	}
	ctRd := bufio.NewReader(os.Stdin)

	ptWr, err := os.Create(plaintext)
	if err != nil {
		err = fmt.Errorf("xoodyak decrypt: %w", err)
		return
	}
	defer ptWr.Close()

	return decryptStream(key, ad, nonce, ctRd, ptWr)
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

func decryptFile(key, ad, nonce []byte, ciphertext, plaintext string) (err error) {
	in, err := os.Open(ciphertext)
	if err != nil {
		err = fmt.Errorf("xoodyak decrypt: %w", err)
		return err
	}
	fmt.Printf("\tKEY:%x\n\tNONCE:%x\n\tAD:%x\n", key, nonce, ad)

	out, err := os.Create(plaintext)
	if err != nil {
		err = fmt.Errorf("xoodyak decrypt: %w", err)
		return err
	}
	defer out.Close()
	return decryptStream(key, ad, nonce, in, out)
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

func (ct *component) ParseInputs() error {
	var err error
	switch {
	case ct.file != "":
		fd, err := os.Open(ct.file)
		if err != nil {
			if err != nil {
				return fmt.Errorf("%s file: %w", ct.name, err)
			}
		}
		defer fd.Close()

		fileinfo, err := fd.Stat()
		if err != nil {
			return fmt.Errorf("%s file: %w", ct.name, err)
		}
		readsize := fileinfo.Size()
		if ct.length > 0 {
			readsize = int64(ct.length)
		}
		ct.raw = make([]byte, readsize)
		n, err := fd.Read(ct.raw)

		if err != nil {
			return fmt.Errorf("%s file: %w", ct.name, err)

		}
		if n < ct.length {
			fmt.Printf("%s file: must be at least %d bytes long (input is %d bytes)\n", ct.name, ct.length, n)
		}
		ct.length = len(ct.raw)

	case ct.encoded != "":
		ct.raw, err = base64.StdEncoding.DecodeString(ct.encoded)
		if err != nil {
			return fmt.Errorf("%s string decode: %w", ct.name, err)

		}
		if len(ct.raw) < ct.length {
			return fmt.Errorf("%s string: decoded content must be at least %d bytes (input is %d bytes)", ct.name, ct.length, len(ct.raw))
		}
		if ct.length > 0 && len(ct.raw) > ct.length {
			// Truncate the raw bytes to the desired length
			ct.raw = ct.raw[:ct.length]
		}
		ct.length = len(ct.raw)

	default:
		if ct.length <= 0 {
			return nil
		}
		ct.raw = make([]byte, ct.length)
		_, err := rand.Read(ct.raw[:])
		if err != nil {
			fmt.Printf("%s generation: %s\n", ct.name, err)

		}
	}
	if ct.encoded == "" {
		ct.encoded = base64.StdEncoding.EncodeToString(ct.raw)
	}
	return nil
}
