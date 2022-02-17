package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/inmcm/xoodoo/xoodyak"
)

var (
	quiet bool
)

func main() {
	flag.BoolVar(&quiet, "q", false, "Quiet mode - only the checksum is printed out")
	flag.BoolVar(&quiet, "quiet", false, "Quiet mode - only the checksum is printed out")

	flag.Usage = printHelp
	flag.Parse()

	if len(flag.Args()) == 0 {
		hashStdIn()
	} else {
		hashFiles(flag.Args())
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

func hashFiles(files []string) int {
	rc := 0
	for _, t := range files {
		fd, err := os.Open(t)
		if err != nil {
			fmt.Printf("xoodyak: %s\n", err)
			rc |= 1
			continue
		}
		hasher := xoodyak.NewXoodyakHash()
		n, err := io.Copy(hasher, fd)
		if err != nil {
			fmt.Printf("xoodyak: %s\n", err)
			rc |= 1
			continue
		}
		hash := hasher.Sum(nil)
		printOutput(hash, n, path.Base(t))
		fd.Close()
	}
	return rc
}

func hashStdIn() int {
	info, err := os.Stdin.Stat()
	if err != nil {
		printHelp()
		return 1
	}
	// if info.Mode()&os.ModeNamedPipe == 0 {
	if info.Mode()&os.ModeCharDevice == 0 {
		printHelp()
		return 1
	}
	reader := bufio.NewReader(os.Stdin)
	hasher := xoodyak.NewXoodyakHash()
	n, err := io.Copy(hasher, reader)
	if err != nil {
		fmt.Printf("xoodyak: %s\n", err)
		return 1
	}
	hash := hasher.Sum(nil)
	printOutput(hash, n, "")
	return 0
}
