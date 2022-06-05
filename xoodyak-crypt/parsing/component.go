package parsing

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/inmcm/xoodyak-tools/xoodyak-crypt/console"
)

var (
	randReader func(b []byte) (n int, err error) = rand.Read
)

type Component struct {
	Name      string // component name
	Raw       []byte // bytes read/decoded
	File      string // absolute path to file containing bytes
	Encoded   string // Base64 encoded version
	Length    int    // Required/populated length, -1 if unlimited
	Generated bool
}

func (ct *Component) Parse(cfgInput string) error {

	var err error
	switch {
	case ct.File != "":
		fd, err := os.Open(ct.File)
		if err != nil {
			if err != nil {
				return fmt.Errorf("%s file: %w", ct.Name, err)
			}
		}
		defer fd.Close()

		fileInfo, err := fd.Stat()
		if err != nil {
			return fmt.Errorf("%s file: %w", ct.Name, err)
		}
		readSize := fileInfo.Size()
		if readSize == 0 && ct.Length > 0 {
			return fmt.Errorf("%s file (%s) contains 0 bytes; requires %d bytes", ct.Name, ct.File, ct.Length)
		}
		if ct.Length > 0 {
			readSize = int64(ct.Length)
		}
		ct.Raw = make([]byte, readSize)
		n, err := fd.Read(ct.Raw)

		if err != nil {
			return fmt.Errorf("%s file: %w", ct.Name, err)

		}
		if n < ct.Length {
			console.Printf("%s file (%s): must be at least %d bytes long (input is %d bytes)\n", ct.Name, ct.File, ct.Length, n)
		}
		ct.Length = len(ct.Raw)

	case ct.Encoded != "", cfgInput != "":
		if cfgInput != "" && ct.Encoded == "" {
			// config file input only takes precedence if no other encoded input is expressly provided
			ct.Encoded = cfgInput
		}
		ct.Raw, err = base64.StdEncoding.DecodeString(ct.Encoded)
		if err != nil {
			return fmt.Errorf("%s string decode: %w", ct.Name, err)

		}
		if len(ct.Raw) < ct.Length {
			return fmt.Errorf("%s string: decoded content must be at least %d bytes (input is %d bytes)", ct.Name, ct.Length, len(ct.Raw))
		}
		if ct.Length > 0 && len(ct.Raw) > ct.Length {
			// Truncate the raw bytes to the desired length
			ct.Raw = ct.Raw[:ct.Length]
		}
		ct.Length = len(ct.Raw)

	default:
		if ct.Length <= 0 {
			return nil
		}
		ct.Raw = make([]byte, ct.Length)
		_, err := randReader(ct.Raw[:])
		if err != nil {
			return fmt.Errorf("%s generation: %s", ct.Name, err)

		}
		ct.Generated = true
	}
	if ct.Encoded == "" {
		ct.Encoded = base64.StdEncoding.EncodeToString(ct.Raw)
	}
	return nil
}
