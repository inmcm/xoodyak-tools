package console

import (
	"fmt"
	"os"
)

var (
	suppressPrint bool
)

func SetQuiet(quiet bool) {
	suppressPrint = quiet
}

func Printf(format string, a ...interface{}) (n int, err error) {
	if !suppressPrint {
		return fmt.Fprintf(os.Stderr, format, a...)
	}
	return 0, nil
}

func Println(a ...interface{}) (n int, err error) {
	if !suppressPrint {
		return fmt.Fprintln(os.Stderr, a...)
	}
	return 0, nil
}
