package help

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
)

func CloseHandle(hP, hT uintptr) {
	windows.CloseHandle(windows.Handle(hP))
	windows.CloseHandle(windows.Handle(hT))
}

func HexToString(str string) string {

	bs, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return string(bs)
}
func Log(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
