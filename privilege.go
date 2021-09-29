package edrRecon

import (
	"os"
)

func CheckIfAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// func ElevateAdmin() error {
// 	verb := "runas"
// 	exe, _ := os.Executable()
// 	cwd, _ := os.Getwd()
// 	args := strings.Join(os.Args[1:], " ")

// 	verbPtr, _ := syscall.UTF16PtrFromString(verb)
// 	exePtr, _ := syscall.UTF16PtrFromString(exe)
// 	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
// 	argPtr, _ := syscall.UTF16PtrFromString(args)

// 	var showCmd int32 = 1 //SW_NORMAL

// 	if err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd); err != nil {
// 		return err
// 	}

// 	return nil
// }
