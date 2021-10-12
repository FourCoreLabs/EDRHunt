package edrRecon

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	// Library
	libpsapi uintptr
	// Functions
	enumDeviceDrivers       uintptr
	getDeviceDriverBaseName uintptr
	getDeviceDriverFileName uintptr
	numberOfDrivers         uint
	driverAddrs             []uintptr
)

type DWORD uint32
type LPVOID uintptr
type LPVOIDARR []byte
type LPWSTR *uint16

type UTF16Slice struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

func init() {
	// Library
	libpsapi = doLoadLibrary("psapi.dll")
	// Functions
	enumDeviceDrivers = doGetProcAddress(libpsapi, "EnumDeviceDrivers")
	getDeviceDriverBaseName = doGetProcAddress(libpsapi, "GetDeviceDriverBaseNameW")
	getDeviceDriverFileName = doGetProcAddress(libpsapi, "GetDeviceDriverFileNameW")
}

func doLoadLibrary(name string) uintptr {
	lib, _ := syscall.LoadLibrary(name)
	return uintptr(lib)
}

func doGetProcAddress(lib uintptr, name string) uintptr {
	addr, _ := syscall.GetProcAddress(syscall.Handle(lib), name)
	return uintptr(addr)
}

func syscall3(trap, nargs, a1, a2, a3 uintptr) uintptr {
	ret, _, _ := syscall.Syscall(trap, nargs, a1, a2, a3)
	return ret
}

// func syscall6(trap, nargs, a1, a2, a3, a4, a5, a6 uintptr) uintptr {
// 	ret, _, _ := syscall.Syscall6(trap, nargs, a1, a2, a3, a4, a5, a6)
// 	return ret
// }

// dodgy function: may cause BOF
func UTF16PtrToString(p *uint16) string {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	if p == nil {
		return ""
	}
	if *p == 0 {
		return ""
	}

	// Find NUL terminator.
	n := 0
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; n++ {
		ptr = unsafe.Pointer(uintptr(ptr) + unsafe.Sizeof(*p))
	}

	var s []uint16
	h := (*UTF16Slice)(unsafe.Pointer(&s))
	h.Data = unsafe.Pointer(p)
	h.Len = n
	h.Cap = n

	return string(utf16.Decode(s))
}

func EnumDeviceDrivers(lpImageBase []uintptr, cb DWORD, lpcbNeeded *uint32) bool {
	ret1 := syscall3(enumDeviceDrivers, 3,
		uintptr(unsafe.Pointer(&lpImageBase[0])),
		uintptr(cb),
		uintptr(unsafe.Pointer(lpcbNeeded)))
	return ret1 != 0
}

func GetDeviceDriverBaseName(imageBase LPVOID, lpBaseName []uint16, nSize DWORD) DWORD {
	ret1 := syscall3(getDeviceDriverBaseName, 3,
		uintptr(unsafe.Pointer(imageBase)),
		uintptr(unsafe.Pointer(&lpBaseName[0])),
		uintptr(nSize))
	return DWORD(ret1)
}

func GetDeviceDriverFileName(imageBase uintptr, lpFilename []uint16, nSize DWORD) DWORD {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("failure in GetDeviceDriverFilename")
			fmt.Println(err)
			return
		}
	}()

	ret1 := syscall3(getDeviceDriverFileName, 3,
		imageBase,
		uintptr(unsafe.Pointer(&lpFilename[0])),
		uintptr(nSize))
	return DWORD(ret1)
}

func GetSizeOfDriversArray() (uint32, error) {
	var bytesNeeded uint32
	// Golang null structs.
	nullBase := make([]uintptr, 1)
	success := EnumDeviceDrivers(nullBase, 0, &bytesNeeded)
	if !success {
		return 0, fmt.Errorf("failed to get size of Driver Array, errorcode : %v", syscall.GetLastError())
	}
	return bytesNeeded, nil
}

func GetDriverFileName(driverAddrs uintptr) (string, error) {
	data := make([]uint16, 1024)

	if driverAddrs == 0 {
		return "", errors.New("nil driver address uintptr")
	}

	result := GetDeviceDriverFileName(driverAddrs, data, DWORD(1000))
	if result == 0 {
		return "", fmt.Errorf("failed to get device driver file name: %v", syscall.GetLastError())
	}

	return syscall.UTF16ToString(data), nil
}

func GetDriverBaseName(driverAddrs uintptr) (string, error) {
	data := make([]uint16, 1024)

	if driverAddrs == 0 {
		return "", errors.New("nil driver address uintptr")
	}

	result := GetDeviceDriverBaseName(LPVOID(driverAddrs), data, DWORD(1000))
	if result == 0 {
		return "", fmt.Errorf("failed to get device driver file name: %v", syscall.GetLastError())
	}

	return syscall.UTF16ToString(data), nil
}

func IterateOverDrivers(numberOfDrivers uint, driverAddrs []uintptr) ([]DriverMetaData, []string) {

	var (
		// counter  uint
		errArray []string
		summary  []DriverMetaData = make([]DriverMetaData, 0)
	)

	for _, addr := range driverAddrs {
		driverFileName, err := GetDriverFileName(addr)
		if err != nil {
			errArray = append(errArray, fmt.Sprintf("%v", err))
			continue
		}
		driverBaseName, err := GetDriverBaseName(addr)
		if err != nil {
			errArray = append(errArray, fmt.Sprintf("%v", err))
			continue
		}
		output, err := AnalyzeDriver(driverFileName, driverBaseName)
		if err != nil {
			errArray = append(errArray, fmt.Sprintf("%v", err))
		}
		if output.DriverBaseName == "" {
			continue
		}
		summary = append(summary, output)
	}

	// for counter = 0; counter < numberOfDrivers; counter++ {
	// }
	return summary, errArray
}

func AnalyzeDriver(driverFileName string, driverBaseName string) (DriverMetaData, error) {
	var err error

	fixedDriverPath := strings.ToLower(driverFileName)
	fixedDriverPath = strings.Replace(fixedDriverPath, `\systemroot\`, `c:\windows\`, -1)
	if strings.HasPrefix(fixedDriverPath, `\windows\`) {
		fixedDriverPath = strings.Replace(fixedDriverPath, `\windows\`, `c:\windows\`, -1)
	} else if strings.HasPrefix(fixedDriverPath, `\??\`) {
		fixedDriverPath = strings.Replace(fixedDriverPath, `\??\`, ``, -1)
	}
	analysis := DriverMetaData{
		DriverBaseName: driverBaseName,
		DriverFilePath: fixedDriverPath,
		ScanMatch:      make([]string, 0),
	}

	analysis.DriverSysMetaData, err = GetFileMetaData(fixedDriverPath)

	for _, edr := range EdrList {
		//regexp as alternate but saving another import. No bully.
		if strings.Contains(
			strings.ToLower(fmt.Sprint(analysis)),
			strings.ToLower(edr)) {
			analysis.ScanMatch = append(analysis.ScanMatch, edr)
		}
	}

	if len(analysis.ScanMatch) > 0 {
		return analysis, err
	}

	return DriverMetaData{ScanMatch: make([]string, 0)}, err
}

// CheckDrivers return a list of drivers matching any suspicious driver names present in edrdata.go.
func CheckDrivers() ([]DriverMetaData, error) {
	sizeOfDriverArrayInBytes, err := GetSizeOfDriversArray()
	if err != nil {
		return []DriverMetaData{}, err
	}

	sizeOfOneDriverAddress := uint(unsafe.Sizeof(uintptr(0)))
	numberOfDrivers = uint(sizeOfDriverArrayInBytes) / sizeOfOneDriverAddress
	driverAddrs = make([]uintptr, numberOfDrivers)

	success := EnumDeviceDrivers(driverAddrs, DWORD(sizeOfDriverArrayInBytes), &sizeOfDriverArrayInBytes)
	if !success {
		return []DriverMetaData{}, fmt.Errorf("failed to enumerate device drivers, error code: %d", syscall.GetLastError())
	}

	// filterErrArray optional || Don't bully.
	summary, filterErrArray := IterateOverDrivers(numberOfDrivers, driverAddrs)
	if strings.TrimSpace(strings.Join(filterErrArray, "")) != "" {
		return summary, fmt.Errorf("%s", filterErrArray)
	}
	return summary, nil
}
