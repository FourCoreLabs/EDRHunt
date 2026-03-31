package edrRecon

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsBuildRequireSeDebugForDriverAddresses = 26100

type osVersionInfoExW struct {
	dwOSVersionInfoSize uint32
	dwMajorVersion      uint32
	dwMinorVersion      uint32
	dwBuildNumber       uint32
	dwPlatformId        uint32
	szCSDVersion        [128]uint16
	wServicePackMajor   uint16
	wServicePackMinor   uint16
	wSuiteMask          uint16
	wProductType        byte
	wReserved           byte
}

func getWindowsBuildNumber() (uint32, error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rtlGetVersion := ntdll.NewProc("RtlGetVersion")

	versionInfo := osVersionInfoExW{dwOSVersionInfoSize: uint32(unsafe.Sizeof(osVersionInfoExW{}))}
	r1, _, callErr := rtlGetVersion.Call(uintptr(unsafe.Pointer(&versionInfo)))
	if r1 != 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return 0, fmt.Errorf("RtlGetVersion failed: %w", callErr)
		}
		return 0, fmt.Errorf("RtlGetVersion returned NTSTATUS 0x%x", uint32(r1))
	}

	return versionInfo.dwBuildNumber, nil
}

func enableSeDebugPrivilegeIfRequired() error {
	buildNumber, err := getWindowsBuildNumber()
	if err != nil {
		return nil
	}

	if buildNumber < windowsBuildRequireSeDebugForDriverAddresses {
		return nil
	}

	var token windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &token)
	if err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("failed to lookup SeDebugPrivilege LUID: %w", err)
	}

	tokenPrivileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &tokenPrivileges, 0, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to adjust token privileges: %w", err)
	}

	if windows.GetLastError() == windows.ERROR_NOT_ALL_ASSIGNED {
		return fmt.Errorf("failed to enable SeDebugPrivilege: %w", windows.ERROR_NOT_ALL_ASSIGNED)
	}

	return nil
}
