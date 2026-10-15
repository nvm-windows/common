//go:build windows

package system

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wscProviderAntivirus = 0x4
	coinitApartment      = 0x2
	clsctxInprocServer   = 0x1
	rpcEChangedMode      = 0x80010106
	sFalse               = 1
)

// CLSID_WSCProductList and IID_IWSCProductList from iwscapi.h.
var (
	clsidWSCProductList = windows.GUID{
		Data1: 0x17072F7B,
		Data2: 0x9ABE,
		Data3: 0x4A74,
		Data4: [8]byte{0xA2, 0x61, 0x1E, 0xB7, 0x6B, 0x55, 0x10, 0x7A},
	}
	iidIWSCProductList = windows.GUID{
		Data1: 0x722A338C,
		Data2: 0x6E8E,
		Data3: 0x4E72,
		Data4: [8]byte{0xAC, 0x27, 0x14, 0x17, 0xFB, 0x0C, 0x81, 0xC2},
	}
	procSysFreeString    = windows.NewLazySystemDLL("oleaut32.dll").NewProc("SysFreeString")
	procCoCreateInstance = windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance")
)

// IDispatch is 7 methods. IWSCProductList adds Initialize, get_Count, get_Item.
type wscProductListVtbl struct {
	QueryInterface   uintptr
	AddRef           uintptr
	Release          uintptr
	GetTypeInfoCount uintptr
	GetTypeInfo      uintptr
	GetIDsOfNames    uintptr
	Invoke           uintptr
	Initialize       uintptr
	GetCount         uintptr
	GetItem          uintptr
}

// IWscProduct starts with IDispatch, then get_ProductName.
type wscProductVtbl struct {
	QueryInterface   uintptr
	AddRef           uintptr
	Release          uintptr
	GetTypeInfoCount uintptr
	GetTypeInfo      uintptr
	GetIDsOfNames    uintptr
	Invoke           uintptr
	GetProductName   uintptr
}

type wscObject struct {
	vtbl *wscProductListVtbl
}

type wscProduct struct {
	vtbl *wscProductVtbl
}

// Agents that often do not register in Security Center.
var knownAntivirusAgents = []struct {
	service string
	label   string
}{
	{service: "ArcticWolfAgent", label: "Arctic Wolf Agent"},
	{service: "CSFalconService", label: "CrowdStrike Falcon"},
	{service: "SentinelAgent", label: "SentinelOne"},
	{service: "CylanceSvc", label: "Cylance"},
	{service: "CarbonBlack", label: "Carbon Black"},
	{service: "CBDefense", label: "Carbon Black"},
}

func init() {
	detectAntivirusProducts = detectAntivirusProductsSystem
}

func detectAntivirusProductsSystem() []string {
	names := securityCenterAntivirusNames()
	names = append(names, runningKnownAgentLabels()...)
	return names
}

func securityCenterAntivirusNames() []string {
	hr := windows.CoInitializeEx(0, coinitApartment)
	if hr != nil && !comAlreadyInitialized(hr) {
		return nil
	}
	if hr == nil || comSuccessExtra(hr) {
		defer windows.CoUninitialize()
	}

	unk, err := coCreateWSCProductList()
	if err != nil || unk == nil {
		return nil
	}
	list := (*wscObject)(unk)
	defer comRelease(list.vtbl.Release, unk)

	if comHRESULT(syscall.SyscallN(list.vtbl.Initialize, uintptr(unk), wscProviderAntivirus)) != nil {
		return nil
	}
	var count int32
	if comHRESULT(syscall.SyscallN(list.vtbl.GetCount, uintptr(unk), uintptr(unsafe.Pointer(&count)))) != nil || count <= 0 {
		return nil
	}
	names := make([]string, 0, count)
	for i := int32(0); i < count; i++ {
		var item unsafe.Pointer
		if comHRESULT(syscall.SyscallN(list.vtbl.GetItem, uintptr(unk), uintptr(uint32(i)), uintptr(unsafe.Pointer(&item)))) != nil || item == nil {
			continue
		}
		product := (*wscProduct)(item)
		var bstr *uint16
		hr := comHRESULT(syscall.SyscallN(product.vtbl.GetProductName, uintptr(item), uintptr(unsafe.Pointer(&bstr))))
		name := ""
		if hr == nil && bstr != nil {
			name = windows.UTF16PtrToString(bstr)
		}
		freeBSTR(bstr)
		comRelease(product.vtbl.Release, item)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func runningKnownAgentLabels() []string {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(scm)

	var labels []string
	for _, agent := range knownAntivirusAgents {
		name, err := windows.UTF16PtrFromString(agent.service)
		if err != nil {
			continue
		}
		handle, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
		if err != nil {
			continue
		}
		var status windows.SERVICE_STATUS
		err = windows.QueryServiceStatus(handle, &status)
		windows.CloseServiceHandle(handle)
		if err == nil && status.CurrentState == windows.SERVICE_RUNNING {
			labels = append(labels, agent.label)
		}
	}
	return labels
}

func coCreateWSCProductList() (unsafe.Pointer, error) {
	var unk unsafe.Pointer
	hr, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidWSCProductList)),
		0,
		clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidIWSCProductList)),
		uintptr(unsafe.Pointer(&unk)),
	)
	if hr != 0 {
		return nil, syscall.Errno(hr)
	}
	return unk, nil
}

func comAlreadyInitialized(err error) bool {
	errno, ok := err.(syscall.Errno)
	if !ok {
		return false
	}
	return uint32(errno) == sFalse || uint32(errno) == rpcEChangedMode
}

func comSuccessExtra(err error) bool {
	errno, ok := err.(syscall.Errno)
	return ok && uint32(errno) == sFalse
}

func comHRESULT(hr uintptr, _ uintptr, _ error) error {
	if hr == 0 {
		return nil
	}
	return syscall.Errno(hr)
}

func comRelease(release uintptr, obj unsafe.Pointer) {
	if release == 0 || obj == nil {
		return
	}
	_, _, _ = syscall.SyscallN(release, uintptr(obj))
}

func freeBSTR(bstr *uint16) {
	if bstr == nil {
		return
	}
	_, _, _ = procSysFreeString.Call(uintptr(unsafe.Pointer(bstr)))
}
