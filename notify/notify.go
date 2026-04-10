//go:build windows

// Package notify sends Windows toast notifications via WinRT COM directly,
// without spawning a PowerShell subprocess.
package notify

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ------------------------------------------------------------------ procs ---

var (
	combase = windows.NewLazySystemDLL("combase.dll")

	procRoInitialize           = combase.NewProc("RoInitialize")
	procRoActivateInstance     = combase.NewProc("RoActivateInstance")
	procRoGetActivationFactory = combase.NewProc("RoGetActivationFactory")
	procWindowsCreateString    = combase.NewProc("WindowsCreateString")
	procWindowsDeleteString    = combase.NewProc("WindowsDeleteString")
)

// --------------------------------------------------------------- HSTRING ---

type hstring uintptr

func newHString(s string) (hstring, error) {
	utf16, err := syscall.UTF16FromString(s)
	if err != nil {
		return 0, err
	}
	var h hstring
	r, _, _ := procWindowsCreateString.Call(
		uintptr(unsafe.Pointer(&utf16[0])),
		uintptr(len(utf16)-1), // length without null terminator
		uintptr(unsafe.Pointer(&h)),
	)
	if r != 0 {
		return 0, fmt.Errorf("WindowsCreateString: 0x%08x", r)
	}
	return h, nil
}

func deleteHString(h hstring) {
	if h != 0 {
		procWindowsDeleteString.Call(uintptr(h))
	}
}

// ---------------------------------------------------------- COM vtable ---

// vtblCall invokes the COM/WinRT method at vtable[idx] on obj.
// obj is prepended automatically as the 'this' pointer.
func vtblCall(obj uintptr, idx int, args ...uintptr) uintptr {
	vtable := *(*uintptr)(unsafe.Pointer(obj))
	method := *(*uintptr)(unsafe.Pointer(vtable + uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	all := make([]uintptr, 0, 1+len(args))
	all = append(all, obj)
	all = append(all, args...)
	r, _, _ := syscall.SyscallN(method, all...)
	return r
}

// vtblRelease calls IUnknown::Release (vtable[2]).
func vtblRelease(obj uintptr) {
	if obj != 0 {
		vtblCall(obj, 2)
	}
}

// ---------------------------------------------------------------- GUIDs ---

var (
	// IXmlDocumentIO — {6CD0E74E-EE65-4489-9EBF-CA43E87BA637}
	iidXmlDocumentIO = windows.GUID{
		Data1: 0x6CD0E74E, Data2: 0xEE65, Data3: 0x4489,
		Data4: [8]byte{0x9E, 0xBF, 0xCA, 0x43, 0xE8, 0x7B, 0xA6, 0x37},
	}
	// IXmlDocument — {F7F3A506-1E87-42D6-BCFB-B8C809FA5494}
	iidXmlDocument = windows.GUID{
		Data1: 0xF7F3A506, Data2: 0x1E87, Data3: 0x42D6,
		Data4: [8]byte{0xBC, 0xFB, 0xB8, 0xC8, 0x09, 0xFA, 0x54, 0x94},
	}
	// IToastNotificationManagerStatics — {50AC103F-D235-4598-BBEF-98FE4D1A3AD4}
	iidToastMgrStatics = windows.GUID{
		Data1: 0x50AC103F, Data2: 0xD235, Data3: 0x4598,
		Data4: [8]byte{0xBB, 0xEF, 0x98, 0xFE, 0x4D, 0x1A, 0x3A, 0xD4},
	}
	// IToastNotificationFactory — {04124B20-82C6-4229-B109-FD9ED4662B53}
	iidToastNotificationFactory = windows.GUID{
		Data1: 0x04124B20, Data2: 0x82C6, Data3: 0x4229,
		Data4: [8]byte{0xB1, 0x09, 0xFD, 0x9E, 0xD4, 0x66, 0x2B, 0x53},
	}
)

// ----------------------------------------------------------------- API ---

// Action represents a button shown in the toast notification.
// URL must be a protocol-handler URI (e.g. "nvm://command?p=x").
type Action struct {
	Label string
	URL   string
}

// Register ensures appID is registered as a known AUMID with the Windows
// notification platform. This must be called (or happen via Send) before
// notifications will be displayed for unpackaged Win32 apps.
func Register(appID, displayName string) error {
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\Classes\AppUserModelId\`+appID,
		registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf("notify register: %w", err)
	}
	defer key.Close()
	return key.SetStringValue("DisplayName", displayName)
}

// Send displays a Windows toast notification.
// title may be empty (single-line notification). appID is the AUMID.
// Optional actions are rendered as protocol-handler buttons.
// Errors are non-fatal; the caller should fall back to a console message.
func Send(appID, title, message string, actions ...Action) error {
	return sendWithSound(appID, title, message, "", actions...)
}

// SendWithSound displays a Windows toast notification with an optional sound URI.
// Use a Windows sound URI like "ms-winsoundevent:Notification.Default".
// When soundURI is empty, the toast is silent.
func SendWithAudio(appID, title, message, soundURI string, actions ...Action) error {
	return sendWithSound(appID, title, message, soundURI, actions...)
}

func sendWithSound(appID, title, message, soundURI string, actions ...Action) error {
	// Ensure the AUMID is registered; Windows silently drops notifications for
	// unregistered app IDs even when CreateToastNotifierWithId returns S_OK.
	Register(appID, appID)

	// RO_INIT_MULTITHREADED = 1
	// 0x00000001 = S_FALSE — already initialised in same apartment, safe to ignore.
	// 0x80010106 = RPC_E_CHANGED_MODE — already initialised differently, safe to ignore.
	r, _, _ := procRoInitialize.Call(1)
	if r != 0 && r != 0x00000001 && r != 0x80010106 {
		return fmt.Errorf("RoInitialize: 0x%08x", r)
	}

	xml := buildXML(title, message, soundURI, actions)

	// --- Load XML into a Windows.Data.Xml.Dom.XmlDocument ---
	xmlClassID, err := newHString("Windows.Data.Xml.Dom.XmlDocument")
	if err != nil {
		return err
	}
	defer deleteHString(xmlClassID)

	var xmlDocObj uintptr // IInspectable*
	r, _, _ = procRoActivateInstance.Call(
		uintptr(xmlClassID),
		uintptr(unsafe.Pointer(&xmlDocObj)),
	)
	if r != 0 {
		return fmt.Errorf("RoActivateInstance XmlDocument: 0x%08x", r)
	}
	defer vtblRelease(xmlDocObj)

	// QI for IXmlDocumentIO → LoadXml at vtable[6]
	var xmlDocIO uintptr
	r = vtblCall(xmlDocObj, 0,
		uintptr(unsafe.Pointer(&iidXmlDocumentIO)),
		uintptr(unsafe.Pointer(&xmlDocIO)),
	)
	if r != 0 {
		return fmt.Errorf("QI IXmlDocumentIO: 0x%08x", r)
	}
	defer vtblRelease(xmlDocIO)

	xmlHStr, err := newHString(xml)
	if err != nil {
		return err
	}
	defer deleteHString(xmlHStr)

	r = vtblCall(xmlDocIO, 6, uintptr(xmlHStr)) // IXmlDocumentIO::LoadXml
	if r != 0 {
		return fmt.Errorf("LoadXml: 0x%08x", r)
	}

	// QI for IXmlDocument (required by CreateToastNotification)
	var xmlDoc uintptr
	r = vtblCall(xmlDocObj, 0,
		uintptr(unsafe.Pointer(&iidXmlDocument)),
		uintptr(unsafe.Pointer(&xmlDoc)),
	)
	if r != 0 {
		return fmt.Errorf("QI IXmlDocument: 0x%08x", r)
	}
	defer vtblRelease(xmlDoc)

	// --- Get IToastNotificationManagerStatics → IToastNotifier ---
	mgrClassID, err := newHString("Windows.UI.Notifications.ToastNotificationManager")
	if err != nil {
		return err
	}
	defer deleteHString(mgrClassID)

	var toastMgrStatics uintptr
	r, _, _ = procRoGetActivationFactory.Call(
		uintptr(mgrClassID),
		uintptr(unsafe.Pointer(&iidToastMgrStatics)),
		uintptr(unsafe.Pointer(&toastMgrStatics)),
	)
	if r != 0 {
		return fmt.Errorf("RoGetActivationFactory ToastNotificationManager: 0x%08x", r)
	}
	defer vtblRelease(toastMgrStatics)

	appIDHStr, err := newHString(appID)
	if err != nil {
		return err
	}
	defer deleteHString(appIDHStr)

	var notifier uintptr
	r = vtblCall(toastMgrStatics, 7, // IToastNotificationManagerStatics::CreateToastNotifierWithId
		uintptr(appIDHStr),
		uintptr(unsafe.Pointer(&notifier)),
	)
	if r != 0 {
		return fmt.Errorf("CreateToastNotifierWithId: 0x%08x", r)
	}
	defer vtblRelease(notifier)

	// --- Get IToastNotificationFactory → IToastNotification ---
	toastClassID, err := newHString("Windows.UI.Notifications.ToastNotification")
	if err != nil {
		return err
	}
	defer deleteHString(toastClassID)

	var toastNotifFactory uintptr
	r, _, _ = procRoGetActivationFactory.Call(
		uintptr(toastClassID),
		uintptr(unsafe.Pointer(&iidToastNotificationFactory)),
		uintptr(unsafe.Pointer(&toastNotifFactory)),
	)
	if r != 0 {
		return fmt.Errorf("RoGetActivationFactory ToastNotification: 0x%08x", r)
	}
	defer vtblRelease(toastNotifFactory)

	var toast uintptr
	r = vtblCall(toastNotifFactory, 6, // IToastNotificationFactory::CreateToastNotification
		xmlDoc,
		uintptr(unsafe.Pointer(&toast)),
	)
	if r != 0 {
		return fmt.Errorf("CreateToastNotification: 0x%08x", r)
	}
	defer vtblRelease(toast)

	// --- IToastNotifier::Show at vtable[6] ---
	r = vtblCall(notifier, 6, toast)
	if r != 0 {
		return fmt.Errorf("Show: 0x%08x", r)
	}

	return nil
}

// --------------------------------------------------------- XML builder ---

func buildXML(title, message, soundURI string, actions []Action) string {
	var sb strings.Builder
	sb.WriteString(`<toast><visual><binding template="ToastGeneric">`)
	if title != "" {
		sb.WriteString("<text>")
		sb.WriteString(escapeXML(title))
		sb.WriteString("</text>")
	}
	sb.WriteString("<text>")
	sb.WriteString(escapeXML(message))
	sb.WriteString("</text>")
	sb.WriteString(`</binding></visual>`)
	if strings.TrimSpace(soundURI) == "" {
		sb.WriteString(`<audio silent="true"/>`)
	} else {
		sb.WriteString(`<audio src="`)
		sb.WriteString(escapeXML(strings.TrimSpace(soundURI)))
		sb.WriteString(`"/>`)
	}
	if len(actions) > 0 {
		sb.WriteString("<actions>")
		for _, a := range actions {
			sb.WriteString(`<action content="`)
			sb.WriteString(escapeXML(a.Label))
			sb.WriteString(`" arguments="`)
			sb.WriteString(escapeXML(a.URL))
			sb.WriteString(`" activationType="protocol"/>`)
		}
		sb.WriteString("</actions>")
	}
	sb.WriteString("</toast>")
	return sb.String()
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}
