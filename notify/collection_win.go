//go:build windows

package notify

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iidToastMgrStatics5 = windows.GUID{
		Data1: 0xd6f5f569, Data2: 0xd40d, Data3: 0x407c,
		Data4: [8]byte{0x89, 0x89, 0x88, 0xca, 0xb4, 0x2c, 0xfd, 0x14},
	}
	iidToastMgrForUser2 = windows.GUID{
		Data1: 0x679c64b7, Data2: 0x81ab, Data3: 0x42c2,
		Data4: [8]byte{0x88, 0x19, 0xc9, 0x58, 0x76, 0x77, 0x53, 0xf4},
	}
	iidToastCollectionFactory = windows.GUID{
		Data1: 0x164dd3d7, Data2: 0x73c4, Data3: 0x44f7,
		Data4: [8]byte{0xb4, 0xff, 0xfb, 0x6d, 0x4b, 0xf1, 0xf4, 0xc6},
	}
	iidAsyncInfo = windows.GUID{
		Data1: 0x00000036, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
	iidUriFactory = windows.GUID{
		Data1: 0x44A9796F, Data2: 0x723E, Data3: 0x4FDF,
		Data4: [8]byte{0xA2, 0x18, 0x03, 0x3E, 0x75, 0xB0, 0xC0, 0x84},
	}
)

var ensureCollectionsOnce sync.Once

const (
	notificationSettingEnabled = 0
	asyncStatusCompleted       = 1
	asyncStatusCanceled        = 2
	asyncStatusError           = 3
)

func notifierSettingDisabled(notifier uintptr) bool {
	if notifier == 0 {
		return false
	}
	var setting int32
	r := vtblCall(notifier, 8, uintptr(unsafe.Pointer(&setting))) // IToastNotifier::get_Setting
	if r != 0 {
		return false
	}
	return setting != notificationSettingEnabled
}

func notifierForCollection(toastMgrStatics uintptr, appID, collectionID string) (uintptr, error) {
	ensureCollectionsOnce.Do(func() {
		_ = saveLiveCollections(toastMgrStatics, appID)
	})
	user, err := toastManagerForUser(toastMgrStatics)
	if err != nil {
		return 0, err
	}
	defer vtblRelease(user)

	var user2 uintptr
	r := vtblCall(user, 0, uintptr(unsafe.Pointer(&iidToastMgrForUser2)), uintptr(unsafe.Pointer(&user2)))
	if r != 0 || user2 == 0 {
		return 0, fmt.Errorf("QI IToastNotificationManagerForUser2: 0x%08x", r)
	}
	defer vtblRelease(user2)

	colH, err := newHString(collectionID)
	if err != nil {
		return 0, err
	}
	defer deleteHString(colH)

	var op uintptr
	r = vtblCall(user2, 6, uintptr(colH), uintptr(unsafe.Pointer(&op))) // GetToastNotifierForToastCollectionIdAsync
	if r != 0 || op == 0 {
		return 0, fmt.Errorf("GetToastNotifierForToastCollectionIdAsync: 0x%08x", r)
	}
	defer vtblRelease(op)
	if err := waitAsync(op, 2*time.Second); err != nil {
		return 0, err
	}
	var notifier uintptr
	r = vtblCall(op, 8, uintptr(unsafe.Pointer(&notifier))) // IAsyncOperation::GetResults
	if r != 0 || notifier == 0 {
		return 0, fmt.Errorf("collection notifier GetResults: 0x%08x", r)
	}
	return notifier, nil
}

func toastManagerForUser(toastMgrStatics uintptr) (uintptr, error) {
	var statics5 uintptr
	r := vtblCall(toastMgrStatics, 0, uintptr(unsafe.Pointer(&iidToastMgrStatics5)), uintptr(unsafe.Pointer(&statics5)))
	if r != 0 || statics5 == 0 {
		return 0, fmt.Errorf("QI IToastNotificationManagerStatics5: 0x%08x", r)
	}
	defer vtblRelease(statics5)
	var user uintptr
	r = vtblCall(statics5, 6, uintptr(unsafe.Pointer(&user))) // GetDefault
	if r != 0 || user == 0 {
		return 0, fmt.Errorf("GetDefault: 0x%08x", r)
	}
	return user, nil
}

func saveLiveCollections(toastMgrStatics uintptr, appID string) error {
	user, err := toastManagerForUser(toastMgrStatics)
	if err != nil {
		return err
	}
	defer vtblRelease(user)

	var user2 uintptr
	r := vtblCall(user, 0, uintptr(unsafe.Pointer(&iidToastMgrForUser2)), uintptr(unsafe.Pointer(&user2)))
	if r != 0 || user2 == 0 {
		return fmt.Errorf("QI ForUser2: 0x%08x", r)
	}
	defer vtblRelease(user2)

	appH, err := newHString(appID)
	if err != nil {
		return err
	}
	defer deleteHString(appH)

	var mgr uintptr
	r = vtblCall(user2, 9, uintptr(appH), uintptr(unsafe.Pointer(&mgr))) // GetToastCollectionManagerWithAppId
	if r != 0 || mgr == 0 {
		return fmt.Errorf("GetToastCollectionManagerWithAppId: 0x%08x", r)
	}
	defer vtblRelease(mgr)

	for _, col := range LiveCollections() {
		if err := saveOneCollection(mgr, col.ID, col.Name); err != nil {
			return err
		}
	}
	return nil
}

func saveOneCollection(mgr uintptr, id, name string) error {
	classID, err := newHString("Windows.UI.Notifications.ToastCollection")
	if err != nil {
		return err
	}
	defer deleteHString(classID)

	var factory uintptr
	r, _, _ := procRoGetActivationFactory.Call(
		uintptr(classID),
		uintptr(unsafe.Pointer(&iidToastCollectionFactory)),
		uintptr(unsafe.Pointer(&factory)),
	)
	if r != 0 || factory == 0 {
		return fmt.Errorf("ToastCollection factory: 0x%08x", r)
	}
	defer vtblRelease(factory)

	idH, err := newHString(id)
	if err != nil {
		return err
	}
	defer deleteHString(idH)
	nameH, err := newHString(name)
	if err != nil {
		return err
	}
	defer deleteHString(nameH)
	launchH, err := newHString("nvm://")
	if err != nil {
		return err
	}
	defer deleteHString(launchH)

	icon, err := createURI("https://nvm-windows.com/favicon.ico")
	if err != nil {
		return err
	}
	defer vtblRelease(icon)

	var collection uintptr
	r = vtblCall(factory, 6, uintptr(idH), uintptr(nameH), uintptr(launchH), icon, uintptr(unsafe.Pointer(&collection)))
	if r != 0 || collection == 0 {
		return fmt.Errorf("ToastCollection.CreateInstance: 0x%08x", r)
	}
	defer vtblRelease(collection)

	var op uintptr
	r = vtblCall(mgr, 6, collection, uintptr(unsafe.Pointer(&op))) // SaveToastCollectionAsync
	if r != 0 || op == 0 {
		return fmt.Errorf("SaveToastCollectionAsync: 0x%08x", r)
	}
	defer vtblRelease(op)
	return waitAsync(op, 2*time.Second)
}

func createURI(raw string) (uintptr, error) {
	classID, err := newHString("Windows.Foundation.Uri")
	if err != nil {
		return 0, err
	}
	defer deleteHString(classID)
	var factory uintptr
	r, _, _ := procRoGetActivationFactory.Call(
		uintptr(classID),
		uintptr(unsafe.Pointer(&iidUriFactory)),
		uintptr(unsafe.Pointer(&factory)),
	)
	if r != 0 || factory == 0 {
		return 0, fmt.Errorf("Uri factory: 0x%08x", r)
	}
	defer vtblRelease(factory)
	rawH, err := newHString(raw)
	if err != nil {
		return 0, err
	}
	defer deleteHString(rawH)
	var uri uintptr
	r = vtblCall(factory, 6, uintptr(rawH), uintptr(unsafe.Pointer(&uri))) // CreateUri
	if r != 0 || uri == 0 {
		return 0, fmt.Errorf("CreateUri: 0x%08x", r)
	}
	return uri, nil
}

func waitAsync(op uintptr, timeout time.Duration) error {
	var info uintptr
	r := vtblCall(op, 0, uintptr(unsafe.Pointer(&iidAsyncInfo)), uintptr(unsafe.Pointer(&info)))
	if r != 0 || info == 0 {
		return fmt.Errorf("QI IAsyncInfo: 0x%08x", r)
	}
	defer vtblRelease(info)

	deadline := time.Now().Add(timeout)
	for {
		var status int32
		r = vtblCall(info, 7, uintptr(unsafe.Pointer(&status))) // get_Status
		if r != 0 {
			return fmt.Errorf("IAsyncInfo.Status: 0x%08x", r)
		}
		switch status {
		case asyncStatusCompleted:
			return nil
		case asyncStatusCanceled:
			return fmt.Errorf("async canceled")
		case asyncStatusError:
			var code uint32
			_ = vtblCall(info, 8, uintptr(unsafe.Pointer(&code)))
			return fmt.Errorf("async error 0x%08x", code)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("async timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
