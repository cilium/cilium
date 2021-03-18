//+build windows

package wguser

import (
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/winpipe"
)

// Expected prefixes when dealing with named pipes.
const (
	pipePrefix = `\\.\pipe\`
	wgPrefix   = `ProtectedPrefix\Administrators\WireGuard\`
)

// dial is the default implementation of Client.dial.
func dial(device string) (net.Conn, error) {
	// Thanks to @zx2c4 for the sample code that makes this possible:
	// https://github.com/WireGuard/wgctrl-go/issues/36#issuecomment-491912143.
	//
	// See also:
	// https://docs.microsoft.com/en-us/windows/desktop/secauthz/impersonation-tokens
	// https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-reverttoself
	//
	// All of these operations require a locked OS thread for the duration of
	// this function. Once the pipe is opened successfully, RevertToSelf
	// terminates the impersonation of a client application.
	runtime.LockOSThread()
	defer func() {
		// Terminate the token impersonation operation. Per the Microsoft
		// documentation, the process should shut down if RevertToSelf fails.
		if err := windows.RevertToSelf(); err != nil {
			panicf("wguser: failed to terminate token impersonation, panicking per Microsoft recommendation: %v", err)
		}

		runtime.UnlockOSThread()
	}()

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err := windows.LookupPrivilegeValue(
		nil,
		windows.StringToUTF16Ptr("SeDebugPrivilege"),
		&privileges.Privileges[0].Luid,
	)
	if err != nil {
		return nil, err
	}

	processes, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(processes)

	e := windows.ProcessEntry32{
		Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{})),
	}

	// Iterate the process list looking for any processes named winlogon.exe.
	//
	// It is possible for an attacker to attempt a denial of service of this
	// application by creating bogus processes with that name, so we must
	// attempt dialing a connection for each matching process until we either
	// succeed or run out of processes to try.
	//
	// It is unlikely that an attacker's process could appear before the true
	// winlogon.exe in this list, but better safe than sorry.
	for err := windows.Process32First(processes, &e); ; err = windows.Process32Next(processes, &e) {
		// Handle any errors from process list iteration.
		switch err {
		case nil:
			// Keep iterating processes.
		case windows.ERROR_NO_MORE_FILES:
			// No more files to check.
			return nil, errors.New("wguser: unable to find suitable winlogon.exe process to communicate with WireGuard")
		default:
			return nil, err
		}

		if strings.ToLower(windows.UTF16ToString(e.ExeFile[:])) != "winlogon.exe" {
			continue
		}

		// Can we communicate with the device by impersonating this process?
		c, err := tryDial(device, e.ProcessID, privileges)
		switch {
		case err == nil:
			// Success, use this connection.
			return c, nil
		case os.IsPermission(err):
			// We found a process named winlogon.exe that doesn't have permission
			// to open a handle to the WireGuard device. Skip it and keep trying.
		default:
			return nil, err
		}
	}
}

// tryDial attempts to impersonate the security token of pid to dial device.
// tryDial _must_ only be invoked by dial.
func tryDial(device string, pid uint32, privileges windows.Tokenprivileges) (net.Conn, error) {
	// Revert to normal thread state before attempting any further manipulation.
	// See comment in dial about the panic.
	if err := windows.RevertToSelf(); err != nil {
		panicf("wguser: failed to terminate token impersonation, panicking per Microsoft recommendation: %v", err)
	}

	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		return nil, err
	}

	thread, err := windows.GetCurrentThread()
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(thread)

	var ttok windows.Token
	err = windows.OpenThreadToken(
		thread,
		windows.TOKEN_ADJUST_PRIVILEGES,
		false,
		&ttok,
	)
	if err != nil {
		return nil, err
	}
	defer ttok.Close()

	err = windows.AdjustTokenPrivileges(
		ttok,
		false,
		&privileges,
		uint32(unsafe.Sizeof(privileges)),
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(proc)

	var ptok windows.Token
	err = windows.OpenProcessToken(
		proc,
		windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE,
		&ptok,
	)
	if err != nil {
		return nil, err
	}
	defer ptok.Close()

	var dup windows.Token
	err = windows.DuplicateTokenEx(
		ptok,
		0,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&dup,
	)
	if err != nil {
		return nil, err
	}
	defer dup.Close()

	if err := windows.SetThreadToken(nil, dup); err != nil {
		return nil, err
	}

	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}

	return winpipe.DialPipe(device, nil, localSystem)
}

// find is the default implementation of Client.find.
func find() ([]string, error) {
	return findNamedPipes(wgPrefix)
}

// findNamedPipes looks for Windows named pipes that match the specified
// search string prefix.
func findNamedPipes(search string) ([]string, error) {
	var (
		pipes []string
		data  windows.Win32finddata
	)

	// Thanks @zx2c4 for the tips on the appropriate Windows APIs here:
	// https://א.cc/dHGpnhxX/c.
	h, err := windows.FindFirstFile(
		// Append * to find all named pipes.
		windows.StringToUTF16Ptr(pipePrefix+"*"),
		&data,
	)
	if err != nil {
		return nil, err
	}

	// FindClose is used to close file search handles instead of the typical
	// CloseHandle used elsewhere, see:
	// https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-findclose.
	defer windows.FindClose(h)

	// Check the first file's name for a match, but also keep searching for
	// WireGuard named pipes until no more files can be iterated.
	for {
		name := windows.UTF16ToString(data.FileName[:])
		if strings.HasPrefix(name, search) {
			// Concatenate strings directly as filepath.Join appears to break the
			// named pipe prefix convention.
			pipes = append(pipes, pipePrefix+name)
		}

		if err := windows.FindNextFile(h, &data); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}

			return nil, err
		}
	}

	return pipes, nil
}
