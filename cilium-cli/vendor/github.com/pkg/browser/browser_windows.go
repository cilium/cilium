//go:generate mkwinsyscall -output zbrowser_windows.go browser_windows.go
//sys shellExecute(hwnd int, verb string, file string, args string, cwd string, showCmd int) (err error) = shell32.ShellExecuteW
package browser

const sW_SHOWNORMAL = 1

func openBrowser(url string) error {
	return shellExecute(0, "", url, "", "", sW_SHOWNORMAL)
}
