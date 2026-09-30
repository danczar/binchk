package analyze

import (
	"sort"
	"strings"
)

type apiLevel struct {
	n   int
	sev Severity
}

// apiCategory groups imported APIs whose combination is telling. A single
// VirtualAllocEx is unremarkable; VirtualAllocEx + WriteProcessMemory +
// CreateRemoteThread is textbook process injection.
type apiCategory struct {
	key, title, detail string
	apis               []string
	levels             []apiLevel // ascending n
}

var apiCategories = []apiCategory{
	{key: "injection", title: "Process injection APIs",
		detail: "Allocating, writing and starting code inside another process.",
		apis: []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
			"RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread", "SetThreadContext", "NtSetContextThread",
			"NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtWriteVirtualMemory", "VirtualProtectEx", "NtMapViewOfSection",
			"task_for_pid", "mach_vm_write", "vm_write", "thread_create_running", "mach_vm_protect", "process_vm_writev"},
		levels: []apiLevel{{2, Medium}, {3, High}}},
	{key: "keylogging", title: "Keyboard capture APIs",
		detail: "Global keyboard hooks or key-state polling.",
		apis:   []string{"SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "RegisterRawInputDevices", "CGEventTapCreate", "IOHIDManagerCreate"},
		levels: []apiLevel{{2, Medium}}},
	{key: "anti-debug", title: "Anti-debugging APIs",
		detail: "Checks for or blocks debuggers — common in malware trying to resist analysis.",
		apis:   []string{"CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "NtSetInformationThread", "ptrace", "DbgBreakPoint"},
		// One alone is common (the Go runtime imports ptrace on macOS).
		levels: []apiLevel{{2, Low}, {3, Medium}}},
	{key: "dropper", title: "Downloads files to disk",
		apis:   []string{"URLDownloadToFile", "URLDownloadToCacheFile"},
		levels: []apiLevel{{1, Low}}},
	{key: "credential-access", title: "Credential store APIs",
		detail: "Decrypting protected data or reading stored credentials.",
		// macOS keychain APIs are deliberately absent: nearly every Mac app
		// stores its own secrets there.
		apis:   []string{"CryptUnprotectData", "CredEnumerate", "CredRead", "LsaRetrievePrivateData", "SamConnect"},
		levels: []apiLevel{{2, Medium}}},
	{key: "privilege", title: "Token / privilege manipulation",
		apis: []string{"AdjustTokenPrivileges", "ImpersonateLoggedOnUser", "DuplicateTokenEx", "SetTokenInformation",
			"CreateProcessWithToken", "CreateProcessAsUser", "SetThreadToken"},
		levels: []apiLevel{{3, Low}, {5, Medium}}},
	{key: "priv-exec-mac", title: "Runs code as root via deprecated Authorization API",
		detail: "AuthorizationExecuteWithPrivileges is deprecated and a favourite of Mac malware installers.",
		apis:   []string{"AuthorizationExecuteWithPrivileges"},
		levels: []apiLevel{{1, Medium}}},
	{key: "driver", title: "Loads kernel drivers",
		apis:   []string{"NtLoadDriver", "ZwLoadDriver"},
		levels: []apiLevel{{1, Medium}}},
	{key: "memory-loading", title: "In-memory code loading",
		detail: "Loads executable code from memory instead of disk, evading file scanning.",
		apis:   []string{"NSCreateObjectFileImageFromMemory", "NSLinkModule", "memfd_create", "fexecve", "execveat"},
		levels: []apiLevel{{2, Medium}}},
	{key: "screen-capture", title: "Screen capture APIs",
		apis:   []string{"CGWindowListCreateImage", "CGDisplayCreateImage", "CGDisplayStreamCreate", "SCScreenshotManager"},
		levels: []apiLevel{{1, Low}}},
	{key: "exec", title: "Legacy command execution",
		apis:   []string{"WinExec"},
		levels: []apiLevel{{1, Low}}},
}

var apiIndex = func() map[string]int {
	m := map[string]int{}
	for i, c := range apiCategories {
		for _, a := range c.apis {
			m[a] = i
		}
	}
	return m
}()

// normalizeAPI strips platform decoration: Mach-O leading underscore,
// ELF symbol versions, Win32 A/W suffixes.
func normalizeAPI(name string) string {
	name = strings.TrimPrefix(name, "_")
	if i := strings.IndexByte(name, '@'); i > 0 {
		name = name[:i]
	}
	if _, ok := apiIndex[name]; ok {
		return name
	}
	if n := len(name); n > 1 && (name[n-1] == 'A' || name[n-1] == 'W') {
		if _, ok := apiIndex[name[:n-1]]; ok {
			return name[:n-1]
		}
	}
	if strings.HasPrefix(name, "Zw") {
		return "Nt" + name[2:]
	}
	return name
}

// tagImports sets Import.Category for notable APIs.
func tagImports(imps []Import) {
	for i := range imps {
		if ci, ok := apiIndex[normalizeAPI(imps[i].Name)]; ok {
			imps[i].Category = apiCategories[ci].key
		}
	}
}

// apiFindings evaluates categories over the set of imported names.
func apiFindings(names map[string]bool) []Finding {
	hits := make([][]string, len(apiCategories))
	for n := range names {
		if ci, ok := apiIndex[normalizeAPI(n)]; ok {
			hits[ci] = append(hits[ci], strings.TrimPrefix(n, "_"))
		}
	}
	var out []Finding
	for ci, h := range hits {
		c := apiCategories[ci]
		sev := Severity(-1)
		for _, l := range c.levels {
			if len(h) >= l.n {
				sev = l.sev
			}
		}
		if sev < 0 {
			continue
		}
		sort.Strings(h)
		out = append(out, Finding{ID: "api-" + c.key, Title: c.title, Detail: c.detail, Severity: sev, Category: "imports", Evidence: h})
	}
	return out
}
