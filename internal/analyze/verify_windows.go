package analyze

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var trustErrors = map[windows.Errno]string{
	0x800B0100: "no signature present",
	0x80096010: "signature digest mismatch — file modified after signing",
	0x800B0109: "certificate chain ends in an untrusted root",
	0x800B0101: "certificate expired",
	0x800B0111: "certificate explicitly distrusted (revoked or blocked)",
	0x800B010C: "certificate revoked",
	0x80096019: "certificate not valid for code signing",
	0x800B0004: "subject not trusted",
}

// platformVerify validates Authenticode with WinVerifyTrust. Revocation
// checks and network retrieval are disabled so it completes in milliseconds.
func platformVerify(ctx context.Context, path string) (bool, string, bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, "", false, err
	}
	fi := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fi),
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verr == nil {
		return true, "WinVerifyTrust: valid Authenticode signature", true, nil
	}
	var errno windows.Errno
	if errors.As(verr, &errno) {
		if msg, found := trustErrors[errno]; found {
			return false, "WinVerifyTrust: " + msg, true, nil
		}
	}
	return false, fmt.Sprintf("WinVerifyTrust: %v", verr), true, nil
}
