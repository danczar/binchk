package analyze

import (
	"context"
	"os/exec"
	"strings"
)

// Failures that mean "this executable was taken out of its app bundle", not
// "this code was modified": the signature seals bundle files that are not
// next to the binary. A quarantined bundle executable always looks like this.
var detachedFromBundle = []string{
	"invalid Info.plist",
	"code has no resources but signature indicates they must be present",
	"a sealed resource is missing or invalid",
	"In subcomponent",
}

// platformVerify asks codesign to validate the code signature: CodeDirectory
// page hashes, CMS signature and certificate chain. Resource sealing is
// skipped (--ignore-resources) because binchk inspects lone executables.
// conclusive is false when verification could not reach a verdict.
func platformVerify(ctx context.Context, path string) (ok bool, detail string, conclusive bool, err error) {
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--ignore-resources", "--verbose=1", path).CombinedOutput()
	if ctx.Err() != nil {
		return false, "", false, ctx.Err()
	}
	msg := strings.TrimSpace(strings.ReplaceAll(string(out), path+": ", ""))
	msg = strings.ReplaceAll(msg, "\n", "; ")
	if err == nil {
		return true, "codesign: " + msg, true, nil
	}
	for _, d := range detachedFromBundle {
		if strings.Contains(msg, d) {
			return false, "codesign: inconclusive — the signature covers app-bundle files that are not present (" + msg + ")", false, nil
		}
	}
	return false, "codesign: " + msg, true, nil
}
