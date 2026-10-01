//go:build !darwin

package container

import (
	"context"
	"errors"
)

const supportsDMG = false

var errNotMac = errors.New("requires macOS")

func bundleVerify(ctx context.Context, p string) (bool, bool, string, error) {
	return false, false, "", errNotMac
}
func codesignInfo(ctx context.Context, p string) (map[string][]string, error) { return nil, errNotMac }

type gkResult struct {
	accepted            bool
	source, origin, raw string
}

func gatekeeper(ctx context.Context, p, typ string) (gkResult, error) { return gkResult{}, errNotMac }

type pkgSig struct {
	status, notarization string
	chain                []string
}

func pkgSignature(ctx context.Context, p string) (pkgSig, error) { return pkgSig{}, errNotMac }

func readPlist(ctx context.Context, p string) (map[string]string, error) { return readXMLPlist(p) }

func (in *inspector) inspectDMG(path string, rescan bool) {}
