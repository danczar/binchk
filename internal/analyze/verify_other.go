//go:build !darwin && !windows

package analyze

import (
	"context"
	"errors"
)

// platformVerify is never scheduled on platforms without native
// verification for these formats; the parsed signer is still reported.
func platformVerify(ctx context.Context, path string) (bool, string, bool, error) {
	return false, "", false, errors.New("unsupported")
}
