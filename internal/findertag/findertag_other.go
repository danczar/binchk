//go:build !darwin

package findertag

const supported = false

func get(path string) ([]string, error) { return nil, nil }

func set(path, verdict string) error { return nil }
