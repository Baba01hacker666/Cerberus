//go:build !linux

package tunnel

import (
	"fmt"
	"os"
)

func (t *Tunnel) setupTUN() error {
	return fmt.Errorf("tunnel not supported on this platform")
}

func openTUN(name string) (*os.File, error) {
	return nil, fmt.Errorf("tunnel not supported on this platform")
}
