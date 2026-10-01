//go:build !linux

package portal

import (
	"context"
	"errors"
)

func readContainers(context.Context, string) ([]ContainerInfo, error) {
	return nil, errors.New("Docker container snapshots require Linux")
}
