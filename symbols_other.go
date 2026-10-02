//go:build !linux

package portal

import (
	"context"
	"errors"
)

func inspectSymbols(context.Context, SymbolRequest) (SymbolResult, error) {
	return SymbolResult{}, errors.New("symbol inspection is unsupported on this platform")
}
