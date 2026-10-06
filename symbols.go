package portal

import (
	"context"

	"github.com/lab47/portal/query"
)

// InspectSymbols resolves symbols without a remote connection.
func InspectSymbols(ctx context.Context, request SymbolRequest) (SymbolResult, error) {
	return query.InspectSymbols(ctx, request)
}
