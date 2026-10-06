package portal

import (
	"time"

	"github.com/lab47/portal/query"
)

func formatTAI64N(t time.Time) string          { return query.FormatTAI64N(t) }
func validateTAI64N(text string) error         { return query.ValidateTAI64N(text) }
func stampEvent(event *Event, last *time.Time) { query.StampEvent(event, last) }
