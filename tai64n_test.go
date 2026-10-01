package portal

import (
	"testing"
	"time"
)

func TestTAI64NEncoding(t *testing.T) {
	for _, tc := range []struct{ utc, want string }{
		// The published libtai example is 1992-06-02 08:07:09 TAI.
		{"1992-06-02T08:06:43Z", "@400000002a2b2c2d00000000"},
		{"2016-12-31T23:59:59Z", "@40000000586846a300000000"},
		{"2017-01-01T00:00:00.999999999Z", "@40000000586846a53b9ac9ff"},
	} {
		utc, err := time.Parse(time.RFC3339Nano, tc.utc)
		if err != nil {
			t.Fatal(err)
		}
		if got := formatTAI64N(utc); got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.utc, got, tc.want)
		}
		if err := validateTAI64N(tc.want); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"", "400000002a2b2c2d00000000", "@400000002A2B2C2D00000000", "@40000000586846a53b9aca00", "@800000000000000000000000", "@gg0000000000000000000000"} {
		if err := validateTAI64N(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestEventTimestampClockRollback(t *testing.T) {
	last := time.Now().UTC().Add(time.Hour)
	before := last
	var event Event
	stampEvent(&event, &last)
	if !last.Equal(before.Add(time.Nanosecond)) || event.TAI64N <= formatTAI64N(before) {
		t.Fatalf("timestamp moved backwards: %+v, %s", event, last)
	}
}
