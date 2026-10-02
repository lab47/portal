package portal

import (
	"errors"
	"fmt"
	"strings"
)

// StackCapture opts in to bounded best-effort eBPF stack capture.
type StackCapture struct {
	User      bool `json:"user,omitempty"`
	Kernel    bool `json:"kernel,omitempty"`
	Depth     int  `json:"depth,omitempty"` // default 32, maximum 64
	Symbolize bool `json:"symbolize,omitempty"`
}

type CapturedStack struct {
	Frames []SymbolFrame `json:"frames,omitempty"`
	Error  string        `json:"error,omitempty"`
}

func (s StackCapture) Validate() error {
	if (!s.User && !s.Kernel) || s.Depth < 0 || s.Depth > 64 {
		return errors.New("stack capture requires user/kernel and depth between 0 and 64")
	}
	return nil
}

func (s StackCapture) depth() int {
	if s.Depth == 0 {
		return 32
	}
	return s.Depth
}

func (s CapturedStack) key() string {
	frames := make([]string, 0, len(s.Frames)+1)
	for _, frame := range s.Frames {
		if frame.Name != "" {
			frames = append(frames, fmt.Sprintf("%s:%s+0x%x", frame.Module, frame.Name, frame.Offset))
		} else {
			frames = append(frames, frame.Address)
		}
	}
	if s.Error != "" {
		frames = append(frames, "["+s.Error+"]")
	}
	return strings.Join(frames, ";")
}
