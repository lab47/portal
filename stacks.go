package portal

import (
	"errors"
	"fmt"
	"strings"
)

// StackCapture opts in to bounded best-effort eBPF stack capture.
type StackCapture struct {
	User        bool        `json:"user,omitempty"`
	Kernel      bool        `json:"kernel,omitempty"`
	Depth       int         `json:"depth,omitempty"` // default 32, maximum 64
	Symbolize   bool        `json:"symbolize,omitempty"`
	UserShape   *StackShape `json:"user_shape,omitempty"`
	KernelShape *StackShape `json:"kernel_shape,omitempty"`
}

// StackShape projects leaf-first frames into aggregation keys, without changing
// raw event frames. Order: remove bottom frames, stop at Until, then keep Top.
type StackShape struct {
	DropOffsets bool   `json:"drop_offsets,omitempty"`
	DropBottom  int    `json:"drop_bottom,omitempty"`
	Top         int    `json:"top,omitempty"`   // zero keeps all remaining frames
	Until       string `json:"until,omitempty"` // exact function name or one edge glob; matching frame is included
}

type CapturedStack struct {
	Frames []SymbolFrame `json:"frames,omitempty"`
	Error  string        `json:"error,omitempty"`
}

func (s StackCapture) Validate() error {
	if (!s.User && !s.Kernel) || s.Depth < 0 || s.Depth > 64 {
		return errors.New("stack capture requires user/kernel and depth between 0 and 64")
	}
	for _, option := range []struct {
		enabled bool
		shape   *StackShape
	}{{s.User, s.UserShape}, {s.Kernel, s.KernelShape}} {
		if option.shape == nil {
			continue
		}
		shape := option.shape
		if !option.enabled {
			return errors.New("stack shaping requires capture of that stack")
		}
		if shape.Top < 0 || shape.Top > 64 || shape.DropBottom < 0 || shape.DropBottom > 64 {
			return errors.New("stack top/drop_bottom must be between 0 and 64")
		}
		if shape.Until != "" && (!s.Symbolize || !validEdgeGlob(shape.Until) || len(shape.Until) > 256) {
			return errors.New("stack until requires symbolization and an exact name or one edge glob (up to 256 bytes)")
		}
	}
	return nil
}

func (s StackCapture) depth() int {
	if s.Depth == 0 {
		return 32
	}
	return s.Depth
}

func (s CapturedStack) key(shape *StackShape) string {
	selected := s.Frames
	if shape != nil {
		selected = selected[:max(0, len(selected)-shape.DropBottom)]
		if shape.Until != "" {
			for i, frame := range selected {
				if frame.Name != "" && processNameMatches(shape.Until, frame.Name) {
					selected = selected[:i+1]
					break
				}
			}
		}
		if shape.Top > 0 && len(selected) > shape.Top {
			selected = selected[:shape.Top]
		}
	}
	frames := make([]string, 0, len(selected)+1)
	for _, frame := range selected {
		if frame.Name != "" {
			name := frame.Module + ":" + frame.Name
			if shape == nil || !shape.DropOffsets {
				name += fmt.Sprintf("+0x%x", frame.Offset)
			}
			frames = append(frames, escapeStackFrame(name))
		} else {
			frames = append(frames, escapeStackFrame(frame.Address))
		}
	}
	if s.Error != "" {
		frames = append(frames, escapeStackFrame("["+s.Error+"]"))
	}
	return strings.Join(frames, ";")
}

// Escape only frame separators/control characters, leaving ordinary symbol
// names readable. Percent is escaped first so encoding cannot create collisions.
var stackFrameEscaper = strings.NewReplacer("%", "%25", ";", "%3B", "\n", "%0A", "\r", "%0D", "\t", "%09")

func escapeStackFrame(frame string) string {
	return stackFrameEscaper.Replace(frame)
}
