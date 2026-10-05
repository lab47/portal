//go:build !windows

package portal

import (
	"errors"
	"os"
	"strconv"
	"syscall"
)

func checkSSHTrustFile(info os.FileInfo, uid string) error {
	targetUID, err := strconv.ParseUint(uid, 10, 32)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || (stat.Uid != uint32(targetUID) && stat.Uid != 0) || info.Mode().Perm()&0022 != 0 {
		return errors.New("must be owned by the target account or root and not group/world writable")
	}
	return nil
}
