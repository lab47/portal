//go:build !windows

package portal

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func setCommandUser(cmd *exec.Cmd, account *user.User) error {
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return err
	}
	if uid != uint64(os.Geteuid()) || gid != uint64(os.Getegid()) {
		if os.Geteuid() != 0 {
			return errors.New("switching users requires the server to run as root")
		}
		groups, err := account.GroupIds()
		if err != nil {
			return err
		}
		credential := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		for _, group := range groups {
			id, err := strconv.ParseUint(group, 10, 32)
			if err != nil {
				return err
			}
			credential.Groups = append(credential.Groups, uint32(id))
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + account.HomeDir, "USER=" + account.Username, "LOGNAME=" + account.Username}
	return nil
}
