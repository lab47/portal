package portal

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
)

// Windows does not support Unix credential switching. An explicitly selected
// account may only be the server's own account.
func setCommandUser(cmd *exec.Cmd, account *user.User) error {
	current, err := user.Current()
	if err != nil {
		return err
	}
	if account.Uid != current.Uid {
		return errors.New("switching users is not supported on Windows")
	}
	cmd.Dir = account.HomeDir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + account.HomeDir, "USER=" + account.Username, "LOGNAME=" + account.Username}
	return nil
}
