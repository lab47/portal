package portal

import "os"

// Windows trust-file protection is governed by the account's filesystem ACLs.
func checkSSHTrustFile(info os.FileInfo, uid string) error { return nil }
