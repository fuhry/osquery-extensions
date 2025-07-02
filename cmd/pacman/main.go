package main

import (
	"go.fuhry.dev/osquery/extcommon"
	"go.fuhry.dev/osquery/pacman"
)

func main() {
	extcommon.MainMulti(
		"pacman",
		extcommon.Tables{
			"pacman_packages": {pacman.PackagesSchema, pacman.PackagesGenerate},
			"pacman_files":    {pacman.FilesSchema, pacman.FilesGenerate},
		})
}
