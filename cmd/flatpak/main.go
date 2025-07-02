package main

import (
	"go.fuhry.dev/osquery/extcommon"
	"go.fuhry.dev/osquery/flatpak"
)

func main() {
	extcommon.Main("flatpak_packages", flatpak.Schema, flatpak.Generate)
}
