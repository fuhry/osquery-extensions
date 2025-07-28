package main

import (
	"go.fuhry.dev/osquery/extcommon"
	"go.fuhry.dev/osquery/x509_certificates"
)

func main() {
	extcommon.Main("x509_certificates", x509_certificates.Schema, x509_certificates.Generate)
}
