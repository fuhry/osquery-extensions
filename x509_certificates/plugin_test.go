package x509_certificates

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRows(t *testing.T) {
	type testCase struct {
		filename, expectError, expectAlg, expectBits string
		index                                        int
	}

	wd, err := os.Getwd()
	assert.NoError(t, err)
	dataDir := path.Join(wd, "testdata")

	var testCases = []*testCase{
		{
			filename:    "ecdsa-p256.crt",
			expectError: "",
			expectAlg:   "ECDSA",
			expectBits:  "256",
		},
		{
			filename:    "ecdsa-p384.crt",
			expectError: "",
			expectAlg:   "ECDSA",
			expectBits:  "384",
		},
		{
			filename:    "ecdsa-p521.crt",
			expectError: "",
			expectAlg:   "ECDSA",
			expectBits:  "521",
		},
		{
			filename:    "rsa-2048.crt",
			expectError: "",
			expectAlg:   "RSA",
			expectBits:  "2048",
		},
		{
			filename:    "rsa-4096.crt",
			expectError: "",
			expectAlg:   "RSA",
			expectBits:  "4096",
		},
		{
			filename:    "all-crts.crt",
			expectError: "",
			expectAlg:   "ECDSA",
			expectBits:  "256",
		},
		{
			filename:    "all-crts.crt",
			expectError: "",
			expectAlg:   "RSA",
			expectBits:  "4096",
			index:       4,
		},
		{
			filename:    "does-not-exist.crt",
			expectError: "stat .+: no such file or directory",
			expectAlg:   "",
			expectBits:  "0",
		},
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("%s-%d", tc.filename, tc.index)
		t.Run(name, func(t *testing.T) {
			fullPath := path.Join(dataDir, tc.filename)
			out := generateRows(fullPath)

			if len(out) < tc.index+1 {
				t.Errorf("index %d not found in output", tc.index)
				t.FailNow()
			}

			row := out[tc.index]
			assert.Regexp(t, tc.expectError, row[ColumnError])
			if tc.expectError != "" {
				return
			}

			assert.Equal(t, "CN=Test certificate for osquery x509_certificates table", row[ColumnSubject])
			assert.Equal(t, tc.expectAlg, row[ColumnPublicKeyAlg])
			assert.Equal(t, tc.expectBits, row[ColumnPublicKeyBits])
		})
	}
}
