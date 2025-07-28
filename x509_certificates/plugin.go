package x509_certificates

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/osquery/osquery-go/plugin/table"
)

const (
	ColumnPath             = "path"
	ColumnIndex            = "index"
	ColumnError            = "error"
	ColumnEncoding         = "encoding"
	ColumnSubject          = "subject"
	ColumnIssuer           = "issuer"
	ColumnSerial           = "serial"
	ColumnIsCA             = "is_ca"
	ColumnPublicKey        = "public_key"
	ColumnPublicKeyAlg     = "public_key_algorithm"
	ColumnPublicKeyBits    = "public_key_size"
	ColumnAltNames         = "alt_names"
	ColumnNotBefore        = "not_before"
	ColumnNotAfter         = "not_after"
	ColumnSecondsRemaining = "remaining_ttl"
	ColumnPercentRemaining = "remaining_pct"
	ColumnValidNow         = "valid_now"
	ColumnThumbprintSHA1   = "sha1_thumbprint"
	ColumnThumbprintSHA256 = "sha256_thumbprint"
)

func Schema() (out []table.ColumnDefinition) {
	return []table.ColumnDefinition{
		table.TextColumn(ColumnPath),
		table.BigIntColumn(ColumnIndex),
		table.TextColumn(ColumnError),
		table.TextColumn(ColumnEncoding),
		table.TextColumn(ColumnSubject),
		table.TextColumn(ColumnIssuer),
		table.TextColumn(ColumnSerial),
		table.IntegerColumn(ColumnIsCA),
		table.TextColumn(ColumnPublicKey),
		table.TextColumn(ColumnPublicKeyAlg),
		table.IntegerColumn(ColumnPublicKeyBits),
		table.TextColumn(ColumnAltNames),
		table.BigIntColumn(ColumnNotBefore),
		table.BigIntColumn(ColumnNotAfter),
		table.IntegerColumn(ColumnSecondsRemaining),
		table.IntegerColumn(ColumnPercentRemaining),
		table.IntegerColumn(ColumnValidNow),
		table.TextColumn(ColumnThumbprintSHA1),
		table.TextColumn(ColumnThumbprintSHA256),
	}
}

var ErrMissingRequiredColumn = errors.New("missing required column in WHERE clause \"path\"")
var ErrUnsupportedColumnOperator = errors.New("unsupported operator in WHERE clause")

func Generate(ctx context.Context, q table.QueryContext) (out []map[string]string, err error) {
	if _, ok := q.Constraints[ColumnPath]; !ok {
		err = ErrMissingRequiredColumn
		return
	}

	for _, c := range q.Constraints[ColumnPath].Constraints {
		if c.Operator != table.OperatorEquals {
			err = ErrUnsupportedColumnOperator
			return
		}

		out = append(out, generateRows(c.Expression)...)
	}

	return out, err
}

func newRow(certPath string, index int) map[string]string {
	return map[string]string{
		ColumnPath:             certPath,
		ColumnIndex:            fmt.Sprintf("%d", index),
		ColumnError:            "",
		ColumnEncoding:         "DER",
		ColumnSubject:          "",
		ColumnIssuer:           "",
		ColumnSerial:           "",
		ColumnIsCA:             "0",
		ColumnPublicKey:        "",
		ColumnPublicKeyAlg:     "",
		ColumnPublicKeyBits:    "0",
		ColumnAltNames:         "",
		ColumnNotBefore:        "",
		ColumnNotAfter:         "",
		ColumnSecondsRemaining: "0",
		ColumnValidNow:         "0",
		ColumnThumbprintSHA1:   "",
		ColumnThumbprintSHA256: "",
	}
}

func generateRows(certPath string) (out []map[string]string) {
	row := newRow(certPath, 0)

	stat, err := os.Stat(certPath)
	if err != nil {
		row[ColumnError] = err.Error()
		out = append(out, row)
		return
	}

	if !stat.Mode().IsRegular() {
		row[ColumnError] = "not a regular file"
		out = append(out, row)
		return
	}

	contents, err := os.ReadFile(certPath)
	if err != nil {
		row[ColumnError] = err.Error()
		out = append(out, row)
		return
	}

	if strings.TrimSpace(string(contents)) == "" {
		row[ColumnError] = "file is empty"
		out = append(out, row)
		return
	}

outer:
	for i := 0; ; i++ {
		if strings.TrimSpace(string(contents)) == "" {
			// reached EOF, return current results
			return
		}

		row = newRow(certPath, i)

		cert, err := x509.ParseCertificate(contents)
		if err == nil {
			// decoded as DER, seek forward in the file so we can grab the next cert
			contents = contents[len(cert.Raw):]
		} else {
			// couldn't decode as DER, try PEM
			for {
				block, remainder := pem.Decode(contents)
				if block == nil && bytes.Equal(remainder, contents) {
					if i == 0 {
						row[ColumnError] = "unable to decode contents as PEM or DER"
						out = append(out, row)
					}
					return
				}
				contents = remainder
				if block.Type != "CERTIFICATE" {
					continue
				}

				cert, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					row[ColumnError] = "PEM certificate block found, but unable to decode " +
						"contents as X.509 certificate"
					out = append(out, row)
					continue outer
				}

				row[ColumnEncoding] = "PEM"
				break
			}
		}

		if cert == nil {
			row[ColumnError] = "certificate is nil after successful decode, should not reach this point"
			return
		}

		row[ColumnSubject] = cert.Subject.String()
		row[ColumnIssuer] = cert.Issuer.String()
		row[ColumnSerial] = hex.EncodeToString(cert.SerialNumber.Bytes())
		row[ColumnNotBefore] = fmt.Sprintf("%d", cert.NotBefore.Unix())
		row[ColumnNotAfter] = fmt.Sprintf("%d", cert.NotAfter.Unix())

		var altNames []string
		for _, name := range cert.DNSNames {
			altNames = append(altNames, fmt.Sprintf("DNS:%s", name))
		}
		for _, name := range cert.EmailAddresses {
			altNames = append(altNames, fmt.Sprintf("MAIL:%s", name))
		}
		for _, name := range cert.IPAddresses {
			altNames = append(altNames, fmt.Sprintf("IP:%s", name.String()))
		}
		for _, name := range cert.URIs {
			altNames = append(altNames, fmt.Sprintf("URI:%s", name.String()))
		}
		row[ColumnAltNames] = strings.Join(altNames, ",")

		if pubkey, err := x509.MarshalPKIXPublicKey(cert.PublicKey); err == nil {
			row[ColumnPublicKey] = string(pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubkey,
			}))
			switch k := cert.PublicKey.(type) {
			case *rsa.PublicKey:
				row[ColumnPublicKeyAlg] = "RSA"
				row[ColumnPublicKeyBits] = strconv.Itoa(8 * k.Size())
			case *ecdsa.PublicKey:
				row[ColumnPublicKeyAlg] = "ECDSA"
				row[ColumnPublicKeyBits] = strconv.Itoa(k.Params().BitSize)
			}
		}

		if cert.IsCA {
			row[ColumnIsCA] = "1"
		}

		now := time.Now()
		if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
			row[ColumnValidNow] = "1"
			ttl := cert.NotAfter.Unix() - cert.NotBefore.Unix()
			remain := cert.NotAfter.Unix() - now.Unix()
			row[ColumnSecondsRemaining] = fmt.Sprintf("%d", remain)
			row[ColumnPercentRemaining] = fmt.Sprintf("%d", (remain*100)/ttl)
		}

		sha := sha1.New()
		_, _ = io.Copy(sha, bytes.NewBuffer(cert.Raw))
		var buf []byte
		row[ColumnThumbprintSHA1] = hex.EncodeToString(sha.Sum(buf))

		sha = sha256.New()
		_, _ = io.Copy(sha, bytes.NewBuffer(cert.Raw))
		buf = nil
		row[ColumnThumbprintSHA256] = hex.EncodeToString(sha.Sum(buf))
		out = append(out, row)
	}
}
