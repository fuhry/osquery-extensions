package flatpak

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/chrisportman/go-gvariant/gvariant"
)

type DeployData_Metadata map[string]gvariant.Variant

// struct for gvariant string "(ssasta{sv})"
// source: https://github.com/flatpak/flatpak/blob/0152272d6caf2622536fad8869573a76001a493b/common/flatpak-dir-private.h#L346
// FLATPAK_DEPLOY_DATA_GVARIANT_FORMAT:
// s - origin
// s - commit
// as - subpaths
// t - installed size
// a{sv} - Metadata
type DeployData struct {
	Origin        string
	Commit        string
	Subpaths      []string
	InstalledSize uint64
	Metadata      []DeployData_Metadata
}

const (
	TypeBool   = "b"
	TypeInt8   = "y"
	TypeInt16  = "n"
	TypeUint16 = "q"
	TypeInt32  = "i"
	TypeUint32 = "u"
	TypeInt64  = "x"
	TypeUint64 = "t"
	TypeFloat  = "d"
	TypeString = "s"

	kAppName         = "appdata-name"
	kAppVersion      = "appdata-version"
	kAppSummary      = "appdata-summary"
	kRuntime         = "runtime"
	kContentRating   = "appdata-content-rating"
	kMetadataVersion = "deploy-version"
	kTimestamp       = "timestamp"
	kLicense         = "appdata-license"
)

var ErrSize = errors.New("variant's data field is the wrong size for the specified type")

// VariantValue decodes the Data field of a Variant to the native Go type.
func VariantValue(v *gvariant.Variant, endianness binary.ByteOrder) (any, error) {
	if v == nil {
		return nil, errors.New("variant is nil")
	}
	switch v.Format {
	case TypeBool:
		return len(v.Data) > 0 && v.Data[0] > 0, nil
	case TypeInt8:
		if len(v.Data) != 1 {
			return nil, ErrSize
		}
		return int8(v.Data[0]), nil
	case TypeInt16:
		if len(v.Data) != 2 {
			return nil, ErrSize
		}
		return int16(endianness.Uint16(v.Data)), nil
	case TypeUint16:
		if len(v.Data) != 2 {
			return nil, ErrSize
		}
		return endianness.Uint16(v.Data), nil
	case TypeInt32:
		if len(v.Data) != 4 {
			return nil, ErrSize
		}
		return int32(endianness.Uint32(v.Data)), nil
	case TypeUint32:
		if len(v.Data) != 4 {
			return nil, ErrSize
		}
		return endianness.Uint32(v.Data), nil
	case TypeInt64:
		if len(v.Data) != 8 {
			return nil, ErrSize
		}
		return int64(endianness.Uint64(v.Data)), nil
	case TypeUint64:
		if len(v.Data) != 8 {
			return nil, ErrSize
		}
		return endianness.Uint64(v.Data), nil
	case TypeFloat:
		switch len(v.Data) {
		case 4:
			var out float32
			buf := bytes.NewBuffer(v.Data)
			if err := binary.Read(buf, endianness, &out); err != nil {
				return nil, err
			}
			return out, nil
		case 8:
			var out float64
			buf := bytes.NewBuffer(v.Data)
			if err := binary.Read(buf, endianness, &out); err != nil {
				return nil, err
			}
			return out, nil
		default:
			return nil, ErrSize
		}
	case TypeString:
		return string(v.Data), nil
	}

	return nil, fmt.Errorf("unsupported format: %q", v.Format)
}

// Keys returns the list of all metadata keys
func (d *DeployData) Keys() (out []string) {
	for _, m := range d.Metadata {
		for k, _ := range m {
			out = append(out, k)
		}
	}
	return
}

// GetMetadata searches the metadata of a DeployData struct for the given key.
func (d *DeployData) GetMetadata(key string) (*gvariant.Variant, bool) {
	for _, m := range d.Metadata {
		if v, ok := m[key]; ok {
			return &v, ok
		}
	}
	return nil, false
}

// LoadDeployData parses and loads the binary `deploy` file.
func LoadDeployData(contents []byte) (*DeployData, error) {
	out := &DeployData{}
	err := gvariant.UnmarshalBigEndian(contents, out)
	if err != nil {
		return nil, err
	}

	return out, nil
}
