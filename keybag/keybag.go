// This has been run against a keybag from Manifest.plist in an iOS backup.
// It will probably need work to handle other keybag variants.
//
// /var/db/lockdown plists appear to no longer contain keybags.  (And 0x835 was needed to decrypt them anyway.)
//
package keybag

import (
	"crypto/sha1"
	"encoding/binary"
	"log"

	"code.google.com/p/go.crypto/pbkdf2"
	"github.com/dunhamsteve/crypto/aeswrap"
)

type Key struct {
	UUID       []byte
	Class      uint32
	Wrap       uint32
	KeyType    uint32
	WrappedKey []byte
	Key        []byte
}

type Keybag struct {
	Version uint32
	Type    uint32

	UUID []byte
	HMAC []byte
	Wrap uint32
	Salt []byte
	Iter uint32
	Keys []*Key
}

var be = binary.BigEndian

func Read(data []byte) Keybag {
	var kb Keybag
	var key *Key
	var state = 0

	for pos := 0; pos+8 < len(data); {
		fourcc := string(data[pos : pos+4])
		size := int(be.Uint32(data[pos+4 : pos+8]))
		pos += 8
		value := data[pos : pos+size]
		var ivalue uint32
		pos += size
		if size == 4 {
			ivalue = be.Uint32(value[:4])
		}

		if state < 2 {
			switch fourcc {
			case "VERS":
				kb.Version = ivalue
			case "TYPE":
				kb.Type = ivalue
			case "WRAP":
				kb.Wrap = ivalue
			case "HMCK":
				kb.HMAC = value
			case "SALT":
				kb.Salt = value
			case "ITER":
				kb.Iter = ivalue
			case "UUID":
				state++
				if state == 2 {
					pos -= 8 + size

				} else {
					kb.UUID = value
				}
			default:
				log.Fatal("fourcc", fourcc, "not handled")
			}
		} else {
			switch fourcc {
			case "UUID":
				key = new(Key)
				kb.Keys = append(kb.Keys, key)
				key.UUID = value
			case "CLAS":
				key.Class = ivalue
			case "WRAP":
				key.Wrap = ivalue
			case "KTYP":
				key.KeyType = ivalue
			case "WPKY":
				key.WrappedKey = value
			default:
				log.Fatal("fourcc ", fourcc, " not handled")
			}
		}
	}
	return kb
}

// Get a class key, or nil if not available
func (kb *Keybag) GetClassKey(class uint32) []byte {
	for _, key := range kb.Keys {
		if key.Class == class {
			return key.Key
		}
	}
	return nil
}

func (kb *Keybag) SetPassword(password string) error {
	passkey := pbkdf2.Key([]byte(password), kb.Salt, int(kb.Iter), 32, sha1.New)
	for _, key := range kb.Keys {
		if key.Wrap == 2 { // 3 means we need 0x835 too, 1 means only 0x835
			key.Key = aeswrap.Unwrap(passkey, key.WrappedKey)
		}
	}
	return nil
}
