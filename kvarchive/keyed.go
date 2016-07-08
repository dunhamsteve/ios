// Package kvarchive will deserialize a key/value archive into generic objects.
//
// This is an old work in progress package.  I intended to eventually allow unmarshalling into
// structs, but got side tracked.  Then needed this code for the "irestore" stuff.
//
// There is a lot of stuff I've learned from writing a python version of this that hasn't made it into
// here yet.
//
package kvarchive

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/dunhamsteve/plist"
	// "encoding/json"
)

func must(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

type KVArchiveTop struct {
	Root plist.UID
}

type KVArchive struct {
	Archiver string        `plist:"$archiver"`
	Top      KVArchiveTop  `plist:"$top"`
	Objects  []interface{} `plist:"$objects"`
	Version  int           `plist:"$version"`
	objects  map[int]interface{}
}

func (kv *KVArchive) coerce(v interface{}) interface{} {
	switch v.(type) {
	case plist.UID:
		return kv.GetObject(v.(plist.UID))
	}
	return v
}

func (kv *KVArchive) GetObject(uid plist.UID) interface{} {
	v := kv.Objects[uid.Value()]
	if s, ok := v.(string); ok && s == "$null" {
		return nil
	}
	if m, ok := v.(map[string]interface{}); ok {
		var className string
		c := kv.Objects[m["$class"].(plist.UID).Value()]
		className = c.(map[string]interface{})["$classname"].(string)

		// fmt.Println("className", className, v)
		switch className {
		case "NSMutableDictionary", "NSDictionary":
			keys := m["NS.keys"].([]interface{})
			values := m["NS.objects"].([]interface{})
			rval := make(map[interface{}]interface{})
			for i, _key := range keys {
				key := kv.coerce(_key)
				value := kv.coerce(values[i])
				rval[key] = value
			}
			return rval
		case "NSMutableData", "NSData":
			return m["NS.data"]
		case "NSMutableArray", "NSArray":
			values := m["NS.objects"].([]interface{})
			rval := make([]interface{}, len(values))
			for i, v := range values {
				rval[i] = kv.coerce(v)
			}
			return rval
		case "NSMutableString", "NSString":
			return m["NS.string"]
		case "NSDecimalNumberPlaceholder":
			bb := m["NS.mantissa"].([]byte)
			bo := m["NS.mantissa.bo"].(int64)
			l := 1 << uint(m["NS.length"].(int64))

			// fmt.Printf("% x %d, %d\n", bb, bo, l)
			var value int64
			for i := 0; i < l; i++ {
				if bo == 0 {
					value = value<<8 | int64(bb[i])
				} else {
					value |= int64(bb[i]) << uint(8*i)
				}
			}
			return value
		case "NSDate":
			stamp := int64(m["NS.time"].(float64)) + 978307200

			return stamp
		default:
			// fmt.Println("Unhandled class", className) // for debugging, but noisy

			rval := make(map[string]interface{})
			rval["_type"] = className
			for k, v := range m {
				if k[0] != '$' {
					rval[k] = kv.coerce(v)
				}
			}
			return rval
		}
	}
	return v
}

// UnArchive deserializes a plist into a graph of generic objects (maps/arrays/etc.)
func UnArchive(r io.ReadSeeker) (rval interface{}, err error) {
	data := new(KVArchive)
	data.objects = make(map[int]interface{})
	err = plist.Unmarshal(r, data)
	if err != nil {
		return
	}
	if data.Archiver != "NSKeyedArchiver" {
		return nil, errors.New("Not a NSKeyedArchiver archiver")
	}
	ruid := data.Top.Root
	rval = data.GetObject(ruid)
	return
}
