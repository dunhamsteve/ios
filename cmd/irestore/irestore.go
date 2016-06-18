package main

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"time"

	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"crypto/aes"

	"code.google.com/p/go.crypto/ssh/terminal"
	"github.com/dunhamsteve/ios/backup"
	"github.com/dunhamsteve/ios/crypto/aeswrap"
	"github.com/dunhamsteve/ios/crypto/gcm"
	"github.com/dunhamsteve/plist"
)

// Quick and Dirty error handling - when I don't expect an error, but want to know if it happens
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func DumpJson(x interface{}) {
	json, err := json.MarshalIndent(x, "", "  ")
	must(err)
	fmt.Println(string(json))
}

func getpass() string {
	pw, err := terminal.ReadPassword(0)
	must(err)

	return string(pw)
}

func domains(db *backup.MobileBackup) {
	for _, domain := range db.Domains() {
		fmt.Println(domain)
	}
}
func apps(db *backup.MobileBackup) {
	for app, _ := range db.Manifest.Applications {
		fmt.Println(app)
	}
}

func list(db *backup.MobileBackup, domain string) {
	for _, rec := range db.Records {
		// just files for now
		if rec.Length > 0 {
			if domain == "*" {
				fmt.Println(rec.MetaData.ProtClass, rec.Domain, rec.Path)
			} else if domain == rec.Domain {
				fmt.Println(rec.MetaData.ProtClass, rec.Path)
			}
		}
	}
}

type KCEntry struct {
	Data []byte `plist:"v_Data"`
	Ref  []byte `plist:"v_PersistentRef"`
}

type Keychain struct {
	Internet []KCEntry `plist:"inet"`
	General  []KCEntry `plist:"genp"`
	Certs    []KCEntry `plist:"cert"`
	Keys     []KCEntry `plist:"keys"`
}

var le = binary.LittleEndian

// Mostly works, but I don't think time is getting populated.
type Entry struct {
	Raw   asn1.RawContent
	Key   string
	Value interface{}
}

type DateEntry struct {
	Key  string
	Time time.Time
}

type EntrySET []Entry

func parseRecord(data []byte) map[string]interface{} {
	var v EntrySET
	rval := make(map[string]interface{})
	_, err := asn1.Unmarshal(data, &v)
	must(err)
	for _, entry := range v {
		// Time values come through as nil, so we try again with a "DateEntry" structure.
		if entry.Value == nil {
			var entry2 DateEntry
			_, err := asn1.Unmarshal(entry.Raw, &entry2)
			if err == nil {
				entry.Value = entry2.Time
			}
		}

		rval[entry.Key] = entry.Value
	}
	return rval
}

func dumpKeyGroup(db *backup.MobileBackup, group []KCEntry) []interface{} {
	var rval []interface{}
	for _, key := range group {
		version := le.Uint32(key.Data)
		class := le.Uint32(key.Data[4:])
		switch version {
		case 3:
			l := le.Uint32(key.Data[8:])
			wkey := key.Data[12 : 12+l]
			edata := key.Data[12+l:]

			// Find key for class
			ckey := db.Keybag.GetClassKey(class)
			if ckey == nil {
				fmt.Println("No key for class", class)
				continue
			}

			key := aeswrap.Unwrap(ckey, wkey)

			// Create a gcm cipher
			c, err := aes.NewCipher(key)
			if err != nil {
				log.Panic(err)
			}
			gcm, err := gcm.NewGCM(c)
			if err != nil {
				log.Panic(err)
			}
			plain, err := gcm.Open(nil, nil, edata, nil)
			must(err)
			record := parseRecord(plain)
			rval = append(rval, record)
		default:
			panic(fmt.Sprintf("Unhandled keychain blob version %d", version))
		}
	}

	return rval
}

func dumpkeys(db *backup.MobileBackup, outfile string) {
	var err error
	fmt.Fprint(os.Stderr, "Backup Password: ")
	err = db.Keybag.SetPassword(getpass())
	must(err)
	for _, rec := range db.Records {
		if rec.Domain == "KeychainDomain" && rec.Path == "keychain-backup.plist" {
			fmt.Println(rec)
			data, err := db.ReadFile(rec)
			must(err)
			ioutil.WriteFile("kcb.plist", data, 0x644)

			fmt.Println("read", len(data))
			var v Keychain
			err = plist.Unmarshal(bytes.NewReader(data), &v)
			must(err)
			// fmt.Println(v)

			dump := make(map[string][]interface{})
			dump["General"] = dumpKeyGroup(db, v.General)
			dump["Internet"] = dumpKeyGroup(db, v.Internet)
			dump["Certs"] = dumpKeyGroup(db, v.Certs)
			dump["Keys"] = dumpKeyGroup(db, v.Keys)
			s, err := json.MarshalIndent(dump, "", "  ")
			must(err)
			if outfile != "" {
				err = ioutil.WriteFile(outfile, s, 0644)
				must(err)
			} else {
				_, err = os.Stdout.Write(s)
				must(err)
			}
		}
	}
}

func restore(db *backup.MobileBackup, domain string, dest string) {
	var err error

	// FIXME - doesn't handle unencrypted records, nor does it gracefully handle files that are ThisDeviceOnly (if any)
	if db.Manifest.IsEncrypted {
		fmt.Print("Backup Password: ")
		err = db.Keybag.SetPassword(getpass())
		must(err)
	}

	var total int64
	for _, rec := range db.Records {
		if rec.Length > 0 {
			var outPath string
			if domain == "*" {
				outPath = path.Join(dest, rec.Domain, rec.Path)
			} else if rec.Domain == domain {
				outPath = path.Join(dest, rec.Path)
			}

			if outPath != "" {
				fmt.Println(rec.Path)

				dir := path.Dir(outPath)
				err = os.MkdirAll(dir, 0755)
				must(err)
				r, err := db.FileReader(rec)
				must(err)
				w, err := os.Create(outPath)
				must(err)
				n, err := io.Copy(w, r)
				total += n
				r.Close()
				w.Close()
			}
		}
	}
	fmt.Println("Wrote", total, "bytes")
}

func main() {
	// first component is udid
	mm, err := backup.Enumerate()
	must(err)

	var selected *backup.Backup

	if len(os.Args) > 1 {
		key := os.Args[1]
		for _, man := range mm {
			dashed := strings.Contains(man.FileName, "-")
			if man.DeviceName == key && !dashed {
				selected = &man
				break
			}
			if man.FileName == key {
				selected = &man
				break
			}
			if strings.Contains(man.DeviceName, key) && !dashed {
				selected = &man
				break
			}
			if strings.Contains(man.FileName, key) && !dashed {
				selected = &man
				break
			}
		}
	}

	if selected == nil {
		for _, man := range mm {
			fmt.Println(man.DeviceName, "\t", man.FileName)
		}
		return
	}
	fmt.Println("Selected", selected.DeviceName, selected.FileName)
	db, err := backup.Open(selected.FileName)
	must(err)

	if len(os.Args) < 2 {
		for _, domain := range db.Domains() {
			fmt.Println(domain)
		}
		return
	}

	help := func() {
		fmt.Println(`Usage:
    ls [domain]
    restore domain dest
    dumpkeys [outputfile]
    apps
`)
	}

	var cmd string
	if len(os.Args) > 2 {
		cmd = os.Args[2]
	}
	switch cmd {
	case "ls", "list":
		if len(os.Args) > 3 {
			list(db, os.Args[3])
		} else {
			domains(db)
		}
	case "restore":
		if len(os.Args) > 4 {
			restore(db, os.Args[3], os.Args[4])
		} else {
			help()
		}
	case "apps":
		apps(db)
	case "dumpkeys":
		var out string
		if len(os.Args) > 3 {
			out = os.Args[3]
		}
		dumpkeys(db, out)
	default:
		help()
	}

	if true {
		return
	}

}
