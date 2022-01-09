package main

import (
	"encoding/binary"
	"encoding/json"
	"encoding/base64"
	"time"
	"reflect"

	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"crypto/aes"

	"github.com/dunhamsteve/ios/backup"
	"github.com/dunhamsteve/ios/crypto/aeswrap"
	"github.com/dunhamsteve/ios/crypto/gcm"
	"github.com/dunhamsteve/ios/encoding/asn1"
	"github.com/dunhamsteve/plist"
	"golang.org/x/crypto/ssh/terminal"
)

// Quick and Dirty error handling - when I don't expect an error, but want to know if it happens
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func dumpJSON(x interface{}) {
	json, err := json.MarshalIndent(x, "", "  ")
	must(err)
	fmt.Println(string(json))
}

func getpass() string {
	fmt.Fprint(os.Stderr, "Backup Password: ")
	pw, err := terminal.ReadPassword(0)
	must(err)
	fmt.Println()
	return string(pw)
}

func domains(db *backup.MobileBackup) {
	for _, domain := range db.Domains() {
		fmt.Println(domain)
	}
}
func apps(db *backup.MobileBackup) {
	for app := range db.Manifest.Applications {
		fmt.Println(app)
	}
}

func list(db *backup.MobileBackup, domain string) {
	for _, rec := range db.Records {
		// just files for now
		if rec.Length > 0 {
			if domain == "*" {
				fmt.Println(rec.Domain, rec.Path)
			} else if domain == rec.Domain {
				fmt.Println(rec.Path)
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
	if err != nil {
		fmt.Println(err)
		ioutil.WriteFile("failed.bin", data, 0644)
	}
	// must(err)
	keys := make([]string, 0, len(v))
	types := make([]string, 0, len(v))
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
		keys = append(keys, entry.Key)
		types = append(types, reflect.TypeOf(entry.Value).String())
	}

	rval["_fieldOrder"] = strings.Join(keys, ",")
	rval["_fieldTypes"] = strings.Join(types, ",")
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
				fmt.Println("No key for class", class, string(key.Ref)[:4], key.Ref[4:])
				continue
			}

			aesKey := aeswrap.Unwrap(ckey, wkey)
			if aesKey == nil {
				fmt.Println("unwrap failed for class", class)
				continue
			}
			// Create a gcm cipher
			c, err := aes.NewCipher(aesKey)
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
			record["_class"] = class
			record["_version"] = version
			record["_wkey"] = wkey
			record["_length"] = l
			record["_ref"] = key.Ref

			rval = append(rval, record)
		default:
			panic(fmt.Sprintf("Unhandled keychain blob version %d", version))
		}
	}

	return rval
}

func dumpkeys(db *backup.MobileBackup, outfile string) {
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

func unparseRecord(record map[string]interface{}) []byte {
	var v EntrySET

	keys := strings.Split(fmt.Sprint(record["_fieldOrder"]), ",")
	types := strings.Split(fmt.Sprint(record["_fieldTypes"]), ",")

	for index, key := range keys {
		if (strings.HasPrefix(key, "_")) {
			continue
		}

		var entry Entry
		entry.Key = key

		switch types[index] {
		case "int64":
			entry.Value = int(record[key].(float64))
		case "string":
			entry.Value = record[key].(string)
		case "time.Time":
			const formatStr = "2006-01-02T15:04:05.999999999Z"
			t, _ := time.Parse(formatStr, record[key].(string))
			entry.Value = t
		default:
			value, _ := base64.StdEncoding.DecodeString(record[key].(string))
			entry.Value = value
		}

		v = append(v, entry)
	}

	entries, err := asn1.Marshal(v)
	if err != nil {
		fmt.Println("Error marshaling record:", err)
	}

	return entries
}

func encryptKeyGroup(db *backup.MobileBackup, group interface {}, class string) []KCEntry {
	var rval []KCEntry

	if (group == nil) {
		return rval
	}

	for _, record := range group.([]interface{}) {
		var entry KCEntry

		recordObject := record.(map[string]interface{})

		ckey := db.Keybag.GetClassKey(uint32(recordObject["_class"].(float64)))
		wkey, _ := base64.StdEncoding.DecodeString(recordObject["_wkey"].(string))
		key := aeswrap.Unwrap(ckey, wkey)

		c, err := aes.NewCipher(key)
		must(err)
	
		gcm, err := gcm.NewGCM(c)
		must(err)
	
		unparsed := unparseRecord(recordObject)

		nonce := []byte{}
		ciphertext := gcm.Seal(nil, nonce, unparsed, nil)

		data := make([]byte, 12)
		le.PutUint32(data, uint32(recordObject["_version"].(float64)))
		le.PutUint32(data[4:], uint32(recordObject["_class"].(float64)))
		le.PutUint32(data[8:], uint32(recordObject["_length"].(float64)))
		data = append(data, wkey...)
		data = append(data, ciphertext...)

		entry.Data = data
		ref, _ := base64.StdEncoding.DecodeString(recordObject["_ref"].(string))
		entry.Ref = ref
		
		rval = append(rval, entry)
	}

	return rval
}

func encryptkeys(db *backup.MobileBackup, keys string, outfile string) {
	jsonFile, err := os.Open(keys)
	must(err)

	defer jsonFile.Close()

	jsonBytes, _ := ioutil.ReadAll(jsonFile)
	jsonMap := make(map[string](interface{}))
	json.Unmarshal([]byte(jsonBytes), &jsonMap)

	path := os.ExpandEnv(outfile)
	plistFile, err := os.Create(path)
	must(err)

	defer plistFile.Close()

	emptyPlist := []byte{98, 112, 108, 105, 115, 116, 48, 48, 208, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
	_, err = plistFile.Write(emptyPlist)
	must(err)

	var v Keychain
	err = plist.Unmarshal(plistFile, v)
	must(err)

	v.General = encryptKeyGroup(db, jsonMap["General"], "genp")
	v.Internet = encryptKeyGroup(db, jsonMap["Internet"], "inet")
	v.Certs = encryptKeyGroup(db, jsonMap["Certs"], "cert")
	v.Keys = encryptKeyGroup(db, jsonMap["Keys"], "keys")

	out, err := plist.Marshal(v)
	must(err)

	err = ioutil.WriteFile(path, out, 0644)
	must(err)
}

func restore(db *backup.MobileBackup, domain string, dest string) {
	var err error
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
				if err != nil {
					log.Println("error reading file", rec, err)
					continue
				}
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

	if db.Manifest.IsEncrypted {
		err = db.SetPassword(getpass())
		must(err)
	}
	must(db.Load())
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
    encryptkeys [inputfile] [outputfile]
    apps`)
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
	case "encryptkeys":
		if len(os.Args) > 4 {
			encryptkeys(db, os.Args[3], os.Args[4])
		}
	default:
		help()
	}
}
