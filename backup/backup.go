// Package backup wraps an iOS backup directory.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"sort"
	"runtime"

	"github.com/dunhamsteve/ios/crypto/aeswrap"
	"github.com/dunhamsteve/ios/keybag"
	"github.com/dunhamsteve/ios/kvarchive"
	"github.com/dunhamsteve/plist"
	_ "github.com/mattn/go-sqlite3"
)

var be = binary.BigEndian

type MetaData struct {
	Mode          uint16
	Inode         uint64
	Uid           uint32
	Gid           uint32
	Mtime         uint32
	Atime         uint32
	Ctime         uint32
	Length        uint64
	ProtClass     uint8
	PropertyCount uint8
}

type Record struct {
	MetaData
	Domain     string
	Path       string
	LinkTarget string
	Digest     []byte
	Key        []byte
	Properties map[string][]byte
}

type DBReader struct {
	io.Reader
	err error
}

func (r *Record) HashCode() string {
	sum := sha1.Sum([]byte(r.Domain + "-" + r.Path))
	return hex.EncodeToString(sum[:])
}

func (r *DBReader) readData() []byte {
	var l uint16
	r.err = binary.Read(r, be, &l)
	if l == 0xffff {
		return nil
	}
	if l > 2048 {
		panic(fmt.Sprintf("long name %d", l))
	}
	buf := make([]byte, l)
	r.Read(buf)
	return buf
}
func (r *DBReader) readRecord() Record {
	var rec Record
	rec.Domain = string(r.readData())
	if r.err != nil {
		return rec
	}
	rec.Path = string(r.readData())
	rec.LinkTarget = string(r.readData())
	rec.Digest = r.readData()
	rec.Key = r.readData()
	binary.Read(r, be, &rec.MetaData)
	rec.Properties = make(map[string][]byte)
	for i := uint8(0); i < rec.PropertyCount; i++ {
		rec.Properties[string(r.readData())] = r.readData()
	}
	return rec
}

func (r *DBReader) readAll() []Record {
	var rval []Record
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in readAll", r)
		}
	}()
	var header [6]byte
	r.Read(header[:])
	for {
		rec := r.readRecord()
		if r.err != nil {
			break
		}
		rval = append(rval, rec)
	}
	return rval
}

// MobileBackup encapsulates a mobile backup manifest
type MobileBackup struct {
	Dir      string
	Manifest Manifest
	Records  []Record
	Keybag   keybag.Keybag

	BlobKey []byte
}

// SetPassword decrypts the keychain.
func (mb *MobileBackup) SetPassword(pass string) error {
	return mb.Keybag.SetPassword(pass)
}

func decrypt(key, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	var iv [16]byte
	for i := range iv {
		iv[i] = byte(i)
	}
	cbc := cipher.NewCBCDecrypter(c, iv[:])
	out := make([]byte, len(data))
	cbc.CryptBlocks(out, data)

	sz := out[len(out)-1]
	if sz > 16 || sz < 1 {
		log.Fatal("bad pkcs7", sz)
	}
	end := len(out) - int(sz)
	for i := end; i < len(out); i++ {
		if out[i] != sz {
			log.Fatalln("bad pkcs7", sz)
		}
	}
	// TODO PKCS7
	return out[:end]
}

// FileKey finds the key for a given file record
func (mb *MobileBackup) FileKey(rec Record) []byte {
	key := mb.Keybag.GetClassKey(uint32(rec.ProtClass))
	if key != nil {
		return aeswrap.Unwrap(key, rec.Key[4:])
	}
	log.Println("No key for protection class", rec.ProtClass)

	return nil
}

var zeroiv = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// ReadFile reads the contents of an encrypted file.
func (mb *MobileBackup) ReadFile(rec Record) ([]byte, error) {
	key := mb.FileKey(rec)
	if key == nil {
		return nil, fmt.Errorf("No key for file %v", rec)
	}
	hcode := rec.HashCode()
	fn := path.Join(mb.Dir, hcode)
	// New path format
	if _, err := os.Stat(fn); err != nil {
		fn = path.Join(mb.Dir, hcode[:2], hcode)
	}
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bm := cipher.NewCBCDecrypter(b, zeroiv)
	bm.CryptBlocks(data, data)

	return unpad(data), nil
}

// unpad removes pkcs7 padding, returns nil if invalid.
func unpad(data []byte) []byte {
	l := len(data)
	c := data[l-1]
	if c > 16 {
		return nil
	}
	for i := 0; i < int(c); i++ {
		if data[l-i-1] != c {
			return nil
		}
	}
	return data[:l-int(c)]
}

// Domains lists the file domains in a backup manifest.
func (mb *MobileBackup) Domains() []string {
	domains := make(map[string]bool)
	for _, rec := range mb.Records {
		domains[rec.Domain] = true
	}
	rval := make([]string, 0, len(domains))
	for k := range domains {
		rval = append(rval, k)
	}
	sort.Strings(rval)
	return rval
}

// FileReader returns an io.Reader for the unencrypted contents of a file record
func (mb *MobileBackup) FileReader(rec Record) (io.ReadCloser, error) {
	rval := new(reader)
	key := mb.FileKey(rec)

	if key == nil {
		return nil, errors.New("Can't get key for " + rec.Domain + "-" + rec.Path)
	}
	hcode := rec.HashCode()
	fn := path.Join(mb.Dir, hcode)
	// New path format
	if _, err := os.Stat(fn); err != nil {
		fn = path.Join(mb.Dir, hcode[:2], hcode)
	}
	rval.r, rval.err = os.Open(fn)
	if rval.err != nil {
		return nil, rval.err
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher := cipher.NewCBCDecrypter(b, zeroiv)
	rval.ch = make(chan []byte)
	// Feeds 4k blocks to the channel until we run out of file.
	// Handles padding on last block and EOF detection by holding 16 bytes in reserve.
	go func() {
		var n int
		prev := make([]byte, 16)
		n, rval.err = io.ReadFull(rval.r, prev)
		if n != 16 {
			rval.err = errors.New("short read of IV")
			rval.ch <- nil
			return
		}
		cipher.CryptBlocks(prev, prev)
		for {
			var n int
			buf := make([]byte, 4096+16)
			copy(buf, prev)
			n, rval.err = io.ReadFull(rval.r, buf[16:])
			if rval.err == io.ErrUnexpectedEOF {
				rval.err = io.EOF
			}
			if rval.err == nil && n != 4096 {
				panic("Unexpected read size")
			}
			cipher.CryptBlocks(buf[16:], buf[16:])
			if rval.err == io.EOF {
				buf = buf[:16+n]
				buf = unpad(buf)
				if buf == nil {
					rval.err = errors.New("Bad Padding")
				}
				rval.ch <- buf
				rval.ch <- nil
				return
			}
			rval.ch <- buf[:n]
			copy(prev, buf[n:])

			if rval.err != nil {
				fmt.Println(" other error", rval.err)
				rval.ch <- nil
				return
			}
		}
	}()
	rval.buf = <-rval.ch
	return rval, rval.err
}

// CBC+PKCS7 reader
type reader struct {
	r      io.ReadCloser
	ch     chan []byte
	cipher cipher.BlockMode
	buf    []byte
	pos    uint32
	err    error
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *reader) Read(p []byte) (n int, err error) {
	want := len(p)
	for {
		if want == 0 {
			return
		}
		if len(r.buf) == 0 {
			r.buf = <-r.ch
			if r.buf == nil {
				return n, r.err
			}
		}
		i := min(want, len(r.buf))
		copy(p, r.buf[:i])
		r.buf = r.buf[i:]
		p = p[i:]
		want -= i
		n += i
	}
}

func (r *reader) Close() error {
	return r.r.Close()
}

type Manifest struct {
	BackupKeyBag []byte
	Lockdown     struct {
		DeviceName string
	}
	Applications map[string]map[string]interface{}
	IsEncrypted  bool
	ManifestKey  []byte // this is wrapped
}

type Backup struct {
	DeviceName string
	FileName   string
}

// Enumerate lists the available backups
func Enumerate() ([]Backup, error) {
	var all []Backup
	var home string
	var dir string
	if runtime.GOOS == "windows" {
		home = os.Getenv("APPDATA")
		dir = path.Join(home, "Apple Computer\\MobileSync\\Backup")
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			dir = path.Join(home, "Apple\\MobileSync\\Backup")
		}
	} else {
		home = os.Getenv("HOME")
		dir = path.Join(home, "Library/Application Support/MobileSync/Backup")
	}
	r, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	infos, err := r.Readdir(-1)
	if err != nil {
		return nil, err
	}
	for _, fi := range infos {
		if fi.IsDir() {
			pl := path.Join(dir, fi.Name(), "Manifest.plist")
			if r, err := os.Open(pl); err == nil {
				defer r.Close()
				var manifest Manifest
				err = plist.Unmarshal(r, &manifest)
				if err == nil {
					all = append(all, Backup{manifest.Lockdown.DeviceName, fi.Name()})
				}
			}
		}
	}

	return all, nil
}

// Open opens a MobileBackup directory corresponding to a given guid.
func Open(guid string) (*MobileBackup, error) {
	var backup MobileBackup
	var home string
	if runtime.GOOS == "windows" {
		home = os.Getenv("APPDATA")
		backup.Dir = path.Join(home, "Apple Computer\\MobileSync\\Backup", guid)
		if _, err := os.Stat(backup.Dir); os.IsNotExist(err) {
			backup.Dir = path.Join(home, "Apple\\MobileSync\\Backup", guid)
		}
	} else {
		home = os.Getenv("HOME")
		backup.Dir = path.Join(home, "Library/Application Support/MobileSync/Backup", guid)
	}

	tmp := path.Join(backup.Dir, "Manifest.plist")
	r, err := os.Open(tmp)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	err = plist.Unmarshal(r, &backup.Manifest)
	if err != nil {
		return nil, err
	}
	backup.Keybag = keybag.Read(backup.Manifest.BackupKeyBag)
	return &backup, nil
}

// Load loads the backup. It must be called after "SetPassword" for
// ios 10.2+ encrypted backups, and must be called before attempting
// to use any other methods on MobileBackup.
func (mb *MobileBackup) Load() error {
	// Try to read old Manifest
	err := mb.readOldManifest()
	if err == nil {
		return nil
	}

	// try to read new manifest
	return mb.readNewManifest()
}

func (mb *MobileBackup) decryptDatabase(fn string, mk []byte) (string, error) {
	var err error
	class := binary.LittleEndian.Uint32(mk)
	ckey := mb.Keybag.GetClassKey(class)
	if ckey == nil {
		return "", fmt.Errorf("No manifest key for class %d", class)
	}
	key := aeswrap.Unwrap(ckey, mk[4:])
	fmt.Println("Got manifest key", key)
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return "", err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	bm := cipher.NewCBCDecrypter(b, zeroiv)
	bm.CryptBlocks(data, data)
	out, err := ioutil.TempFile("", "db")
	if err != nil {
		return "", err
	}
	out.Write(data)
	out.Close()
	return out.Name(), nil
}

func (mb *MobileBackup) readNewManifest() error {
	var err error
	fmt.Println("load")
	tmp := path.Join(mb.Dir, "Manifest.db")
	mk := mb.Manifest.ManifestKey

	if mk != nil {
		tmp, err = mb.decryptDatabase(tmp, mk)
		if err != nil {
			return err
		}
		defer os.Remove(tmp)
	}

	db, err := sql.Open("sqlite3", tmp)
	if err != nil {
		return err
	}
	rows, err := db.Query("select * from files")
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, domain, path *string
		var data []byte
		var flags int
		var record Record

		err = rows.Scan(&id, &domain, &path, &flags, &data)
		if err != nil {
			return err
		}
		// Not sure if this happens anymore
		if domain == nil {
			continue
		}

		record.Domain = *domain

		tmp, err := kvarchive.UnArchive(bytes.NewReader(data))
		if err != nil {
			panic(err)
		}
		frec := tmp.(map[string]interface{})
		// TODO - teach kvarchive to read into structures.
		record.Key, _ = frec["EncryptionKey"].([]byte)
		record.ProtClass = uint8(frec["ProtectionClass"].(int64))
		record.Length = uint64(frec["Size"].(int64))
		record.Mode = uint16(frec["Mode"].(int64))
		record.Gid = uint32(frec["GroupID"].(int64))
		record.Uid = uint32(frec["UserID"].(int64))
		record.Ctime = uint32(frec["Birth"].(int64))
		record.Atime = uint32(frec["LastModified"].(int64))
		record.Path = frec["RelativePath"].(string)

		mb.Records = append(mb.Records, record)
	}

	return nil
}

func (mb *MobileBackup) readOldManifest() error {
	tmp := path.Join(mb.Dir, "Manifest.mbdb")
	r2, err := os.Open(tmp)
	if err == nil {
		var dbr DBReader
		dbr.Reader = r2
		defer r2.Close()
		mb.Records = dbr.readAll()
		return nil
	}
	return err
}
