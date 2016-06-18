// The backup package wraps an iOS backup directory.  This will need updating to handle the directories from
// macOS sierra.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
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

	"github.com/dunhamsteve/ios/crypto/aeswrap"
	"github.com/dunhamsteve/ios/keybag"
	"github.com/dunhamsteve/plist"
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
			fmt.Println("Recovered in f", r)
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

type MobileBackup struct {
	Dir      string
	Manifest Manifest
	Records  []Record
	Keybag   keybag.Keybag
}

func (mb *MobileBackup) FileKey(rec Record) []byte {
	for _, key := range mb.Keybag.Keys {
		if key.Class == uint32(rec.ProtClass) {

			if key.Key != nil {
				x := aeswrap.Unwrap(key.Key, rec.Key[4:])
				return x
			} else {
				log.Println("Locked key for protection class", rec.ProtClass)
				return nil
			}
		}
	}
	return nil
}

var zeroiv = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func (mb *MobileBackup) ReadFile(rec Record) ([]byte, error) {

	key := mb.FileKey(rec)
	if key == nil {
		return nil, errors.New("No key")
	}
	fn := path.Join(mb.Dir, rec.HashCode())
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

func (mb *MobileBackup) Domains() []string {
	domains := make(map[string]bool)
	for _, rec := range mb.Records {
		domains[rec.Domain] = true
	}
	rval := make([]string, 0, len(domains))
	for k, _ := range domains {
		rval = append(rval, k)
	}
	sort.Strings(rval)
	return rval
}

// Not yet implemented
func (mb *MobileBackup) FileReader(rec Record) (io.ReadCloser, error) {
	rval := new(reader)
	key := mb.FileKey(rec)

	if key == nil {
		return nil, errors.New("Can't get key for " + rec.Domain + "-" + rec.Path)
	}

	fn := path.Join(mb.Dir, rec.HashCode())
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
			} else {
				rval.ch <- buf[:n]
				copy(prev, buf[n:])
			}
			if rval.err != nil {
				fmt.Println(" other error", rval.err)
				rval.ch <- nil
				return
			}
		}
	}()
	rval.buf = <-rval.ch
	return rval, nil
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
}

type Backup struct {
	DeviceName string
	FileName   string
}

func Enumerate() ([]Backup, error) {
	var all []Backup
	home := os.Getenv("HOME")
	dir := path.Join(home, "Library/Application Support/MobileSync/Backup")
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

func Open(guid string) (*MobileBackup, error) {
	var backup MobileBackup
	home := os.Getenv("HOME")
	backup.Dir = path.Join(home, "Library/Application Support/MobileSync/Backup", guid)
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
	tmp = path.Join(backup.Dir, "Manifest.mbdb")

	var dbr DBReader
	r2, err := os.Open(tmp)
	if err != nil {
		return nil, err
	}
	dbr.Reader = r2
	defer r2.Close()
	backup.Records = dbr.readAll()

	return &backup, nil
}
