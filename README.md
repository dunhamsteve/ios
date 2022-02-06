# iOS Backup Extraction

This repository contains `irestore`, a program for inspecting and pulling files and the keychain out of an encrypted iOS backup tree. It is written in Go and based on work done in the `iphone-dataprotection` project found on google code. 

If you are using an encrypted backup, it also can read parts of the keychain and dump it as json. 

Without options, `irestore` will list the current backups found on your machine. You may reference a backup by name or guid.

```shell
# irestore
MyPhone 5069636b6c656448657272696e674170706c6573
MyPad 43686f636f6c61746552616d656b696e73546f6f
```

The first argument is the device id or device name:

```shell
# irestore MyPad
Selected MyPad 43686f636f6c61746552616d656b696e73546f6f
Usage:
    ls [domain] .cred(optional)
    restore domain dest .cred(optional)
    dumpkeys [outputfile] .cred(optional)
    apps .cred(optional)
```

The `ls` command will list domains or files in a domain.

The `restore` command will restore the files in a domain into a directory tree.

The `dumpkeys` command will dump the readable portions of the keychain to json.

The `apps` command will list the installed apps.

The `.cred` is an optional arguement that must be positioned at the end of the arguements list with a path to a file ending with or called `.cred`, and contains a string with no newline with the password to the database

_Changes to the database format in recent iOS releases:_

## iOS 10 (deprecated)

iOS 10 is using a different format for the manifest. It stores the data in a sqlite3 database called `Manifest.db`, which contains two tables. And the actual files themselves are moved to subdirectories whose names are the first two characters of the filename.

### Properties

The `Properties` table contains a list of key/value pairs.  The key `salt` contains the salt for the backup password. 
The key `passwordHash` contains `sha256(password||salt)`.

### Files

The `Files` table contains a row for each file. The columns are `fileID`, `domain`, `relativePath`, `flags`, and `file`.  The `fileID` is the hash of `domain + "-" + relativePath`. 

The `file` field is an encrypted with AES128-CBC.  The key is the first 16 bytes of `sha1(password||salt)`, the initialization vector is the sequence of bytes `0, 1, 2, ..., 15`. 

The decrypted data is a binary plist, specifically a key-valued archive of a `MBFile` object.  This object has a `ProtectionClass` field that gives the files protection class (used for choosing an appropriate key from the keybag) and an `EncryptionKey` field containing an `NSMutableData` with the same format as the encryption key in the MBDB file. (A little endian uint32 containing the protection class, followed by the file's key AES-WRAPed by the key for that protection class.)

## iOS 10.1

The properties table described above is now empty, and the "file" column is a bare plist. To keep the code simple, I no longer support the iOS 10.0 
backup format.


## iOS 10.2

There are a few changes in iOS 10.2.  The Manifest database itself is encrypted, its key is stored, wrapped with protection class 4, in the `ManifestKey` property `Manifest.plist`. This necessitates asking for the password before listing files.

Further, the keybag has a second round of PBKDF2 with different parameters and a sha256 hash function. This one takes about 10 seconds in Go, so the code now prints the decrypted key in hex. If you provide this hex key instead of your password, you can skip the long key derivation step.

(iOS 10.2 details came from a github thread.)
