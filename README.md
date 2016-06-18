# Go iOS Utilities

This repository contains `irestore`, a program for inspecting and pulling files and the keychain out of an iOS backup
tree. It is written in Go and based on work done in the `iphone-dataprotection` project found on google code. 

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
    ls [domain]
    restore domain dest
    dumpkeys [outputfile]
    apps
```

The `ls` command will list domains or files in a domain.

The `restore` command will restore the files in a domain into a directory tree.

The `dumpkeys` command will dump the readable portions of the keychain to json.

The `apps` command will list the installed apps.

_**Note:** The format of the backup database has recently changed (possibly just in MacOS 10.12) to be a sqlite database.  I'm checking this into github before porting to the new format._



