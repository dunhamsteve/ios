package aeswrap

import (
    "encoding/hex"
    "testing"
    "bytes"
)

func TestWrap(t *testing.T) {
    // A single test vector from the RFC.
    kek,_ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    key,_ := hex.DecodeString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
    ctext,_ := hex.DecodeString("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
    
    tmp := Wrap(kek,key)
        t.Logf("HAVE %x WANT %x",tmp,ctext)
    if !bytes.Equal(tmp,ctext) {
        t.Error("wrap failed")
    }
}


func TestUnwrap(t *testing.T) {
    // A single test vector from the RFC.
    kek,_ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    key,_ := hex.DecodeString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
    ctext,_ := hex.DecodeString("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
    
    tmp := Unwrap(kek,ctext)
        t.Logf("HAVE %x WANT %x",tmp,key)
    if !bytes.Equal(tmp,key) {
        t.Error("unwrap failed")
    }
}