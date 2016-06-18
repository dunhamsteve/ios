// Implements rfc3394 - AES keywrapping.
package aeswrap

import (
	"bytes"
	"crypto/aes"
)

var rfc3394iv = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// Wrap will wrap 'in' with the key in 'kek'.
func Wrap(kek []byte, in []byte) []byte {
	// 1) Initialize variables.
	//     Set A = IV, an initial value (see 2.2.3)
	//     For i = 1 to n
	//         R[i] = P[i]

	var A, B, R []byte
	A = make([]byte, 8)
	B = make([]byte, 16)
	R = make([]byte, len(in)+8)

	copy(A, rfc3394iv)
	copy(R[8:], in)

	n := len(in) / 8
	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil
	}

	// 2) Calculate intermediate values.
	//
	//     For j = 0 to 5
	//         For i=1 to n
	//             B = AES(K, A | R[i])
	//             A = MSB(64, B) ^ t where t = (n*j)+i
	//             R[i] = LSB(64, B)
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(B, A)
			copy(B[8:], R[8*i:])
			cipher.Encrypt(B, B)
			copy(A, B)
			t := (n * j) + i
			if t > 255 {
				panic("IMPLEMENT")
			}
			A[7] ^= byte(t & 255)
			copy(R[8*i:], B[8:])
		}
	}

	// 3) Output the results.
	//
	//     Set C[0] = A
	//     For i = 1 to n
	//         C[i] = R[i]
	copy(R, A)
	return R
}

// Unwrap will unwap the value in "in" with the key "kek". Returns nil on failure.
func Unwrap(kek []byte, in []byte) []byte {
	// TODO add a few more checks..
	if len(kek) < 16 || len(in)%8 != 0 {
		return nil
	}

	// 1) Initialize variables.
	//
	//        Set A = C[0]
	//        For i = 1 to n
	//            R[i] = C[i]
	var A, B, R []byte
	A = make([]byte, 8)
	B = make([]byte, 16)
	R = make([]byte, len(in))

	copy(A, in)
	copy(R, in)

	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil
	}

	//    2) Compute intermediate values.
	//
	//        For j = 5 to 0
	//            For i = n to 1
	//                B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
	//                A = MSB(64, B)
	//                R[i] = LSB(64, B)
	n := len(in)/8 - 1
	for j := 5; j >= 0; j-- {
		for i := n; i > 0; i-- {
			// OPERATION

			copy(B, A)
			copy(B[8:], R[i*8:])
			t := uint64(n*j + i)
			if t > 255 {
				panic("IMPLEMENT")
			}
			B[7] ^= uint8(t & 0xff)
			cipher.Decrypt(B, B)
			copy(A, B)
			copy(R[i*8:], B[8:])
		}
	}

	//    3) Output results.
	//
	//    If A is an appropriate initial value (see 2.2.3),
	//    Then
	//        For i = 1 to n
	//            P[i] = R[i]
	//    Else
	//        Return an error
	if !bytes.Equal(A, rfc3394iv) {
		return nil
	}
	return R[8:]
}
