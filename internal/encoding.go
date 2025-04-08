package internal

import "io"

// writeVaruint32 writes a uint32 to the destination buffer passed with a size of 1-5 bytes. It uses byte
// slice b in order to prevent allocations.
func writeVaruint32(dst io.Writer, x uint32, b []byte) error {
	clear(b[:5])
	i := 0
	for x >= 0x80 {
		b[i] = byte(x) | 0x80
		i++
		x >>= 7
	}
	b[i] = byte(x)
	_, err := dst.Write(b[:i+1])
	return err
}

// dynamicWriteVaruint32 returns a byte slice of a uint32 written in varuint32 format. It uses byte slice b in order
// to prevent allocations.
func dynamicWriteVaruint32(x uint32, b []byte) []byte {
	clear(b[:5])
	i := 0
	for x >= 0x80 {
		b[i] = byte(x) | 0x80
		i++
		x >>= 7
	}
	b[i] = byte(x)
	return b[:i+1]
}
