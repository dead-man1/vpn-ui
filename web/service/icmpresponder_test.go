package service

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestBuildIcmpEchoReply checks the fabricated reply is a well-formed IPv4 ICMP
// echo-reply: src/dst swapped, type flipped to 0, id/seq/payload preserved, and both
// checksums valid (the one's-complement checksum over a field that already holds its
// checksum is 0).
func TestBuildIcmpEchoReply(t *testing.T) {
	req := make([]byte, 32)
	req[0] = 0x45
	binary.BigEndian.PutUint16(req[2:], uint16(len(req)))
	req[8] = 64
	req[9] = 1                            // ICMP
	copy(req[12:16], []byte{10, 7, 0, 5}) // src = client
	copy(req[16:20], []byte{8, 8, 8, 8})  // dst = pinged target
	req[20] = 8                           // echo-request
	binary.BigEndian.PutUint16(req[24:], 0x1234) // id
	binary.BigEndian.PutUint16(req[26:], 0x0007) // seq
	copy(req[28:], []byte{0xde, 0xad, 0xbe, 0xef})

	reply, dst, ok := buildIcmpEchoReply(req)
	if !ok {
		t.Fatal("expected an echo-request to be accepted")
	}
	if dst != [4]byte{10, 7, 0, 5} {
		t.Errorf("dst = %v; want the client 10.7.0.5", dst)
	}
	if !bytes.Equal(reply[12:16], []byte{8, 8, 8, 8}) {
		t.Errorf("reply src = %v; want the pinged target 8.8.8.8", reply[12:16])
	}
	if !bytes.Equal(reply[16:20], []byte{10, 7, 0, 5}) {
		t.Errorf("reply dst = %v; want the client", reply[16:20])
	}
	if reply[20] != 0 {
		t.Errorf("icmp type = %d; want 0 (echo-reply)", reply[20])
	}
	if binary.BigEndian.Uint16(reply[24:]) != 0x1234 || binary.BigEndian.Uint16(reply[26:]) != 0x0007 {
		t.Error("id/seq not preserved")
	}
	if !bytes.Equal(reply[28:32], []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Error("payload not preserved")
	}
	if onesComplementChecksum(reply[:20]) != 0 {
		t.Error("IP header checksum invalid")
	}
	if onesComplementChecksum(reply[20:]) != 0 {
		t.Error("ICMP checksum invalid")
	}
}

func TestBuildIcmpEchoReplyRejects(t *testing.T) {
	base := make([]byte, 28)
	base[0] = 0x45
	base[9] = 1
	base[20] = 8
	// A valid echo-request is accepted as the control.
	if _, _, ok := buildIcmpEchoReply(base); !ok {
		t.Fatal("control echo-request should be accepted")
	}
	cases := map[string]func([]byte){
		"not IPv4":       func(b []byte) { b[0] = 0x65 },
		"not ICMP":       func(b []byte) { b[9] = 6 },
		"not echo-req":   func(b []byte) { b[20] = 0 },
		"truncated ICMP": func(b []byte) { b[0] = 0x4f }, // IHL 15 => header claims 60 bytes
	}
	for name, mutate := range cases {
		b := make([]byte, len(base))
		copy(b, base)
		mutate(b)
		if _, _, ok := buildIcmpEchoReply(b); ok {
			t.Errorf("%s: expected rejection", name)
		}
	}
}
