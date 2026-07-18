package service

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"golang.org/x/sys/unix"
)

// icmpQueueNum is the NFQUEUE number the nftables rule (see nftables.go) hands client
// ICMP echo-requests to. Kept out of the low range to avoid clashing with anything a
// host firewall might use.
const icmpQueueNum = 100

// Why this exists: the VPN data plane routes client TCP/UDP through Xray (TPROXY +
// dokodemo), and Xray carries only TCP and UDP — it has no ICMP. So a client's
// `ping 8.8.8.8` is never proxied; it would be FORWARDed out the WAN with an un-NATed
// 10.x source and get no reply, i.e. "clients get no ICMP". Real per-user ICMP through
// Xray is not possible without replacing the core (even tun-based clients like
// Shadowrocket / sing-box do not truly forward ICMP — they FABRICATE a local reply).
//
// This responder gives clients the SAME experience those clients give: an nftables rule
// hands each client echo-request bound for the internet to NFQUEUE, and we fabricate an
// echo-reply (source = the pinged target) sent straight back down the tunnel, then DROP
// the original so nothing leaks out the WAN. Replies are cosmetic — a dead host still
// "answers" and traceroute/PMTUD are unaffected — but `ping` succeeds at tunnel latency,
// which is what users expect. Gateway ping and client-to-client ping keep their existing
// kernel paths (the nft rule excludes destinations inside the client space).

var (
	icmpResponderOnce sync.Once
	icmpEnabled       atomic.Bool
	icmpEnabledReadAt atomic.Int64 // unix-nanos of the last answerIcmp setting read
)

// icmpAnswerEnabled reports the cached answerIcmp setting, re-reading it at most once
// every few seconds so a toggle takes effect without a restart, without a DB hit per
// packet.
func icmpAnswerEnabled() bool {
	now := time.Now().UnixNano()
	if now-icmpEnabledReadAt.Load() > int64(5*time.Second) {
		if v, err := (&SettingService{}).GetAnswerIcmp(); err == nil {
			icmpEnabled.Store(v)
		}
		icmpEnabledReadAt.Store(now)
	}
	return icmpEnabled.Load()
}

// StartIcmpResponder launches the local ICMP echo responder once, for the lifetime of
// the process. It is safe to call when no VPN inbounds exist: with no nft rule feeding
// the queue it simply sits idle, and if the kernel lacks NFQUEUE support it disables
// itself with a warning (the nft rule uses `bypass`, so ICMP then behaves as before).
func StartIcmpResponder() {
	icmpResponderOnce.Do(func() {
		icmpEnabled.Store(true) // optimistic default; icmpAnswerEnabled refreshes it
		go runIcmpResponder()
	})
}

func runIcmpResponder() {
	// A raw IPv4 socket with the header included by us (IPPROTO_RAW implies IP_HDRINCL),
	// used to inject the fabricated replies. The kernel routes each by its destination
	// (the client's tunnel IP), so the reply goes back down the tunnel.
	sendFd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		logger.Warning("ICMP responder: raw socket unavailable, ping-through-tunnel disabled:", err)
		return
	}
	defer unix.Close(sendFd)

	for {
		if err := icmpQueueLoop(sendFd); err != nil {
			logger.Warning("ICMP responder: nfqueue unavailable, retrying in 30s:", err)
			time.Sleep(30 * time.Second)
			continue
		}
		return // clean shutdown (never happens with a background context)
	}
}

func icmpQueueLoop(sendFd int) error {
	cfg := &nfqueue.Config{
		NfQueue:      icmpQueueNum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}
	nf, err := nfqueue.Open(cfg)
	if err != nil {
		return err
	}
	defer nf.Close()

	ctx := context.Background()
	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID
		if a.Payload == nil || !icmpAnswerEnabled() {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}
		reply, dst, ok := buildIcmpEchoReply(*a.Payload)
		if !ok {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}
		// Inject the fabricated reply toward the client, then DROP the request so it
		// never leaks out the WAN un-NATed.
		if err := unix.Sendto(sendFd, reply, 0, &unix.SockaddrInet4{Addr: dst}); err != nil {
			logger.Debug("ICMP responder: send failed:", err)
		}
		_ = nf.SetVerdict(id, nfqueue.NfDrop)
		return 0
	}
	errFn := func(e error) int {
		logger.Debug("ICMP responder nfqueue error:", e)
		return 0
	}
	if err := nf.RegisterWithErrorFunc(ctx, fn, errFn); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// buildIcmpEchoReply turns a client's IPv4 ICMP echo-REQUEST into a ready-to-send
// echo-REPLY (source/destination swapped, type 8 -> 0, id/seq/payload preserved, both
// checksums recomputed) and returns the reply's destination (the client). ok is false
// for anything that is not an IPv4 ICMP echo-request.
func buildIcmpEchoReply(req []byte) ([]byte, [4]byte, bool) {
	var dst [4]byte
	if len(req) < 20 || req[0]>>4 != 4 {
		return nil, dst, false
	}
	ihl := int(req[0]&0x0f) * 4
	if ihl < 20 || len(req) < ihl+8 || req[9] != 1 /* ICMP */ {
		return nil, dst, false
	}
	icmp := req[ihl:]
	if icmp[0] != 8 /* echo-request */ {
		return nil, dst, false
	}

	total := 20 + len(icmp)
	out := make([]byte, total)
	out[0] = 0x45 // IPv4, IHL 5
	binary.BigEndian.PutUint16(out[2:], uint16(total))
	out[8] = 64 // TTL
	out[9] = 1  // ICMP
	copy(out[12:16], req[16:20]) // src = request's dst (the pinged target)
	copy(out[16:20], req[12:16]) // dst = request's src (the client)
	binary.BigEndian.PutUint16(out[10:], onesComplementChecksum(out[:20]))

	copy(out[20:], icmp)
	out[20] = 0 // type: echo-reply
	out[22], out[23] = 0, 0
	binary.BigEndian.PutUint16(out[22:], onesComplementChecksum(out[20:]))

	copy(dst[:], out[16:20])
	return out, dst, true
}

// onesComplementChecksum is the 16-bit one's-complement checksum shared by the IPv4
// header and the ICMP message.
func onesComplementChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
