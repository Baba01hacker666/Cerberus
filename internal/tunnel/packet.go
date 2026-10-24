package tunnel

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// ParsePacketAddrs extracts IPv4 or IPv6 source and destination addresses without heap allocations on the fast path.
func ParsePacketAddrs(pkt []byte) (src, dst netip.Addr, ok bool) {
	if len(pkt) < 20 {
		return netip.Addr{}, netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		var s4, d4 [4]byte
		copy(s4[:], pkt[12:16])
		copy(d4[:], pkt[16:20])
		return netip.AddrFrom4(s4), netip.AddrFrom4(d4), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, netip.Addr{}, false
		}
		var s6, d6 [16]byte
		copy(s6[:], pkt[8:24])
		copy(d6[:], pkt[24:40])
		return netip.AddrFrom16(s6), netip.AddrFrom16(d6), true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}

func dstIP(pkt []byte) string {
	_, dst, ok := ParsePacketAddrs(pkt)
	if !ok {
		return ""
	}
	return dst.String()
}

// ForwardCopy makes a copy of pkt with decremented TTL/HopLimit and updated IPv4 header checksum.
// Returns (nil, false) if packet is invalid or TTL has expired (<= 1).
func ForwardCopy(pkt []byte) ([]byte, bool) {
	if len(pkt) < 20 {
		return nil, false
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return nil, false
		}
		if pkt[8] <= 1 {
			return nil, false
		}
		out := make([]byte, len(pkt))
		copy(out, pkt)
		out[8]--
		out[10] = 0
		out[11] = 0
		csum := internetChecksum(out[:ihl])
		binary.BigEndian.PutUint16(out[10:12], csum)
		return out, true
	case 6:
		if len(pkt) < 40 || pkt[7] <= 1 {
			return nil, false
		}
		out := make([]byte, len(pkt))
		copy(out, pkt)
		out[7]--
		return out, true
	default:
		return nil, false
	}
}

func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// BuildICMPEchoRequest constructs a valid raw IPv4 ICMP Echo Request packet.
func BuildICMPEchoRequest(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	s4 := src.As4()
	d4 := dst.As4()
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], seq)
	pkt[8] = 64 // TTL
	pkt[9] = 1  // Protocol: ICMPv4
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], internetChecksum(pkt[:20]))

	// ICMPv4 header + payload
	icmp := pkt[20:]
	icmp[0] = 8 // Echo Request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))
	return pkt
}

// BuildICMPEchoReply turns an inbound IPv4 ICMP Echo Request into a valid ICMP Echo Reply.
func BuildICMPEchoReply(req []byte) ([]byte, bool) {
	if len(req) < 28 || (req[0]>>4) != 4 {
		return nil, false
	}
	ihl := int(req[0]&0x0f) * 4
	if ihl < 20 || len(req) < ihl+8 || req[9] != 1 {
		return nil, false
	}
	icmpReq := req[ihl:]
	if icmpReq[0] != 8 { // not Echo Request
		return nil, false
	}
	rep := make([]byte, len(req))
	copy(rep, req)
	// Swap src & dst IPv4
	copy(rep[12:16], req[16:20])
	copy(rep[16:20], req[12:16])
	rep[8] = 64
	rep[10] = 0
	rep[11] = 0
	binary.BigEndian.PutUint16(rep[10:12], internetChecksum(rep[:ihl]))

	icmpRep := rep[ihl:]
	icmpRep[0] = 0 // Echo Reply
	icmpRep[1] = 0
	icmpRep[2] = 0
	icmpRep[3] = 0
	binary.BigEndian.PutUint16(icmpRep[2:4], internetChecksum(icmpRep))
	return rep, true
}

// ParseICMPEchoReply parses an IPv4 ICMP Echo Reply packet.
func ParseICMPEchoReply(pkt []byte) (src netip.Addr, id, seq uint16, payload []byte, ok bool) {
	if len(pkt) < 28 || (pkt[0]>>4) != 4 {
		return netip.Addr{}, 0, 0, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 || pkt[9] != 1 {
		return netip.Addr{}, 0, 0, nil, false
	}
	icmp := pkt[ihl:]
	if icmp[0] != 0 {
		return netip.Addr{}, 0, 0, nil, false
	}
	var s4 [4]byte
	copy(s4[:], pkt[12:16])
	id = binary.BigEndian.Uint16(icmp[4:6])
	seq = binary.BigEndian.Uint16(icmp[6:8])
	return netip.AddrFrom4(s4), id, seq, icmp[8:], true
}

// BuildUDPDatagram builds a valid raw IPv4+UDP packet (handy for high-concurrency throughput testing & diagnostics).
func BuildUDPDatagram(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	s4 := src.As4()
	d4 := dst.As4()
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], internetChecksum(pkt[:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// IPv4 UDP checksum 0 = optional per RFC 768
	copy(udp[8:], payload)
	return pkt
}

// ParseUDPDatagram extracts metadata and payload from a raw IPv4+UDP packet.
func ParseUDPDatagram(pkt []byte) (src, dst netip.Addr, srcPort, dstPort uint16, payload []byte, ok bool) {
	if len(pkt) < 28 || (pkt[0]>>4) != 4 {
		return netip.Addr{}, netip.Addr{}, 0, 0, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 || pkt[9] != 17 {
		return netip.Addr{}, netip.Addr{}, 0, 0, nil, false
	}
	var s4, d4 [4]byte
	copy(s4[:], pkt[12:16])
	copy(d4[:], pkt[16:20])
	udp := pkt[ihl:]
	srcPort = binary.BigEndian.Uint16(udp[0:2])
	dstPort = binary.BigEndian.Uint16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || len(udp) < udpLen {
		return netip.AddrFrom4(s4), netip.AddrFrom4(d4), srcPort, dstPort, udp[8:], true
	}
	return netip.AddrFrom4(s4), netip.AddrFrom4(d4), srcPort, dstPort, udp[8:udpLen], true
}

func MeshIPWithPrefix(ip string, cidr string) string {
	if ip == "" {
		return ""
	}
	for i := 0; i < len(ip); i++ {
		if ip[i] == '/' {
			return ip
		}
	}
	if _, n, err := net.ParseCIDR(cidr); err == nil {
		ones, _ := n.Mask.Size()
		return ip + "/" + uitoa(ones)
	}
	return ip + "/32"
}

func uitoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
