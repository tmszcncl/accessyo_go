package checks

import (
	"net"
)

type cdnRange struct {
	name   string
	ranges [][2]uint32
}

var cdnRanges = []cdnRange{
	{
		name: "Cloudflare",
		ranges: [][2]uint32{
			{ipToInt("103.21.244.0"), 22},
			{ipToInt("103.22.200.0"), 22},
			{ipToInt("103.31.4.0"), 22},
			{ipToInt("104.16.0.0"), 13},
			{ipToInt("104.24.0.0"), 14},
			{ipToInt("108.162.192.0"), 18},
			{ipToInt("131.0.72.0"), 22},
			{ipToInt("141.101.64.0"), 18},
			{ipToInt("162.158.0.0"), 15},
			{ipToInt("172.64.0.0"), 13},
			{ipToInt("173.245.48.0"), 20},
			{ipToInt("188.114.96.0"), 20},
			{ipToInt("190.93.240.0"), 20},
			{ipToInt("197.234.240.0"), 22},
			{ipToInt("198.41.128.0"), 17},
		},
	},
}

func DetectCdnFromIPs(ips []string) *string {
	for _, ip := range ips {
		if name := matchCdn(ip); name != nil {
			return name
		}
	}
	return nil
}

func matchCdn(ip string) *string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}

	v4 := parsed.To4()
	if v4 == nil {
		return nil
	}

	ipInt := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	for _, cdn := range cdnRanges {
		for _, r := range cdn.ranges {
			if inRange(ipInt, r[0], r[1]) {
				name := cdn.name
				return &name
			}
		}
	}
	return nil
}

func inRange(ip, network, prefix uint32) bool {
	var mask uint32
	if prefix == 0 {
		mask = 0
	} else {
		mask = ^uint32(0) << (32 - prefix)
	}
	return (ip & mask) == (network & mask)
}

func ipToInt(ip string) uint32 {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	v4 := parsed.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}
