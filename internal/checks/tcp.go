package checks

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

func CheckTCP(host string, port int, timeoutMs int) types.TcpResult {
	start := time.Now()
	target := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", target, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		message := formatTCPError(err)
		return types.TcpResult{
			Ok:         false,
			DurationMs: elapsedMs(start),
			Port:       port,
			Error:      &message,
		}
	}
	_ = conn.Close()

	return types.TcpResult{
		Ok:         true,
		DurationMs: elapsedMs(start),
		Port:       port,
	}
}

func formatTCPError(err error) string {
	if err == nil {
		return "Unknown TCP error"
	}

	lowered := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lowered, "connection refused"):
		return "Connection refused - port closed or firewall blocking"
	case strings.Contains(lowered, "no route to host"), strings.Contains(lowered, "host unreachable"):
		return "Host unreachable"
	case strings.Contains(lowered, "network is unreachable"):
		return "Network unreachable"
	case strings.Contains(lowered, "i/o timeout"), strings.Contains(lowered, "timed out"):
		return "Connection timed out"
	default:
		return fmt.Sprintf("%v", err)
	}
}
