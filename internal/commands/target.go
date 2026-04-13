package commands

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type parsedTarget struct {
	input            string
	host             string
	port             int
	normalizedTarget string
	parsedFrom       *string
	httpTarget       string
}

func parseTarget(input string, defaultPort int) parsedTarget {
	raw := strings.TrimSpace(input)
	if parsed, ok := parseAsURL(raw); ok {
		return parsed
	}

	host, port := parseHostPort(raw)
	if host == "" {
		host = stripHostBrackets(raw)
	}
	if port == 0 {
		port = defaultPort
	}
	return parsedTarget{
		input:            raw,
		host:             host,
		port:             port,
		normalizedTarget: formatHostPort(host, port),
		httpTarget:       buildHTTPURL("https", host, port, "/"),
	}
}

func parseAsURL(raw string) (parsedTarget, bool) {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return parsedTarget{}, false
	}

	protocol := ""
	if u.Scheme == "http" {
		protocol = "http"
	} else if u.Scheme == "https" {
		protocol = "https"
	} else {
		return parsedTarget{}, false
	}

	host := u.Hostname()
	if host == "" {
		return parsedTarget{}, false
	}

	port := readPort(u.Port(), map[bool]int{true: 80, false: 443}[protocol == "http"])
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	parsedFrom := raw
	return parsedTarget{
		input:            raw,
		host:             host,
		port:             port,
		normalizedTarget: formatHostPort(host, port),
		parsedFrom:       &parsedFrom,
		httpTarget:       buildHTTPURL(protocol, host, port, path),
	}, true
}

func parseHostPort(raw string) (string, int) {
	idx := strings.LastIndex(raw, ":")
	if idx <= 0 || idx >= len(raw)-1 {
		return "", 0
	}

	hostPart := strings.TrimSpace(raw[:idx])
	portPart := strings.TrimSpace(raw[idx+1:])
	if hostPart == "" || portPart == "" {
		return "", 0
	}
	for _, r := range portPart {
		if r < '0' || r > '9' {
			return "", 0
		}
	}

	parsedPort, err := strconv.Atoi(portPart)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return "", 0
	}

	return stripHostBrackets(hostPart), parsedPort
}

func readPort(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 1 || parsed > 65535 {
		return fallback
	}
	return parsed
}

func stripHostBrackets(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

func formatHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func buildHTTPURL(protocol string, host string, port int, path string) string {
	hostPort := formatHostPort(host, port)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return protocol + "://" + hostPort + path
}
