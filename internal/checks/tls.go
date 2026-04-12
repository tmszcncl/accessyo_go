package checks

import (
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

func CheckTLS(host string, port int, timeoutMs int) types.TlsResult {
	start := time.Now()

	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), newTLSConfig(host))
	if err != nil {
		message := formatTLSError(err)
		return types.TlsResult{
			Ok:         false,
			DurationMs: elapsedMs(start),
			Error:      &message,
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	protocol := tlsVersionName(state.Version)
	cipherName := tls.CipherSuiteName(state.CipherSuite)

	result := types.TlsResult{
		Ok:           true,
		DurationMs:   elapsedMs(start),
		Protocol:     &protocol,
		Cipher:       &cipherName,
		AlpnProtocol: negotiatedALPN(state),
	}
	hostnameMatch := true
	result.HostnameMatch = &hostnameMatch

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
			issuer := cert.Issuer.Organization[0]
			result.CertIssuer = &issuer
		} else if cert.Issuer.CommonName != "" {
			issuer := cert.Issuer.CommonName
			result.CertIssuer = &issuer
		}

		validTo := cert.NotAfter.UTC().Format(time.RFC1123)
		expired := cert.NotAfter.Before(time.Now())
		daysRemaining := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
		result.CertValidTo = &validTo
		result.CertExpired = &expired
		result.CertDaysRemaining = &daysRemaining
	}

	return result
}

func newTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

func negotiatedALPN(state tls.ConnectionState) *string {
	if state.NegotiatedProtocol == "" {
		return nil
	}
	return strPtr(state.NegotiatedProtocol)
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return "unknown"
	}
}

func formatTLSError(err error) string {
	if err == nil {
		return "Unknown TLS error"
	}

	lowered := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lowered, "certificate has expired"), strings.Contains(lowered, "expired"):
		return "Certificate expired"
	case strings.Contains(lowered, "self signed"):
		return "Self-signed certificate - not trusted by browsers"
	case strings.Contains(lowered, "not valid for any names"), strings.Contains(lowered, "certificate is valid for"):
		return "Certificate hostname mismatch"
	case strings.Contains(lowered, "unknown authority"), strings.Contains(lowered, "unable to verify"):
		return "Certificate chain verification failed"
	case strings.Contains(lowered, "handshake"):
		return "TLS handshake failed"
	default:
		return err.Error()
	}
}
