package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"time"
)

type Metrics struct {
	ClientIp            string   `json:"client_ip"`
	ServerHostname      string   `json:"server_hostname"`
	ServerIp            string   `json:"server_ip"`
	StartTime           string   `json:"start_time"`
	DnsLookupSeconds    string   `json:"dns_lookup_seconds"`
	TcpConnectSeconds   string   `json:"tcp_connect_seconds"`
	TlsConnectSeconds   string   `json:"tls_connect_seconds"`
	RequestSentSeconds  string   `json:"request_sent_seconds"`
	TtfbReachedSeconds  string   `json:"ttfb_reached_seconds"`
	TotalConnectSeconds string   `json:"total_connect_seconds"`
	HttpStatus          string   `json:"http_status"`
	RedirectUrl         string   `json:"redirect_url,omitempty"`
	TlsVersion          string   `json:"tls_version,omitempty"`
	CipherSuite         string   `json:"cipher_suite,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
	Error               string   `json:"error"`
}

var globalWarnings []string
var establishedTLSVersion string
var establishedCipherSuite string

func getLocalPrivateIP(isIPv6 bool) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if isIPv6 && ipnet.IP.To4() == nil && strings.Contains(ipnet.IP.String(), ":") {
				if !ipnet.IP.IsLinkLocalUnicast() {
					return ipnet.IP.String()
				}
			}
			if !isIPv6 && ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}

	if isIPv6 {
		return "::1"
	}
	return "127.0.0.1"
}

func getClientIP(isIPv6 bool) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second,
		}).DialContext,
	}
	client := &http.Client{Transport: transport}

	url := "https://v4.ident.me"
	if isIPv6 {
		url = "https://v6.ident.me"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "127.0.0.1"
	}

	resp, err := client.Do(req)
	if err != nil {
		return "127.0.0.1"
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "127.0.0.1"
	}

	return strings.TrimSpace(string(body))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <hostname>")
		return
	}
	hostname := os.Args[1]
	url := "https://" + hostname

	globalWarnings = []string{}
	establishedTLSVersion = ""
	establishedCipherSuite = ""

	var dnsEnd, connectEnd, tlsEnd, wroteRequestTime, firstByteTime time.Time
	var remoteIP string
	var errMsg string
	var statusCode string
	var redirectLocation string

	var connectedIP net.IP

	startTime := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	trace := &httptrace.ClientTrace{
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			dnsEnd = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connectEnd = time.Now()
			if err != nil {
				errMsg = err.Error()
			} else {
				host, _, _ := net.SplitHostPort(addr)
				remoteIP = host
				connectedIP = net.ParseIP(host)
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				tlsEnd = time.Now()
			} else {
				errMsg = err.Error()
			}
		},
		WroteRequest: func(_ httptrace.WroteRequestInfo) {
			wroteRequestTime = time.Now()
		},
		GotFirstResponseByte: func() { firstByteTime = time.Now() },
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       dialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			host, _, _ := net.SplitHostPort(addr)

			tlsConfig := &tls.Config{
				ServerName:         host,
				MinVersion:         tls.VersionTLS10,
				InsecureSkipVerify: true,
				CipherSuites: []uint16{
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
			}
			tlsConn := tls.Client(conn, tlsConfig)

			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				if errMsg == "" {
					errMsg = err.Error()
				}
				tlsConn.Close()
				return nil, err
			}

			state := tlsConn.ConnectionState()

			// Record TLS Version
			switch state.Version {
			case tls.VersionTLS10:
				establishedTLSVersion = "TLS 1.0"
			case tls.VersionTLS11:
				establishedTLSVersion = "TLS 1.1"
			case tls.VersionTLS12:
				establishedTLSVersion = "TLS 1.2"
			case tls.VersionTLS13:
				establishedTLSVersion = "TLS 1.3"
			default:
				establishedTLSVersion = fmt.Sprintf("Unknown (0x%04X)", state.Version)
			}

			// Record Cipher Suite
			establishedCipherSuite = tls.CipherSuiteName(state.CipherSuite)

			// 1. Check TLS Version
			if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
				var verStr string
				if state.Version == tls.VersionTLS10 {
					verStr = "TLS 1.0"
				} else {
					verStr = "TLS 1.1"
				}
				globalWarnings = append(globalWarnings, fmt.Sprintf("Weak Protocol %s Detected", verStr))
			}

			// 2. Check Cipher Suite
			switch state.CipherSuite {
			case tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:

				suiteName := tls.CipherSuiteName(state.CipherSuite)
				globalWarnings = append(globalWarnings, fmt.Sprintf("Weak Cipher Suite Detected (%s)", suiteName))
			}

			// 3. Verify Certificate
			if len(state.PeerCertificates) > 0 {
				leafCert := state.PeerCertificates[0]
				opts := x509.VerifyOptions{
					DNSName:       host,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range state.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}

				if _, verifyErr := leafCert.Verify(opts); verifyErr != nil {
					if errMsg == "" {
						errMsg = verifyErr.Error()
					}
				}
			}

			return tlsConn, nil
		},
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		fmt.Printf(`{"ERROR_MESSAGE": "%s"}`+"\n", err.Error())
		return
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)

	if err != nil {
		if errMsg == "" {
			errMsg = err.Error()
		}
		statusCode = "0"
	} else {
		defer resp.Body.Close()

		statusCode = strconv.Itoa(resp.StatusCode)

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			redirectLocation = resp.Header.Get("Location")
		}

		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil && errMsg == "" {
			errMsg = err.Error()
		}
	}

	totalTime := time.Since(startTime)

	isIPv6 := false
	isPrivate := false

	if connectedIP != nil {
		if connectedIP.To4() == nil {
			isIPv6 = true
		}
		if connectedIP.IsPrivate() || connectedIP.IsLoopback() {
			isPrivate = true
		}
	}

	clientIP := "127.0.0.1"
	if isPrivate {
		clientIP = getLocalPrivateIP(isIPv6)
	} else {
		clientIP = getClientIP(isIPv6)
	}

	var timeDNS float64
	if !dnsEnd.IsZero() {
		timeDNS = dnsEnd.Sub(startTime).Seconds()
	}

	var timeConnect float64
	if !connectEnd.IsZero() {
		timeConnect = connectEnd.Sub(startTime).Seconds()
	}

	var timeTLS float64
	if !tlsEnd.IsZero() {
		timeTLS = tlsEnd.Sub(startTime).Seconds()
	} else {
		timeTLS = timeConnect
	}

	var timePretransfer float64
	if !wroteRequestTime.IsZero() {
		timePretransfer = wroteRequestTime.Sub(startTime).Seconds()
	} else {
		timePretransfer = timeTLS
	}

	var timeStartTransfer float64
	if !firstByteTime.IsZero() {
		timeStartTransfer = firstByteTime.Sub(startTime).Seconds()
	} else {
		timeStartTransfer = timeTLS
	}

	metrics := Metrics{
		ClientIp:            clientIP,
		ServerHostname:      hostname,
		ServerIp:            remoteIP,
		StartTime:           startTime.Format("Mon Jan 2 15:04:05 MST 2006"),
		DnsLookupSeconds:    fmt.Sprintf("%.6f", timeDNS),
		TcpConnectSeconds:   fmt.Sprintf("%.6f", timeConnect),
		TlsConnectSeconds:   fmt.Sprintf("%.6f", timeTLS),
		RequestSentSeconds:  fmt.Sprintf("%.6f", timePretransfer),
		TtfbReachedSeconds:  fmt.Sprintf("%.6f", timeStartTransfer),
		TotalConnectSeconds: fmt.Sprintf("%.6f", totalTime.Seconds()),
		HttpStatus:          statusCode,
		RedirectUrl:         redirectLocation,
		TlsVersion:          establishedTLSVersion,
		CipherSuite:         establishedCipherSuite,
		Warnings:            globalWarnings,
		Error:               errMsg,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	if err := enc.Encode(metrics); err != nil {
		fmt.Printf(`{"ERROR_MESSAGE": "%s"}`+"\n", err.Error())
		return
	}

	fmt.Print(buf.String())
}
