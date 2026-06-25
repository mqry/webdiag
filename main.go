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
	ServerHostname   string   `json:"server_hostname"`
	ServerIp         string   `json:"server_ip"`
	StartTime        string   `json:"start_time"`
	DnsLookupMsec    string   `json:"dns_lookup_msec"`
	TcpConnectMsec   string   `json:"tcp_connect_msec"`
	TlsConnectMsec   string   `json:"tls_connect_msec"`
	RequestSentMsec  string   `json:"request_sent_msec"`
	TtfbReachedMsec  string   `json:"ttfb_reached_msec"`
	TotalConnectMsec string   `json:"total_connect_msec"`
	HttpStatus       string   `json:"http_status"`
	RedirectUrl      string   `json:"redirect_url,omitempty"`
	TlsVersion       string   `json:"tls_version,omitempty"`
	CipherSuite      string   `json:"cipher_suite,omitempty"`
	CertExpiryDate   string   `json:"cert_expiry_date,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	Error            string   `json:"error"`
}

var globalWarnings []string
var establishedTLSVersion string
var establishedCipherSuite string
var certExpiryStr string

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <hostname>")
		return
	}
	hostname := os.Args[1]
	url := hostname
	if strings.Contains(hostname, "https://") {
		url = hostname
		hostname = strings.TrimPrefix(url, "https://")
	} else if strings.Contains(hostname, "http://") {
		url = hostname
		hostname = strings.TrimPrefix(url, "http://")
	}

	globalWarnings = []string{}
	establishedTLSVersion = ""
	establishedCipherSuite = ""
	certExpiryStr = ""

	var dnsEnd, connectEnd, tlsEnd, wroteRequestTime, firstByteTime time.Time
	var remoteIP string
	var errMsg string
	var statusCode string
	var redirectLocation string

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
				certExpiryStr = leafCert.NotAfter.Format("2006-01-02 15:04:05 UTC")

				daysLeft := time.Until(leafCert.NotAfter).Hours() / 24.0
				if daysLeft <= 7.0 && daysLeft > 0 {
					globalWarnings = append(globalWarnings, fmt.Sprintf("Certificate will expire %.1f days left (%s)", daysLeft, certExpiryStr))
				}

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

	var timeDNS int64
	if !dnsEnd.IsZero() {
		timeDNS = dnsEnd.Sub(startTime).Milliseconds()
	}

	var timeConnect int64
	if !connectEnd.IsZero() {
		timeConnect = connectEnd.Sub(startTime).Milliseconds() - timeDNS
	}

	var timeTLS int64
	if !tlsEnd.IsZero() {
		timeTLS = tlsEnd.Sub(startTime).Milliseconds() - (timeDNS + timeConnect)
	} else {
		timeTLS = 0
	}

	var timePretransfer int64
	if !wroteRequestTime.IsZero() {
		timePretransfer = wroteRequestTime.Sub(startTime).Milliseconds() - (timeDNS + timeConnect + timeTLS)
	} else {
		timePretransfer = 0
	}

	var timeStartTransfer int64
	if !firstByteTime.IsZero() {
		timeStartTransfer = firstByteTime.Sub(startTime).Milliseconds() - (timeDNS + timeConnect + timeTLS + timePretransfer)
	} else {
		timeStartTransfer = 0
	}

	metrics := Metrics{
		ServerHostname:   hostname,
		ServerIp:         remoteIP,
		StartTime:        startTime.Format("Mon Jan 2 15:04:05 MST 2006"),
		DnsLookupMsec:    fmt.Sprintf("%d", timeDNS),
		TcpConnectMsec:   fmt.Sprintf("%d", timeConnect),
		TlsConnectMsec:   fmt.Sprintf("%d", timeTLS),
		RequestSentMsec:  fmt.Sprintf("%d", timePretransfer),
		TtfbReachedMsec:  fmt.Sprintf("%d", timeStartTransfer),
		TotalConnectMsec: fmt.Sprintf("%d", totalTime.Milliseconds()),
		HttpStatus:       statusCode,
		RedirectUrl:      redirectLocation,
		TlsVersion:       establishedTLSVersion,
		CipherSuite:      establishedCipherSuite,
		CertExpiryDate:   certExpiryStr,
		Warnings:         globalWarnings,
		Error:            errMsg,
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
