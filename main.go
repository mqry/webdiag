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
	"strings"
	"time"
)

type Response struct {
	Site        Site      `json:"site"`
	StartTime   string    `json:"start_time"`
	StatusCode  int       `json:"status_code"`
	RedirectUrl string    `json:"redirect_url,omitempty"`
	Ok          bool      `json:"ok"`
	TimingsMs   Timings   `json:"timings_ms"`
	TLS         TLSConfig `json:"tls"`
	Message     Message   `json:"message"`
}

type Site struct {
	URL string `json:"url"`
	IP  string `json:"ip"`
}

type Timings struct {
	DnsLookup        int `json:"dns_lookup"`
	TcpConnect       int `json:"tcp_connect"`
	TlsHandshake     int `json:"tls_handshake"`
	ServerProcessing int `json:"server_processing"`
	ContentTransfer  int `json:"content_transfer"`
	Total            int `json:"total"`
}

type TLSConfig struct {
	Version     string      `json:"version"`
	Cipher      string      `json:"cipher"`
	Certificate Certificate `json:"certificate"`
}

type Certificate struct {
	IsValid       bool   `json:"is_valid"`
	DaysRemaining int    `json:"days_remaining"`
	ExpiryDate    string `json:"expiry_date"`
}

type Message struct {
	Warnings []string `json:"warnings,omitempty"`
	Error    Error    `json:"error"`
}

type Error struct {
	ErrorConn string `json:"connection,omitempty"`
	ErrorCert string `json:"certificate,omitempty"`
}

var globalWarnings []string
var establishedTLSVersion string
var establishedCipherSuite string
var certExpiryStr string
var hostname string
var daysLeft int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <hostname>")
		return
	}
	url := os.Args[1]
	if strings.Contains(url, "https://") {
		hostname = strings.TrimPrefix(url, "https://")
	} else if strings.Contains(hostname, "http://") {
		hostname = strings.TrimPrefix(url, "http://")
	} else {
		hostname = url
	}

	globalWarnings = []string{}
	establishedTLSVersion = ""
	establishedCipherSuite = ""
	certExpiryStr = ""

	var dnsEnd, connectEnd, tlsEnd, wroteRequestTime, firstByteTime time.Time
	var remoteIP string
	var errConnMsg string
	var errCertMsg string
	var statusCode int
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
				errConnMsg = err.Error()
			} else {
				host, _, _ := net.SplitHostPort(addr)
				remoteIP = host
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				tlsEnd = time.Now()
			} else {
				errConnMsg = err.Error()
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
				if errConnMsg == "" {
					errConnMsg = err.Error()
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
				globalWarnings = append(globalWarnings, fmt.Sprintf("weak cipher suite detected (%s)", suiteName))
			}

			// 3. Verify Certificate
			if len(state.PeerCertificates) > 0 {
				leafCert := state.PeerCertificates[0]
				certExpiryStr = leafCert.NotAfter.Format(time.RFC3339)

				daysLeft = int(time.Until(leafCert.NotAfter).Hours() / 24.0)
				if daysLeft <= 7.0 && daysLeft > 0 {
					globalWarnings = append(globalWarnings, fmt.Sprintf("certificate will expire %d days left (%s)", daysLeft, certExpiryStr))
				}

				opts := x509.VerifyOptions{
					DNSName:       host,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range state.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}

				if _, verifyErr := leafCert.Verify(opts); verifyErr != nil {
					if errCertMsg == "" {
						errCertMsg = verifyErr.Error()
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
		if errConnMsg == "" {
			errConnMsg = err.Error()
		}
		statusCode = 0
	} else {
		defer resp.Body.Close()

		statusCode = resp.StatusCode

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			redirectLocation = resp.Header.Get("Location")
		}

		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil && errConnMsg == "" {
			errConnMsg = err.Error()
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

	metrics := Response{
		Site: Site{
			URL: url,
			IP:  remoteIP,
		},
		StartTime:   startTime.Format(time.RFC3339),
		StatusCode:  statusCode,
		RedirectUrl: redirectLocation,
		Ok:          errConnMsg == "",
		TimingsMs: Timings{
			DnsLookup:        int(timeDNS),
			TcpConnect:       int(timeConnect),
			TlsHandshake:     int(timeTLS),
			ServerProcessing: int(timePretransfer),
			ContentTransfer:  int(timeStartTransfer),
			Total:            int(totalTime.Milliseconds()),
		},
		TLS: TLSConfig{
			Version: establishedTLSVersion,
			Cipher:  establishedCipherSuite,
			Certificate: Certificate{
				IsValid:       errCertMsg == "",
				DaysRemaining: daysLeft,
				ExpiryDate:    certExpiryStr,
			},
		},
		Message: Message{
			Warnings: globalWarnings,
			Error: Error{
				ErrorConn: errConnMsg,
				ErrorCert: errCertMsg,
			},
		},
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
