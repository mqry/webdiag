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

	"golang.org/x/net/http2"
)

type Response struct {
	Scan        Scan        `json:"scan"`
	Site        Site        `json:"site"`
	Http        Http        `json:"http"`
	Http3       Http3       `json:"http3"`
	TimingsMs   Timings     `json:"timings_ms"`
	TLS         TLSConfig   `json:"tls"`
	Certificate Certificate `json:"certificate"`
	Message     Message     `json:"message"`
}

type Scan struct {
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Duration  int    `json:"duration_ms"`
}

type Site struct {
	URL string `json:"url"`
	IP  string `json:"ip"`
}

type Timings struct {
	DnsLookup    int `json:"dns_lookup"`
	TcpConnect   int `json:"tcp_connect"`
	TlsHandshake int `json:"tls_handshake"`
	Pretransfer  int `json:"pretransfer"`
	Ttfb         int `json:"ttfb"`
	Total        int `json:"total"`
}

type Http struct {
	Ok          bool   `json:"ok"`
	StatusCode  int    `json:"status_code"`
	RedirectUrl string `json:"redirect_url,omitempty"`
	Version     string `json:"version,omitempty"`
}

type Http3 struct {
	HTTP3Supported bool   `json:"http3_supported"`
	AltSvc         string `json:"alt_svc,omitempty"`
}

type TLSConfig struct {
	SNI     string `json:"sni,omitempty"`
	Version string `json:"version"`
	ALPN    string `json:"alpn,omitempty"`
	Cipher  string `json:"cipher"`
	AltSvc  string `json:"alt_svc,omitempty"`
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
var establishedALPNProtocol string
var certExpiryStr string
var hostname string
var daysLeft int
var http3Supported bool
var altSvcHeader string

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <url>")
		return
	}
	url := os.Args[1]
	if !strings.Contains(url, "https://") && !strings.Contains(url, "http://") {
		hostname = url
		url = "https://" + hostname
	} else {
		hostname = strings.Split(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"), "/")[0]
	}
	globalWarnings = []string{}
	establishedTLSVersion = ""
	establishedCipherSuite = ""
	establishedALPNProtocol = ""
	certExpiryStr = ""
	http3Supported = false
	altSvcHeader = ""

	var dnsEnd, connectEnd, tlsEnd, wroteRequestTime, firstByteTime time.Time
	var remoteIP string
	var errConnMsg string
	var errCertMsg string
	var statusCode int
	var httpVersion string
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
				NextProtos:         []string{"h2", "http/1.1"},
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

			// Record ALPN Protocol
			if len(state.NegotiatedProtocol) > 0 {
				establishedALPNProtocol = state.NegotiatedProtocol
			}

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
				if daysLeft <= 30.0 && daysLeft > 0 {
					globalWarnings = append(globalWarnings, fmt.Sprintf("certificate will expire %d days left (%s)", daysLeft, certExpiryStr))
				} else if daysLeft <= 0 {
					errCertMsg = fmt.Sprintf("certificate has expired (%s)", certExpiryStr)
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

	// Validate HTTP/2 support
	if err := http2.ConfigureTransport(transport); err != nil {
		fmt.Printf(`{"ERROR_MESSAGE": "Failed to configure HTTP/2: %s"}`+"\n", err.Error())
		return
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
		httpVersion = resp.Proto

		// Check Alt-Svc header for HTTP/3 support
		altSvcHeader = resp.Header.Get("Alt-Svc")
		if altSvcHeader != "" {
			// Check if h3 or h3-* is present in Alt-Svc header
			if strings.Contains(altSvcHeader, "h3=") || strings.Contains(altSvcHeader, "h3-") {
				http3Supported = true
			}
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			redirectLocation = resp.Header.Get("Location")
		}

		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil && errConnMsg == "" {
			errConnMsg = err.Error()
		}
	}

	totalTime := time.Since(startTime)
	endTime := time.Now()

	var timeDNS int64
	if !dnsEnd.IsZero() {
		timeDNS = dnsEnd.Sub(startTime).Milliseconds()
	}

	var timeConnect int64
	if !connectEnd.IsZero() {
		timeConnect = connectEnd.Sub(dnsEnd).Milliseconds()
	}

	var timeTLS int64
	if !tlsEnd.IsZero() {
		timeTLS = tlsEnd.Sub(connectEnd).Milliseconds()
	} else {
		timeTLS = 0
	}

	var timePretransfer int64
	if !wroteRequestTime.IsZero() {
		timePretransfer = wroteRequestTime.Sub(tlsEnd).Milliseconds()
	} else {
		timePretransfer = 0
	}

	var ttfb int64
	if !firstByteTime.IsZero() {
		ttfb = firstByteTime.Sub(wroteRequestTime).Milliseconds()
	} else {
		ttfb = 0
	}

	metrics := Response{
		Scan: Scan{
			StartTime: startTime.Format(time.RFC3339),
			EndTime:   endTime.Format(time.RFC3339),
			Duration:  int(totalTime.Milliseconds()),
		},
		Site: Site{
			URL: url,
			IP:  remoteIP,
		},
		Http: Http{
			Ok:          errConnMsg == "",
			StatusCode:  statusCode,
			RedirectUrl: redirectLocation,
			Version:     httpVersion,
		},
		TimingsMs: Timings{
			DnsLookup:    int(timeDNS),
			TcpConnect:   int(timeConnect),
			TlsHandshake: int(timeTLS),
			Pretransfer:  int(timePretransfer),
			Ttfb:         int(ttfb),
			Total:        int(totalTime.Milliseconds()),
		},
		TLS: TLSConfig{
			SNI:     hostname,
			Version: establishedTLSVersion,
			Cipher:  establishedCipherSuite,
			ALPN:    establishedALPNProtocol,
		},
		Certificate: Certificate{
			IsValid:       errCertMsg == "" && establishedTLSVersion != "",
			DaysRemaining: daysLeft,
			ExpiryDate:    certExpiryStr,
		},
		Http3: Http3{
			HTTP3Supported: http3Supported,
			AltSvc:         altSvcHeader,
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
