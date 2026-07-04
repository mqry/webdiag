package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"golang.org/x/net/http2"
)

type Overall struct {
	Scan         Scan           `json:"scan"`
	Site         Site           `json:"site"`
	DNS          Dns            `json:"dns"`
	TCP          Tcp            `json:"tcp"`
	TLS          TLSConfig      `json:"tls"`
	Certificate  Certificate    `json:"certificate"`
	TimingsMs    Timings        `json:"timings_ms"`
	Http         Http           `json:"http"`
	RedirectUrls []string       `json:"redirect_urls"`
	Http3        Http3          `json:"http3"`
	Message      OverallMessage `json:"message"`
}

type DiagnosticResult struct {
	Overall   Overall    `json:"overall"`
	Redirects []Response `json:"redirects"`
}

type Response struct {
	Scan        Scan        `json:"scan"`
	Site        Site        `json:"site"`
	DNS         Dns         `json:"dns"`
	TCP         Tcp         `json:"tcp"`
	TLS         TLSConfig   `json:"tls"`
	Certificate Certificate `json:"certificate"`
	Http        Http        `json:"http"`
	Http3       Http3       `json:"http3"`
	TimingsMs   Timings     `json:"timings_ms"`
}

type Scan struct {
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Duration  int    `json:"duration_ms"`
}

type Site struct {
	URL      string `json:"url"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

type Dns struct {
	Status   string `json:"status"`
	ErrorDns string `json:"error"`
}

type Tcp struct {
	Status    string `json:"status"`
	Port      string `json:"port"`
	ErrorConn string `json:"error"`
}

type Http struct {
	Status      string `json:"status"`
	StatusCode  int    `json:"status_code"`
	RedirectUrl string `json:"redirect_url"`
	Version     string `json:"version"`
	ErrorHttp   string `json:"error"`
}

type Http3 struct {
	HTTP3Supported string `json:"http3_supported"`
	AltSvc         string `json:"alt_svc"`
}

type TLSConfig struct {
	Status      string   `json:"status"`
	SNI         string   `json:"sni"`
	Version     string   `json:"version"`
	ALPN        string   `json:"alpn"`
	Cipher      string   `json:"cipher"`
	AltSvc      string   `json:"alt_svc"`
	ErrorTls    string   `json:"error"`
	TlsWarnings []string `json:"warnings"`
}

type Certificate struct {
	Status        string   `json:"status"`
	DaysRemaining int      `json:"days_remaining"`
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	Chains        []string `json:"chains"`
	DnsNames      []string `json:"dns_names,omitempty"`
	ExpiryDate    string   `json:"expiry_date"`
	ErrorCert     string   `json:"error"`
}

type Timings struct {
	DnsLookup    ResponseTime `json:"dns_lookup"`
	TcpConnect   ResponseTime `json:"tcp_connect"`
	TlsHandshake ResponseTime `json:"tls_handshake"`
	Pretransfer  ResponseTime `json:"pre_transfer"`
	Ttfb         ResponseTime `json:"ttfb"`
	Total        ResponseTime `json:"total"`
}

type Warnings struct {
	TlsWarnings []string `json:"tlsWarnings"`
}

type Error struct {
	ErrorDns  string `json:"dnsError"`
	ErrorConn string `json:"tcpError"`
	ErrorTls  string `json:"tlsError"`
	ErrorCert string `json:"certError"`
	ErrorHttp string `json:"httpError"`
}

type ResponseTime struct {
	Duration int    `json:"duration"`
	Status   string `json:"status"`
}

type Message struct {
	Warnings []string `json:"warnings"`
	Error    Error    `json:"error"`
}

type RedirectMessage struct {
	OverallWarnings OverallWarinings `json:"overall_warnings"`
	OverallErrors   OverallErros     `json:"overall_errors"`
}

type OverallMessage struct {
	PerRedirect []RedirectMessage `json:"per_redirect"`
}

type OverallWarinings struct {
	URL      string   `json:"url"`
	Warnings Warnings `json:"warnings"`
}

type OverallErros struct {
	URL   string `json:"url"`
	Error Error  `json:"errors"`
}

func evaluateTiming(diagType string, diagDuration int) string {
	switch diagType {
	case "dns":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 20:
			return "good"
		case diagDuration > 20 && diagDuration <= 50:
			return "ok"
		case diagDuration > 50 && diagDuration <= 100:
			return "warn"
		case diagDuration > 100:
			return "bad"
		}
	case "tcp":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 10:
			return "good"
		case diagDuration > 10 && diagDuration <= 50:
			return "ok"
		case diagDuration > 50 && diagDuration <= 100:
			return "warn"
		case diagDuration > 100:
			return "bad"
		}
	case "tls":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 50:
			return "good"
		case diagDuration > 50 && diagDuration <= 100:
			return "ok"
		case diagDuration > 100 && diagDuration <= 200:
			return "warn"
		case diagDuration > 200:
			return "bad"
		}
	case "pre":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 2:
			return "good"
		case diagDuration > 2 && diagDuration <= 4:
			return "ok"
		case diagDuration > 4 && diagDuration <= 10:
			return "warn"
		case diagDuration > 10:
			return "bad"
		}
	case "ttfb":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 200:
			return "good"
		case diagDuration > 200 && diagDuration <= 500:
			return "ok"
		case diagDuration > 500 && diagDuration <= 800:
			return "warn"
		case diagDuration > 800:
			return "bad"
		}
	case "total":
		return "-"
	}
	return "error"
}

func diagnoseSite(targetURL string) Response {
	var hostname string
	var port string
	var establishedTLSVersion string
	var establishedCipherSuite string
	var establishedALPNProtocol string
	var systemPool *x509.CertPool
	var certSubject string
	var certIssuer string
	var certChains []string
	var certDnsNames []string
	var certStatus string
	var certExpiryStr string
	var daysLeft int
	var http3Supported string
	var altSvcHeader string
	var tlsWarnings []string

	url := targetURL
	if !strings.Contains(url, "https://") && !strings.Contains(url, "http://") {
		hostname = url
		url = "https://" + hostname
	} else {
		hostname = strings.Split(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"), "/")[0]
	}

	tlsWarnings = []string{}
	certChains = []string{}
	certDnsNames = []string{}

	var dnsEnd, connectEnd, tlsEnd, wroteRequestTime, firstByteTime time.Time
	var remoteIP string
	var errDnsMsg string
	var errConnMsg string
	var errTlsMsg string
	var errCertMsg string
	var errHttpMsg string
	var dnsStatus string = "unused"
	var tcpStatus string
	var tlsStatus string
	var statusCode int
	var httpStatus string
	var httpVersion string
	var redirectLocation string

	startTime := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	trace := &httptrace.ClientTrace{
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			if dnsInfo.Err != nil {
				dnsEnd = time.Now()
				errDnsMsg = dnsInfo.Err.Error()
				dnsStatus = "error"
				return
			} else {
				dnsEnd = time.Now()
				dnsStatus = "ok"
			}
		},
		ConnectDone: func(network, addr string, err error) {
			connectEnd = time.Now()
			host, _, _ := net.SplitHostPort(addr)
			remoteIP = host
			_, port, _ = net.SplitHostPort(addr)
			if err != nil {
				errConnMsg = err.Error()
				tcpStatus = "error"
			} else {
				tcpStatus = "ok"
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				tlsEnd = time.Now()
				tlsStatus = "ok"
			} else {
				errTlsMsg = err.Error()
				tlsStatus = "error"
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
				if errTlsMsg == "" {
					errTlsMsg = err.Error()
					tlsStatus = "error"
				}
				tlsConn.Close()
				return nil, err
			}

			state := tlsConn.ConnectionState()

			// Record TLS Version
			switch state.Version {
			case tls.VersionTLS10:
				establishedTLSVersion = "1.0"
			case tls.VersionTLS11:
				establishedTLSVersion = "1.1"
			case tls.VersionTLS12:
				establishedTLSVersion = "1.2"
			case tls.VersionTLS13:
				establishedTLSVersion = "1.3"
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
				tlsWarnings = append(tlsWarnings, fmt.Sprintf("Weak Protocol %s Detected", verStr))
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
				tlsWarnings = append(tlsWarnings, fmt.Sprintf("Weak Cipher Suite Detected (%s)", suiteName))
			}

			// 3. Verify Certificate
			systemPool, err = x509.SystemCertPool()
			if err != nil {
				systemPool = x509.NewCertPool()
			}

			for _, cert := range state.PeerCertificates[1:] {
				systemPool.AddCert(cert)
			}
			for _, cert := range state.PeerCertificates {
				certChains = append(certChains, cert.Issuer.String())
			}

			if len(state.PeerCertificates) > 0 {
				leafCert := state.PeerCertificates[0]
				certExpiryStr = leafCert.NotAfter.Format(time.RFC3339)
				certSubject = leafCert.Subject.String()
				certIssuer = leafCert.Issuer.String()
				certDnsNames = leafCert.DNSNames

				daysLeft = int(time.Until(leafCert.NotAfter).Hours() / 24.0)
				if daysLeft <= 30.0 && daysLeft > 0 {
					tlsWarnings = append(tlsWarnings, fmt.Sprintf("certificate will expire %d days left (%s)", daysLeft, certExpiryStr))
				} else if daysLeft <= 0 {
					errCertMsg = fmt.Sprintf("certificate has expired (%s)", certExpiryStr)
				}

				opts := x509.VerifyOptions{
					DNSName: host,
					Roots:   systemPool,
				}

				if _, verifyErr := leafCert.Verify(opts); verifyErr != nil {
					if errCertMsg == "" {
						errCertMsg = verifyErr.Error()
					}
				}

				if errCertMsg == "" {
					certStatus = "ok"
				} else {
					certStatus = "error"
				}
			}

			return tlsConn, nil
		},
	}

	// Validate HTTP/2 support
	if err := http2.ConfigureTransport(transport); err != nil {
		errHttpMsg = "Failed to configure HTTP/2: " + err.Error()
		return Response{
			Scan: Scan{
				StartTime: startTime.Format(time.RFC3339),
				EndTime:   time.Now().Format(time.RFC3339),
				Duration:  0,
			},
			Site: Site{
				URL:      url,
				Hostname: hostname,
				IP:       "",
			},
			Http: Http{
				Status:     "error",
				StatusCode: 0,
				ErrorHttp:  errHttpMsg,
			},
		}
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		errHttpMsg = err.Error()
		return Response{
			Scan: Scan{
				StartTime: startTime.Format(time.RFC3339),
				EndTime:   time.Now().Format(time.RFC3339),
				Duration:  0,
			},
			Site: Site{
				URL:      url,
				Hostname: hostname,
				IP:       "",
			},
			Http: Http{
				Status:     "error",
				StatusCode: 0,
				ErrorHttp:  errHttpMsg,
			},
		}
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)

	if err != nil {
		if errDnsMsg == "" && errConnMsg == "" && errTlsMsg == "" && errCertMsg == "" && errHttpMsg == "" {
			errHttpMsg = err.Error()
			httpStatus = "error"
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
				http3Supported = "yes"
			}
		} else {
			http3Supported = "no"
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			if loc, err := resp.Location(); err == nil {
				redirectLocation = loc.String()
			}
		}

		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil && errHttpMsg == "" {
			errHttpMsg = err.Error()
		}

		if errHttpMsg == "" {
			httpStatus = "ok"
		} else {
			httpStatus = "error"
		}
	}

	totalTime := time.Since(startTime).Milliseconds()
	endTime := time.Now()

	var timeDNS int64
	if !dnsEnd.IsZero() {
		timeDNS = dnsEnd.Sub(startTime).Milliseconds()
	}

	var timeConnect int64
	if !connectEnd.IsZero() {
		if !dnsEnd.IsZero() {
			timeConnect = connectEnd.Sub(dnsEnd).Milliseconds()
		} else {
			timeConnect = connectEnd.Sub(startTime).Milliseconds()
		}
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
			Duration:  int(totalTime),
		},
		Site: Site{
			URL:      url,
			Hostname: hostname,
			IP:       remoteIP,
		},
		DNS: Dns{
			Status:   dnsStatus,
			ErrorDns: errDnsMsg,
		},
		TCP: Tcp{
			Status:    tcpStatus,
			Port:      port,
			ErrorConn: errConnMsg,
		},
		TLS: TLSConfig{
			Status:      tlsStatus,
			SNI:         hostname,
			Version:     establishedTLSVersion,
			Cipher:      establishedCipherSuite,
			ALPN:        establishedALPNProtocol,
			ErrorTls:    errTlsMsg,
			TlsWarnings: tlsWarnings,
		},
		Certificate: Certificate{
			Status:        certStatus,
			Subject:       certSubject,
			Issuer:        certIssuer,
			Chains:        certChains,
			DnsNames:      certDnsNames,
			DaysRemaining: daysLeft,
			ExpiryDate:    certExpiryStr,
			ErrorCert:     errCertMsg,
		},
		Http: Http{
			Status:      httpStatus,
			StatusCode:  statusCode,
			RedirectUrl: redirectLocation,
			Version:     httpVersion,
			ErrorHttp:   errHttpMsg,
		},
		Http3: Http3{
			HTTP3Supported: http3Supported,
			AltSvc:         altSvcHeader,
		},
		TimingsMs: Timings{
			DnsLookup:    ResponseTime{Duration: int(timeDNS), Status: evaluateTiming("dns", int(timeDNS))},
			TcpConnect:   ResponseTime{Duration: int(timeConnect), Status: evaluateTiming("tcp", int(timeConnect))},
			TlsHandshake: ResponseTime{Duration: int(timeTLS), Status: evaluateTiming("tls", int(timeTLS))},
			Pretransfer:  ResponseTime{Duration: int(timePretransfer), Status: evaluateTiming("pre", int(timePretransfer))},
			Ttfb:         ResponseTime{Duration: int(ttfb), Status: evaluateTiming("ttfb", int(ttfb))},
			Total:        ResponseTime{Duration: int(totalTime), Status: evaluateTiming("total", int(totalTime))},
		},
	}

	return metrics
}

func upper(s string) string {
	return strings.ToUpper(s)
}

// printJSON outputs the diagnostic result in JSON format
func printJSON(diagnosticResult DiagnosticResult) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	if err := enc.Encode(diagnosticResult); err != nil {
		fmt.Printf(`{"ERROR_MESSAGE": "%s"}`+"\n", err.Error())
		return ""
	}

	return fmt.Sprint(buf.String())
}

// printVerbose outputs detailed diagnostic information for each redirect
func printVerbose(allRedirects []Response) string {
	var b strings.Builder
	for i, redirect := range allRedirects {
		// Time
		fmt.Fprintf(&b, "Time\n")
		fmt.Fprintf(&b, "----\n")
		fmt.Fprintf(&b, "%s\n", redirect.Scan.StartTime)
		fmt.Fprintf(&b, "\n")

		// URL
		fmt.Fprintf(&b, "URL\n")
		fmt.Fprintf(&b, "---\n")
		fmt.Fprintf(&b, "%s\n", redirect.Site.URL)
		fmt.Fprintf(&b, "\n")

		// DNS
		fmt.Fprintf(&b, "DNS\n")
		fmt.Fprintf(&b, "---\n")
		fmt.Fprintf(&b, "%-15s%s\n", "Status", upper(redirect.DNS.Status))
		fmt.Fprintf(&b, "%-15s%s\n", "Hostname", redirect.Site.Hostname)
		fmt.Fprintf(&b, "%-15s%s\n", "IP", redirect.Site.IP)
		fmt.Fprintf(&b, "%-15s%s\n", "ERROR", redirect.DNS.ErrorDns)
		fmt.Fprintf(&b, "\n")

		// TCP
		fmt.Fprintf(&b, "TCP\n")
		fmt.Fprintf(&b, "---\n")
		fmt.Fprintf(&b, "%-15s%s\n", "Status", upper(redirect.TCP.Status))
		fmt.Fprintf(&b, "%-15s%s\n", "Port", redirect.TCP.Port)
		fmt.Fprintf(&b, "%-15s%s\n", "ERROR", redirect.TCP.ErrorConn)
		fmt.Fprintf(&b, "\n")

		// TLS
		fmt.Fprintf(&b, "TLS\n")
		fmt.Fprintf(&b, "---\n")
		fmt.Fprintf(&b, "%-15s%s\n", "Status", upper(redirect.TLS.Status))
		fmt.Fprintf(&b, "%-15s%s\n", "Version", redirect.TLS.Version)
		fmt.Fprintf(&b, "%-15s%s\n", "ALPN", redirect.TLS.ALPN)
		fmt.Fprintf(&b, "%-15s%s\n", "Cipher", redirect.TLS.Cipher)
		if redirect.TLS.Status == "ok" {
			fmt.Fprintf(&b, "%-15s%s\n", "SNI", redirect.TLS.SNI)
		}
		fmt.Fprintf(&b, "%-15s%s\n", "ERROR", redirect.TLS.ErrorTls)
		for num, warning := range redirect.TLS.TlsWarnings {
			fmt.Fprintf(&b, "%s#%-6d %s\n", "Warning", num+1, warning)
		}
		fmt.Fprintf(&b, "\n")

		// Certificate
		fmt.Fprintf(&b, "Certificate\n")
		fmt.Fprintf(&b, "-----------\n")
		fmt.Fprintf(&b, "%-15s%s\n", "Status", upper(redirect.Certificate.Status))
		fmt.Fprintf(&b, "%-15s%s\n", "Subject", redirect.Certificate.Subject)
		fmt.Fprintf(&b, "%-15s%s\n", "Issuer", redirect.Certificate.Issuer)
		for num, certificate := range redirect.Certificate.Chains {
			fmt.Fprintf(&b, "%s#%-8d %s\n", "Chain", num+1, certificate)
		}
		fmt.Fprintf(&b, "%-15s%s\n", "Expires", redirect.Certificate.ExpiryDate)
		if redirect.TLS.Status == "ok" {
			fmt.Fprintf(&b, "%-15s%d\n", "Days Left", redirect.Certificate.DaysRemaining)
		}
		fmt.Fprintf(&b, "%-15s%s\n", "ERROR", redirect.Certificate.ErrorCert)
		fmt.Fprintf(&b, "\n")

		// HTTP
		fmt.Fprintf(&b, "HTTP\n")
		fmt.Fprintf(&b, "----\n")
		fmt.Fprintf(&b, "%-15s%s\n", "Status", upper(redirect.Http.Status))
		fmt.Fprintf(&b, "%-15s%s\n", "Version", redirect.Http.Version)
		if redirect.Http.StatusCode != 0 {
			fmt.Fprintf(&b, "%-15s%d\n", "Status", redirect.Http.StatusCode)
		}
		fmt.Fprintf(&b, "%-15s%s\n", "Redirect", redirect.Http.RedirectUrl)
		fmt.Fprintf(&b, "%-15s%s\n", "ERROR", redirect.Http.ErrorHttp)
		fmt.Fprintf(&b, "\n")

		// HTTP/3
		fmt.Fprintf(&b, "HTTP/3\n")
		fmt.Fprintf(&b, "------\n")
		fmt.Fprintf(&b, "")
		fmt.Fprintf(&b, "%-15s%s\n", "Supported", upper(redirect.Http3.HTTP3Supported))
		fmt.Fprintf(&b, "%-15s%s\n", "Alt-Svc", redirect.Http3.AltSvc)
		fmt.Fprintf(&b, "\n")

		// Timings
		fmt.Fprintf(&b, "Timinigs\n")
		fmt.Fprintf(&b, "--------\n")
		fmt.Fprintf(&b, "%-8s%8d ms  (%s)\n", "DNS", redirect.TimingsMs.DnsLookup.Duration, upper(redirect.TimingsMs.DnsLookup.Status))
		fmt.Fprintf(&b, "%-8s%8d ms  (%s)\n", "TCP", redirect.TimingsMs.TcpConnect.Duration, upper(redirect.TimingsMs.TcpConnect.Status))
		fmt.Fprintf(&b, "%-8s%8d ms  (%s)\n", "TLS", redirect.TimingsMs.TlsHandshake.Duration, upper(redirect.TimingsMs.TlsHandshake.Status))
		fmt.Fprintf(&b, "%-8s%8d ms  (%s)\n", "PRE", redirect.TimingsMs.Pretransfer.Duration, upper(redirect.TimingsMs.Pretransfer.Status))
		fmt.Fprintf(&b, "%-8s%8d ms  (%s)\n", "TTFB", redirect.TimingsMs.Ttfb.Duration, upper(redirect.TimingsMs.Ttfb.Status))
		fmt.Fprintf(&b, "%-8s%8d ms\n", "Total", redirect.TimingsMs.Total.Duration)
		fmt.Fprintf(&b, "\n")

		// Option: Redirect Arrow
		if i+1 < len(allRedirects) {
			fmt.Fprintf(&b, "|\n")
			fmt.Fprintf(&b, "|\n")
			fmt.Fprintf(&b, "| Redirect: %d\n", redirect.Http.StatusCode)
			fmt.Fprintf(&b, "|\n")
			fmt.Fprintf(&b, "v\n")
			fmt.Fprintf(&b, "\n")
		}
	}

	return b.String()
}

// printDefault outputs a summary of the diagnostic result
func printDefault(overall Overall, isColor bool) string {
	keyColor := color.New(color.FgHiBlue).SprintFunc()
	valColor := color.New(color.FgHiGreen).SprintFunc()
	warnColor := color.New(color.FgHiYellow).SprintFunc()
	errColor := color.New(color.FgHiRed).SprintFunc()

	var b strings.Builder

	switch isColor {
	case true:
		// Site
		fmt.Fprintf(&b, "%-24s%s\n", keyColor("URL"), valColor(overall.Site.URL))

		// DNS
		ipStr := fmt.Sprintf("(%s)", overall.Site.IP)
		switch overall.DNS.Status {
		case "ok":
			fmt.Fprintf(&b, "%-24s%s %s\n", keyColor("DNS"), valColor(upper(overall.DNS.Status)), valColor(ipStr))
		case "error":
			fmt.Fprintf(&b, "%-24s%s\n", keyColor("DNS"), errColor(upper(overall.DNS.Status)))
			fmt.Fprintf(&b, " %-23s%s\n", keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorDns))
		default:
			fmt.Fprintf(&b, "%-24s%s\n", "IP", valColor(valColor(overall.Site.IP)))
		}

		// TCP
		portStr := fmt.Sprintf("(%s port)", overall.TCP.Port)
		switch overall.TCP.Status {
		case "ok":
			fmt.Fprintf(&b, "%-24s%s %s\n", keyColor("TCP"), valColor(upper(overall.TCP.Status)), valColor(portStr))
		case "error":
			fmt.Fprintf(&b, "%-24s%s %s\n", keyColor("TCP"), errColor(upper(overall.TCP.Status)), errColor(overall.TCP.Port))
			fmt.Fprintf(&b, " %-23s%s\n", keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorConn))
		}

		// TLS
		switch overall.TLS.Status {
		case "ok":
			fmt.Fprintf(&b, "%-24s%s\n", keyColor("TLS"), valColor(upper(overall.TLS.Status)))
			fmt.Fprintf(&b, " %-23s%s\n", keyColor("Version"), valColor(overall.TLS.Version))
			fmt.Fprintf(&b, " %-23s%s\n", keyColor("Cipher"), valColor(overall.TLS.Cipher))
		case "error":
			fmt.Fprintf(&b, "%-24s%s\n", keyColor("TLS"), errColor(upper(overall.TLS.Status)))
			fmt.Fprintf(&b, " %-23s%s\n", keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorTls))
		}

		// Certificate
		daysStr := fmt.Sprintf("(%d days)", overall.Certificate.DaysRemaining)
		switch overall.Certificate.Status {
		case "ok":
			fmt.Fprintf(&b, " %-23s%s %s\n", keyColor("Certificate"), valColor(upper(overall.Certificate.Status)), valColor(daysStr))
		case "error":
			fmt.Fprintf(&b, " %-23s%s\n", keyColor("Certificate"), errColor(upper(overall.Certificate.Status)))
			fmt.Fprintf(&b, "  %-22s%s\n", keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorCert))
		}

		// HTTP
		switch overall.Http.Status {
		case "ok":
			fmt.Fprintf(&b, "%-24s%s\n", keyColor("HTTP"), valColor(upper(overall.Http.Status)))
			fmt.Fprintf(&b, " %-23s%s\n", keyColor("Version"), valColor(upper(overall.Http.Version)))
			fmt.Fprintf(&b, " %-23s%s\n", keyColor("Status"), valColor(overall.Http.StatusCode))
			if len(overall.RedirectUrls) > 0 {
				for num, redirectUrl := range overall.RedirectUrls {
					if len(overall.RedirectUrls) == 1 {
						fmt.Fprintf(&b, " %-23s%s\n", keyColor(keyColor("Redirect")), valColor(redirectUrl))
					} else {
						fmt.Fprintf(&b, " %s%-14s%s\n", keyColor(keyColor("Redirect#")), keyColor(num+1), valColor(redirectUrl))
					}
				}
			} else {
				fmt.Fprintf(&b, " %-23s%s\n", keyColor("Redirect"), valColor("None"))
			}
		case "error":
			fmt.Fprintf(&b, "%-24s%s\n", keyColor("HTTP"), errColor(upper(overall.Http.Status)))
			fmt.Fprintf(&b, " %-23s%s\n", keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorHttp))
		}

		// Timings
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprint(&b, keyColor("Timings\n"))
		}

		// DNS
		timingsDnsDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.DnsLookup.Duration)
		timingsDnsStatusStr := fmt.Sprintf("(%s)", upper(overall.TimingsMs.DnsLookup.Status))
		if overall.DNS.Status == "ok" {
			switch overall.TimingsMs.DnsLookup.Status {
			case "good":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(timingsDnsStatusStr))
			case "ok":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(timingsDnsStatusStr))
			case "warn":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("DNS"), warnColor(timingsDnsDurationStr), warnColor(timingsDnsStatusStr))
			default:
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("DNS"), errColor(timingsDnsDurationStr), errColor(timingsDnsStatusStr))
			}
		}

		// TCP
		timingsTcpDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.TcpConnect.Duration)
		timingsTcpStatusStr := fmt.Sprintf("(%s)", upper(overall.TimingsMs.TcpConnect.Status))
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			switch overall.TimingsMs.TcpConnect.Status {
			case "good":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(timingsTcpStatusStr))
			case "ok":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(timingsTcpStatusStr))
			case "warn":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TCP"), warnColor(timingsTcpDurationStr), warnColor(timingsTcpStatusStr))
			default:
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TCP"), errColor(timingsTcpDurationStr), errColor(timingsTcpStatusStr))
			}
		}

		// TLS or TTFB
		timingsTlsDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.TlsHandshake.Duration)
		timingsTlsStatusStr := fmt.Sprintf("(%s)", upper(overall.TimingsMs.TlsHandshake.Status))
		timingsTtfbDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.Ttfb.Duration)
		timingsTtfbStatusStr := fmt.Sprintf("(%s)", upper(overall.TimingsMs.Ttfb.Status))

		if overall.TCP.Status == "ok" {
			switch overall.TimingsMs.TlsHandshake.Status {
			case "good":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(timingsTlsStatusStr))
			case "ok":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(timingsTlsStatusStr))
			case "warn":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TLS"), warnColor(timingsTlsDurationStr), warnColor(timingsTlsStatusStr))
			default:
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TLS"), errColor(timingsTlsDurationStr), errColor(timingsTlsStatusStr))
			}

			switch overall.TimingsMs.Ttfb.Status {
			case "good":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(timingsTtfbStatusStr))
			case "ok":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(timingsTtfbStatusStr))
			case "warn":
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TTFB"), warnColor(timingsTtfbDurationStr), warnColor(timingsTtfbStatusStr))
			default:
				fmt.Fprintf(&b, " %-20s%16s %s\n", keyColor("TTFB"), errColor(timingsTtfbDurationStr), errColor(timingsTtfbStatusStr))
			}
		}

		// Total
		timingsTotalDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.Total.Duration)
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprintf(&b, " %-20s%16s\n", keyColor("Total"), valColor(timingsTotalDurationStr))
		}

		fmt.Fprintf(&b, "\n")

		return b.String()

	default:
		// Site
		fmt.Fprintf(&b, "%-15s%s\n", "URL", overall.Site.URL)

		// DNS
		switch overall.DNS.Status {
		case "ok":
			fmt.Fprintf(&b, "%-15s%s (%s)\n", "DNS", upper(overall.DNS.Status), overall.Site.IP)
		case "error":
			fmt.Fprintf(&b, "%-15s%s\n", "DNS", upper(overall.DNS.Status))
			fmt.Fprintf(&b, " %-14s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorDns)
		default:
			fmt.Fprintf(&b, "%-15s%s\n", "IP", overall.Site.IP)
		}

		// TCP
		switch overall.TCP.Status {
		case "ok":
			fmt.Fprintf(&b, "%-15s%s (%s port)\n", "TCP", upper(overall.TCP.Status), overall.TCP.Port)
		case "error":
			fmt.Fprintf(&b, "%-15s%s (%s port)\n", "TCP", upper(overall.TCP.Status), overall.TCP.Port)
			fmt.Fprintf(&b, " %-14s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorConn)
		}

		// TLS
		switch overall.TLS.Status {
		case "ok":
			fmt.Fprintf(&b, "%-15s%s\n", "TLS", upper(overall.TLS.Status))
			fmt.Fprintf(&b, " %-14s%s\n", "Version", overall.TLS.Version)
			fmt.Fprintf(&b, " %-14s%s\n", "Cipher", overall.TLS.Cipher)
		case "error":
			fmt.Fprintf(&b, "%-15s%s\n", "TLS", upper(overall.TLS.Status))
			fmt.Fprintf(&b, " %-14s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorTls)
		}

		// Certificate
		switch overall.Certificate.Status {
		case "ok":
			fmt.Fprintf(&b, " %-14s%s (%d days)\n", "Certificate", upper(overall.Certificate.Status), overall.Certificate.DaysRemaining)
		case "error":
			fmt.Fprintf(&b, " %-14s%s\n", "Certificate", upper(overall.Certificate.Status))
			fmt.Fprintf(&b, "  %-13s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorCert)
		}

		// HTTP
		switch overall.Http.Status {
		case "ok":
			fmt.Fprintf(&b, "%-15s%s\n", "HTTP", upper(overall.Http.Status))
			fmt.Fprintf(&b, " %-14s%s\n", "Version", upper(overall.Http.Version))
			fmt.Fprintf(&b, " %-14s%d\n", "Status", overall.Http.StatusCode)
			if len(overall.RedirectUrls) > 0 {
				for num, redirectUrl := range overall.RedirectUrls {
					if len(overall.RedirectUrls) == 1 {
						fmt.Fprintf(&b, " %-14s%s\n", "Redirect", redirectUrl)
					} else {
						fmt.Fprintf(&b, " %s#%-4d %s\n", "Redirect", num+1, redirectUrl)
					}
				}
			} else {
				fmt.Fprintf(&b, " %-14s%s\n", "Redirect", "None")
			}
		case "error":
			fmt.Fprintf(&b, "%-15s%s\n", "HTTP", upper(overall.Http.Status))
			fmt.Fprintf(&b, " %-14s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorHttp)
		}

		// Timings
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprintf(&b, "Timings\n")
		}

		// DNS
		if overall.DNS.Status == "ok" {
			fmt.Fprintf(&b, " %-7s%8d ms  (%s)\n", "DNS", overall.TimingsMs.DnsLookup.Duration, upper(overall.TimingsMs.DnsLookup.Status))
		}

		// TCP
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprintf(&b, " %-7s%8d ms  (%s)\n", "TCP", overall.TimingsMs.TcpConnect.Duration, upper(overall.TimingsMs.TcpConnect.Status))
		}

		// TLS or TTFB
		if overall.TCP.Status == "ok" {
			fmt.Fprintf(&b, " %-7s%8d ms  (%s)\n", "TLS", overall.TimingsMs.TlsHandshake.Duration, upper(overall.TimingsMs.TlsHandshake.Status))
			fmt.Fprintf(&b, " %-7s%8d ms  (%s)\n", "TTFB", overall.TimingsMs.Ttfb.Duration, upper(overall.TimingsMs.Ttfb.Status))
		}

		// Total
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprintf(&b, " %-7s%8d ms\n", "Total", overall.TimingsMs.Total.Duration)
		}

		fmt.Fprintf(&b, "\n")

		return b.String()
	}
}

// performDiagnosis executes the diagnostic process and returns the result
func performDiagnosis(initialURL string) DiagnosticResult {
	// Track redirect
	var allRedirects []Response
	var redirectUrls []string
	currentURL := initialURL
	maxRedirects := 10

	for i := 0; i < maxRedirects; i++ {
		result := diagnoseSite(currentURL)
		allRedirects = append(allRedirects, result)

		if result.Http.RedirectUrl != "" {
			redirectUrls = append(redirectUrls, result.Http.RedirectUrl)
			currentURL = result.Http.RedirectUrl
		} else {
			break
		}
	}

	// Define Overall Variable
	firstResult := allRedirects[0]
	lastResult := allRedirects[len(allRedirects)-1]

	// Calculate Overall Duration
	var totalDuration int
	var totalTimingsDnsDuration, totalTimingsTcpDuration, totalTimingsTlsDuration, totalTimingsPreDuration, totalTimingsTtfbDuration, totalTimingsTotalDuration int
	for _, redirect := range allRedirects {
		totalDuration += redirect.Scan.Duration
		totalTimingsDnsDuration += redirect.TimingsMs.DnsLookup.Duration
		totalTimingsTcpDuration += redirect.TimingsMs.TcpConnect.Duration
		totalTimingsTlsDuration += redirect.TimingsMs.TlsHandshake.Duration
		totalTimingsPreDuration += redirect.TimingsMs.Pretransfer.Duration
		totalTimingsTtfbDuration += redirect.TimingsMs.Ttfb.Duration
		totalTimingsTotalDuration += redirect.TimingsMs.Total.Duration
	}

	// Calcurate Per Status
	var totalTimingsDnsStatus, totalTimingsTcpStatus, totalTimingsTlsStatus, totalTimingsPreStatus, totalTimingsTtfbStatus, totalTimingsTotalStatus string
	totalTimingsDnsStatus = evaluateTiming("dns", totalTimingsDnsDuration)
	totalTimingsTcpStatus = evaluateTiming("tcp", totalTimingsTcpDuration)
	totalTimingsTlsStatus = evaluateTiming("tls", totalTimingsTlsDuration)
	totalTimingsPreStatus = evaluateTiming("pre", totalTimingsPreDuration)
	totalTimingsTtfbStatus = evaluateTiming("ttfb", totalTimingsTtfbDuration)
	totalTimingsTotalStatus = evaluateTiming("totalTimings", totalTimingsTotalDuration)

	// Collect Aggregate Message
	var redirectMessages []RedirectMessage
	for _, redirect := range allRedirects {
		redirectMessages = append(redirectMessages, RedirectMessage{
			OverallWarnings: OverallWarinings{
				URL: redirect.Site.URL,
				Warnings: Warnings{
					TlsWarnings: redirect.TLS.TlsWarnings,
				},
			},
			OverallErrors: OverallErros{
				URL: redirect.Site.URL,
				Error: Error{
					ErrorDns:  redirect.DNS.ErrorDns,
					ErrorConn: redirect.TCP.ErrorConn,
					ErrorTls:  redirect.TLS.ErrorTls,
					ErrorCert: redirect.Certificate.ErrorCert,
					ErrorHttp: redirect.Http.ErrorHttp,
				},
			},
		})
	}

	overall := Overall{
		Scan: Scan{
			StartTime: firstResult.Scan.StartTime,
			EndTime:   lastResult.Scan.EndTime,
			Duration:  totalDuration,
		},
		Site: Site{
			URL:      firstResult.Site.URL,
			Hostname: firstResult.Site.Hostname,
			IP:       lastResult.Site.IP,
		},
		DNS: Dns{
			Status: lastResult.DNS.Status,
		},
		TCP: Tcp{
			Status: lastResult.TCP.Status,
			Port:   lastResult.TCP.Port,
		},
		TLS:         lastResult.TLS,
		Certificate: lastResult.Certificate,
		TimingsMs: Timings{
			DnsLookup:    ResponseTime{Duration: totalTimingsDnsDuration, Status: totalTimingsDnsStatus},
			TcpConnect:   ResponseTime{Duration: totalTimingsTcpDuration, Status: totalTimingsTcpStatus},
			TlsHandshake: ResponseTime{Duration: totalTimingsTlsDuration, Status: totalTimingsTlsStatus},
			Pretransfer:  ResponseTime{Duration: totalTimingsDnsDuration, Status: totalTimingsPreStatus},
			Ttfb:         ResponseTime{Duration: totalTimingsTtfbDuration, Status: totalTimingsTtfbStatus},
			Total:        ResponseTime{Duration: totalTimingsTotalDuration, Status: totalTimingsTotalStatus},
		},
		Message: OverallMessage{
			PerRedirect: redirectMessages,
		},
		Http:         lastResult.Http,
		Http3:        lastResult.Http3,
		RedirectUrls: redirectUrls,
	}

	return DiagnosticResult{
		Overall:   overall,
		Redirects: allRedirects,
	}
}

func main() {
	jsonFlag := flag.Bool("json", false, "Enable JSON output")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		fmt.Println("Usage: webdiag <url>")
		return
	}

	initialURL := args[0]

	var output io.Writer = os.Stdout
	isTerminal := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())

	// less
	if isTerminal {
		if lessPath, err := exec.LookPath("less"); err == nil {
			cmd := exec.Command(lessPath, "-RFX")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			lessStdin, err := cmd.StdinPipe()
			if err == nil {
				if err := cmd.Start(); err == nil {
					output = lessStdin
					defer func() {
						lessStdin.Close()
						cmd.Wait()
					}()
				}
			}
		}
	}

	// highlight
	if isTerminal {
		color.NoColor = false
	} else {
		color.NoColor = true
	}

	// Perform diagnosis
	diagnosticResult := performDiagnosis(initialURL)

	// Output based on flags
	var result string = ""
	if *jsonFlag {
		result = printJSON(diagnosticResult)
	} else if *verboseFlag {
		result = printVerbose(diagnosticResult.Redirects)
	} else {
		result = printDefault(diagnosticResult.Overall, isTerminal)
	}

	// // color function
	// green := color.New(color.FgGreen).SprintFunc()
	// yellow := color.New(color.FgYellow).SprintFunc()
	// cyan := color.New(color.FgCyan).SprintFunc()

	// // create colored data
	// lines := strings.Split(result, "\n")
	// for line := range lines {
	// 	line += fmt.Sprintf(
	// 		green("SUCCESS"),
	// 		cyan("highlight"),
	// 	)
	// }

	fmt.Fprint(output, result)
}
