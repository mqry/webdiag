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
	"strings"
	"time"

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

// printJSON outputs the diagnostic result in JSON format
func printJSON(diagnosticResult DiagnosticResult) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	if err := enc.Encode(diagnosticResult); err != nil {
		fmt.Printf(`{"ERROR_MESSAGE": "%s"}`+"\n", err.Error())
		return
	}
	fmt.Print(buf.String())
}

// printVerbose outputs detailed diagnostic information for each redirect
func printVerbose(allRedirects []Response) {
	for i, redirect := range allRedirects {
		// Time
		fmt.Printf("Time\n")
		fmt.Printf("----\n")
		fmt.Printf("%s\n", redirect.Scan.StartTime)
		fmt.Printf("\n")

		// URL
		fmt.Printf("URL\n")
		fmt.Printf("---\n")
		fmt.Printf("%s\n", redirect.Site.URL)
		fmt.Printf("\n")

		// DNS
		fmt.Printf("DNS\n")
		fmt.Printf("---\n")
		fmt.Printf("%-15s%s\n", "Status", strings.ToUpper(redirect.DNS.Status))
		fmt.Printf("%-15s%s\n", "Hostname", redirect.Site.Hostname)
		fmt.Printf("%-15s%s\n", "IP", redirect.Site.IP)
		fmt.Printf("%-15s%s\n", "ERROR", redirect.DNS.ErrorDns)
		fmt.Printf("\n")

		// TCP
		fmt.Printf("TCP\n")
		fmt.Printf("---\n")
		fmt.Printf("%-15s%s\n", "Status", strings.ToUpper(redirect.TCP.Status))
		fmt.Printf("%-15s%s\n", "Port", redirect.TCP.Port)
		fmt.Printf("%-15s%s\n", "ERROR", redirect.TCP.ErrorConn)
		fmt.Printf("\n")

		// TLS
		fmt.Printf("TLS\n")
		fmt.Printf("---\n")
		fmt.Printf("%-15s%s\n", "Status", strings.ToUpper(redirect.TLS.Status))
		fmt.Printf("%-15s%s\n", "Version", redirect.TLS.Version)
		fmt.Printf("%-15s%s\n", "ALPN", redirect.TLS.ALPN)
		fmt.Printf("%-15s%s\n", "Cipher", redirect.TLS.Cipher)
		if redirect.TLS.Status == "ok" {
			fmt.Printf("%-15s%s\n", "SNI", redirect.TLS.SNI)
		}
		fmt.Printf("%-15s%s\n", "ERROR", redirect.TLS.ErrorTls)
		for num, warning := range redirect.TLS.TlsWarnings {
			fmt.Printf("%s#%-6d %s\n", "Warning", num+1, warning)
		}
		fmt.Printf("\n")

		// Certificate
		fmt.Printf("Certificate\n")
		fmt.Printf("-----------\n")
		fmt.Printf("%-15s%s\n", "Status", strings.ToUpper(redirect.Certificate.Status))
		fmt.Printf("%-15s%s\n", "Subject", redirect.Certificate.Subject)
		fmt.Printf("%-15s%s\n", "Issuer", redirect.Certificate.Issuer)
		for num, certificate := range redirect.Certificate.Chains {
			fmt.Printf("%s#%-8d %s\n", "Chain", num+1, certificate)
		}
		fmt.Printf("%-15s%s\n", "Expires", redirect.Certificate.ExpiryDate)
		if redirect.TLS.Status == "ok" {
			fmt.Printf("%-15s%d\n", "Days Left", redirect.Certificate.DaysRemaining)
		}
		fmt.Printf("%-15s%s\n", "ERROR", redirect.Certificate.ErrorCert)
		fmt.Printf("\n")

		// HTTP
		fmt.Printf("HTTP\n")
		fmt.Printf("----\n")
		fmt.Printf("%-15s%s\n", "Status", strings.ToUpper(redirect.Http.Status))
		fmt.Printf("%-15s%s\n", "Version", redirect.Http.Version)
		if redirect.Http.StatusCode != 0 {
			fmt.Printf("%-15s%d\n", "Status", redirect.Http.StatusCode)
		}
		fmt.Printf("%-15s%s\n", "Redirect", redirect.Http.RedirectUrl)
		fmt.Printf("%-15s%s\n", "ERROR", redirect.Http.ErrorHttp)
		fmt.Printf("\n")

		// HTTP/3
		fmt.Printf("HTTP/3\n")
		fmt.Printf("------\n")
		fmt.Printf("")
		fmt.Printf("%-15s%s\n", "Supported", strings.ToUpper(redirect.Http3.HTTP3Supported))
		fmt.Printf("%-15s%s\n", "Alt-Svc", redirect.Http3.AltSvc)
		fmt.Printf("\n")

		// Timings
		fmt.Printf("Timinigs\n")
		fmt.Printf("--------\n")
		fmt.Printf("%-8s%8d ms  (%s)\n", "DNS", redirect.TimingsMs.DnsLookup.Duration, strings.ToUpper(redirect.TimingsMs.DnsLookup.Status))
		fmt.Printf("%-8s%8d ms  (%s)\n", "TCP", redirect.TimingsMs.TcpConnect.Duration, strings.ToUpper(redirect.TimingsMs.TcpConnect.Status))
		fmt.Printf("%-8s%8d ms  (%s)\n", "TLS", redirect.TimingsMs.TlsHandshake.Duration, strings.ToUpper(redirect.TimingsMs.TlsHandshake.Status))
		fmt.Printf("%-8s%8d ms  (%s)\n", "PRE", redirect.TimingsMs.Pretransfer.Duration, strings.ToUpper(redirect.TimingsMs.Pretransfer.Status))
		fmt.Printf("%-8s%8d ms  (%s)\n", "TTFB", redirect.TimingsMs.Ttfb.Duration, strings.ToUpper(redirect.TimingsMs.Ttfb.Status))
		fmt.Printf("%-8s%8d ms\n", "Total", redirect.TimingsMs.Total.Duration)
		fmt.Printf("\n")

		// Option: Redirect Arrow
		if i+1 < len(allRedirects) {
			fmt.Printf("|\n")
			fmt.Printf("|\n")
			fmt.Printf("| Redirect: %d\n", redirect.Http.StatusCode)
			fmt.Printf("|\n")
			fmt.Printf("v\n")
			fmt.Printf("\n")
		}
	}
}

// printDefault outputs a summary of the diagnostic result
func printDefault(overall Overall) {
	// Site
	fmt.Printf("%-15s%s\n", "URL", overall.Site.URL)

	// DNS
	switch overall.DNS.Status {
	case "ok":
		fmt.Printf("%-15s%s (%s)\n", "DNS", strings.ToUpper(overall.DNS.Status), overall.Site.IP)
	case "error":
		fmt.Printf("%-15s%s\n", "DNS", strings.ToUpper(overall.DNS.Status))
		fmt.Printf(" %-14s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorDns)
	default:
		fmt.Printf("%-15s%s\n", "IP", overall.Site.IP)
	}

	// TCP
	switch overall.TCP.Status {
	case "ok":
		fmt.Printf("%-15s%s (%s port)\n", "TCP", strings.ToUpper(overall.TCP.Status), overall.TCP.Port)
	case "error":
		fmt.Printf("%-15s%s (%s port)\n", "TCP", strings.ToUpper(overall.TCP.Status), overall.TCP.Port)
		fmt.Printf(" %-14s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorConn)
	}

	// TLS
	switch overall.TLS.Status {
	case "ok":
		fmt.Printf("%-15s%s\n", "TLS", strings.ToUpper(overall.TLS.Status))
		fmt.Printf(" %-14s%s\n", "Version", overall.TLS.Version)
		fmt.Printf(" %-14s%s\n", "Cipher", overall.TLS.Cipher)
	case "error":
		fmt.Printf("%-15s%s\n", "TLS", strings.ToUpper(overall.TLS.Status))
		fmt.Printf(" %-14s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorTls)
	}

	// Certificate
	switch overall.Certificate.Status {
	case "ok":
		fmt.Printf(" %-14s%s (%d days)\n", "Certificate", strings.ToUpper(overall.Certificate.Status), overall.Certificate.DaysRemaining)
	case "error":
		fmt.Printf(" %-14s%s\n", "Certificate", strings.ToUpper(overall.Certificate.Status))
		fmt.Printf("  %-13s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorCert)
	}

	// HTTP
	switch overall.Http.Status {
	case "ok":
		fmt.Printf("%-15s%s\n", "HTTP", strings.ToUpper(overall.Http.Status))
		fmt.Printf(" %-14s%s\n", "Version", strings.ToUpper(overall.Http.Version))
		fmt.Printf(" %-14s%d\n", "Status", overall.Http.StatusCode)
		if len(overall.RedirectUrls) > 0 {
			for num, redirectUrl := range overall.RedirectUrls {
				if len(overall.RedirectUrls) == 1 {
					fmt.Printf(" %-14s%s\n", "Redirect", redirectUrl)
				} else {
					fmt.Printf(" %s#%-4d %s\n", "Redirect", num+1, redirectUrl)
				}
			}
		} else {
			fmt.Printf(" %-14s%s\n", "Redirect", "None")
		}
	case "error":
		fmt.Printf("%-15s%s\n", "HTTP", strings.ToUpper(overall.Http.Status))
		fmt.Printf(" %-14s%s\n", "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorHttp)
	}

	// Timings
	if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
		fmt.Printf("Timings\n")
	}

	// DNS
	if overall.DNS.Status == "ok" {
		fmt.Printf(" %-8s%8d ms  (%s)\n", "DNS", overall.TimingsMs.DnsLookup.Duration, strings.ToUpper(overall.TimingsMs.DnsLookup.Status))
	}

	// TCP
	if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
		fmt.Printf(" %-8s%8d ms  (%s)\n", "TCP", overall.TimingsMs.TcpConnect.Duration, strings.ToUpper(overall.TimingsMs.TcpConnect.Status))
	}

	// TLS or TTFB
	if overall.TCP.Status == "ok" {
		fmt.Printf(" %-8s%8d ms  (%s)\n", "TLS", overall.TimingsMs.TlsHandshake.Duration, strings.ToUpper(overall.TimingsMs.TlsHandshake.Status))
		fmt.Printf(" %-8s%8d ms  (%s)\n", "TTFB", overall.TimingsMs.Ttfb.Duration, strings.ToUpper(overall.TimingsMs.Ttfb.Status))
	}

	// Total
	if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
		fmt.Printf(" %-8s%8d ms\n", "Total", overall.TimingsMs.Total.Duration)
	}

	fmt.Printf("\n")
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

	// Perform diagnosis
	diagnosticResult := performDiagnosis(initialURL)

	// Output based on flags
	if *jsonFlag {
		printJSON(diagnosticResult)
	} else if *verboseFlag {
		printVerbose(diagnosticResult.Redirects)
	} else {
		printDefault(diagnosticResult.Overall)
	}
}
