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

type Summary struct {
	Scan         Scan           `json:"scan"`
	Site         Site           `json:"site"`
	TimingsMs    Timings        `json:"timings_ms"`
	Message      SummaryMessage `json:"message"`
	Http         Http           `json:"http"`
	RedirectUrls []string       `json:"redirect_urls,omitempty"`
	Http3        Http3          `json:"http3"`
	TLS          TLSConfig      `json:"tls"`
	Certificate  Certificate    `json:"certificate"`
}

type DiagnosticResult struct {
	Summary Summary    `json:"summary"`
	Details []Response `json:"details"`
}

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
	DnsLookup    ResponseTime `json:"dns_lookup"`
	TcpConnect   ResponseTime `json:"tcp_connect"`
	TlsHandshake ResponseTime `json:"tls_handshake"`
	Pretransfer  ResponseTime `json:"pre_transfer"`
	Ttfb         ResponseTime `json:"ttfb"`
	Total        ResponseTime `json:"total"`
}

type ResponseTime struct {
	Duration int    `json:"duration"`
	Score    int    `json:"score"`
	Status   string `json:"status"`
}

type Http struct {
	Status      string `json:"status"`
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
	Status        string   `json:"status"`
	DaysRemaining int      `json:"days_remaining"`
	Subject       string   `json:"subject,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	Chains        []string `json:"chains,omitempty"`
	// DnsNames      []string `json:"dns_names,omitempty"`
	ExpiryDate string `json:"expiry_date"`
}

type Message struct {
	Warnings []string `json:"warnings,omitempty"`
	Error    Error    `json:"error"`
}

type RedirectMessage struct {
	URL      string   `json:"url"`
	Warnings []string `json:"warnings,omitempty"`
	Error    Error    `json:"error"`
}

type SummaryMessage struct {
	PerRedirect []RedirectMessage `json:"per_redirect"`
}

type Error struct {
	ErrorConn string `json:"connection,omitempty"`
	ErrorCert string `json:"certificate,omitempty"`
}

func evaluateTiming(diagType string, diagDuration int) string {
	switch diagType {
	case "dns":
		switch {
		case diagDuration <= 20:
			return "good"
		case diagDuration > 20 && diagDuration <= 50:
			return "ok"
		case diagDuration > 50 && diagDuration <= 100:
			return "warn"
		case diagDuration > 100:
			return "error"
		}
	case "tcp":
		switch {
		case diagDuration <= 10:
			return "good"
		case diagDuration > 10 && diagDuration <= 30:
			return "ok"
		case diagDuration > 50 && diagDuration <= 100:
			return "warn"
		case diagDuration > 100:
			return "error"
		}
	case "tls":
		switch {
		case diagDuration <= 50:
			return "good"
		case diagDuration > 50 && diagDuration <= 100:
			return "ok"
		case diagDuration > 100 && diagDuration <= 200:
			return "warn"
		case diagDuration > 200:
			return "error"
		}
	case "pre":
		switch {
		case diagDuration <= 2:
			return "good"
		case diagDuration > 3 && diagDuration <= 4:
			return "ok"
		case diagDuration > 5 && diagDuration <= 10:
			return "warn"
		case diagDuration > 10:
			return "error"
		}
	case "ttfb":
		switch {
		case diagDuration <= 200:
			return "good"
		case diagDuration > 200 && diagDuration <= 500:
			return "ok"
		case diagDuration > 500 && diagDuration <= 800:
			return "warn"
		case diagDuration > 800:
			return "error"
		}
	case "total":
		switch {
		case diagDuration <= 200:
			return "good"
		case diagDuration > 200 && diagDuration <= 500:
			return "ok"
		case diagDuration > 500 && diagDuration <= 1000:
			return "warn"
		case diagDuration > 1000:
			return "error"
		}
	}
	return "error"
}

func diagnoseSite(targetURL string) Response {
	var hostname string
	var establishedTLSVersion string
	var establishedCipherSuite string
	var establishedALPNProtocol string
	var systemPool *x509.CertPool
	var certSubject string
	var certIssuer string
	var certChains []string
	// var certDnsNames []string
	var certValid bool
	var certStatus string
	var certExpiryStr string
	var daysLeft int
	var http3Supported bool
	var altSvcHeader string
	var globalWarnings []string

	url := targetURL
	if !strings.Contains(url, "https://") && !strings.Contains(url, "http://") {
		hostname = url
		url = "https://" + hostname
	} else {
		hostname = strings.Split(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"), "/")[0]
	}

	globalWarnings = []string{}
	certChains = []string{}
	// certDnsNames = []string{}

	var dnsEnd, connectEnd, tlsEnd, wroteRequestTime, firstByteTime time.Time
	var remoteIP string
	var errConnMsg string
	var errCertMsg string
	var statusCode int
	var httpStatus string
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
				// certDnsNames = leafCert.DNSNames

				daysLeft = int(time.Until(leafCert.NotAfter).Hours() / 24.0)
				if daysLeft <= 30.0 && daysLeft > 0 {
					globalWarnings = append(globalWarnings, fmt.Sprintf("certificate will expire %d days left (%s)", daysLeft, certExpiryStr))
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
				} else {
					certValid = true
				}
			}

			return tlsConn, nil
		},
	}

	// Validate HTTP/2 support
	if err := http2.ConfigureTransport(transport); err != nil {
		// HTTP/2 設定エラーの場合、空の Response を返す
		errConnMsg = "Failed to configure HTTP/2: " + err.Error()
		return Response{
			Scan: Scan{
				StartTime: startTime.Format(time.RFC3339),
				EndTime:   time.Now().Format(time.RFC3339),
				Duration:  0,
			},
			Site: Site{
				URL: url,
				IP:  "",
			},
			Http: Http{
				Status:     "error",
				StatusCode: 0,
			},
			Message: Message{
				Error: Error{
					ErrorConn: errConnMsg,
				},
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
		// リクエスト作成エラーの場合、空の Response を返す
		errConnMsg = err.Error()
		return Response{
			Scan: Scan{
				StartTime: startTime.Format(time.RFC3339),
				EndTime:   time.Now().Format(time.RFC3339),
				Duration:  0,
			},
			Site: Site{
				URL: url,
				IP:  "",
			},
			Http: Http{
				Status:     "error",
				StatusCode: 0,
			},
			Message: Message{
				Error: Error{
					ErrorConn: errConnMsg,
				},
			},
		}
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

		if errConnMsg == "" {
			httpStatus = "ok"
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

	if certValid && establishedTLSVersion != "" {
		certStatus = "ok"
	} else {
		certStatus = "error"
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
			URL: url,
			IP:  remoteIP,
		},
		Http: Http{
			Status:      httpStatus,
			StatusCode:  statusCode,
			RedirectUrl: redirectLocation,
			Version:     httpVersion,
		},
		TimingsMs: Timings{
			DnsLookup:    ResponseTime{Duration: int(timeDNS), Score: 100, Status: "ok"},
			TcpConnect:   ResponseTime{Duration: int(timeConnect), Score: 100, Status: "ok"},
			TlsHandshake: ResponseTime{Duration: int(timeTLS), Score: 100, Status: "ok"},
			Pretransfer:  ResponseTime{Duration: int(timePretransfer), Score: 100, Status: "ok"},
			Ttfb:         ResponseTime{Duration: int(ttfb), Score: 100, Status: "ok"},
			Total:        ResponseTime{Duration: int(totalTime), Score: 100, Status: "ok"},
		},
		TLS: TLSConfig{
			SNI:     hostname,
			Version: establishedTLSVersion,
			Cipher:  establishedCipherSuite,
			ALPN:    establishedALPNProtocol,
		},
		Certificate: Certificate{
			Status:  certStatus,
			Subject: certSubject,
			Issuer:  certIssuer,
			// DnsNames:      certDnsNames,
			Chains:        certChains,
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

	return metrics
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

	// リダイレクトを追跡
	var allDetails []Response
	var redirectUrls []string
	currentURL := initialURL
	maxRedirects := 10

	for i := 0; i < maxRedirects; i++ {
		result := diagnoseSite(currentURL)
		allDetails = append(allDetails, result)

		// リダイレクトがある場合
		if result.Http.RedirectUrl != "" {
			redirectUrls = append(redirectUrls, result.Http.RedirectUrl)
			currentURL = result.Http.RedirectUrl
		} else {
			// リダイレクトがなければ終了
			break
		}
	}

	// 全体のまとめを作成
	firstResult := allDetails[0]
	lastResult := allDetails[len(allDetails)-1]

	// 全体の Duration と タイミングの合算
	var totalDuration int
	var totalDnsLookupDuration, totalTcpConnectDuration, totalTlsHandshakeDuration, totalPretransferDuration, totalTtfbDuration, totalTimingsTotalDuration int
	for _, detail := range allDetails {
		totalDuration += detail.Scan.Duration
		totalDnsLookupDuration += detail.TimingsMs.DnsLookup.Duration
		totalTcpConnectDuration += detail.TimingsMs.TcpConnect.Duration
		totalTlsHandshakeDuration += detail.TimingsMs.TlsHandshake.Duration
		totalPretransferDuration += detail.TimingsMs.Pretransfer.Duration
		totalTtfbDuration += detail.TimingsMs.Ttfb.Duration
		totalTimingsTotalDuration += detail.TimingsMs.Total.Duration
	}

	// Calcurate Per Status
	var totalDnsLookupStatus, totalTcpConnectStatus, totalTlsHandshakeStatus, totalPretransferStatus, totalTtfbStatus, totalTimingsTotalStatus string
	totalDnsLookupStatus = evaluateTiming("dns", totalDnsLookupDuration)
	totalTcpConnectStatus = evaluateTiming("tcp", totalTcpConnectDuration)
	totalTlsHandshakeStatus = evaluateTiming("tls", totalTlsHandshakeDuration)
	totalPretransferStatus = evaluateTiming("pre", totalPretransferDuration)
	totalTtfbStatus = evaluateTiming("ttfb", totalTtfbDuration)
	totalTimingsTotalStatus = evaluateTiming("total", totalTimingsTotalDuration)

	// 各リダイレクト先ごとのメッセージを収集
	var redirectMessages []RedirectMessage
	for _, detail := range allDetails {
		redirectMessages = append(redirectMessages, RedirectMessage{
			URL:      detail.Site.URL,
			Warnings: detail.Message.Warnings,
			Error: Error{
				ErrorConn: detail.Message.Error.ErrorConn,
				ErrorCert: detail.Message.Error.ErrorCert,
			},
		})
	}

	summary := Summary{
		Scan: Scan{
			StartTime: firstResult.Scan.StartTime,
			EndTime:   lastResult.Scan.EndTime,
			Duration:  totalDuration,
		},
		Site: Site{
			URL: firstResult.Site.URL,
			IP:  lastResult.Site.IP,
		},
		TimingsMs: Timings{
			DnsLookup:    ResponseTime{Duration: totalDnsLookupDuration, Score: 100, Status: totalDnsLookupStatus},
			TcpConnect:   ResponseTime{Duration: totalTcpConnectDuration, Score: 100, Status: totalTcpConnectStatus},
			TlsHandshake: ResponseTime{Duration: totalTlsHandshakeDuration, Score: 100, Status: totalTlsHandshakeStatus},
			Pretransfer:  ResponseTime{Duration: totalPretransferDuration, Score: 100, Status: totalPretransferStatus},
			Ttfb:         ResponseTime{Duration: totalTtfbDuration, Score: 100, Status: totalTtfbStatus},
			Total:        ResponseTime{Duration: totalTimingsTotalDuration, Score: 100, Status: totalTimingsTotalStatus},
		},
		Message: SummaryMessage{
			PerRedirect: redirectMessages,
		},
		Http:         lastResult.Http,
		Http3:        lastResult.Http3,
		TLS:          lastResult.TLS,
		Certificate:  lastResult.Certificate,
		RedirectUrls: redirectUrls,
	}

	diagnosticResult := DiagnosticResult{
		Summary: summary,
		Details: allDetails,
	}

	// JSON Mode
	if *jsonFlag {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")

		if err := enc.Encode(diagnosticResult); err != nil {
			fmt.Printf(`{"ERROR_MESSAGE": "%s"}`+"\n", err.Error())
			return
		}
		fmt.Print(buf.String())
		return
	}

	// Verbose Mode
	if *verboseFlag {
		fmt.Println("[INFO] The diagnostic results will be displayed in detail...")
		for _, detail := range allDetails {
			fmt.Printf("[DETAILS] %s\n", detail.Scan.StartTime)
			fmt.Printf("[DETAILS] %s\n", detail.Scan.EndTime)
			fmt.Printf("[DETAILS] %s\n", detail.Site.URL)
		}
		return
	}

	// Default Mode
	summary = diagnosticResult.Summary
	fmt.Printf("URL            %s\n", summary.Site.URL)
	fmt.Printf("IP             %s\n", summary.Site.IP)
	fmt.Printf("\n")
	fmt.Printf("HTTP           %d\n", summary.Http.StatusCode)
	fmt.Printf("Version        %s\n", summary.Http.Version)
	fmt.Printf("Redirect       %s\n", summary.RedirectUrls)
	fmt.Printf("TLS            %s\n", summary.TLS.Version)
	fmt.Printf("Certificate    %s (%d days)\n", strings.ToUpper(summary.Certificate.Status), summary.Certificate.DaysRemaining)
	fmt.Printf("\n")
	fmt.Printf("Timings\n")
	fmt.Printf("  DNS          %d ms\n", summary.TimingsMs.DnsLookup.Duration)
	fmt.Printf("  TCP          %d ms\n", summary.TimingsMs.TcpConnect.Duration)
	fmt.Printf("  TLS          %d ms\n", summary.TimingsMs.TlsHandshake.Duration)
	fmt.Printf("  TTFB         %d ms\n", summary.TimingsMs.Ttfb.Duration)
	fmt.Printf("  Total        %d ms\n", summary.TimingsMs.Total.Duration)
}
