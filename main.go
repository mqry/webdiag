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
	"strconv"
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

func str(i int) string {
	return strconv.Itoa(i)
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
func printVerbose(allRedirects []Response, isColor bool) string {
	titleColor := color.New(color.FgMagenta, color.Bold).SprintFunc()
	keyColor := color.New(color.FgBlue, color.Bold).SprintFunc()
	valColor := color.New(color.FgGreen).SprintFunc()
	warnColor := color.New(color.FgYellow).SprintFunc()
	errColor := color.New(color.FgRed).SprintFunc()
	kvColorFormat := "%-27s%s\n"
	kvColorTimingsFormat := "%-25s%16s %s\n"
	kvNoColorFormat := "%-15s%s\n"
	kvNoColorTimingsFormat := "%-9s%8d ms  (%s)\n"

	var b strings.Builder

	switch isColor {
	case true:
		for i, redirect := range allRedirects {
			// Time
			fmt.Fprint(&b, titleColor("Time\n"))
			fmt.Fprint(&b, titleColor("----\n"))
			fmt.Fprintf(&b, "%s\n", keyColor(redirect.Scan.StartTime))
			fmt.Fprint(&b, "\n")

			// URL
			fmt.Fprint(&b, titleColor("URL\n"))
			fmt.Fprint(&b, titleColor("---\n"))
			fmt.Fprintf(&b, "%s\n", keyColor(redirect.Site.URL))
			fmt.Fprint(&b, "\n")

			// DNS
			fmt.Fprint(&b, titleColor("DNS\n"))
			fmt.Fprint(&b, titleColor("---\n"))
			switch redirect.DNS.Status {
			case "ok":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.DNS.Status)))
			case "error":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), errColor(upper(redirect.DNS.Status)))
			default:
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.DNS.Status)))
			}
			fmt.Fprintf(&b, kvColorFormat, keyColor("Hostname"), valColor(redirect.Site.Hostname))
			fmt.Fprintf(&b, kvColorFormat, keyColor("IP"), valColor(redirect.Site.IP))
			fmt.Fprintf(&b, kvColorFormat, keyColor("ERROR"), errColor(redirect.DNS.ErrorDns))
			fmt.Fprint(&b, "\n")

			// TCP
			fmt.Fprint(&b, titleColor("TCP\n"))
			fmt.Fprint(&b, titleColor("---\n"))
			switch redirect.TCP.Status {
			case "ok":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.TCP.Status)))
			case "error":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), errColor(upper(redirect.TCP.Status)))
			default:
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.TCP.Status)))
			}
			fmt.Fprintf(&b, kvColorFormat, keyColor("Port"), valColor(redirect.TCP.Port))
			fmt.Fprintf(&b, kvColorFormat, keyColor("ERROR"), errColor(redirect.TCP.ErrorConn))
			fmt.Fprint(&b, "\n")

			// TLS
			fmt.Fprint(&b, titleColor("TLS\n"))
			fmt.Fprint(&b, titleColor("---\n"))
			switch redirect.TLS.Status {
			case "ok":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.TLS.Status)))
			case "error":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), errColor(upper(redirect.TLS.Status)))
			default:
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.TLS.Status)))
			}
			fmt.Fprintf(&b, kvColorFormat, keyColor("Version"), valColor(redirect.TLS.Version))
			fmt.Fprintf(&b, kvColorFormat, keyColor("ALPN"), valColor(redirect.TLS.ALPN))
			fmt.Fprintf(&b, kvColorFormat, keyColor("Cipher"), valColor(redirect.TLS.Cipher))
			if redirect.TLS.Status == "ok" {
				fmt.Fprintf(&b, kvColorFormat, keyColor("SNI"), valColor(redirect.TLS.SNI))
			}
			fmt.Fprintf(&b, kvColorFormat, keyColor("ERROR"), errColor(redirect.TLS.ErrorTls))
			for num, warning := range redirect.TLS.TlsWarnings {
				fmt.Fprintf(&b, "%s%-15s %s\n", keyColor("Warning#"), keyColor(num+1), warnColor(warning))
			}
			fmt.Fprint(&b, "\n")

			// Certificate
			fmt.Fprint(&b, titleColor("Certificate\n"))
			fmt.Fprint(&b, titleColor("-----------\n"))
			switch redirect.Certificate.Status {
			case "ok":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.Certificate.Status)))
			case "error":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), errColor(upper(redirect.Certificate.Status)))
			default:
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.Certificate.Status)))
			}
			fmt.Fprintf(&b, kvColorFormat, keyColor("Subject"), valColor(redirect.Certificate.Subject))
			fmt.Fprintf(&b, kvColorFormat, keyColor("Issuer"), valColor(redirect.Certificate.Issuer))
			for num, certificate := range redirect.Certificate.Chains {
				fmt.Fprintf(&b, "%s%-20s %s\n", keyColor("Chain#"), keyColor(num+1), valColor(certificate))
			}
			fmt.Fprintf(&b, kvColorFormat, keyColor("Expires"), valColor(redirect.Certificate.ExpiryDate))
			if redirect.TLS.Status == "ok" {
				fmt.Fprintf(&b, kvColorFormat, keyColor("Days Left"), valColor(redirect.Certificate.DaysRemaining))
			}
			fmt.Fprintf(&b, kvColorFormat, keyColor("ERROR"), errColor(redirect.Certificate.ErrorCert))
			fmt.Fprint(&b, "\n")

			// HTTP
			fmt.Fprint(&b, titleColor("HTTP\n"))
			fmt.Fprint(&b, titleColor("----\n"))
			switch redirect.Http.Status {
			case "ok":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.Http.Status)))
			case "error":
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), errColor(upper(redirect.Http.Status)))
			default:
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(upper(redirect.Http.Status)))
			}
			fmt.Fprintf(&b, kvColorFormat, keyColor("Version"), valColor(redirect.Http.Version))
			if redirect.Http.StatusCode != 0 {
				fmt.Fprintf(&b, kvColorFormat, keyColor("Status"), valColor(redirect.Http.StatusCode))
			}
			fmt.Fprintf(&b, kvColorFormat, keyColor("Redirect"), valColor(redirect.Http.RedirectUrl))
			fmt.Fprintf(&b, kvColorFormat, keyColor("ERROR"), errColor(redirect.Http.ErrorHttp))
			fmt.Fprint(&b, "\n")

			// HTTP/3
			fmt.Fprint(&b, titleColor("HTTP/3\n"))
			fmt.Fprint(&b, titleColor("------\n"))
			fmt.Fprintf(&b, kvColorFormat, keyColor("Supported"), valColor(upper(redirect.Http3.HTTP3Supported)))
			fmt.Fprintf(&b, kvColorFormat, keyColor("Alt-Svc"), valColor(redirect.Http3.AltSvc))
			fmt.Fprint(&b, "\n")

			// Timings
			fmt.Fprint(&b, titleColor("Timinigs\n"))
			fmt.Fprint(&b, titleColor("--------\n"))

			timingsDnsStatusStr := fmt.Sprintf("(%s)", redirect.TimingsMs.DnsLookup.Status)
			timingsTcpStatusStr := fmt.Sprintf("(%s)", redirect.TimingsMs.TcpConnect.Status)
			timingsTlsStatusStr := fmt.Sprintf("(%s)", redirect.TimingsMs.TlsHandshake.Status)
			timingsPreStatusStr := fmt.Sprintf("(%s)", redirect.TimingsMs.Pretransfer.Status)
			timingsTtfbStatusStr := fmt.Sprintf("(%s)", redirect.TimingsMs.Ttfb.Status)
			timingsTotalStatusStr := fmt.Sprintf("(%s)", redirect.TimingsMs.Total.Status)

			timingsDnsDurationStr := fmt.Sprintf("%d ms", redirect.TimingsMs.DnsLookup.Duration)
			timingsTcpDurationStr := fmt.Sprintf("%d ms", redirect.TimingsMs.TcpConnect.Duration)
			timingsTlsDurationStr := fmt.Sprintf("%d ms", redirect.TimingsMs.TlsHandshake.Duration)
			timingsPreDurationStr := fmt.Sprintf("%d ms", redirect.TimingsMs.Pretransfer.Duration)
			timingsTtfbDurationStr := fmt.Sprintf("%d ms", redirect.TimingsMs.Ttfb.Duration)
			timingsTotalDurationStr := fmt.Sprintf("%d ms", redirect.TimingsMs.Total.Duration)

			// Timings DNS
			switch redirect.TimingsMs.DnsLookup.Status {
			case "good":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(upper(timingsDnsStatusStr)))
			case "ok":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(upper(timingsDnsStatusStr)))
			case "warn":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("DNS"), warnColor(timingsDnsDurationStr), warnColor(upper(timingsDnsStatusStr)))
			case "bad":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("DNS"), errColor(timingsDnsDurationStr), errColor(upper(timingsDnsStatusStr)))
			default:
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(upper(timingsDnsStatusStr)))
			}

			// Timings TCP
			switch redirect.TimingsMs.TcpConnect.Status {
			case "good":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(upper(timingsTcpStatusStr)))
			case "ok":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(upper(timingsTcpStatusStr)))
			case "warn":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TCP"), warnColor(timingsTcpDurationStr), warnColor(upper(timingsTcpStatusStr)))
			case "bad":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TCP"), errColor(timingsTcpDurationStr), errColor(upper(timingsTcpStatusStr)))
			default:
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(upper(timingsTcpStatusStr)))
			}

			// Timings TLS
			switch redirect.TimingsMs.TlsHandshake.Status {
			case "good":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(upper(timingsTlsStatusStr)))
			case "ok":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(upper(timingsTlsStatusStr)))
			case "warn":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TLS"), warnColor(timingsTlsDurationStr), warnColor(upper(timingsTlsStatusStr)))
			case "bad":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TLS"), errColor(timingsTlsDurationStr), errColor(upper(timingsTlsStatusStr)))
			default:
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(upper(timingsTlsStatusStr)))
			}

			// Timings PreTransfer
			switch redirect.TimingsMs.Pretransfer.Status {
			case "good":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("PRE"), valColor(timingsPreDurationStr), valColor(upper(timingsPreStatusStr)))
			case "ok":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("PRE"), valColor(timingsPreDurationStr), valColor(upper(timingsPreStatusStr)))
			case "warn":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("PRE"), warnColor(timingsPreDurationStr), warnColor(upper(timingsPreStatusStr)))
			case "bad":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("PRE"), errColor(timingsPreDurationStr), errColor(upper(timingsPreStatusStr)))
			default:
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("PRE"), valColor(timingsPreDurationStr), valColor(upper(timingsPreStatusStr)))
			}

			// Timings TTFB
			switch redirect.TimingsMs.Ttfb.Status {
			case "good":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(upper(timingsTtfbStatusStr)))
			case "ok":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(upper(timingsTtfbStatusStr)))
			case "warn":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TTFB"), warnColor(timingsTtfbDurationStr), warnColor(upper(timingsTtfbStatusStr)))
			case "bad":
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TTFB"), errColor(timingsTtfbDurationStr), errColor(upper(timingsTtfbStatusStr)))
			default:
				fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(upper(timingsTtfbStatusStr)))
			}

			// Timings Total
			fmt.Fprintf(&b, kvColorTimingsFormat, keyColor("Total"), valColor(timingsTotalDurationStr), valColor(timingsTotalStatusStr))

			fmt.Fprint(&b, "\n")

			// Option: Redirect Arrow
			if i+1 < len(allRedirects) {
				fmt.Fprint(&b, "|\n")
				fmt.Fprint(&b, "|\n")
				fmt.Fprintf(&b, "| Redirect: %d\n", redirect.Http.StatusCode)
				fmt.Fprint(&b, "|\n")
				fmt.Fprint(&b, "v\n")
				fmt.Fprint(&b, "\n")
			}
		}
	default:
		for i, redirect := range allRedirects {
			// Time
			fmt.Fprint(&b, "Time\n")
			fmt.Fprint(&b, "----\n")
			fmt.Fprintf(&b, "%s\n", redirect.Scan.StartTime)
			fmt.Fprint(&b, "\n")

			// URL
			fmt.Fprint(&b, "URL\n")
			fmt.Fprint(&b, "---\n")
			fmt.Fprintf(&b, "%s\n", redirect.Site.URL)
			fmt.Fprint(&b, "\n")

			// DNS
			fmt.Fprint(&b, "DNS\n")
			fmt.Fprint(&b, "---\n")
			fmt.Fprintf(&b, kvNoColorFormat, "Status", upper(redirect.DNS.Status))
			fmt.Fprintf(&b, kvNoColorFormat, "Hostname", redirect.Site.Hostname)
			fmt.Fprintf(&b, kvNoColorFormat, "IP", redirect.Site.IP)
			fmt.Fprintf(&b, kvNoColorFormat, "ERROR", redirect.DNS.ErrorDns)
			fmt.Fprint(&b, "\n")

			// TCP
			fmt.Fprint(&b, "TCP\n")
			fmt.Fprint(&b, "---\n")
			fmt.Fprintf(&b, kvNoColorFormat, "Status", upper(redirect.TCP.Status))
			fmt.Fprintf(&b, kvNoColorFormat, "Port", redirect.TCP.Port)
			fmt.Fprintf(&b, kvNoColorFormat, "ERROR", redirect.TCP.ErrorConn)
			fmt.Fprintf(&b, "\n")

			// TLS
			fmt.Fprint(&b, "TLS\n")
			fmt.Fprint(&b, "---\n")
			fmt.Fprintf(&b, kvNoColorFormat, "Status", upper(redirect.TLS.Status))
			fmt.Fprintf(&b, kvNoColorFormat, "Version", redirect.TLS.Version)
			fmt.Fprintf(&b, kvNoColorFormat, "ALPN", redirect.TLS.ALPN)
			fmt.Fprintf(&b, kvNoColorFormat, "Cipher", redirect.TLS.Cipher)
			if redirect.TLS.Status == "ok" {
				fmt.Fprintf(&b, kvNoColorFormat, "SNI", redirect.TLS.SNI)
			}
			fmt.Fprintf(&b, kvNoColorFormat, "ERROR", redirect.TLS.ErrorTls)
			for num, warning := range redirect.TLS.TlsWarnings {
				fmt.Fprintf(&b, "%s#%-6d %s\n", "Warning", num+1, warning)
			}
			fmt.Fprint(&b, "\n")

			// Certificate
			fmt.Fprint(&b, "Certificate\n")
			fmt.Fprint(&b, "-----------\n")
			fmt.Fprintf(&b, kvNoColorFormat, "Status", upper(redirect.Certificate.Status))
			fmt.Fprintf(&b, kvNoColorFormat, "Subject", redirect.Certificate.Subject)
			fmt.Fprintf(&b, kvNoColorFormat, "Issuer", redirect.Certificate.Issuer)
			for num, certificate := range redirect.Certificate.Chains {
				fmt.Fprintf(&b, "%s#%-8d %s\n", "Chain", num+1, certificate)
			}
			fmt.Fprintf(&b, kvNoColorFormat, "Expires", redirect.Certificate.ExpiryDate)
			if redirect.TLS.Status == "ok" {
				fmt.Fprintf(&b, "%-15s%d\n", "Days Left", redirect.Certificate.DaysRemaining)
			}
			fmt.Fprintf(&b, kvNoColorFormat, "ERROR", redirect.Certificate.ErrorCert)
			fmt.Fprint(&b, "\n")

			// HTTP
			fmt.Fprint(&b, "HTTP\n")
			fmt.Fprint(&b, "----\n")
			fmt.Fprintf(&b, kvNoColorFormat, "Status", upper(redirect.Http.Status))
			fmt.Fprintf(&b, kvNoColorFormat, "Version", redirect.Http.Version)
			if redirect.Http.StatusCode != 0 {
				fmt.Fprintf(&b, "%-15s%d\n", "Status", redirect.Http.StatusCode)
			}
			fmt.Fprintf(&b, kvNoColorFormat, "Redirect", redirect.Http.RedirectUrl)
			fmt.Fprintf(&b, kvNoColorFormat, "ERROR", redirect.Http.ErrorHttp)
			fmt.Fprint(&b, "\n")

			// HTTP/3
			fmt.Fprint(&b, "HTTP/3\n")
			fmt.Fprint(&b, "------\n")
			fmt.Fprintf(&b, kvNoColorFormat, "Supported", upper(redirect.Http3.HTTP3Supported))
			fmt.Fprintf(&b, kvNoColorFormat, "Alt-Svc", redirect.Http3.AltSvc)
			fmt.Fprint(&b, "\n")

			// Timings
			fmt.Fprint(&b, "Timinigs\n")
			fmt.Fprint(&b, "--------\n")
			fmt.Fprintf(&b, kvNoColorTimingsFormat, "DNS", redirect.TimingsMs.DnsLookup.Duration, upper(redirect.TimingsMs.DnsLookup.Status))
			fmt.Fprintf(&b, kvNoColorTimingsFormat, "TCP", redirect.TimingsMs.TcpConnect.Duration, upper(redirect.TimingsMs.TcpConnect.Status))
			fmt.Fprintf(&b, kvNoColorTimingsFormat, "TLS", redirect.TimingsMs.TlsHandshake.Duration, upper(redirect.TimingsMs.TlsHandshake.Status))
			fmt.Fprintf(&b, kvNoColorTimingsFormat, "PRE", redirect.TimingsMs.Pretransfer.Duration, upper(redirect.TimingsMs.Pretransfer.Status))
			fmt.Fprintf(&b, kvNoColorTimingsFormat, "TTFB", redirect.TimingsMs.Ttfb.Duration, upper(redirect.TimingsMs.Ttfb.Status))
			fmt.Fprintf(&b, "%-9s%8d ms\n", "Total", redirect.TimingsMs.Total.Duration)
			fmt.Fprint(&b, "\n")

			// Option: Redirect Arrow
			if i+1 < len(allRedirects) {
				fmt.Fprint(&b, "|\n")
				fmt.Fprint(&b, "|\n")
				fmt.Fprintf(&b, "| Redirect: %d\n", redirect.Http.StatusCode)
				fmt.Fprint(&b, "|\n")
				fmt.Fprint(&b, "v\n")
				fmt.Fprint(&b, "\n")
			}
		}
	}

	return b.String()
}

// printDefault outputs a summary of the diagnostic result
func printDefault(overall Overall, isColor bool) string {
	keyColor := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	valColor := color.New(color.FgGreen).SprintFunc()
	warnColor := color.New(color.FgYellow).SprintFunc()
	errColor := color.New(color.FgRed).SprintFunc()

	kvColorFormat1 := "%-29s%s %s\n"
	kvColorFormat2 := "%-29s%s\n"
	kvColorFormat3 := " %-28s%s\n"
	kvColorFormat4 := "  %-27s%s\n"
	kvColorFormat5 := " %-28s%s %s\n"
	kvColorFormat6 := " %s%-28s%s\n"
	kvColorFormat7 := " %-26s%16s %s\n"
	kvColorFormat8 := " %-26s%16s\n"

	kvNoColorFormat1 := "%-15s%s %s\n"
	kvNoColorFormat2 := "%-15s%s\n"
	kvNoColorFormat3 := " %-14s%s\n"
	kvNoColorFormat4 := "  %-13s%s\n"
	kvNoColorFormat5 := " %-14s%s %s\n"
	kvNoColorFormat6 := " %s%-14s%s\n"
	kvNoColorFormat7 := " %-8s%11s %s\n"
	kvNoColorFormat8 := " %-8s%11s\n"

	timingsDnsDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.DnsLookup.Duration)
	timingsDnsStatusStr := fmt.Sprintf("(%s)", upper(overall.TimingsMs.DnsLookup.Status))
	timingsTcpDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.TcpConnect.Duration)
	timingsTcpStatusStr := fmt.Sprintf("(%s)", upper(overall.TimingsMs.TcpConnect.Status))
	timingsTlsDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.TlsHandshake.Duration)
	timingsTlsStatusStr := fmt.Sprintf("(%s)", upper(overall.TimingsMs.TlsHandshake.Status))
	timingsTtfbDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.Ttfb.Duration)
	timingsTtfbStatusStr := fmt.Sprintf("(%s)", upper(overall.TimingsMs.Ttfb.Status))
	timingsTotalDurationStr := fmt.Sprintf("%d ms", overall.TimingsMs.Total.Duration)

	ipStr := fmt.Sprintf("(%s)", overall.Site.IP)
	portStr := fmt.Sprintf("(%s port)", overall.TCP.Port)
	daysStr := fmt.Sprintf("(%d days)", overall.Certificate.DaysRemaining)

	var b strings.Builder

	switch isColor {
	case true:
		// Site
		fmt.Fprintf(&b, kvColorFormat2, keyColor("URL"), valColor(overall.Site.URL))

		// DNS
		switch overall.DNS.Status {
		case "ok":
			fmt.Fprintf(&b, kvColorFormat1, keyColor("DNS"), valColor(upper(overall.DNS.Status)), valColor(ipStr))
		case "error":
			fmt.Fprintf(&b, kvColorFormat2, keyColor("DNS"), errColor(upper(overall.DNS.Status)))
			fmt.Fprintf(&b, kvColorFormat3, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorDns))
		default:
			fmt.Fprintf(&b, kvColorFormat2, keyColor("IP"), valColor(overall.Site.IP))
		}

		// TCP
		switch overall.TCP.Status {
		case "ok":
			fmt.Fprintf(&b, kvColorFormat1, keyColor("TCP"), valColor(upper(overall.TCP.Status)), valColor(portStr))
		case "error":
			fmt.Fprintf(&b, kvColorFormat1, keyColor("TCP"), errColor(upper(overall.TCP.Status)), errColor(portStr))
			fmt.Fprintf(&b, kvColorFormat3, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorConn))
		}

		// TLS
		switch overall.TLS.Status {
		case "ok":
			fmt.Fprintf(&b, kvColorFormat2, keyColor("TLS"), valColor(upper(overall.TLS.Status)))
			fmt.Fprintf(&b, kvColorFormat3, keyColor("Version"), valColor(overall.TLS.Version))
			fmt.Fprintf(&b, kvColorFormat3, keyColor("Cipher"), valColor(overall.TLS.Cipher))
		case "error":
			fmt.Fprintf(&b, kvColorFormat2, keyColor("TLS"), errColor(upper(overall.TLS.Status)))
			fmt.Fprintf(&b, kvColorFormat3, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorTls))
		}

		// Certificate
		switch overall.Certificate.Status {
		case "ok":
			fmt.Fprintf(&b, kvColorFormat5, keyColor("Certificate"), valColor(upper(overall.Certificate.Status)), valColor(daysStr))
		case "error":
			fmt.Fprintf(&b, kvColorFormat3, keyColor("Certificate"), errColor(upper(overall.Certificate.Status)))
			fmt.Fprintf(&b, kvColorFormat4, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorCert))
		}

		// HTTP
		switch overall.Http.Status {
		case "ok":
			fmt.Fprintf(&b, kvColorFormat2, keyColor("HTTP"), valColor(upper(overall.Http.Status)))
			fmt.Fprintf(&b, kvColorFormat3, keyColor("Version"), valColor(upper(overall.Http.Version)))
			fmt.Fprintf(&b, kvColorFormat3, keyColor("Status"), valColor(overall.Http.StatusCode))
			if len(overall.RedirectUrls) > 0 {
				for num, redirectUrl := range overall.RedirectUrls {
					if len(overall.RedirectUrls) == 1 {
						fmt.Fprintf(&b, kvColorFormat3, keyColor("Redirect"), valColor(redirectUrl))
					} else {
						fmt.Fprintf(&b, kvColorFormat6, keyColor("Redirect#"), keyColor(num+1), valColor(redirectUrl))
					}
				}
			} else {
				fmt.Fprintf(&b, kvColorFormat3, keyColor("Redirect"), valColor("None"))
			}
		case "error":
			fmt.Fprintf(&b, kvColorFormat2, keyColor("HTTP"), errColor(upper(overall.Http.Status)))
			fmt.Fprintf(&b, kvColorFormat3, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorHttp))
		}

		// Timings
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprint(&b, keyColor("Timings\n"))
		}

		// Timings DNS
		if overall.DNS.Status == "ok" {
			switch overall.TimingsMs.DnsLookup.Status {
			case "good":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(timingsDnsStatusStr))
			case "ok":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(timingsDnsStatusStr))
			case "warn":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("DNS"), warnColor(timingsDnsDurationStr), warnColor(timingsDnsStatusStr))
			case "bad":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("DNS"), errColor(timingsDnsDurationStr), errColor(timingsDnsStatusStr))
			default:
				fmt.Fprintf(&b, kvColorFormat7, keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(timingsDnsStatusStr))
			}
		}

		// Timings TCP
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			switch overall.TimingsMs.TcpConnect.Status {
			case "good":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(timingsTcpStatusStr))
			case "ok":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(timingsTcpStatusStr))
			case "warn":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TCP"), warnColor(timingsTcpDurationStr), warnColor(timingsTcpStatusStr))
			case "bad":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TCP"), errColor(timingsTcpDurationStr), errColor(timingsTcpStatusStr))
			default:
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(timingsTcpStatusStr))
			}
		}

		// Timings TLS or TTFB
		if overall.TCP.Status == "ok" {
			switch overall.TimingsMs.TlsHandshake.Status {
			case "good":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(timingsTlsStatusStr))
			case "ok":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(timingsTlsStatusStr))
			case "warn":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TLS"), warnColor(timingsTlsDurationStr), warnColor(timingsTlsStatusStr))
			case "bad":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TLS"), errColor(timingsTlsDurationStr), errColor(timingsTlsStatusStr))
			default:
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(timingsTlsStatusStr))
			}

			switch overall.TimingsMs.Ttfb.Status {
			case "good":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(timingsTtfbStatusStr))
			case "ok":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(timingsTtfbStatusStr))
			case "warn":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TTFB"), warnColor(timingsTtfbDurationStr), warnColor(timingsTtfbStatusStr))
			case "bad":
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TTFB"), errColor(timingsTtfbDurationStr), errColor(timingsTtfbStatusStr))
			default:
				fmt.Fprintf(&b, kvColorFormat7, keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(timingsTtfbStatusStr))
			}
		}

		// Timings Total
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprintf(&b, kvColorFormat8, keyColor("Total"), valColor(timingsTotalDurationStr))
		}

		fmt.Fprintf(&b, "\n")

		return b.String()

	default:
		// Site
		fmt.Fprintf(&b, kvNoColorFormat2, "URL", overall.Site.URL)

		// DNS
		switch overall.DNS.Status {
		case "ok":
			fmt.Fprintf(&b, kvNoColorFormat1, "DNS", upper(overall.DNS.Status), ipStr)
		case "error":
			fmt.Fprintf(&b, kvNoColorFormat2, "DNS", upper(overall.DNS.Status))
			fmt.Fprintf(&b, kvNoColorFormat3, "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorDns)
		default:
			fmt.Fprintf(&b, kvNoColorFormat2, "IP", overall.Site.IP)
		}

		// TCP
		switch overall.TCP.Status {
		case "ok":
			fmt.Fprintf(&b, kvNoColorFormat1, "TCP", upper(overall.TCP.Status), portStr)
		case "error":
			fmt.Fprintf(&b, kvNoColorFormat1, "TCP", upper(overall.TCP.Status), portStr)
			fmt.Fprintf(&b, kvNoColorFormat3, "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorConn)
		}

		// TLS
		switch overall.TLS.Status {
		case "ok":
			fmt.Fprintf(&b, kvNoColorFormat2, "TLS", upper(overall.TLS.Status))
			fmt.Fprintf(&b, kvNoColorFormat3, "Version", overall.TLS.Version)
			fmt.Fprintf(&b, kvNoColorFormat3, "Cipher", overall.TLS.Cipher)
		case "error":
			fmt.Fprintf(&b, kvNoColorFormat2, "TLS", upper(overall.TLS.Status))
			fmt.Fprintf(&b, kvNoColorFormat3, "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorTls)
		}

		// Certificate
		switch overall.Certificate.Status {
		case "ok":
			fmt.Fprintf(&b, kvNoColorFormat5, "Certificate", upper(overall.Certificate.Status), daysStr)
		case "error":
			fmt.Fprintf(&b, kvNoColorFormat3, "Certificate", upper(overall.Certificate.Status))
			fmt.Fprintf(&b, kvNoColorFormat4, "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorCert)
		}

		// HTTP
		switch overall.Http.Status {
		case "ok":
			fmt.Fprintf(&b, kvNoColorFormat2, "HTTP", upper(overall.Http.Status))
			fmt.Fprintf(&b, kvNoColorFormat3, "Version", upper(overall.Http.Version))
			fmt.Fprintf(&b, kvNoColorFormat3, "Status", str(overall.Http.StatusCode))
			if len(overall.RedirectUrls) > 0 {
				for num, redirectUrl := range overall.RedirectUrls {
					if len(overall.RedirectUrls) == 1 {
						fmt.Fprintf(&b, kvNoColorFormat3, "Redirect", redirectUrl)
					} else {
						fmt.Fprintf(&b, kvNoColorFormat6, "Redirect#", num+1, redirectUrl)
					}
				}
			} else {
				fmt.Fprintf(&b, kvNoColorFormat3, "Redirect", "None")
			}
		case "error":
			fmt.Fprintf(&b, kvNoColorFormat2, "HTTP", upper(overall.Http.Status))
			fmt.Fprintf(&b, kvNoColorFormat3, "Reason", overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorHttp)
		}

		// Timings
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprintf(&b, "Timings\n")
		}

		// Timings DNS
		if overall.DNS.Status == "ok" {
			fmt.Fprintf(&b, kvNoColorFormat7, "DNS", timingsDnsDurationStr, timingsDnsStatusStr)
		}

		// Timings TCP
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprintf(&b, kvNoColorFormat7, "TCP", timingsTcpDurationStr, timingsTcpStatusStr)
		}

		// Timings TLS or TTFB
		if overall.TCP.Status == "ok" {
			fmt.Fprintf(&b, kvNoColorFormat7, "TLS", timingsTlsDurationStr, timingsTlsStatusStr)
			fmt.Fprintf(&b, kvNoColorFormat7, "TTFB", timingsTtfbDurationStr, timingsTtfbStatusStr)
		}

		// Timings Total
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprintf(&b, kvNoColorFormat8, "Total", timingsTotalDurationStr)
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
	noColorFlag := flag.Bool("no-color", false, "Enable no color output")
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		fmt.Println("Usage: webdiag <url>")
		return
	}

	initialURL := args[0]

	var output io.Writer = os.Stdout
	isTerminal := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	isColor := isTerminal && !*noColorFlag

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
	if isColor {
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
		result = printVerbose(diagnosticResult.Redirects, isColor)
	} else {
		result = printDefault(diagnosticResult.Overall, isColor)
	}

	fmt.Fprint(output, result)
}
