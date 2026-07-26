package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

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
	var certStartStr string
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
				certStartStr = leafCert.NotBefore.Format(time.RFC3339)
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

		if resp.StatusCode >= 400 && resp.StatusCode < 600 {
			errHttpMsg = http.StatusText(resp.StatusCode)
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
			Status:     dnsStatus,
			Resolution: traceDomain(hostname),
			ErrorDns:   errDnsMsg,
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
			StartDate:     certStartStr,
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
