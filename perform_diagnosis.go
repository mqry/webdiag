package main

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

	// Collect Aggregate Info & Message
	var redirectInfo []RedirectInfo
	var redirectMessages []RedirectMessage
	for _, redirect := range allRedirects {
		redirectInfo = append(redirectInfo, RedirectInfo{
			URL:        redirect.Site.URL,
			RedirectTo: redirect.Http.RedirectUrl,
			StatusCode: redirect.Http.StatusCode,
			TotalTime: ResponseTime{
				redirect.TimingsMs.Total.Duration,
				redirect.TimingsMs.Total.Status,
			},
		})
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
		Http:        lastResult.Http,
		Redirects: OverallInfo{
			RedirectsInfo: redirectInfo,
		},
		Http3: lastResult.Http3,
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
	}

	return DiagnosticResult{
		Overall:   overall,
		Redirects: allRedirects,
	}
}
