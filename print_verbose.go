package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// printVerbose outputs detailed diagnostic information for each redirect
func printVerbose(allRedirects []Response, isColor bool) string {
	// Color functions
	var titleColor, keyColor, valColor, warnColor, errColor func(a ...any) string
	if isColor {
		titleColor = color.New(color.FgMagenta, color.Bold).SprintFunc()
		keyColor = color.New(color.FgBlue, color.Bold).SprintFunc()
		valColor = color.New(color.FgGreen).SprintFunc()
		warnColor = color.New(color.FgYellow).SprintFunc()
		errColor = color.New(color.FgRed).SprintFunc()
	} else {
		noColor := func(a ...any) string { return fmt.Sprint(a...) }
		titleColor, keyColor, valColor, warnColor, errColor = noColor, noColor, noColor, noColor, noColor
	}

	// Format strings
	var kvFormat, kvTimingsFormat string
	if isColor {
		kvFormat = "%-27s%s\n"
		kvTimingsFormat = "%-25s%16s %s\n"
	} else {
		kvFormat = "%-15s%s\n"
		kvTimingsFormat = "%-9s%8d ms  (%s)\n"
	}

	var b strings.Builder

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
		var dnsStatusColorFunc func(a ...any) string
		if redirect.DNS.Status == "error" {
			dnsStatusColorFunc = errColor
		} else {
			dnsStatusColorFunc = valColor
		}
		fmt.Fprintf(&b, kvFormat, keyColor("Status"), dnsStatusColorFunc(upper(redirect.DNS.Status)))
		fmt.Fprintf(&b, kvFormat, keyColor("Hostname"), valColor(redirect.Site.Hostname))
		fmt.Fprintf(&b, kvFormat, keyColor("IP"), valColor(redirect.Site.IP))
		fmt.Fprintf(&b, kvFormat, keyColor("ERROR"), errColor(redirect.DNS.ErrorDns))
		fmt.Fprint(&b, "\n")

		// TCP
		fmt.Fprint(&b, titleColor("TCP\n"))
		fmt.Fprint(&b, titleColor("---\n"))
		var tcpStatusColorFunc func(a ...any) string
		if redirect.TCP.Status == "error" {
			tcpStatusColorFunc = errColor
		} else {
			tcpStatusColorFunc = valColor
		}
		fmt.Fprintf(&b, kvFormat, keyColor("Status"), tcpStatusColorFunc(upper(redirect.TCP.Status)))
		fmt.Fprintf(&b, kvFormat, keyColor("Port"), valColor(redirect.TCP.Port))
		fmt.Fprintf(&b, kvFormat, keyColor("ERROR"), errColor(redirect.TCP.ErrorConn))
		fmt.Fprint(&b, "\n")

		// TLS
		fmt.Fprint(&b, titleColor("TLS\n"))
		fmt.Fprint(&b, titleColor("---\n"))
		var tlsStatusColorFunc func(a ...any) string
		if redirect.TLS.Status == "error" {
			tlsStatusColorFunc = errColor
		} else {
			tlsStatusColorFunc = valColor
		}
		fmt.Fprintf(&b, kvFormat, keyColor("Status"), tlsStatusColorFunc(upper(redirect.TLS.Status)))
		fmt.Fprintf(&b, kvFormat, keyColor("Version"), valColor(redirect.TLS.Version))
		fmt.Fprintf(&b, kvFormat, keyColor("ALPN"), valColor(redirect.TLS.ALPN))
		fmt.Fprintf(&b, kvFormat, keyColor("Cipher"), valColor(redirect.TLS.Cipher))
		if redirect.TLS.Status == "ok" {
			fmt.Fprintf(&b, kvFormat, keyColor("SNI"), valColor(redirect.TLS.SNI))
		}
		fmt.Fprintf(&b, kvFormat, keyColor("ERROR"), errColor(redirect.TLS.ErrorTls))
		for num, warning := range redirect.TLS.TlsWarnings {
			if isColor {
				fmt.Fprintf(&b, "%s%-15s %s\n", keyColor("Warning#"), keyColor(num+1), warnColor(warning))
			} else {
				fmt.Fprintf(&b, "%s#%-6d %s\n", "Warning", num+1, warning)
			}
		}
		fmt.Fprint(&b, "\n")

		// Certificate
		fmt.Fprint(&b, titleColor("Certificate\n"))
		fmt.Fprint(&b, titleColor("-----------\n"))
		var certStatusColorFunc func(a ...any) string
		if redirect.Certificate.Status == "error" {
			certStatusColorFunc = errColor
		} else {
			certStatusColorFunc = valColor
		}
		fmt.Fprintf(&b, kvFormat, keyColor("Status"), certStatusColorFunc(upper(redirect.Certificate.Status)))
		fmt.Fprintf(&b, kvFormat, keyColor("Subject"), valColor(redirect.Certificate.Subject))
		fmt.Fprintf(&b, kvFormat, keyColor("Issuer"), valColor(redirect.Certificate.Issuer))
		for num, certificate := range redirect.Certificate.Chains {
			if isColor {
				fmt.Fprintf(&b, "%s%-20s %s\n", keyColor("Chain#"), keyColor(num+1), valColor(certificate))
			} else {
				fmt.Fprintf(&b, "%s#%-8d %s\n", "Chain", num+1, certificate)
			}
		}
		fmt.Fprintf(&b, kvFormat, keyColor("Expires"), valColor(redirect.Certificate.ExpiryDate))
		if redirect.TLS.Status == "ok" {
			if isColor {
				fmt.Fprintf(&b, kvFormat, keyColor("Days Left"), valColor(redirect.Certificate.DaysRemaining))
			} else {
				fmt.Fprintf(&b, "%-15s%d\n", "Days Left", redirect.Certificate.DaysRemaining)
			}
		}
		fmt.Fprintf(&b, kvFormat, keyColor("ERROR"), errColor(redirect.Certificate.ErrorCert))
		fmt.Fprint(&b, "\n")

		// HTTP
		fmt.Fprint(&b, titleColor("HTTP\n"))
		fmt.Fprint(&b, titleColor("----\n"))
		var httpStatusColorFunc func(a ...any) string
		if redirect.Http.Status == "error" {
			httpStatusColorFunc = errColor
		} else {
			httpStatusColorFunc = valColor
		}
		fmt.Fprintf(&b, kvFormat, keyColor("Status"), httpStatusColorFunc(upper(redirect.Http.Status)))
		fmt.Fprintf(&b, kvFormat, keyColor("Version"), valColor(redirect.Http.Version))
		if redirect.Http.StatusCode != 0 {
			if isColor {
				fmt.Fprintf(&b, kvFormat, keyColor("Status"), valColor(redirect.Http.StatusCode))
			} else {
				fmt.Fprintf(&b, "%-15s%d\n", "Status", redirect.Http.StatusCode)
			}
		}
		fmt.Fprintf(&b, kvFormat, keyColor("Redirect"), valColor(redirect.Http.RedirectUrl))
		fmt.Fprintf(&b, kvFormat, keyColor("ERROR"), errColor(redirect.Http.ErrorHttp))
		fmt.Fprint(&b, "\n")

		// HTTP/3
		fmt.Fprint(&b, titleColor("HTTP/3\n"))
		fmt.Fprint(&b, titleColor("------\n"))
		fmt.Fprintf(&b, kvFormat, keyColor("Supported"), valColor(upper(redirect.Http3.HTTP3Supported)))
		fmt.Fprintf(&b, kvFormat, keyColor("Alt-Svc"), valColor(redirect.Http3.AltSvc))
		fmt.Fprint(&b, "\n")

		// Timings
		fmt.Fprint(&b, titleColor("Timinigs\n"))
		fmt.Fprint(&b, titleColor("--------\n"))

		// Helper to select color based on timing status
		getTimingColor := func(status string) func(a ...any) string {
			if !isColor {
				return valColor
			}
			switch status {
			case "warn":
				return warnColor
			case "bad":
				return errColor
			default:
				return valColor
			}
		}

		// Timing metrics
		timings := []struct {
			label    string
			duration int
			status   string
		}{
			{"DNS", redirect.TimingsMs.DnsLookup.Duration, redirect.TimingsMs.DnsLookup.Status},
			{"TCP", redirect.TimingsMs.TcpConnect.Duration, redirect.TimingsMs.TcpConnect.Status},
			{"TLS", redirect.TimingsMs.TlsHandshake.Duration, redirect.TimingsMs.TlsHandshake.Status},
			{"PRE", redirect.TimingsMs.Pretransfer.Duration, redirect.TimingsMs.Pretransfer.Status},
			{"TTFB", redirect.TimingsMs.Ttfb.Duration, redirect.TimingsMs.Ttfb.Status},
		}

		for _, t := range timings {
			colorFunc := getTimingColor(t.status)
			if isColor {
				durationStr := fmt.Sprintf("%d ms", t.duration)
				statusStr := fmt.Sprintf("(%s)", upper(t.status))
				fmt.Fprintf(&b, kvTimingsFormat, keyColor(t.label), colorFunc(durationStr), colorFunc(statusStr))
			} else {
				fmt.Fprintf(&b, kvTimingsFormat, t.label, t.duration, upper(t.status))
			}
		}

		// Total
		if isColor {
			totalDurationStr := fmt.Sprintf("%d ms", redirect.TimingsMs.Total.Duration)
			totalStatusStr := fmt.Sprintf("(%s)", redirect.TimingsMs.Total.Status)
			fmt.Fprintf(&b, kvTimingsFormat, keyColor("Total"), valColor(totalDurationStr), valColor(totalStatusStr))
		} else {
			fmt.Fprintf(&b, "%-9s%8d ms\n", "Total", redirect.TimingsMs.Total.Duration)
		}

		fmt.Fprint(&b, "\n")

		// Redirect arrow
		if i+1 < len(allRedirects) {
			fmt.Fprint(&b, "|\n")
			fmt.Fprint(&b, "|\n")
			fmt.Fprintf(&b, "| Redirect: %d\n", redirect.Http.StatusCode)
			fmt.Fprint(&b, "|\n")
			fmt.Fprint(&b, "v\n")
			fmt.Fprint(&b, "\n")
		}
	}

	return b.String()
}
