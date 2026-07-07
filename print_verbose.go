package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

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
