package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

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
	kvColorFormat6 := " %-26s%16s %s\n"
	kvColorFormat7 := " %-26s%16s\n"

	kvNoColorFormat1 := "%-15s%s %s\n"
	kvNoColorFormat2 := "%-15s%s\n"
	kvNoColorFormat3 := " %-14s%s\n"
	kvNoColorFormat4 := "  %-13s%s\n"
	kvNoColorFormat5 := " %-14s%s %s\n"
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
			if len(overall.Redirects.RedirectsInfo) > 0 {
				for num, redirect := range overall.Redirects.RedirectsInfo {
					if len(overall.Redirects.RedirectsInfo) == 1 {
						fmt.Fprintf(&b, kvColorFormat3, keyColor("Redirect"), valColor(redirect.URL))
					} else {
						fmt.Fprintf(&b, kvColorFormat3, keyColor(fmt.Sprintf("Redirect#%d", num+1)), valColor(redirect.URL))
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
				fmt.Fprintf(&b, kvColorFormat6, keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(timingsDnsStatusStr))
			case "ok":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(timingsDnsStatusStr))
			case "warn":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("DNS"), warnColor(timingsDnsDurationStr), warnColor(timingsDnsStatusStr))
			case "bad":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("DNS"), errColor(timingsDnsDurationStr), errColor(timingsDnsStatusStr))
			default:
				fmt.Fprintf(&b, kvColorFormat6, keyColor("DNS"), valColor(timingsDnsDurationStr), valColor(timingsDnsStatusStr))
			}
		}

		// Timings TCP
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			switch overall.TimingsMs.TcpConnect.Status {
			case "good":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(timingsTcpStatusStr))
			case "ok":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(timingsTcpStatusStr))
			case "warn":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TCP"), warnColor(timingsTcpDurationStr), warnColor(timingsTcpStatusStr))
			case "bad":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TCP"), errColor(timingsTcpDurationStr), errColor(timingsTcpStatusStr))
			default:
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TCP"), valColor(timingsTcpDurationStr), valColor(timingsTcpStatusStr))
			}
		}

		// Timings TLS or TTFB
		if overall.TCP.Status == "ok" {
			switch overall.TimingsMs.TlsHandshake.Status {
			case "good":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(timingsTlsStatusStr))
			case "ok":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(timingsTlsStatusStr))
			case "warn":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TLS"), warnColor(timingsTlsDurationStr), warnColor(timingsTlsStatusStr))
			case "bad":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TLS"), errColor(timingsTlsDurationStr), errColor(timingsTlsStatusStr))
			default:
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TLS"), valColor(timingsTlsDurationStr), valColor(timingsTlsStatusStr))
			}

			switch overall.TimingsMs.Ttfb.Status {
			case "good":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(timingsTtfbStatusStr))
			case "ok":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(timingsTtfbStatusStr))
			case "warn":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TTFB"), warnColor(timingsTtfbDurationStr), warnColor(timingsTtfbStatusStr))
			case "bad":
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TTFB"), errColor(timingsTtfbDurationStr), errColor(timingsTtfbStatusStr))
			default:
				fmt.Fprintf(&b, kvColorFormat6, keyColor("TTFB"), valColor(timingsTtfbDurationStr), valColor(timingsTtfbStatusStr))
			}
		}

		// Timings Total
		if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
			fmt.Fprintf(&b, kvColorFormat7, keyColor("Total"), valColor(timingsTotalDurationStr))
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
			if len(overall.Redirects.RedirectsInfo) > 0 {
				for num, redirect := range overall.Redirects.RedirectsInfo {
					if len(overall.Redirects.RedirectsInfo) == 1 {
						fmt.Fprintf(&b, kvNoColorFormat3, "Redirect", redirect.URL)
					} else {
						fmt.Fprintf(&b, kvNoColorFormat3, fmt.Sprintf("Redirect#%d", num+1), redirect.URL)
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
