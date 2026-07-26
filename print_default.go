package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// printDefault outputs a summary of the diagnostic result
func printDefault(overall Overall, isColor bool) string {
	// Color Settings
	var keyColor, valColor, warnColor, errColor func(a ...any) string
	if isColor {
		keyColor = color.New(color.FgBlue, color.Bold).SprintFunc()
		valColor = color.New(color.FgGreen).SprintFunc()
		warnColor = color.New(color.FgYellow).SprintFunc()
		errColor = color.New(color.FgRed).SprintFunc()
	} else {
		noColor := func(a ...any) string { return fmt.Sprint(a...) }
		keyColor, valColor, warnColor, errColor = noColor, noColor, noColor, noColor
	}

	// Selct Format Chracter
	var kvFormat1, kvFormat2, kvFormat3, kvFormat4, kvFormat5, kvFormat6, kvFormat7 string
	if isColor {
		kvFormat1 = "%-29s%s %s\n"
		kvFormat2 = "%-29s%s\n"
		kvFormat3 = " %-28s%s\n"
		kvFormat4 = "  %-27s%s\n"
		kvFormat5 = " %-28s%s %s\n"
		kvFormat6 = " %-26s%16s %s\n"
		kvFormat7 = " %-26s%16s\n"
	} else {
		kvFormat1 = "%-15s%s %s\n"
		kvFormat2 = "%-15s%s\n"
		kvFormat3 = " %-14s%s\n"
		kvFormat4 = "  %-13s%s\n"
		kvFormat5 = " %-14s%s %s\n"
		kvFormat6 = " %-8s%11s %s\n"
		kvFormat7 = " %-8s%11s\n"
	}

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
	cnameResult := traceDomain(overall.Site.Hostname)
	cnameChain := strings.Join(cnameResult, " => ")
	cnameStr := fmt.Sprintf("(%s)", cnameChain)
	portStr := fmt.Sprintf("(%s port)", overall.TCP.Port)
	daysStr := fmt.Sprintf("(%d days)", overall.Certificate.DaysRemaining)

	var b strings.Builder

	// Site
	fmt.Fprintf(&b, kvFormat2, keyColor("URL"), valColor(overall.Site.URL))

	// DNS
	switch overall.DNS.Status {
	case "ok":
		if len(cnameResult) == 0 {
			fmt.Fprintf(&b, kvFormat1, keyColor("DNS"), valColor(upper(overall.DNS.Status)), valColor(ipStr))
		} else {
			fmt.Fprintf(&b, kvFormat1, keyColor("DNS"), valColor(upper(overall.DNS.Status)), valColor(cnameStr))
		}
	case "error":
		fmt.Fprintf(&b, kvFormat2, keyColor("DNS"), errColor(upper(overall.DNS.Status)))
		fmt.Fprintf(&b, kvFormat3, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorDns))
	default:
		fmt.Fprintf(&b, kvFormat2, keyColor("IP"), valColor(overall.Site.IP))
	}

	// TCP
	switch overall.TCP.Status {
	case "ok":
		fmt.Fprintf(&b, kvFormat1, keyColor("TCP"), valColor(upper(overall.TCP.Status)), valColor(portStr))
	case "error":
		fmt.Fprintf(&b, kvFormat1, keyColor("TCP"), errColor(upper(overall.TCP.Status)), errColor(portStr))
		fmt.Fprintf(&b, kvFormat3, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorConn))
	}

	// TLS
	switch overall.TLS.Status {
	case "ok":
		fmt.Fprintf(&b, kvFormat2, keyColor("TLS"), valColor(upper(overall.TLS.Status)))
		fmt.Fprintf(&b, kvFormat3, keyColor("Version"), valColor(overall.TLS.Version))
		fmt.Fprintf(&b, kvFormat3, keyColor("Cipher"), valColor(overall.TLS.Cipher))
	case "error":
		fmt.Fprintf(&b, kvFormat2, keyColor("TLS"), errColor(upper(overall.TLS.Status)))
		fmt.Fprintf(&b, kvFormat3, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorTls))
	}

	// Certificate
	switch overall.Certificate.Status {
	case "ok":
		fmt.Fprintf(&b, kvFormat5, keyColor("Certificate"), valColor(upper(overall.Certificate.Status)), valColor(daysStr))
	case "error":
		fmt.Fprintf(&b, kvFormat3, keyColor("Certificate"), errColor(upper(overall.Certificate.Status)))
		fmt.Fprintf(&b, kvFormat4, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorCert))
	}

	// HTTP
	switch overall.Http.Status {
	case "ok":
		var statusCodeStr string
		if isColor {
			statusCodeStr = fmt.Sprintf("%d", overall.Http.StatusCode)
		} else {
			statusCodeStr = str(overall.Http.StatusCode)
		}
		fmt.Fprintf(&b, kvFormat2, keyColor("HTTP"), valColor(upper(overall.Http.Status)))
		fmt.Fprintf(&b, kvFormat3, keyColor("Version"), valColor(upper(overall.Http.Version)))
		fmt.Fprintf(&b, kvFormat3, keyColor("Status"), valColor(statusCodeStr))
		if len(overall.Redirects.RedirectsInfo) > 1 {
			for num, redirect := range overall.Redirects.RedirectsInfo {
				if redirect.RedirectTo != "" {
					redirectHop := fmt.Sprintf("%d ->", redirect.StatusCode)
					fmt.Fprintf(&b, kvFormat5, keyColor(fmt.Sprintf("Redirect#%d", num+1)), valColor(redirectHop), valColor(redirect.RedirectTo))
					continue
				}

				finalHop := fmt.Sprintf("%d ->", redirect.StatusCode)
				fmt.Fprintf(&b, kvFormat5, keyColor("Final"), valColor(finalHop), valColor(redirect.URL))
			}
		} else {
			fmt.Fprintf(&b, kvFormat3, keyColor("Redirect"), valColor("None"))
		}
	case "error":
		fmt.Fprintf(&b, kvFormat2, keyColor("HTTP"), errColor(upper(overall.Http.Status)))
		fmt.Fprintf(&b, kvFormat3, keyColor("Reason"), errColor(overall.Message.PerRedirect[len(overall.Message.PerRedirect)-1].OverallErrors.Error.ErrorHttp))
	}

	// Timings
	if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
		fmt.Fprint(&b, keyColor("Timings\n"))
	}

	// Timings DNS
	if overall.DNS.Status == "ok" {
		var dnsColorFunc func(a ...any) string
		if isColor {
			switch overall.TimingsMs.DnsLookup.Status {
			case "warn":
				dnsColorFunc = warnColor
			case "bad":
				dnsColorFunc = errColor
			default:
				dnsColorFunc = valColor
			}
		} else {
			dnsColorFunc = valColor
		}
		fmt.Fprintf(&b, kvFormat6, keyColor("DNS"), dnsColorFunc(timingsDnsDurationStr), dnsColorFunc(timingsDnsStatusStr))
	}

	// Timings TCP
	if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
		var tcpColorFunc func(a ...any) string
		if isColor {
			switch overall.TimingsMs.TcpConnect.Status {
			case "warn":
				tcpColorFunc = warnColor
			case "bad":
				tcpColorFunc = errColor
			default:
				tcpColorFunc = valColor
			}
		} else {
			tcpColorFunc = valColor
		}
		fmt.Fprintf(&b, kvFormat6, keyColor("TCP"), tcpColorFunc(timingsTcpDurationStr), tcpColorFunc(timingsTcpStatusStr))
	}

	// Timings TLS or TTFB
	if overall.TCP.Status == "ok" {
		var tlsColorFunc func(a ...any) string
		if isColor {
			switch overall.TimingsMs.TlsHandshake.Status {
			case "warn":
				tlsColorFunc = warnColor
			case "bad":
				tlsColorFunc = errColor
			default:
				tlsColorFunc = valColor
			}
		} else {
			tlsColorFunc = valColor
		}
		fmt.Fprintf(&b, kvFormat6, keyColor("TLS"), tlsColorFunc(timingsTlsDurationStr), tlsColorFunc(timingsTlsStatusStr))

		var ttfbColorFunc func(a ...any) string
		if isColor {
			switch overall.TimingsMs.Ttfb.Status {
			case "warn":
				ttfbColorFunc = warnColor
			case "bad":
				ttfbColorFunc = errColor
			default:
				ttfbColorFunc = valColor
			}
		} else {
			ttfbColorFunc = valColor
		}
		fmt.Fprintf(&b, kvFormat6, keyColor("TTFB"), ttfbColorFunc(timingsTtfbDurationStr), ttfbColorFunc(timingsTtfbStatusStr))
	}

	// Timings Total
	if overall.DNS.Status == "ok" || overall.DNS.Status == "unused" {
		fmt.Fprintf(&b, kvFormat7, keyColor("Total"), valColor(timingsTotalDurationStr))
	}

	fmt.Fprintf(&b, "\n")

	return b.String()
}
