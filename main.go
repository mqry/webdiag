package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
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

func upper(s string) string {
	return strings.ToUpper(s)
}

func str(i int) string {
	return strconv.Itoa(i)
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
		result = printJSON(diagnosticResult, isColor)
	} else if *verboseFlag {
		result = printVerbose(diagnosticResult.Redirects, isColor)
	} else {
		result = printDefault(diagnosticResult.Overall, isColor)
	}

	fmt.Fprint(output, result)
}
