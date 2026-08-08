package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
)

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
