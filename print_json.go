package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

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
