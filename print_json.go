package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
)

// printJSON outputs the diagnostic result in JSON format
func printJSON(diagnosticResult DiagnosticResult, isColor bool) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")

	if err := enc.Encode(diagnosticResult); err != nil {
		return fmt.Sprintf(`{"ERROR_MESSAGE": "%s"}`+"\n", err.Error())
	}

	if !isColor {
		return fmt.Sprint(buf.String())
	} else {
		cleanedBytes := bytes.TrimSpace(buf.Bytes())

		blue := color.New(color.FgBlue).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()

		var result bytes.Buffer
		inQuote := false
		isKey := true
		arrayDepth := 0

		objectDepth := 0
		var currentToken bytes.Buffer

		for i := 0; i < len(cleanedBytes); i++ {
			char := cleanedBytes[i]

			if inQuote {
				currentToken.WriteByte(char)
				if char == '"' && (i == 0 || cleanedBytes[i-1] != '\\') {
					inQuote = false
					strStr := currentToken.String()
					currentToken.Reset()

					if arrayDepth > 0 && objectDepth == 0 {
						result.WriteString(green(strStr))
					} else if isKey {
						result.WriteString(blue(strStr))
					} else {
						result.WriteString(green(strStr))
					}
				}
				continue
			}

			switch char {
			case '"':
				inQuote = true
				currentToken.WriteByte(char)

			case ':':
				isKey = false
				result.WriteByte(char)

			case '{':
				objectDepth++
				isKey = true
				if currentToken.Len() > 0 {
					result.WriteString(currentToken.String())
					currentToken.Reset()
				}
				result.WriteByte(char)

			case '}':
				objectDepth--
				if arrayDepth > 0 {
					isKey = false
				} else {
					isKey = true
				}
				if currentToken.Len() > 0 {
					result.WriteString(currentToken.String())
					currentToken.Reset()
				}
				result.WriteByte(char)

			case '[':
				arrayDepth++
				isKey = false
				if currentToken.Len() > 0 {
					result.WriteString(currentToken.String())
					currentToken.Reset()
				}
				result.WriteByte(char)

			case ']':
				arrayDepth--
				if arrayDepth > 0 {
					isKey = false
				} else {
					isKey = true
				}
				if currentToken.Len() > 0 {
					result.WriteString(currentToken.String())
					currentToken.Reset()
				}
				result.WriteByte(char)

			case ',', '\n':
				if currentToken.Len() > 0 {
					result.WriteString(currentToken.String())
					currentToken.Reset()
				}

				if objectDepth > 0 {
					isKey = true
				} else if arrayDepth > 0 {
					isKey = false
				} else {
					isKey = true
				}
				result.WriteByte(char)

			case ' ', '\t', '\r':
				if currentToken.Len() > 0 {
					currentToken.WriteByte(char)
				} else {
					result.WriteByte(char)
				}

			default:
				currentToken.WriteByte(char)
			}
		}

		if currentToken.Len() > 0 {
			result.WriteString(currentToken.String())
		}

		return fmt.Sprintf("%s\n", result.String())
	}
}
