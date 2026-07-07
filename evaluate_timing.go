package main

func evaluateTiming(diagType string, diagDuration int) string {
	switch diagType {
	case "dns":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 20:
			return "good"
		case diagDuration > 20 && diagDuration <= 50:
			return "ok"
		case diagDuration > 50 && diagDuration <= 100:
			return "warn"
		case diagDuration > 100:
			return "bad"
		}
	case "tcp":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 10:
			return "good"
		case diagDuration > 10 && diagDuration <= 50:
			return "ok"
		case diagDuration > 50 && diagDuration <= 100:
			return "warn"
		case diagDuration > 100:
			return "bad"
		}
	case "tls":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 50:
			return "good"
		case diagDuration > 50 && diagDuration <= 100:
			return "ok"
		case diagDuration > 100 && diagDuration <= 200:
			return "warn"
		case diagDuration > 200:
			return "bad"
		}
	case "pre":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 2:
			return "good"
		case diagDuration > 2 && diagDuration <= 4:
			return "ok"
		case diagDuration > 4 && diagDuration <= 10:
			return "warn"
		case diagDuration > 10:
			return "bad"
		}
	case "ttfb":
		switch {
		case diagDuration == 0:
			return "-"
		case diagDuration > 0 && diagDuration <= 200:
			return "good"
		case diagDuration > 200 && diagDuration <= 500:
			return "ok"
		case diagDuration > 500 && diagDuration <= 800:
			return "warn"
		case diagDuration > 800:
			return "bad"
		}
	case "total":
		return "-"
	}
	return "error"
}
