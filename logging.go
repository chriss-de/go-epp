package epp

import (
	"fmt"
	"os"
)

type Logger interface {
	Error(msg string, args ...any)
	Info(msg string, args ...any)
}

type DefaultLogger struct{}

func (l *DefaultLogger) parseLog(v ...any) string {
	message := ""
	paramLogs := ""
	for i := 0; i < len(v); i = i + 2 {
		if len(v) > i+1 {
			paramLogs += fmt.Sprintf("%v=%v ", v[i], v[i+1])
		} else {
			message = fmt.Sprintf("%v", v[i])
		}
	}

	return fmt.Sprint(message, "  [", paramLogs, "]\n")
}

func (l *DefaultLogger) Error(msg string, args ...any) {
	_, _ = fmt.Fprint(os.Stderr, "ERR: "+msg, l.parseLog(args...))
}

func (l *DefaultLogger) Info(msg string, args ...any) {
	_, _ = fmt.Fprint(os.Stdout, "INF: "+msg, l.parseLog(args...))
}
