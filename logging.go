package epp

import (
	"fmt"
	"os"
)

type Logger interface {
	Error(v ...interface{})
	Warning(v ...interface{})
	Info(v ...interface{})
}

type DefaultLogger struct{}

func (l *DefaultLogger) parseLog(v ...interface{}) string {
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

func (l *DefaultLogger) Error(v ...interface{}) {
	_, _ = fmt.Fprint(os.Stderr, "ERR: ", l.parseLog(v...))
}

func (l *DefaultLogger) Warning(v ...interface{}) {
	_, _ = fmt.Fprint(os.Stdout, "WRN: ", l.parseLog(v...))
}

func (l *DefaultLogger) Info(v ...interface{}) {
	_, _ = fmt.Fprint(os.Stdout, "INF: ", l.parseLog(v...))
}
