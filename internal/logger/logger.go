package logger

import (
	"io"
	"log"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Entry
	name string
}

func New() *Logger {
	return &Logger{
		Entry: logrus.NewEntry(logrus.New()),
	}
}

func Of(l *logrus.Logger) *Logger {
	return &Logger{
		Entry: logrus.NewEntry(l),
	}
}

func (l Logger) Log(level hclog.Level, msg string, args ...interface{}) {
	l.withArgs(args).Logf(getLevel(level), msg)
}

func (l Logger) Trace(msg string, args ...interface{}) {
	l.withArgs(args).Entry.Trace(msg)
}

func (l Logger) Debug(msg string, args ...interface{}) {
	l.withArgs(args).Entry.Debug(msg)
}

func (l Logger) Info(msg string, args ...interface{}) {
	l.withArgs(args).Entry.Info(msg)
}

func (l Logger) Warn(msg string, args ...interface{}) {
	l.withArgs(args).Entry.Warn(msg)
}

func (l Logger) Error(msg string, args ...interface{}) {
	l.withArgs(args).Entry.Error(msg)
}

func (l Logger) IsTrace() bool {
	return l.Logger.IsLevelEnabled(logrus.TraceLevel)
}

func (l Logger) IsDebug() bool {
	return l.Logger.IsLevelEnabled(logrus.DebugLevel)
}

func (l Logger) IsInfo() bool {
	return l.Logger.IsLevelEnabled(logrus.InfoLevel)
}

func (l Logger) IsWarn() bool {
	return l.Logger.IsLevelEnabled(logrus.WarnLevel)
}

func (l Logger) IsError() bool {
	return l.Logger.IsLevelEnabled(logrus.ErrorLevel)
}

func (l Logger) ImpliedArgs() []interface{} {
	return nil
}

func (l Logger) With(args ...interface{}) hclog.Logger {
	return l.withArgs(args)
}

func (l Logger) Name() string {
	return l.name
}

func (l Logger) Named(name string) hclog.Logger {
	res := l.withArgs("name", name)
	if res.name != "" {
		res.name = res.name + "." + name
	} else {
		res.name = name
	}

	return res
}

func (l *Logger) ResetNamed(name string) hclog.Logger {
	res := l.withArgs("name", name)

	res.name = name

	return res
}

func (l *Logger) SetLevel(level hclog.Level) {
	l.Logger.SetLevel(getLevel(level))
}

func (l Logger) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	if opts == nil {
		opts = &hclog.StandardLoggerOptions{}
	}

	return log.New(l.StandardWriter(opts), "", 0)
}

func (l Logger) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return l.Logger.Out
}

func (l Logger) withArgs(args ...interface{}) *Logger {
	if args == nil || len(args) == 1 || len(args)%2 != 0 {
		return &Logger{l.Entry, l.name}
	}
	f := make(logrus.Fields)
	for i := 1; i < len(args); i += 2 {
		if s, ok := args[i-1].(string); ok {
			f[s] = args[i]
		}
	}
	return &Logger{l.WithFields(f), l.name}
}

func getLevel(level hclog.Level) logrus.Level {
	switch level {
	case hclog.Trace:
		return logrus.TraceLevel
	case hclog.Debug:
		return logrus.DebugLevel
	case hclog.Warn:
		return logrus.WarnLevel
	case hclog.Error:
		return logrus.ErrorLevel
	default:
		return logrus.InfoLevel
	}
}
