package app

import (
	"context"

	"go.uber.org/zap"
)

// Logger adapts *zap.Logger to sing's logger.ContextLogger interface.
type Logger struct {
	*zap.Logger
}

func (l *Logger) Trace(args ...any)                             { l.Logger.Sugar().Debug(args...) }
func (l *Logger) Debug(args ...any)                             { l.Logger.Sugar().Debug(args...) }
func (l *Logger) Info(args ...any)                              { l.Logger.Sugar().Info(args...) }
func (l *Logger) Warn(args ...any)                              { l.Logger.Sugar().Warn(args...) }
func (l *Logger) Error(args ...any)                             { l.Logger.Sugar().Error(args...) }
func (l *Logger) Fatal(args ...any)                             { l.Logger.Sugar().Fatal(args...) }
func (l *Logger) Panic(args ...any)                             { l.Logger.Sugar().Panic(args...) }
func (l *Logger) TraceContext(ctx context.Context, args ...any) { l.Logger.Sugar().Debug(args...) }
func (l *Logger) DebugContext(ctx context.Context, args ...any) { l.Logger.Sugar().Debug(args...) }
func (l *Logger) InfoContext(ctx context.Context, args ...any)  { l.Logger.Sugar().Info(args...) }
func (l *Logger) WarnContext(ctx context.Context, args ...any)  { l.Logger.Sugar().Warn(args...) }
func (l *Logger) ErrorContext(ctx context.Context, args ...any) { l.Logger.Sugar().Error(args...) }
func (l *Logger) FatalContext(ctx context.Context, args ...any) { l.Logger.Sugar().Fatal(args...) }
func (l *Logger) PanicContext(ctx context.Context, args ...any) { l.Logger.Sugar().Panic(args...) }
