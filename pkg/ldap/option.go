package ldap

import (
	"crypto/tls"
	"net"

	"github.com/go-logr/logr"
)

func newOptions(opts ...Option) Options {
	opt := Options{}

	for _, o := range opts {
		o(&opt)
	}

	return opt
}

type Option func(o *Options)

type Options struct {
	Addr      string
	Logger    logr.Logger
	Listener  net.Listener
	TLSConfig *tls.Config
}

func Addr(val string) Option {
	return func(o *Options) {
		o.Addr = val
	}
}
func TLSConfig(val *tls.Config) Option {
	return func(o *Options) {
		o.TLSConfig = val
	}
}
func Logger(val logr.Logger) Option {
	return func(o *Options) {
		o.Logger = val
	}
}
func Listener(val net.Listener) Option {
	return func(o *Options) {
		o.Listener = val
	}
}
