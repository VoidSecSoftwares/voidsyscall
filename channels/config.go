package channels

import "errors"

var (
	ErrUnsupportedChannel = errors.New("unsupported channel type")
	ErrConnectionFailed   = errors.New("connection failed")
	ErrTimeout            = errors.New("timeout")
)

type Config struct {
	HTTPAddr    string
	HTTPSPort   int
	DNSAddr     string
	DNSPort     int
	ICMPAddr    string
	ICMPPort    int
	DoHURL      string
	DoHDomain   string
	DoHAddr     string
	UserAgent   string
	BeaconPath  string
	JitterMax   int // percent
	JitterMin   int // percent
	Key         []byte
	Passphrase  []byte
	MaxRetries  int
	TimeoutSec  int
}

func DefaultConfig() *Config {
	return &Config{
		HTTPAddr:   "0.0.0.0",
		HTTPSPort:  443,
		DNSAddr:    "0.0.0.0",
		DNSPort:    53,
		ICMPAddr:   "0.0.0.0",
		ICMPPort:   0,
		DoHURL:     "https://dns.google/resolve",
		DoHDomain:  "voidsec.local",
		DoHAddr:    "0.0.0.0",
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		BeaconPath: "/api/v2/health",
		JitterMax:  30,
		JitterMin:  5,
		MaxRetries: 3,
		TimeoutSec: 10,
	}
}
