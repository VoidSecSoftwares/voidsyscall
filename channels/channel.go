package channels

import "context"

type ChannelType string

const (
	ChannelHTTPS ChannelType = "https"
	ChannelDNS   ChannelType = "dns"
	ChannelICMP  ChannelType = "icmp"
)

type Message struct {
	ID   [16]byte
	Type uint8
	Data []byte
}

type Channel interface {
	Type() ChannelType
	Send(ctx context.Context, msg *Message) (*Message, error)
	Listen(ctx context.Context, addr string, handler func(*Message) *Message) error
	Close() error
}

func New(typ ChannelType, config *Config) (Channel, error) {
	switch typ {
	case ChannelHTTPS:
		return newHTTPChannel(config)
	case ChannelDNS:
		return newDNSChannel(config)
	case ChannelICMP:
		return newICMPChannel(config)
	default:
		return nil, ErrUnsupportedChannel
	}
}
