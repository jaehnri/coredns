package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/coredns/coredns/core/dnsserver"
	"math"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// Proxy defines an upstream host.
type Proxy struct {
	addr string

	tlsConfig  *tls.Config
	quicConfig *quic.Config

	// Conn defines the connection with a DoQ proxy.
	// This connection might be closed and reopened at times.
	conn quic.Connection
}

// newProxy returns a new proxy.
func newProxy(addr string, tlsServerName string, tlsConfig *tls.Config) (*Proxy, error) {
	if tlsConfig != nil {
		tlsConfig.NextProtos = []string{"doq"}
		tlsConfig.ServerName = tlsServerName
	}

	quicConfig := &quic.Config{
		MaxIncomingStreams:    math.MaxUint16,
		MaxIncomingUniStreams: math.MaxUint16,
	}

	conn, err := quic.DialAddrEarly(context.Background(), addr, tlsConfig.Clone(), &quic.Config{})
	if err != nil {
		return nil, err
	}

	return &Proxy{
		addr:       addr,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		conn:       conn,
	}, nil
}

func (p *Proxy) queryQUIC(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {

	// In DoQ, one query consumes one stream.
	// The client MUST select the next available client-initiated bidirectional
	// stream for each subsequent query on a QUIC connection.
	stream, err := p.openStream(ctx, p.conn)
	if err != nil {
		return nil, fmt.Errorf("open new stream to %s: %v", p.addr, err)
	}

	// When forwarding a DNS message from another transport over DoQ, the Message
	// ID MUST be set to 0.
	id := req.Id
	req.Id = 0

	buf, err := req.Pack()
	if err != nil {
		return nil, err
	}

	_, err = stream.Write(addPrefix(buf))
	if err != nil {
		return nil, err
	}
	_ = stream.Close()

	respBuf, err := dnsserver.ReadDOQMessage(stream)
	if err != nil {
		return nil, err
	}

	reply := dns.Msg{}
	err = reply.Unpack(respBuf)
	if err != nil {
		return nil, fmt.Errorf("unpacking response from %s: %s", p.addr, err)
	}

	// Restore the original ID to not break compatibility
	reply.Id = id
	return &reply, nil
}

// openStream opens a new QUIC stream for the specified connection.
func (p *Proxy) openStream(ctx context.Context, conn quic.Connection) (quic.Stream, error) {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(defaultTimeout))
	defer cancel()

	return conn.OpenStreamSync(ctx)
}

// addPrefix adds a 2-byte prefix with the DNS message length.
func addPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}
