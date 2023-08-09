package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// Proxy defines an upstream host.
type Proxy struct {
	addr string

	// connection
	conn quic.Connection
}

// newProxy returns a new proxy.
func newProxy(addr string, tlsServerName string, tlsConfig *tls.Config) (*Proxy, error) {
	p := &Proxy{
		addr: addr,
	}

	if tlsConfig != nil {
		tlsConfig.NextProtos = []string{"doq"}
		tlsConfig.ServerName = tlsServerName
	}

	// TODO: Allow different quic.Config
	conn, err := quic.DialAddrEarly(context.Background(), addr, tlsConfig.Clone(), &quic.Config{})
	if err != nil {
		return nil, err
	}

	p.conn = conn
	return p, nil
}

func (p *Proxy) queryQUIC(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	stream, err := p.openStream(ctx, p.conn)
	if err != nil {
		return nil, fmt.Errorf("open new stream to %s: %v", p.addr, err)
	}

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

	respBuf, err := io.ReadAll(stream)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %s", p.addr, err)
	}
	if len(respBuf) == 0 {
		return nil, fmt.Errorf("empty response from %s", p.addr)
	}

	reply := dns.Msg{}
	err = reply.Unpack(respBuf[2:])

	if err != nil {
		return nil, fmt.Errorf("unpacking response from %s: %s", p.addr, err)
	}

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
