package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/quic-go/quic-go"
	"io"
	"strconv"
	"time"

	"github.com/coredns/coredns/pb"

	"github.com/miekg/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Proxy defines an upstream host.
type Proxy struct {
	addr string

	// connection
	client   pb.DnsServiceClient
	dialOpts []grpc.DialOption
}

// newProxy returns a new proxy.
func newProxy(addr string, tlsConfig *tls.Config) (*Proxy, error) {
	p := &Proxy{
		addr: addr,
	}

	if tlsConfig != nil {
		p.dialOpts = append(p.dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		p.dialOpts = append(p.dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.Dial(p.addr, p.dialOpts...)
	if err != nil {
		return nil, err
	}
	p.client = pb.NewDnsServiceClient(conn)

	return p, nil
}

func (p *Proxy) queryQUIC(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	dialCtx, dialCancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer dialCancel()

	session, err := quic.DialAddr(dialCtx, p.addr, nil, &quic.Config{})
	if err != nil {
		return nil, fmt.Errorf("opening quic session to %s: %v", p.addr, err)
	}

	openStreamCtx, openStreamCancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer openStreamCancel()
	stream, err := session.OpenStreamSync(openStreamCtx)
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

// addPrefix adds a 2-byte prefix with the DNS message length.
func addPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}

// query sends the request and waits for a response.
func (p *Proxy) query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	start := time.Now()

	msg, err := req.Pack()
	if err != nil {
		return nil, err
	}

	reply, err := p.client.Query(ctx, &pb.DnsPacket{Msg: msg})
	if err != nil {
		// if not found message, return empty message with NXDomain code
		if status.Code(err) == codes.NotFound {
			m := new(dns.Msg).SetRcode(req, dns.RcodeNameError)
			return m, nil
		}
		return nil, err
	}
	ret := new(dns.Msg)
	if err := ret.Unpack(reply.Msg); err != nil {
		return nil, err
	}

	rc, ok := dns.RcodeToString[ret.Rcode]
	if !ok {
		rc = strconv.Itoa(ret.Rcode)
	}

	RequestCount.WithLabelValues(p.addr).Add(1)
	RcodeCount.WithLabelValues(rc, p.addr).Add(1)
	RequestDuration.WithLabelValues(p.addr).Observe(time.Since(start).Seconds())

	return ret, nil
}
