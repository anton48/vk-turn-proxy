package turnbind

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"golang.zx2c4.com/wireguard/conn"
)

type TURNBind struct {
	proxy *proxy.Proxy
	mu    sync.Mutex
	open  bool
}

func NewTURNBind(p *proxy.Proxy) *TURNBind {
	return &TURNBind{
		proxy: p,
	}
}

func (b *TURNBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.open {
		return nil, 0, fmt.Errorf("TURNBind already open")
	}

	if err := b.proxy.Start(); err != nil {
		return nil, 0, fmt.Errorf("proxy start: %w", err)
	}

	b.open = true

	recvFunc := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 {
			return 0, nil
		}
		n, err := b.proxy.ReceivePacket(packets[0])
		if err != nil {
			return 0, &net.OpError{
				Op:  "read",
				Net: "turn",
				Err: err,
			}
		}
		sizes[0] = n
		eps[0] = &TURNEndpoint{}
		return 1, nil
	}

	return []conn.ReceiveFunc{recvFunc}, 0, nil
}

func (b *TURNBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.open {
		return nil
	}
	b.open = false
	b.proxy.Stop()
	return nil
}

func (b *TURNBind) SetMark(mark uint32) error {
	return nil
}

func (b *TURNBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if err := b.proxy.SendPacket(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *TURNBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &TURNEndpoint{addr: s}, nil
}

func (b *TURNBind) BatchSize() int {
	return 1
}

type TURNEndpoint struct {
	addr string
}

func (e *TURNEndpoint) ClearSrc()            {}
func (e *TURNEndpoint) SrcToString() string   { return "" }
func (e *TURNEndpoint) DstToString() string {
	if e.addr != "" {
		return e.addr
	}
	return "turn-relay"
}
func (e *TURNEndpoint) DstToBytes() []byte { return []byte{0, 0, 0, 0} }
func (e *TURNEndpoint) DstIP() netip.Addr {
	if e.addr != "" {
		ap, err := netip.ParseAddrPort(e.addr)
		if err == nil {
			return ap.Addr()
		}
	}
	return netip.Addr{}
}
func (e *TURNEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
