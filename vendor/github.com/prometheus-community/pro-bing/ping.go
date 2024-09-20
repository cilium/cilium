// Package probing is a simple but powerful ICMP echo (ping) library.
//
// Here is a very simple example that sends and receives three packets:
//
//	pinger, err := probing.NewPinger("www.google.com")
//	if err != nil {
//		panic(err)
//	}
//	pinger.Count = 3
//	err = pinger.Run() // blocks until finished
//	if err != nil {
//		panic(err)
//	}
//	stats := pinger.Statistics() // get send/receive/rtt stats
//
// Here is an example that emulates the traditional UNIX ping command:
//
//	pinger, err := probing.NewPinger("www.google.com")
//	if err != nil {
//		panic(err)
//	}
//	// Listen for Ctrl-C.
//	c := make(chan os.Signal, 1)
//	signal.Notify(c, os.Interrupt)
//	go func() {
//		for _ = range c {
//			pinger.Stop()
//		}
//	}()
//	pinger.OnRecv = func(pkt *probing.Packet) {
//		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
//			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
//	}
//	pinger.OnFinish = func(stats *probing.Statistics) {
//		fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
//		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
//			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
//		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
//			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
//	}
//	fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
//	err = pinger.Run()
//	if err != nil {
//		panic(err)
//	}
//
// It sends ICMP Echo Request packet(s) and waits for an Echo Reply in response.
// If it receives a response, it calls the OnRecv callback. When it's finished,
// it calls the OnFinish callback.
//
// For a full ping example, see "cmd/ping/ping.go".
package probing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

const (
	timeSliceLength  = 8
	trackerLength    = len(uuid.UUID{})
	protocolICMP     = 1
	protocolIPv6ICMP = 58

	networkIP   = "ip"
	networkIPv4 = "ip4"
	networkIPv6 = "ip6"
)

var (
	ipv4Proto = map[string]string{"icmp": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"icmp": "ip6:ipv6-icmp", "udp": "udp6"}

	ErrMarkNotSupported = errors.New("setting SO_MARK socket option is not supported on this platform")
	ErrDFNotSupported   = errors.New("setting do-not-fragment bit is not supported on this platform")
)

// New returns a new Pinger struct pointer.
func New(addr string) *Pinger {
	r := rand.New(rand.NewSource(getSeed()))
	firstUUID := uuid.New()
	var firstSequence = map[uuid.UUID]map[int]struct{}{}
	firstSequence[firstUUID] = make(map[int]struct{})
	return &Pinger{
		Count:      -1,
		Interval:   time.Second,
		RecordRtts: true,
		Size:       timeSliceLength + trackerLength,
		Timeout:    time.Duration(math.MaxInt64),

		addr:              addr,
		done:              make(chan interface{}),
		id:                r.Intn(math.MaxUint16),
		trackerUUIDs:      []uuid.UUID{firstUUID},
		ipaddr:            nil,
		ipv4:              false,
		network:           networkIP,
		protocol:          "udp",
		awaitingSequences: firstSequence,
		TTL:               64,
		logger:            StdLogger{Logger: log.New(log.Writer(), log.Prefix(), log.Flags())},
	}
}

// NewPinger returns a new Pinger and resolves the address.
func NewPinger(addr string) (*Pinger, error) {
	p := New(addr)
	return p, p.Resolve()
}

// Pinger represents a packet sender/receiver.
type Pinger struct {
	// Interval is the wait time between each packet send. Default is 1s.
	Interval time.Duration

	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration

	// ResolveTimeout specifies a timeout to resolve an IP address or domain name
	ResolveTimeout time.Duration

	// Count tells pinger to stop after sending (and receiving) Count echo
	// packets. If this option is not specified, pinger will operate until
	// interrupted.
	Count int

	// Debug runs in debug mode
	Debug bool

	// Number of packets sent
	PacketsSent int

	// Number of packets received
	PacketsRecv int

	// Number of duplicate packets received
	PacketsRecvDuplicates int

	// Round trip time statistics
	minRtt    time.Duration
	maxRtt    time.Duration
	avgRtt    time.Duration
	stdDevRtt time.Duration
	stddevm2  time.Duration
	statsMu   sync.RWMutex

	// If true, keep a record of rtts of all received packets.
	// Set to false to avoid memory bloat for long running pings.
	RecordRtts bool

	// rtts is all of the Rtts
	rtts []time.Duration

	// OnSetup is called when Pinger has finished setting up the listening socket
	OnSetup func()

	// OnSend is called when Pinger sends a packet
	OnSend func(*Packet)

	// OnRecv is called when Pinger receives and processes a packet
	OnRecv func(*Packet)

	// OnFinish is called when Pinger exits
	OnFinish func(*Statistics)

	// OnDuplicateRecv is called when a packet is received that has already been received.
	OnDuplicateRecv func(*Packet)

	// OnSendError is called when an error occurs while Pinger attempts to send a packet
	OnSendError func(*Packet, error)

	// OnRecvError is called when an error occurs while Pinger attempts to receive a packet
	OnRecvError func(error)

	// Size of packet being sent
	Size int

	// Tracker: Used to uniquely identify packets - Deprecated
	Tracker uint64

	// Source is the source IP address
	Source string

	// Channel and mutex used to communicate when the Pinger should stop between goroutines.
	done chan interface{}
	lock sync.Mutex

	ipaddr *net.IPAddr
	addr   string

	// mark is a SO_MARK (fwmark) set on outgoing icmp packets
	mark uint

	// df when true sets the do-not-fragment bit in the outer IP or IPv6 header
	df bool

	// trackerUUIDs is the list of UUIDs being used for sending packets.
	trackerUUIDs []uuid.UUID

	ipv4     bool
	id       int
	sequence int
	// awaitingSequences are in-flight sequence numbers we keep track of to help remove duplicate receipts
	awaitingSequences map[uuid.UUID]map[int]struct{}
	// network is one of "ip", "ip4", or "ip6".
	network string
	// protocol is "icmp" or "udp".
	protocol string

	logger Logger

	TTL int
}

type packet struct {
	bytes  []byte
	nbytes int
	ttl    int
	addr   net.Addr
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// NBytes is the number of bytes in the message.
	Nbytes int

	// Seq is the ICMP sequence number.
	Seq int

	// TTL is the Time To Live on the packet.
	TTL int

	// ID is the ICMP identifier.
	ID int
}

// Statistics represent the stats of a currently running or finished
// pinger operation.
type Statistics struct {
	// PacketsRecv is the number of packets received.
	PacketsRecv int

	// PacketsSent is the number of packets sent.
	PacketsSent int

	// PacketsRecvDuplicates is the number of duplicate responses there were to a sent packet.
	PacketsRecvDuplicates int

	// PacketLoss is the percentage of packets lost.
	PacketLoss float64

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// Rtts is all of the round-trip times sent via this pinger.
	Rtts []time.Duration

	// MinRtt is the minimum round-trip time sent via this pinger.
	MinRtt time.Duration

	// MaxRtt is the maximum round-trip time sent via this pinger.
	MaxRtt time.Duration

	// AvgRtt is the average round-trip time sent via this pinger.
	AvgRtt time.Duration

	// StdDevRtt is the standard deviation of the round-trip times sent via
	// this pinger.
	StdDevRtt time.Duration
}

func (p *Pinger) updateStatistics(pkt *Packet) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()

	p.PacketsRecv++
	if p.RecordRtts {
		p.rtts = append(p.rtts, pkt.Rtt)
	}

	if p.PacketsRecv == 1 || pkt.Rtt < p.minRtt {
		p.minRtt = pkt.Rtt
	}

	if pkt.Rtt > p.maxRtt {
		p.maxRtt = pkt.Rtt
	}

	pktCount := time.Duration(p.PacketsRecv)
	// welford's online method for stddev
	// https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
	delta := pkt.Rtt - p.avgRtt
	p.avgRtt += delta / pktCount
	delta2 := pkt.Rtt - p.avgRtt
	p.stddevm2 += delta * delta2

	p.stdDevRtt = time.Duration(math.Sqrt(float64(p.stddevm2 / pktCount)))
}

// SetIPAddr sets the ip address of the target host.
func (p *Pinger) SetIPAddr(ipaddr *net.IPAddr) {
	p.ipv4 = isIPv4(ipaddr.IP)

	p.ipaddr = ipaddr
	p.addr = ipaddr.String()
}

// IPAddr returns the ip address of the target host.
func (p *Pinger) IPAddr() *net.IPAddr {
	return p.ipaddr
}

// Resolve does the DNS lookup for the Pinger address and sets IP protocol.
func (p *Pinger) Resolve() error {
	if len(p.addr) == 0 {
		return errors.New("addr cannot be empty")
	}
	var (
		ipaddr *net.IPAddr
		err    error
	)
	if p.ResolveTimeout > time.Duration(0) {
		var (
			ctx = context.Background()
			ips []net.IP
		)
		ctx, cancel := context.WithTimeout(ctx, p.ResolveTimeout)
		defer cancel()
		ips, err = net.DefaultResolver.LookupIP(ctx, p.network, p.addr)
		if err != nil {
			return err
		}
		if len(ips) == 0 {
			return fmt.Errorf("lookup %s failed: no addresses found", p.addr)
		}
		ipaddr = &net.IPAddr{IP: ips[0]}
		for _, ip := range ips {
			if p.network == networkIPv6 {
				if ip.To4() == nil && ip.To16() != nil {
					ipaddr = &net.IPAddr{IP: ip}
					break
				}
				continue
			}
			if ip.To4() != nil {
				ipaddr = &net.IPAddr{IP: ip}
			}
		}
	} else {
		ipaddr, err = net.ResolveIPAddr(p.network, p.addr)
		if err != nil {
			return err
		}
	}

	p.ipv4 = isIPv4(ipaddr.IP)

	p.ipaddr = ipaddr

	return nil
}

// SetAddr resolves and sets the ip address of the target host, addr can be a
// DNS name like "www.google.com" or IP like "127.0.0.1".
func (p *Pinger) SetAddr(addr string) error {
	oldAddr := p.addr
	p.addr = addr
	err := p.Resolve()
	if err != nil {
		p.addr = oldAddr
		return err
	}
	return nil
}

// Addr returns the string ip address of the target host.
func (p *Pinger) Addr() string {
	return p.addr
}

// SetNetwork allows configuration of DNS resolution.
// * "ip" will automatically select IPv4 or IPv6.
// * "ip4" will select IPv4.
// * "ip6" will select IPv6.
func (p *Pinger) SetNetwork(n string) {
	switch n {
	case networkIPv4:
		p.network = networkIPv4
	case networkIPv6:
		p.network = networkIPv6
	default:
		p.network = networkIP
	}
}

// SetPrivileged sets the type of ping pinger will send.
// false means pinger will send an "unprivileged" UDP ping.
// true means pinger will send a "privileged" raw ICMP ping.
// NOTE: setting to true requires that it be run with super-user privileges.
func (p *Pinger) SetPrivileged(privileged bool) {
	if privileged {
		p.protocol = "icmp"
	} else {
		p.protocol = "udp"
	}
}

// Privileged returns whether pinger is running in privileged mode.
func (p *Pinger) Privileged() bool {
	return p.protocol == "icmp"
}

// SetLogger sets the logger to be used to log events from the pinger.
func (p *Pinger) SetLogger(logger Logger) {
	p.logger = logger
}

// SetID sets the ICMP identifier.
func (p *Pinger) SetID(id int) {
	p.id = id
}

// ID returns the ICMP identifier.
func (p *Pinger) ID() int {
	return p.id
}

// SetMark sets a mark intended to be set on outgoing ICMP packets.
func (p *Pinger) SetMark(m uint) {
	p.mark = m
}

// Mark returns the mark to be set on outgoing ICMP packets.
func (p *Pinger) Mark() uint {
	return p.mark
}

// SetDoNotFragment sets the do-not-fragment bit in the outer IP header to the desired value.
func (p *Pinger) SetDoNotFragment(df bool) {
	p.df = df
}

// Run runs the pinger. This is a blocking function that will exit when it's
// done. If Count or Interval are not specified, it will run continuously until
// it is interrupted.
func (p *Pinger) Run() error {
	return p.RunWithContext(context.Background())
}

// RunWithContext runs the pinger with a context. This is a blocking function that will exit when it's
// done or if the context is canceled. If Count or Interval are not specified, it will run continuously until
// it is interrupted.
func (p *Pinger) RunWithContext(ctx context.Context) error {
	var conn packetConn
	var err error
	if p.Size < timeSliceLength+trackerLength {
		return fmt.Errorf("size %d is less than minimum required size %d", p.Size, timeSliceLength+trackerLength)
	}
	if p.ipaddr == nil {
		err = p.Resolve()
	}
	if err != nil {
		return err
	}
	if conn, err = p.listen(); err != nil {
		return err
	}
	defer conn.Close()

	if p.mark != 0 {
		if err := conn.SetMark(p.mark); err != nil {
			return fmt.Errorf("error setting mark: %v", err)
		}
	}

	if p.df {
		if err := conn.SetDoNotFragment(); err != nil {
			return fmt.Errorf("error setting do-not-fragment: %v", err)
		}
	}

	conn.SetTTL(p.TTL)
	return p.run(ctx, conn)
}

func (p *Pinger) run(ctx context.Context, conn packetConn) error {
	if err := conn.SetFlagTTL(); err != nil {
		return err
	}
	defer p.finish()

	recv := make(chan *packet, 5)
	defer close(recv)

	if p.OnSetup != nil {
		p.OnSetup()
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		select {
		case <-ctx.Done():
			p.Stop()
			return ctx.Err()
		case <-p.done:
		}
		return nil
	})

	g.Go(func() error {
		defer p.Stop()
		return p.recvICMP(conn, recv)
	})

	g.Go(func() error {
		defer p.Stop()
		return p.runLoop(conn, recv)
	})

	return g.Wait()
}

func (p *Pinger) runLoop(
	conn packetConn,
	recvCh <-chan *packet,
) error {
	logger := p.logger
	if logger == nil {
		logger = NoopLogger{}
	}

	timeout := time.NewTicker(p.Timeout)
	interval := time.NewTicker(p.Interval)
	defer func() {
		interval.Stop()
		timeout.Stop()
	}()

	if err := p.sendICMP(conn); err != nil {
		return err
	}

	for {
		select {
		case <-p.done:
			return nil

		case <-timeout.C:
			return nil

		case r := <-recvCh:
			err := p.processPacket(r)
			if err != nil {
				// FIXME: this logs as FATAL but continues
				logger.Fatalf("processing received packet: %s", err)
			}

		case <-interval.C:
			if p.Count > 0 && p.PacketsSent >= p.Count {
				interval.Stop()
				continue
			}
			err := p.sendICMP(conn)
			if err != nil {
				// FIXME: this logs as FATAL but continues
				logger.Fatalf("sending packet: %s", err)
			}
		}
		if p.Count > 0 && p.PacketsRecv >= p.Count {
			return nil
		}
	}
}

func (p *Pinger) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()

	open := true
	select {
	case _, open = <-p.done:
	default:
	}

	if open {
		close(p.done)
	}
}

func (p *Pinger) finish() {
	if p.OnFinish != nil {
		p.OnFinish(p.Statistics())
	}
}

// Statistics returns the statistics of the pinger. This can be run while the
// pinger is running or after it is finished. OnFinish calls this function to
// get it's finished statistics.
func (p *Pinger) Statistics() *Statistics {
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()
	sent := p.PacketsSent

	var loss float64
	if sent > 0 {
		loss = float64(sent-p.PacketsRecv) / float64(sent) * 100
	}

	s := Statistics{
		PacketsSent:           sent,
		PacketsRecv:           p.PacketsRecv,
		PacketsRecvDuplicates: p.PacketsRecvDuplicates,
		PacketLoss:            loss,
		Rtts:                  p.rtts,
		Addr:                  p.addr,
		IPAddr:                p.ipaddr,
		MaxRtt:                p.maxRtt,
		MinRtt:                p.minRtt,
		AvgRtt:                p.avgRtt,
		StdDevRtt:             p.stdDevRtt,
	}
	return &s
}

type expBackoff struct {
	baseDelay time.Duration
	maxExp    int64
	c         int64
}

func (b *expBackoff) Get() time.Duration {
	if b.c < b.maxExp {
		b.c++
	}

	return b.baseDelay * time.Duration(rand.Int63n(1<<b.c))
}

func newExpBackoff(baseDelay time.Duration, maxExp int64) expBackoff {
	return expBackoff{baseDelay: baseDelay, maxExp: maxExp}
}

func (p *Pinger) recvICMP(
	conn packetConn,
	recv chan<- *packet,
) error {
	// Start by waiting for 50 µs and increase to a possible maximum of ~ 100 ms.
	expBackoff := newExpBackoff(50*time.Microsecond, 11)
	delay := expBackoff.Get()

	// Workaround for https://github.com/golang/go/issues/47369
	offset := 0
	if p.ipv4 && !p.Privileged() && runtime.GOOS == "darwin" {
		offset = 20
	}

	for {
		select {
		case <-p.done:
			return nil
		default:
			bytes := make([]byte, p.getMessageLength()+offset)
			if err := conn.SetReadDeadline(time.Now().Add(delay)); err != nil {
				return err
			}
			n, ttl, addr, err := conn.ReadFrom(bytes)
			if err != nil {
				if p.OnRecvError != nil {
					p.OnRecvError(err)
				}
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						// Read timeout
						delay = expBackoff.Get()
						continue
					}
				}
				return err
			}

			select {
			case <-p.done:
				return nil
			case recv <- &packet{bytes: bytes, nbytes: n, ttl: ttl, addr: addr}:
			}
		}
	}
}

// getPacketUUID scans the tracking slice for matches.
func (p *Pinger) getPacketUUID(pkt []byte) (*uuid.UUID, error) {
	var packetUUID uuid.UUID
	err := packetUUID.UnmarshalBinary(pkt[timeSliceLength : timeSliceLength+trackerLength])
	if err != nil {
		return nil, fmt.Errorf("error decoding tracking UUID: %w", err)
	}

	for _, item := range p.trackerUUIDs {
		if item == packetUUID {
			return &packetUUID, nil
		}
	}
	return nil, nil
}

// getCurrentTrackerUUID grabs the latest tracker UUID.
func (p *Pinger) getCurrentTrackerUUID() uuid.UUID {
	return p.trackerUUIDs[len(p.trackerUUIDs)-1]
}

func (p *Pinger) processPacket(recv *packet) error {
	receivedAt := time.Now()
	var proto int
	if p.ipv4 {
		proto = protocolICMP
		// Workaround for https://github.com/golang/go/issues/47369
		recv.nbytes = stripIPv4Header(recv.nbytes, recv.bytes)
	} else {
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, recv.bytes); err != nil {
		return fmt.Errorf("error parsing icmp message: %w", err)
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil
	}

	// If initial ip is a broadcast ip, ping responses will come from machines' in the
	// subnet, thus ip will differ. Below gets real ip from received package.
	var realIP *net.IPAddr

	switch v := recv.addr.(type) {
	case *net.IPAddr: // For ICMP
		realIP = v
	case *net.UDPAddr:
		realIP = &net.IPAddr{IP: v.IP}
	default:
		p.logger.Infof("received address: %s it neither an Ip address (ICMP) nor UDP address, shouldn't happen. using initial address", recv.addr)
		realIP = p.ipaddr
	}

	inPkt := &Packet{
		Nbytes: recv.nbytes,
		IPAddr: realIP,
		Addr:   realIP.String(),
		TTL:    recv.ttl,
		ID:     p.id,
	}

	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		if !p.matchID(pkt.ID) {
			return nil
		}

		if len(pkt.Data) < timeSliceLength+trackerLength {
			return fmt.Errorf("insufficient data received; got: %d %v",
				len(pkt.Data), pkt.Data)
		}

		pktUUID, err := p.getPacketUUID(pkt.Data)
		if err != nil || pktUUID == nil {
			return err
		}

		timestamp := bytesToTime(pkt.Data[:timeSliceLength])
		inPkt.Rtt = receivedAt.Sub(timestamp)
		inPkt.Seq = pkt.Seq
		// If we've already received this sequence, ignore it.
		if _, inflight := p.awaitingSequences[*pktUUID][pkt.Seq]; !inflight {
			p.PacketsRecvDuplicates++
			if p.OnDuplicateRecv != nil {
				p.OnDuplicateRecv(inPkt)
			}
			return nil
		}
		// remove it from the list of sequences we're waiting for so we don't get duplicates.
		delete(p.awaitingSequences[*pktUUID], pkt.Seq)
		p.updateStatistics(inPkt)
	default:
		// Very bad, not sure how this can happen
		return fmt.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
	}

	if p.OnRecv != nil {
		p.OnRecv(inPkt)
	}

	return nil
}

func (p *Pinger) sendICMP(conn packetConn) error {
	var dst net.Addr = p.ipaddr
	if p.protocol == "udp" {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}

	currentUUID := p.getCurrentTrackerUUID()
	uuidEncoded, err := currentUUID.MarshalBinary()
	if err != nil {
		return fmt.Errorf("unable to marshal UUID binary: %w", err)
	}
	t := append(timeToBytes(time.Now()), uuidEncoded...)
	if remainSize := p.Size - timeSliceLength - trackerLength; remainSize > 0 {
		t = append(t, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   p.id,
		Seq:  p.sequence,
		Data: t,
	}

	msg := &icmp.Message{
		Type: conn.ICMPRequestType(),
		Code: 0,
		Body: body,
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	for {
		if _, err := conn.WriteTo(msgBytes, dst); err != nil {
			// Try to set broadcast flag
			if errors.Is(err, syscall.EACCES) && runtime.GOOS == "linux" {
				if e := conn.SetBroadcastFlag(); e != nil {
					p.logger.Warnf("had EACCES syscall error, check your local firewall")
				}
				p.logger.Infof("Pinging a broadcast address")
				continue
			}
			if p.OnSendError != nil {
				outPkt := &Packet{
					Nbytes: len(msgBytes),
					IPAddr: p.ipaddr,
					Addr:   p.addr,
					Seq:    p.sequence,
					ID:     p.id,
				}
				p.OnSendError(outPkt, err)
			}
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
			return err
		}
		if p.OnSend != nil {
			outPkt := &Packet{
				Nbytes: len(msgBytes),
				IPAddr: p.ipaddr,
				Addr:   p.addr,
				Seq:    p.sequence,
				ID:     p.id,
			}
			p.OnSend(outPkt)
		}
		// mark this sequence as in-flight
		p.awaitingSequences[currentUUID][p.sequence] = struct{}{}
		p.PacketsSent++
		p.sequence++
		if p.sequence > 65535 {
			newUUID := uuid.New()
			p.trackerUUIDs = append(p.trackerUUIDs, newUUID)
			p.awaitingSequences[newUUID] = make(map[int]struct{})
			p.sequence = 0
		}
		break
	}

	return nil
}

func (p *Pinger) listen() (packetConn, error) {
	var (
		conn packetConn
		err  error
	)

	if p.ipv4 {
		var c icmpv4Conn
		c.c, err = icmp.ListenPacket(ipv4Proto[p.protocol], p.Source)
		conn = &c
	} else {
		var c icmpV6Conn
		c.c, err = icmp.ListenPacket(ipv6Proto[p.protocol], p.Source)
		conn = &c
	}

	if err != nil {
		p.Stop()
		return nil, err
	}
	return conn, nil
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

var seed = time.Now().UnixNano()

// getSeed returns a goroutine-safe unique seed
func getSeed() int64 {
	return atomic.AddInt64(&seed, 1)
}

// stripIPv4Header strips IPv4 header bytes if present
// https://github.com/golang/go/commit/3b5be4522a21df8ce52a06a0c4ba005c89a8590f
func stripIPv4Header(n int, b []byte) int {
	if len(b) < 20 {
		return n
	}
	l := int(b[0]&0x0f) << 2
	if 20 > l || l > len(b) {
		return n
	}
	if b[0]>>4 != 4 {
		return n
	}
	copy(b, b[l:])
	return n - l
}
