// Package fastping is an ICMP ping library inspired by AnyEvent::FastPing Perl
// module to send ICMP ECHO REQUEST packets quickly. Original Perl module is
// available at
// http://search.cpan.org/~mlehmann/AnyEvent-FastPing-2.01/
//
// It hasn't been fully implemented original functions yet.
//
// Here is an example:
//
//	p := fastping.NewPinger()
//	ra, err := net.ResolveIPAddr("ip4:icmp", os.Args[1])
//	if err != nil {
//		fmt.Println(err)
//		os.Exit(1)
//	}
//	p.AddIPAddr(ra)
//	p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
//		fmt.Printf("IP Addr: %s receive, RTT: %v\n", addr.String(), rtt)
//	}
//	p.OnIdle = func() {
//		fmt.Println("finish")
//	}
//	err = p.Run()
//	if err != nil {
//		fmt.Println(err)
//	}
//
// It sends an ICMP packet and wait a response. If it receives a response,
// it calls "receive" callback. After that, MaxRTT time passed, it calls
// "idle" callback. If you need more example, please see "cmd/ping/ping.go".
//
// This library needs to run as a superuser for sending ICMP packets when
// privileged raw ICMP endpoints is used so in such a case, to run go test
// for the package, please run like a following
//
//	sudo go test
//
package mpping

import (
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	TimeSliceLength  = 8
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

func byteSliceOfSize(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < len(b); i++ {
		b[i] = 1
	}

	return b
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
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

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

func ipv4Payload(b []byte) []byte {
	if len(b) < ipv4.HeaderLen {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[hdrlen:]
}

type packet struct {
	bytes []byte
	addr  net.Addr
}

type context struct {
	stop chan bool
	done chan bool
	err  error
}

func newContext() *context {
	return &context{
		stop: make(chan bool),
		done: make(chan bool),
	}
}

type pingHost struct {
	id   int
	seqn int
	addr *net.IPAddr
}

// Pinger represents ICMP packet sender/receiver
type Pinger struct {
	hosts   map[string]pingHost
	rounds  int
	network string
	source  string
	source6 string
	hasIPv4 bool
	hasIPv6 bool
	ctx     *context
	mu      sync.Mutex

	// Set whether size should be constant or from a pattern
	UsePattern bool
	// If no pattern, size in bytes of the payload to send
	Size int
	// If pattern, the list of sizes to use
	Pattern []int

	//Variable to keep track of how many time we triggered SendIMCP
	SentICMP int

	//Procesed ICMP counter
	ProcessedICMP int

	//Slice to keep track of all the RTTs collected
	//RTTS []time.Duration

	//Slice to keep track of all the Sequence numbers collected
	//SeqsNums []int

	//Map to keep track of ICMP_ECHO_REPLIES Sequence numbers and RTT value
	SeqsAndRTTS map[int]float32

	//Map to track seq.numbers and times
	SeqsAndTime map[int]string

	//Map to keep track of time
	//times []string

	// Number of (nano,milli)seconds of an idle timeout. Once it passed,
	// the library calls an idle callback function. It is also used for an
	// interval time of RunLoop() method
	// Distance between Trains, in other word time distance between batches of pings
	MaxRTT time.Duration

	//Tiemout - Time we wait for a reponse before calling the OnIdle function,
	//this is a differnet timer from the MaxRTT which will be associated to how
	//often we send an IMCP message and process the received message.
	Timeout time.Duration

	// Lambda, to follow an exponental distribution and apply Poisson analysis
	// we define lambda which is the rate parameter.
	Rate float64

	// Gamma to be used to determine the distribution of pings
	Gamma time.Duration
	// If true it runs at each instance it runs train of pings
	Train bool

	// Distance between trains. If 0 then no distance
	// Time distance between pings included in a batch of pings
	TrainInt time.Duration

	// The number of pings to send in a train
	TrainSize int

	// OnRecv is called with a response packet's source address, its
	// elapsed time when Pinger receives a response packet and the sequence number.
	OnRecv func(*net.IPAddr, time.Duration, int)

	// OnIdle is called when MaxRTT time passed
	OnIdle func()
	// If Debug is true, it prints debug messages to stdout.
	Debug bool
}

// NewPinger returns a new Pinger struct pointer
func NewPinger() *Pinger {
	rand.Seed(time.Now().UnixNano())
	return &Pinger{
		hosts:         make(map[string]pingHost),
		SeqsAndRTTS:   make(map[int]float32),
		SeqsAndTime:   make(map[int]string),
		rounds:        1,
		SentICMP:      0,
		ProcessedICMP: 0,
		network:       "ip",
		source:        "",
		source6:       "",
		hasIPv4:       false,
		hasIPv6:       false,
		UsePattern:    false,
		Size:          TimeSliceLength,
		MaxRTT:        time.Second,
		Timeout:       time.Second * 1,
		Gamma:         time.Millisecond * 0,
		Rate:          0.0,
		Train:         false,
		TrainInt:      time.Millisecond * 0,
		TrainSize:     1,
		OnRecv:        nil,
		OnIdle:        nil,
		Debug:         false,
	}
}

// Get next wait time to send ping based on whether it has to be constant or
// uniformly distributed
func (p *Pinger) getNextWait() time.Duration {
	//var temp time.Duration
	var lambda, next_interval float64
	var next_interval_time time.Duration
	if p.Rate > float64(0) {
		lambda = float64(1) / p.Rate
		fmt.Printf("Next Batch.\n")
		//fmt.Printf("%s \n", time.Now())
		//temp = p.MaxRTT + time.Duration(rand.Intn(2*int(p.Gamma))) - p.Gamma
		//temp = p.MaxRTT + time.Duration(-math.Log(1-rand.Float64())/rateParameter)
		//temp = p.MaxRTT + time.Duration(-math.Log(1-rand.Float64())/lambda)

		//fmt.Printf("Value of Rate Defined is: %v\n", p.Rate)

		//We multiply by 60,000 as in each minute we have 60,000 msecs
		//We use minutes as reference as our interval is defined by a minute
		//Therefore we go from msec to minutes by multiplying by 60,000
		next_interval = (-math.Log(1-rand.Float64()) / lambda) * 60000

		//fmt.Printf("NextWaitTime is: %v\n", next_interval)

		next_interval_time = time.Millisecond * time.Duration(next_interval)
		//fmt.Printf("NextWaitTime in Milliseconds is: %v\n", next_interval_time)
		//fmt.Printf("Interval + NextWaitTime value is: %v\n", p.MaxRTT+next_interval_time)

		//temp = p.MaxRTT + time.Duration(next_interval)
		//fmt.Printf("Value of Next Wait Time is: %v\n", temp)
		//fmt.Println()
		//return temp
		return p.MaxRTT + next_interval_time
	} else {
		return p.MaxRTT
	}
}

// Use a pattern of sizes to transmit data
func (p *Pinger) SetPattern(pattern []int) {
	if len(pattern) <= 0 {
		return
	} else {
		p.UsePattern = true
		p.Pattern = make([]int, len(pattern))
		copy(p.Pattern, pattern)
	}
}

// Network sets a network endpoints for ICMP ping and returns the previous
// setting. network arg should be "ip" or "udp" string or if others are
// specified, it returns an error. If this function isn't called, Pinger
// uses "ip" as default.
func (p *Pinger) Network(network string) (string, error) {
	origNet := p.network
	switch network {
	case "ip":
		fallthrough
	case "udp":
		p.network = network
	default:
		return origNet, errors.New(network + " can't be used as ICMP endpoint")
	}
	return origNet, nil
}

// Source sets ipv4/ipv6 source IP for sending ICMP packets and returns the previous
// setting. Empty value indicates to use system default one (for both ipv4 and ipv6).
func (p *Pinger) Source(source string) (string, error) {
	// using ipv4 previous value for new empty one
	origSource := p.source
	if "" == source {
		p.mu.Lock()
		p.source = ""
		p.source6 = ""
		p.mu.Unlock()
		return origSource, nil
	}

	addr := net.ParseIP(source)
	if addr == nil {
		return origSource, errors.New(source + " is not a valid textual representation of an IPv4/IPv6 address")
	}

	if isIPv4(addr) {
		p.mu.Lock()
		p.source = source
		p.mu.Unlock()
	} else if isIPv6(addr) {
		origSource = p.source6
		p.mu.Lock()
		p.source6 = source
		p.mu.Unlock()
	} else {
		return origSource, errors.New(source + " is not a valid textual representation of an IPv4/IPv6 address")
	}

	return origSource, nil
}

// AddIP adds an IP address to Pinger. ipaddr arg should be a string like
// "192.0.2.1".
func (p *Pinger) AddIP(ipaddr string) error {
	addr := net.ParseIP(ipaddr)
	if addr == nil {
		return fmt.Errorf("%s is not a valid textual representation of an IP address", ipaddr)
	}
	p.mu.Lock()
	p.hosts[addr.String()] = pingHost{
		id:   rand.Intn(0xffff),
		seqn: 0,
		addr: &net.IPAddr{IP: addr},
	}
	if isIPv4(addr) {
		p.hasIPv4 = true
	} else if isIPv6(addr) {
		p.hasIPv6 = true
	}
	p.mu.Unlock()
	return nil
}

// AddIPAddr adds an IP address to Pinger. ip arg should be a net.IPAddr
// pointer.
func (p *Pinger) AddIPAddr(ip *net.IPAddr) {
	p.mu.Lock()
	p.hosts[ip.String()] = pingHost{
		id:   rand.Intn(0xffff),
		seqn: 0,
		addr: ip,
	}
	if isIPv4(ip.IP) {
		p.hasIPv4 = true
	} else if isIPv6(ip.IP) {
		p.hasIPv6 = true
	}
	p.mu.Unlock()
}

// RemoveIP removes an IP address from Pinger. ipaddr arg should be a string
// like "192.0.2.1".
func (p *Pinger) RemoveIP(ipaddr string) error {
	addr := net.ParseIP(ipaddr)
	if addr == nil {
		return fmt.Errorf("%s is not a valid textual representation of an IP address", ipaddr)
	}
	p.mu.Lock()
	delete(p.hosts, addr.String())
	p.mu.Unlock()
	return nil
}

// RemoveIPAddr removes an IP address from Pinger. ip arg should be a net.IPAddr
// pointer.
func (p *Pinger) RemoveIPAddr(ip *net.IPAddr) {
	p.mu.Lock()
	delete(p.hosts, ip.String())
	p.mu.Unlock()
}

// AddHandler adds event handler to Pinger. event arg should be "receive" or
// "idle" string.
//
// **CAUTION** This function is deprecated. Please use OnRecv and OnIdle field
// of Pinger struct to set following handlers.
//
// "receive" handler should be
//
//	func(addr *net.IPAddr, rtt time.Duration, seqn int)
//
// type function. The handler is called with a response packet's source address
// and its elapsed time when Pinger receives a response packet and the sequence number of the ICMP message.
//
// "idle" handler should be
//
//	func()
//
// type function. The handler is called when MaxRTT time passed. For more
// detail, please see Run() and RunLoop().
func (p *Pinger) AddHandler(event string, handler interface{}) error {
	switch event {
	case "receive":
		if hdl, ok := handler.(func(*net.IPAddr, time.Duration, int)); ok {
			p.mu.Lock()
			p.OnRecv = hdl
			p.mu.Unlock()
			return nil
		}
		return errors.New("receive event handler should be `func(*net.IPAddr, time.Duration)`")
	case "idle":
		if hdl, ok := handler.(func()); ok {
			p.mu.Lock()
			p.OnIdle = hdl
			p.mu.Unlock()
			return nil
		}
		return errors.New("idle event handler should be `func()`")
	}
	return errors.New("No such event: " + event)
}

// Run invokes a single send/receive procedure. It sends packets to all hosts
// which have already been added by AddIP() etc. and wait those responses. When
// it receives a response, it calls "receive" handler registered by AddHander().
// After MaxRTT seconds, it calls "idle" handler and returns to caller with
// an error value. It means it blocks until MaxRTT seconds passed. For the
// purpose of sending/receiving packets over and over, use RunLoop().
func (p *Pinger) Run() error {
	p.mu.Lock()
	p.ctx = newContext()
	p.mu.Unlock()
	p.run(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ctx.err
}

// RunLoop invokes send/receive procedure repeatedly. It sends packets to all
// hosts which have already been added by AddIP() etc. and wait those responses.
// When it receives a response, it calls "receive" handler registered by
// AddHander(). After MaxRTT seconds, it calls "idle" handler, resend packets
// and wait those response. MaxRTT works as an interval time.
//
// This is a non-blocking method so immediately returns. If you want to monitor
// and stop sending packets, use Done() and Stop() methods. For example,
//
//	p.RunLoop()
//	ticker := time.NewTicker(time.Millisecond * 250)
//	select {
//	case <-p.Done():
//		if err := p.Err(); err != nil {
//			log.Fatalf("Ping failed: %v", err)
//		}
//	case <-ticker.C:
//		break
//	}
//	ticker.Stop()
//	p.Stop()
//
// For more details, please see "cmd/ping/ping.go".
func (p *Pinger) RunLoop() {
	p.mu.Lock()
	p.ctx = newContext()
	p.mu.Unlock()
	go p.run(false)
}

/*
 * Run a batch of pings for at most deadline Milliseconds
 */
// func (p *Pinger) RunBatchWithDeadline(freq, deadline time.Duration) (){
// 	p.ctx = newContext()
// 	p.runSync(freq, deadline)
// }

/*
 * Run a batch of pings for at most deadline Milliseconds
 */
// func (p *Pinger) RunBatchWithTotNumber(freq time.Duration, total int) (){
// 	p.ctx = newContext()
// 	p.runSync(freq, deadline)
// }

// Done returns a channel that is closed when RunLoop() is stopped by an error
// or Stop(). It must be called after RunLoop() call. If not, it causes panic.
func (p *Pinger) Done() <-chan bool {
	return p.ctx.done
}

// Stop stops RunLoop(). It must be called after RunLoop(). If not, it causes
// panic.
func (p *Pinger) Stop() {
	p.debugln("Stop(): close(p.ctx.stop)")
	close(p.ctx.stop)
	p.debugln("Stop(): <-p.ctx.done")
	<-p.ctx.done
}

// Stop stops RunLoop(). It must be called after RunLoop(). If not, it causes
// panic.
// Calls triggers the channel for done
func (p *Pinger) StopAndSend() {
	p.ctx.done <- true
	p.debugln("StopAndSend(): close(p.ctx.stop)")
	close(p.ctx.stop)
	p.debugln("StopAndSend(): <-p.ctx.done")
	<-p.ctx.done
}

// Err returns an error that is set by RunLoop(). It must be called after
// RunLoop(). If not, it causes panic.
func (p *Pinger) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ctx.err
}

// Function to reset inner variables
func (p *Pinger) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	//TODO implement reset of the values
}

func (p *Pinger) listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {
		p.mu.Lock()
		p.ctx.err = err
		p.mu.Unlock()
		p.debugln("Run(): close(p.ctx.done)")
		close(p.ctx.done)
		return nil
	}
	return conn
}

func (p *Pinger) run(once bool) {
	p.debugln("Run(): Start")
	var conn, conn6 *icmp.PacketConn
	if p.hasIPv4 {
		if conn = p.listen(ipv4Proto[p.network], p.source); conn == nil {
			return
		}
		defer conn.Close()
	}

	if p.hasIPv6 {
		if conn6 = p.listen(ipv6Proto[p.network], p.source6); conn6 == nil {
			return
		}
		defer conn6.Close()
	}

	recv := make(chan *packet, 1)
	recvCtx := newContext()
	wg := new(sync.WaitGroup)

	p.debugln("Run(): call recvICMP()")
	if conn != nil {
		wg.Add(1)
		go p.recvICMP(conn, recv, recvCtx, wg)
	}
	if conn6 != nil {
		wg.Add(1)
		go p.recvICMP(conn6, recv, recvCtx, wg)
	}

	if p.Train {
		p.rounds = p.TrainSize
	}

	p.debugln("Run(): call sendICMP()")
	queue, err := p.sendICMP(conn, conn6)

	//ticker := time.NewTicker(p.MaxRTT)
	//timer := time.NewTimer(p.getNextWait()) // Original Line
	timer := time.NewTimer(p.Timeout) //We set the OnIdle to be called after 1 sec of timeout.
	// This time we do not send ICMP message is received.
	timer2 := time.NewTimer(p.getNextWait()) // Line to decide when to send the next IMCP

mainloop:
	for {
		select {
		case <-p.ctx.stop:
			p.debugln("Run(): <-p.ctx.stop")
			break mainloop
		case <-recvCtx.done:
			p.debugln("Run(): <-recvCtx.done")
			p.mu.Lock()
			err = recvCtx.err
			p.mu.Unlock()
			break mainloop
		case <-timer.C:
			p.mu.Lock()
			handler := p.OnIdle
			p.mu.Unlock()
			if handler != nil {
				handler()
			}
			if once || err != nil {
				break mainloop
			}
			//p.debugln("Run(): call sendICMP()")
			//queue, err = p.sendICMP(conn, conn6)
			//timer.Reset(p.getNextWait()) // Original Line
			//timer.Reset(p.getNextWait()) // Modified Line
		case <-timer2.C:
			queue, err = p.sendICMP(conn, conn6)
			timer2.Reset(p.getNextWait())
		case r := <-recv:
			p.debugln("Run(): <-recv")
			p.procRecv(r, queue)
		}
	}
	//ticker.Stop()

	if !timer.Stop() {
		<-timer.C
	}

	p.debugln("Run(): close(recvCtx.stop)")
	close(recvCtx.stop)
	p.debugln("Run(): wait recvICMP()")
	wg.Wait()

	p.mu.Lock()
	p.ctx.err = err
	p.mu.Unlock()

	p.debugln("Run(): close(p.ctx.done)")
	close(p.ctx.done)
	p.debugln("Run(): End")
}

func delayedTransmit(delay time.Duration, typ icmp.Type, conn *icmp.PacketConn, ra net.Addr, size, id, seqn int) {

	if delay > 0 {
		timer := time.NewTimer(delay)
		<-timer.C
	}

	t := timeToBytes(time.Now())

	if size-TimeSliceLength != 0 {
		t = append(t, byteSliceOfSize(size-TimeSliceLength)...)
	}

	bytes, err := (&icmp.Message{
		Type: typ, Code: 0,
		Body: &icmp.Echo{
			ID: id, Seq: seqn,
			Data: t,
		},
	}).Marshal(nil)

	if err != nil {
		return
	}

	for {
		if _, err := conn.WriteTo(bytes, ra); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		break
	}
}

func (p *Pinger) sendICMP(conn, conn6 *icmp.PacketConn) (map[int]map[int]bool, error) {
	p.debugln("sendICMP(): Start")
	queue := make(map[int]map[int]bool)
	wg := new(sync.WaitGroup)
	for _, host := range p.hosts {
		queue[host.id] = make(map[int]bool)
		var typ icmp.Type
		var cn *icmp.PacketConn
		if isIPv4(host.addr.IP) {
			typ = ipv4.ICMPTypeEcho
			cn = conn
		} else if isIPv6(host.addr.IP) {
			typ = ipv6.ICMPTypeEchoRequest
			cn = conn6
		} else {
			continue
		}
		if cn == nil {
			continue
		}
		var dst net.Addr = host.addr
		if p.network == "udp" {
			dst = &net.UDPAddr{IP: host.addr.IP, Zone: host.addr.Zone}
		}
		for i := 1; i <= p.rounds; i++ {
			queue[host.id][host.seqn+i] = true
			p.debugln("sendICMP(): Invoke goroutine")
			if p.UsePattern {
				/*
					fmt.Printf("================================ We entered usePattern for sendICMP ================================ \n")
					fmt.Printf("Value of i: %v.\n", i)
					fmt.Printf("Value of p.TrainInt: %v.\n", p.TrainInt)
					fmt.Printf("Value of delay being sent to the Delay Function: %v.\n", p.TrainInt*time.Duration(i))
					fmt.Printf("================================ End of case with Use Pattern sendICMP ================================ \n")
				*/
				go delayedTransmit(p.TrainInt*time.Duration(i), typ, cn, dst, p.Pattern[(host.seqn+i)%len(p.Pattern)], host.id, host.seqn+i)
				p.SentICMP++
			} else {
				/*
					fmt.Printf("================================ We entered Without usePattern for sendICMP ================================ \n")
					fmt.Printf("Value of i: %v.\n", i)
					fmt.Printf("Value of p.TrainInt: %v.\n", p.TrainInt)
					fmt.Printf("Value of delay being sent to the Delay Function: %v.\n", p.TrainInt*time.Duration(i))
					fmt.Printf("================================ End of case with Without Pattern sendICMP ================================ \n")
				*/
				go delayedTransmit(p.TrainInt*time.Duration(i), typ, cn, dst, p.Size, host.id, host.seqn+i)
				p.SentICMP++
			}
		}
	}

	p.mu.Lock()
	for key, host := range p.hosts {
		host.seqn = host.seqn + p.rounds
		p.hosts[key] = host
	}
	p.mu.Unlock()

	wg.Wait()
	p.debugln("sendICMP(): End")
	return queue, nil
}

func (p *Pinger) recvICMP(conn *icmp.PacketConn, recv chan<- *packet, ctx *context, wg *sync.WaitGroup) {
	p.debugln("recvICMP(): Start")
	for {
		select {
		case <-ctx.stop:
			p.debugln("recvICMP(): <-ctx.stop")
			wg.Done()
			p.debugln("recvICMP(): wg.Done()")
			return
		default:
		}

		bytes := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		p.debugln("recvICMP(): ReadFrom Start")
		_, ra, err := conn.ReadFrom(bytes)
		p.debugln("recvICMP(): ReadFrom End")
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					p.debugln("recvICMP(): Read Timeout")
					continue
				} else {
					p.debugln("recvICMP(): OpError happen", err)
					p.mu.Lock()
					ctx.err = err
					p.mu.Unlock()
					p.debugln("recvICMP(): close(ctx.done)")
					close(ctx.done)
					p.debugln("recvICMP(): wg.Done()")
					wg.Done()
					return
				}
			}
		}
		p.debugln("recvICMP(): p.recv <- packet")

		select {
		case recv <- &packet{bytes: bytes, addr: ra}:
		case <-ctx.stop:
			p.debugln("recvICMP(): <-ctx.stop")
			wg.Done()
			p.debugln("recvICMP(): wg.Done()")
			return
		}
	}
}

func (p *Pinger) procRecv(recv *packet, queue map[int]map[int]bool) {
	var ipaddr *net.IPAddr
	switch adr := recv.addr.(type) {
	case *net.IPAddr:
		ipaddr = adr
	case *net.UDPAddr:
		ipaddr = &net.IPAddr{IP: adr.IP, Zone: adr.Zone}
	default:
		p.debugln("procRecv(): Wrong address type", recv.addr)
		return
	}

	addr := ipaddr.String()
	//fmt.Printf("Value of address: %v.\n", addr)
	p.mu.Lock()
	if _, ok := p.hosts[addr]; !ok {
		p.mu.Unlock()
		p.debugln("procRecv(): Addr ", addr, " not in pool of addresses")
		return
	}
	host := p.hosts[addr]
	//fmt.Printf("Value of host's address: %v.\n", host.addr)
	p.mu.Unlock()

	var bytes []byte
	var proto int
	if isIPv4(ipaddr.IP) {
		if p.network == "ip" {
			bytes = ipv4Payload(recv.bytes)
		} else {
			bytes = recv.bytes
		}
		proto = ProtocolICMP
	} else if isIPv6(ipaddr.IP) {
		bytes = recv.bytes
		proto = ProtocolIPv6ICMP
	} else {
		p.debugln("procRecv(): ", ipaddr.IP, " !isIPv4")
		return
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, bytes); err != nil {
		p.debugln("procRecv(): Error parsing ICMP ", err)
		return
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		return
	}

	var rtt time.Duration
	var rttFormatted float32
	var seqNum int
	var timestamp = time.Now()
	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		//handler := p.OnRecv
		rtt = time.Since(bytesToTime(pkt.Data[:TimeSliceLength]))
		rttFormatted = float32(rtt) / float32(time.Millisecond)
		seqNum = pkt.Seq
		//handler(ipaddr, rtt, pkt.Seq)
		//fmt.Printf("After validating ICMP message, value of rtt: %v.\n", rtt)

		p.SeqsAndRTTS[seqNum] = rttFormatted
		p.SeqsAndTime[seqNum] = timestamp.Format("2006-01-02 15:04:05")

		//p.RTTS = append(p.RTTS, rtt)
		//p.SeqsNums = append(p.SeqsNums, seqNum)

		p.ProcessedICMP++

		//fmt.Printf("len=%d cap=%d %v\n", len(p.RTTS), cap(p.RTTS), p.RTTS)
		//fmt.Printf("\n")
		//fmt.Printf("Value of Host ID: %v.\n", host.id)
		//fmt.Printf("Value of Packet ID: %v.\n", pkt.ID)
		if host.id == pkt.ID {
			if h, ok := queue[pkt.ID]; ok {
				if _, ok := h[pkt.Seq]; ok {
					delete(queue[pkt.ID], pkt.Seq)
					rtt = time.Since(bytesToTime(pkt.Data[:TimeSliceLength]))
					p.mu.Lock()
					handler := p.OnRecv
					p.mu.Unlock()
					if handler != nil {
						//fmt.Printf("After validating host id, matches packet id, Value of rtt: %v.\n", rtt)
						//p.RTTS = append(p.RTTS, rtt)
						//fmt.Printf("len=%d cap=%d %v\n", len(p.RTTS), cap(p.RTTS), p.RTTS)
						handler(ipaddr, rtt, pkt.Seq)
					}
				} else {
					p.debugln("procRecv(): error mapping Seqs ", pkt.Seq, h)
				}
			} else {
				p.debugln("procRecv(): Waiting no packets for ", host.id)
			}
		}
	default:
		p.debugln("procRecv(): Not an ICMP packet")
		return

	}

}

func (p *Pinger) debugln(args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Debug {
		log.Println(args...)
	}
}

func (p *Pinger) debugf(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Debug {
		log.Printf(format, args...)
	}
}
