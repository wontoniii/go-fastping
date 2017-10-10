/*
 *
 */

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	mpping "github.com/wontoniii/go-mp-ping"
)

type response struct {
	addr *net.IPAddr
	rtt  time.Duration
	seqn int
}

func ping(hostname, source string, useUDP, debug bool, count, interval, trainS, trainI, gamma int, pattern []int) {
	p := mpping.NewPinger()
	if useUDP {
		p.Network("udp")
	}

	if debug {
		p.Debug = true
	}

	netProto := "ip4:icmp"
	if strings.Index(hostname, ":") != -1 {
		netProto = "ip6:ipv6-icmp"
	}
	ra, err := net.ResolveIPAddr(netProto, hostname)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if source != "" {
		p.Source(source)
	}

	if trainS > 1 {
		p.Train = true
		p.TrainSize = trainS
		if trainI > 0 {
			p.TrainInt = time.Duration(trainI) * time.Millisecond
		}
	}

	if gamma > 0 {
		p.Gamma = time.Duration(gamma) * time.Millisecond
	}

	if len(pattern) > 0 {
		p.SetPattern(pattern)
	}

	p.AddIPAddr(ra)

	onRecv, onIdle := make(chan *response), make(chan bool)
	p.OnRecv = func(addr *net.IPAddr, t time.Duration, seqn int) {
		onRecv <- &response{addr: addr, rtt: t, seqn: seqn}
	}
	p.OnIdle = func() {
		onIdle <- true
	}

	p.MaxRTT = time.Duration(interval) * time.Millisecond

	var sent, received, crec int
	var min, max, avg, mdev float32
	results := make([]float32, 0)
	fmt.Printf("PING %s (%s) %d(%d) bytes of data\n", hostname, ra.String(), 0, 0)
	st := time.Now()

	sent = trainS
	p.RunLoop()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

loop:
	for {
		select {
		case <-c:
			break loop
		case res := <-onRecv:
			results = append(results, float32(res.rtt)/float32(time.Millisecond))
			received += 1
			crec += 1
			fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n", p.Size+56, res.addr, res.seqn, 128, float32(res.rtt)/float32(time.Millisecond))
			if sent/trainS >= count && received/trainS == count {
				break loop
			}
		case <-onIdle:
			if sent/trainS >= count {
				break loop
			}
			sent += trainS
			if crec == 0 {
				fmt.Printf("%s : unreachable\n", hostname)
			} else {
				crec = 0
			}
		case <-p.Done():
			if err = p.Err(); err != nil {
				fmt.Println("Ping failed:", err)
			}
			break loop
		}
	}
	et := time.Now()
	elapsed := et.Sub(st)
	fmt.Printf("--- %s ping statistics ---\n", hostname)
	fmt.Printf("%d packets transmitted, %d received, %.2f%% packet loss, time %d ms\n", sent, received, float32(sent-received)/float32(sent), int(elapsed/time.Millisecond))
	lenResults := float32(len(results))
	if lenResults > 0 {
		min = 1000000
		max = -1
		avg = 0
		mdev = 0
		for _, val := range results {
			if val < min {
				min = val
			}
			if val > max {
				max = val
			}
			avg += val
		}
		avg = avg / lenResults
		for _, val := range results {
			mdev += (val - avg) * (val - avg)
		}
		mdev = mdev / lenResults
		fmt.Printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min, avg, max, mdev)
	}
	signal.Stop(c)
	p.Stop()
}

func main() {
	var useUDP, debug bool
	var count, interval, trainS, trainI, gamma int
	var source, hostname, pattern string
	var intPattern []int
	flag.BoolVar(&useUDP, "u", false, "use non-privileged datagram-oriented UDP as ICMP endpoints (shorthand)")
	flag.BoolVar(&debug, "d", false, "debug statements")
	flag.IntVar(&count, "c", 10, "number of probes to send")
	flag.IntVar(&interval, "i", 1000, "average for probes interarrival (milliseconds)")
	flag.IntVar(&trainS, "t", 1, "number of pings in single train")
	flag.IntVar(&trainI, "I", 100, "interval in between probes in a train (milliseconds)")
	flag.IntVar(&gamma, "g", 0, "gamma for uniform distribution (milliseconds)")
	flag.StringVar(&source, "s", "", "source address")
	flag.StringVar(&pattern, "p", "", "pattern of sizes to use in comma separated format (no spaces)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [options] hostname [source]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	hostname = flag.Arg(0)
	if len(hostname) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if pattern != "" {
		//Process pattern
		vals := strings.Split(pattern, ",")
		for _, i := range vals {
			j, err := strconv.Atoi(i)
			if err != nil {
				flag.Usage()
				os.Exit(1)
			}
			intPattern = append(intPattern, j)
		}
	}

	ping(hostname, source, useUDP, debug, count, interval, trainS, trainI, gamma, intPattern)

}
