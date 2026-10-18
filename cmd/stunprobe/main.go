package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"
)

func main() {
	count := flag.Int("count", 100, "number of fresh UDP sockets to probe")
	server := flag.String("server", "stun.l.google.com:19302", "STUN server host:port")
	expectedIP := flag.String("expected-ip", "", "expected public IP")
	wrongIP := flag.String("wrong-ip", "", "unexpected public IP (wrong adapter)")
	flag.Parse()

	var (
		correctCount int
		wrongCount   int
		otherCount   int
		timeoutCount int
		rtts         []float64
	)

	fmt.Printf("Starting STUN probe: %d iterations to %s (expecting %s, wrong %s)\n",
		*count, *server, *expectedIP, *wrongIP)

	for i := 0; i < *count; i++ {
		ip, rtt, err := probeOnce(*server)
		if err != nil {
			timeoutCount++
			if timeoutCount <= 5 {
				fmt.Printf("Probe %d error: %v\n", i, err)
			}
			continue
		}
		rtts = append(rtts, rtt.Seconds()*1000)
		ipStr := ip.String()

		switch {
		case *expectedIP != "" && ipStr == *expectedIP:
			correctCount++
		case *wrongIP != "" && ipStr == *wrongIP:
			wrongCount++
		default:
			otherCount++
			if otherCount <= 5 {
				fmt.Printf("Probe %d other IP: %s\n", i, ipStr)
			}
		}

		// Small interval between sockets so kernel socket table has distinct rows
		time.Sleep(10 * time.Millisecond)
	}

	medianRTT := 0.0
	if len(rtts) > 0 {
		sort.Float64s(rtts)
		medianRTT = rtts[len(rtts)/2]
	}

	fmt.Printf("RESULTS count=%d correct=%d wrong=%d other=%d timeouts=%d medianRtt=%.2fms\n",
		*count, correctCount, wrongCount, otherCount, timeoutCount, medianRTT)
	if wrongCount > 0 {
		os.Exit(1)
	}
}

func probeOnce(server string) (netip.Addr, time.Duration, error) {
	raddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	defer conn.Close()

	var req [20]byte
	req[0] = 0x00
	req[1] = 0x01
	binary.BigEndian.PutUint32(req[4:8], 0x2112a442)
	rand.Read(req[8:20])

	start := time.Now()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.WriteToUDP(req[:], raddr); err != nil {
		return netip.Addr{}, 0, err
	}

	var resp [512]byte
	n, _, err := conn.ReadFromUDP(resp[:])
	rtt := time.Since(start)
	if err != nil {
		return netip.Addr{}, rtt, err
	}

	if n < 20 || binary.BigEndian.Uint16(resp[0:2]) != 0x0101 {
		return netip.Addr{}, rtt, fmt.Errorf("invalid STUN response")
	}

	buf := resp[20:n]
	for len(buf) >= 4 {
		attrType := binary.BigEndian.Uint16(buf[0:2])
		attrLen := int(binary.BigEndian.Uint16(buf[2:4]))
		buf = buf[4:]
		if len(buf) < attrLen {
			break
		}
		val := buf[:attrLen]
		pad := (4 - (attrLen % 4)) % 4
		if len(buf) >= attrLen+pad {
			buf = buf[attrLen+pad:]
		} else {
			buf = nil
		}

		if attrType == 0x0020 && attrLen >= 8 {
			if val[1] == 0x01 {
				ipBytes := binary.BigEndian.Uint32(val[4:8]) ^ 0x2112a442
				var ip [4]byte
				binary.BigEndian.PutUint32(ip[:], ipBytes)
				return netip.AddrFrom4(ip), rtt, nil
			}
		}
	}
	return netip.Addr{}, rtt, fmt.Errorf("no mapped address")
}
