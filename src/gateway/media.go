package gateway

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"ks-intercom-gateway/src/audio"
)

// ---- RTP session -------------------------------------------------------

const (
	samplesPer20ms = 160
	kioskFrame     = 1280 // 80 ms at 16 kHz, samples (2560 bytes)
	maxTxQueue     = 1600 // 200 ms at 8 kHz
)

type rtpSession struct {
	conn *net.UDPConn
	pt   uint8

	mu     sync.Mutex
	remote *net.UDPAddr
	latch  bool
	txq    []int16
	down   audio.Downsampler

	ssrc uint32
	seq  uint16
	ts   uint32

	onAudio func(frame []byte)
	quit    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

func newRTPSession(ip string, minPort, maxPort int) (*rtpSession, error) {
	if maxPort <= minPort {
		return nil, errors.New("rtp port range")
	}
	n := (maxPort - minPort) / 2
	start := rand.Intn(n + 1)
	for i := 0; i <= n; i++ {
		port := minPort + 2*((start+i)%(n+1))
		c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err != nil {
			continue
		}
		return &rtpSession{
			conn: c, quit: make(chan struct{}),
			ssrc: rand.Uint32(), seq: uint16(rand.Intn(1 << 16)), ts: rand.Uint32(),
		}, nil
	}
	return nil, errors.New("no free RTP port")
}

func (r *rtpSession) Port() int { return r.conn.LocalAddr().(*net.UDPAddr).Port }

func (r *rtpSession) SetRemote(a *net.UDPAddr, pt uint8) {
	r.mu.Lock()
	r.remote, r.pt = a, pt
	r.mu.Unlock()
}

// Start runs the receive and send loops. onAudio gets 80 ms frames of
// PCM16 mono 16 kHz, the intercom's own format.
func (r *rtpSession) Start(onAudio func(frame []byte)) {
	r.onAudio = onAudio
	r.wg.Add(2)
	go r.rxLoop()
	go r.txLoop()
}

func (r *rtpSession) Close() {
	r.once.Do(func() {
		close(r.quit)
		r.conn.Close()
	})
	r.wg.Wait()
}

func (r *rtpSession) rxLoop() {
	defer r.wg.Done()
	buf := make([]byte, 2048)
	var (
		have     bool
		expected uint16
		up       audio.Upsampler
		pcm8     []int16
		pcm16    []int16
	)
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if len(pkt) < 12 || pkt[0]>>6 != 2 {
			continue
		}
		r.mu.Lock()
		pt := r.pt
		if !r.latch {
			// Symmetric RTP: answer where the media really comes from.
			r.latch = true
			r.remote = src
		}
		r.mu.Unlock()
		if pkt[1]&0x7F != pt {
			continue // DTMF, comfort noise...
		}
		hdr := 12 + 4*int(pkt[0]&0x0F)
		if pkt[0]&0x10 != 0 {
			if len(pkt) < hdr+4 {
				continue
			}
			hdr += 4 + 4*int(binary.BigEndian.Uint16(pkt[hdr+2:]))
		}
		end := len(pkt)
		if pkt[0]&0x20 != 0 && end > hdr {
			end -= int(pkt[end-1])
		}
		if hdr >= end {
			continue
		}
		seq := binary.BigEndian.Uint16(pkt[2:])
		if have {
			d := int16(seq - expected)
			if d < 0 {
				continue // late or duplicate
			}
			if d > 0 && d <= 10 {
				for i := 0; i < int(d)*samplesPer20ms; i++ {
					pcm8 = append(pcm8, 0)
				}
			}
		}
		have = true
		expected = seq + 1
		pcm8 = audio.DecodeG711(pt, pkt[hdr:end], pcm8)
		pcm16 = up.Process(pcm8, pcm16)
		pcm8 = pcm8[:0]
		for len(pcm16) >= kioskFrame {
			if r.onAudio != nil {
				r.onAudio(audio.PCMBytes(pcm16[:kioskFrame]))
			}
			pcm16 = pcm16[kioskFrame:]
		}
	}
}

// PushFromKiosk queues a frame of 16 kHz PCM16 for the SIP side.
func (r *rtpSession) PushFromKiosk(frame []byte) {
	s := audio.PCMSamples(frame)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txq = r.down.Process(s, r.txq)
	if len(r.txq) > maxTxQueue {
		r.txq = r.txq[len(r.txq)-maxTxQueue:]
	}
}

func (r *rtpSession) txLoop() {
	defer r.wg.Done()
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	pkt := make([]byte, 12, 12+samplesPer20ms)
	for {
		select {
		case <-r.quit:
			return
		case <-t.C:
		}
		r.mu.Lock()
		remote, pt := r.remote, r.pt
		var chunk []int16
		if len(r.txq) >= samplesPer20ms {
			chunk = append(chunk, r.txq[:samplesPer20ms]...)
			r.txq = r.txq[samplesPer20ms:]
		}
		seq, ts := r.seq, r.ts
		r.seq++
		r.ts += samplesPer20ms
		r.mu.Unlock()
		if remote == nil {
			continue
		}
		pkt = pkt[:12]
		pkt[0], pkt[1] = 0x80, pt
		binary.BigEndian.PutUint16(pkt[2:], seq)
		binary.BigEndian.PutUint32(pkt[4:], ts)
		binary.BigEndian.PutUint32(pkt[8:], r.ssrc)
		if chunk == nil {
			for i := 0; i < samplesPer20ms; i++ {
				pkt = append(pkt, audio.SilenceByte(pt))
			}
		} else {
			pkt = audio.EncodeG711(pt, chunk, pkt)
		}
		_, _ = r.conn.WriteToUDP(pkt, remote)
	}
}
