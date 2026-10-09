package tests

import (
	"math"
	"reflect"
	"testing"

	"ks-intercom-gateway/src/audio"
)

// Reference values from ITU-T G.711.
func TestG711Vectors(t *testing.T) {
	ulaw := []struct {
		pcm int16
		b   byte
	}{{0, 0xFF}, {-1, 0x7F}, {32767, 0x80}, {-32768, 0x00}}
	for _, c := range ulaw {
		if got := audio.UlawEncode(c.pcm); got != c.b {
			t.Errorf("ulaw encode %d = %#x, want %#x", c.pcm, got, c.b)
		}
	}
	if audio.UlawDecode(0x80) != 32124 || audio.UlawDecode(0x00) != -32124 || audio.UlawDecode(0xFF) != 0 {
		t.Error("ulaw decode vectors")
	}
	alaw := []struct {
		pcm int16
		b   byte
	}{{0, 0xD5}, {-1, 0x55}, {32767, 0xAA}, {-32768, 0x2A}}
	for _, c := range alaw {
		if got := audio.AlawEncode(c.pcm); got != c.b {
			t.Errorf("alaw encode %d = %#x, want %#x", c.pcm, got, c.b)
		}
	}
	if audio.AlawDecode(0xAA) != 32256 || audio.AlawDecode(0x2A) != -32256 ||
		audio.AlawDecode(0xD5) != 8 || audio.AlawDecode(0x55) != -8 {
		t.Error("alaw decode vectors")
	}
}

func TestG711RoundTrip(t *testing.T) {
	for v := -32000; v <= 32000; v += 97 {
		tol := math.Max(40, math.Abs(float64(v))*0.05)
		if got := audio.UlawDecode(audio.UlawEncode(int16(v))); math.Abs(float64(got)-float64(v)) > tol {
			t.Fatalf("ulaw %d -> %d", v, got)
		}
		if got := audio.AlawDecode(audio.AlawEncode(int16(v))); math.Abs(float64(got)-float64(v)) > tol {
			t.Fatalf("alaw %d -> %d", v, got)
		}
	}
}

func tone(n int) []int16 {
	s := make([]int16, n)
	for i := range s {
		s[i] = int16(8000 * math.Sin(2*math.Pi*400*float64(i)/8000))
	}
	return s
}

func TestResampleKeepsLengthAndLevel(t *testing.T) {
	var up audio.Upsampler
	var down audio.Downsampler
	hi := up.Process(tone(640), nil)
	if len(hi) != 1280 {
		t.Fatalf("up: %d samples", len(hi))
	}
	lo := down.Process(hi, nil)
	if len(lo) != 640 {
		t.Fatalf("down: %d samples", len(lo))
	}
	var peak int16
	for _, v := range lo[100:] {
		if v > peak {
			peak = v
		}
	}
	if peak < 6500 {
		t.Fatalf("a 400 Hz tone lost its level: peak %d", peak)
	}
}

// Frames arrive in arbitrary sizes; the result must not depend on the chunking.
func TestResampleIsChunkIndependent(t *testing.T) {
	in := tone(1000)
	var u1, u2 audio.Upsampler
	var d1, d2 audio.Downsampler
	if !reflect.DeepEqual(u1.Process(in, nil), append(u2.Process(in[:333], nil), u2.Process(in[333:], nil)...)) {
		t.Error("upsampler output depends on chunking")
	}
	hi := tone(2000)
	if !reflect.DeepEqual(d1.Process(hi, nil), append(d2.Process(hi[:501], nil), d2.Process(hi[501:], nil)...)) {
		t.Error("downsampler output depends on chunking")
	}
}
