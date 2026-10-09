// Package audio holds the sample-level pieces of the gateway: G.711
// companding and the 8 kHz <-> 16 kHz conversion.
package audio

// ---- G.711 -------------------------------------------------------------

func UlawDecode(u byte) int16 {
	u = ^u
	t := (int(u&0x0F) << 3) + 0x84
	t <<= (u & 0x70) >> 4
	if u&0x80 != 0 {
		return int16(0x84 - t)
	}
	return int16(t - 0x84)
}

func UlawEncode(pcm int16) byte {
	const bias, clip = 0x84, 32635
	s := int(pcm)
	mask := 0xFF
	if s < 0 {
		s = -s
		mask = 0x7F
	}
	if s > clip {
		s = clip
	}
	s += bias
	seg := 7
	for m := 0x4000; seg > 0 && s&m == 0; m >>= 1 {
		seg--
	}
	return (byte(seg<<4) | byte((s>>(seg+3))&0x0F)) ^ byte(mask)
}

func AlawDecode(a byte) int16 {
	a ^= 0x55
	t := int(a&0x0F) << 4
	seg := (a & 0x70) >> 4
	switch seg {
	case 0:
		t += 8
	case 1:
		t += 0x108
	default:
		t += 0x108
		t <<= seg - 1
	}
	if a&0x80 != 0 {
		return int16(t)
	}
	return int16(-t)
}

var alawEnd = [8]int{0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF}

func AlawEncode(pcm int16) byte {
	v := int(pcm) >> 3
	mask := byte(0xD5)
	if v < 0 {
		mask = 0x55
		v = -v - 1
	}
	seg := 0
	for seg < 8 && v > alawEnd[seg] {
		seg++
	}
	if seg >= 8 {
		return 0x7F ^ mask
	}
	a := byte(seg << 4)
	if seg < 2 {
		a |= byte((v >> 1) & 0x0F)
	} else {
		a |= byte((v >> seg) & 0x0F)
	}
	return a ^ mask
}

// Static RTP payload types of the two G.711 variants.
const (
	PCMU = 0
	PCMA = 8
)

func DecodeG711(pt uint8, in []byte, out []int16) []int16 {
	for _, b := range in {
		if pt == PCMA {
			out = append(out, AlawDecode(b))
		} else {
			out = append(out, UlawDecode(b))
		}
	}
	return out
}

func EncodeG711(pt uint8, in []int16, out []byte) []byte {
	for _, s := range in {
		if pt == PCMA {
			out = append(out, AlawEncode(s))
		} else {
			out = append(out, UlawEncode(s))
		}
	}
	return out
}

func SilenceByte(pt uint8) byte {
	if pt == PCMA {
		return AlawEncode(0)
	}
	return UlawEncode(0)
}
