package audio

import "encoding/binary"

// ---- resampling 8 kHz <-> 16 kHz ------------------------------------------

// Upsampler doubles the rate by linear interpolation.
type Upsampler struct{ last int16 }

func (u *Upsampler) Process(in []int16, out []int16) []int16 {
	for _, x := range in {
		out = append(out, int16((int32(u.last)+int32(x))/2), x)
		u.last = x
	}
	return out
}

// Downsampler halves the rate with a [1 2 1]/4 low-pass.
type Downsampler struct {
	prev  int16 // x[2n-1]
	carry []int16
}

func (d *Downsampler) Process(in []int16, out []int16) []int16 {
	buf := append(d.carry, in...)
	i := 0
	for ; i+1 < len(buf); i += 2 {
		y := (int32(d.prev) + 2*int32(buf[i]) + int32(buf[i+1])) / 4
		out = append(out, int16(y))
		d.prev = buf[i+1]
	}
	d.carry = append([]int16(nil), buf[i:]...)
	return out
}

func PCMBytes(s []int16) []byte {
	b := make([]byte, 2*len(s))
	for i, v := range s {
		binary.LittleEndian.PutUint16(b[2*i:], uint16(v))
	}
	return b
}

func PCMSamples(b []byte) []int16 {
	s := make([]int16, len(b)/2)
	for i := range s {
		s[i] = int16(binary.LittleEndian.Uint16(b[2*i:]))
	}
	return s
}
