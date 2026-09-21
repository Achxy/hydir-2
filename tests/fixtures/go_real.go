package main

var sink uint64

//go:noinline
func hydirMix(value uint64, count uint) uint64 {
	for index := uint(0); index < count; index++ {
		value = (value << 7) | (value >> 57)
		value ^= uint64(index) * 0x9e3779b97f4a7c15
	}
	return value
}

func main() {
	sink = hydirMix(0x123456789abcdef0, 7)
}
