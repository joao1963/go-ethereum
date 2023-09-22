package bloom

import (
	"encoding/binary"
	"testing"
	"time"
)

type hashable []byte

func (h hashable) Write(p []byte) (n int, err error) { panic("not implemented") }
func (h hashable) Sum(b []byte) []byte               { panic("not implemented") }
func (h hashable) Reset()                            { panic("not implemented") }
func (h hashable) BlockSize() int                    { panic("not implemented") }
func (h hashable) Size() int                         { return 8 }
func (h hashable) Sum64() uint64 {
	hash := make([]byte, 8)
	copy(hash, h)
	return binary.BigEndian.Uint64(hash[0:8])
}

func TestBloom(t *testing.T) {
	bloom, _ := NewExpiringBloom(3, 1024, 10*time.Millisecond)

	testKey := hashable([]byte{0x01})
	bloom.Add(testKey)
	if !bloom.Contains(testKey) {
		t.Fatal()
	}
	time.Sleep(11 * time.Millisecond)
	if !bloom.Contains(testKey) {
		t.Fatal()
	}
	time.Sleep(11 * time.Millisecond)
	if !bloom.Contains(testKey) {
		t.Fatal()
	}
	time.Sleep(11 * time.Millisecond)
	if bloom.Contains(testKey) {
		t.Fatal()
	}
}

func TestBloom2(t *testing.T) {
	bloom, _ := NewExpiringBloom(3, 1024, 10*time.Second)

	testKey := hashable([]byte{0x01})
	// Add key in bloom 0
	bloom.Add(testKey)
	if !bloom.Contains(testKey) {
		t.Fatal()
	}
	// Override bloom 1
	bloom.tick()
	if !bloom.Contains(testKey) {
		t.Fatal()
	}
	// Override bloom 2
	bloom.tick()
	if !bloom.Contains(testKey) {
		t.Fatal()
	}
	// Override bloom 0
	bloom.tick()
	if bloom.Contains(testKey) {
		t.Fatal()
	}
}

func BenchmarkAdd(b *testing.B) {
	bloom, _ := NewExpiringBloom(2, 1024, 10*time.Second)

	testKey := hashable([]byte{0x01})
	for i := 0; i < b.N; i++ {
		bloom.Add(testKey)
	}
}

func BenchmarkAddGet(b *testing.B) {
	bloom, _ := NewExpiringBloom(2, 1024, 10*time.Second)

	var putKey = make([]byte, 8)
	var getKey = make([]byte, 8)
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(putKey, uint64(i))
		bloom.Add(hashable(putKey))
		binary.BigEndian.PutUint64(getKey, uint64(i^(i>>1)))
		_ = bloom.Contains(hashable(getKey))
	}
}

func BenchmarkGetEmpty(b *testing.B) {
	bloom, _ := NewExpiringBloom(10, 42*1024, 10*time.Second)
	var key = make([]byte, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(key, uint64(i))
		_ = bloom.Contains(hashable(key))
	}
}

func BenchmarkTick(b *testing.B) {
	bloom, _ := NewExpiringBloom(2, 1024, 10*time.Second)

	for i := 0; i < b.N; i++ {
		bloom.tick()
	}
}
