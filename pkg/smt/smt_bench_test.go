//nolint:errcheck // benchmark assertions
package smt

import (
	"fmt"
	"testing"
)

func BenchmarkSMTInsert(b *testing.B) {
	sizes := []int{10, 100, 1000}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			data := make([][2][]byte, n)
			for i := range data {
				data[i][0] = []byte(fmt.Sprintf("key-%d", i))
				data[i][1] = []byte(fmt.Sprintf("val-%d", i))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tree := New(256)
				for j := 0; j < n; j++ {
					tree.Insert(data[j][0], data[j][1])
				}
			}
		})
	}
}

func BenchmarkSMTProve(b *testing.B) {
	sizes := []int{10, 100, 1000}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			tree := New(256)
			keys := make([][]byte, n)
			for i := 0; i < n; i++ {
				k := []byte(fmt.Sprintf("key-%d", i))
				keys[i] = k
				tree.Insert(k, []byte(fmt.Sprintf("val-%d", i)))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tree.Prove(keys[i%n])
			}
		})
	}
}

func BenchmarkSMTVerify(b *testing.B) {
	n := 100
	tree := New(256)
	type entry struct {
		key   []byte
		value []byte
		proof [][hashLen]byte
	}
	entries := make([]entry, n)
	for i := 0; i < n; i++ {
		k := []byte(fmt.Sprintf("key-%d", i))
		v := []byte(fmt.Sprintf("val-%d", i))
		tree.Insert(k, v)
	}
	root := tree.Root()
	for i := 0; i < n; i++ {
		k := []byte(fmt.Sprintf("key-%d", i))
		v := []byte(fmt.Sprintf("val-%d", i))
		p, _ := tree.Prove(k)
		entries[i] = entry{k, v, p}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := entries[i%n]
		tree.Verify(e.key, e.value, root, e.proof)
	}
}

func BenchmarkSMTBulkInsert(b *testing.B) {
	sizes := []int{10, 100, 1000}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			entries := make(map[string][]byte, n)
			for i := 0; i < n; i++ {
				entries[fmt.Sprintf("key-%d", i)] = []byte(fmt.Sprintf("val-%d", i))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tree := New(256)
				tree.BulkInsert(entries)
			}
		})
	}
}
