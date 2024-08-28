// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"slices"

	"github.com/holiman/uint256"
)

// stackArena is an arena which actual evm stacks use for data storage
type stackArena struct {
	data []uint256.Int
	top  int // first free slot
}

func (sa *stackArena) push(value *uint256.Int) {
	if len(sa.data) <= sa.top {
		// we need to grow the arena
		sa.data = slices.Grow(sa.data, 512)
		sa.data = sa.data[:cap(sa.data)]
	}
	sa.data[sa.top] = *value
	sa.top++
}

func (sa *stackArena) pop() {
	sa.top--
}

func newArena() *stackArena {
	return &stackArena{
		data: make([]uint256.Int, 1024),
	}
}

// stack returns an instance of a stack which uses the underlying arena. The instance
// must be released by invoking the (*Stack).release() method
func (sa *stackArena) stack() *Stack {
	return &Stack{
		bottom: sa.top,
		size:   0,
		inner:  sa,
	}
}

// release un-claims the area of the arena which was claimed by the stack.
func (s *Stack) release() {
	// When the stack is returned, need to notify the arena that the new 'top' is
	// the returned stack's bottom.
	s.inner.top = s.bottom
}

// newStackForTesting is meant to be used solely for testing. It creates a stack
// backed by a newly allocated arena.
func newStackForTesting() *Stack {
	arena := &stackArena{
		data: make([]uint256.Int, 256),
	}
	return arena.stack()
}

// Stack is an object for basic stack operations. Items popped to the stack are
// expected to be changed and modified. stack does not take care of adding newly
// initialized objects.
type Stack struct {
	bottom int // bottom is the index of the first element of this stack
	size   int // size is the number of elements in this stack
	inner  *stackArena
}

// Data returns the underlying uint256.Int array.
func (st *Stack) Data() []uint256.Int {
	return st.inner.data[st.bottom : st.bottom+st.size]
}

func (st *Stack) push(d *uint256.Int) {
	// NOTE push limit (1024) is checked in baseCheck
	st.inner.push(d)
	st.size++
}

func (st *Stack) pop() uint256.Int {
	ret := st.inner.data[st.bottom+st.size-1]
	st.inner.pop()
	st.size--
	return ret
}

func (st *Stack) len() int {
	return st.size
}

func (st *Stack) swap1() {
	st.inner.data[st.bottom+st.size-2], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-2]
}
func (st *Stack) swap2() {
	st.inner.data[st.bottom+st.size-3], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-3]
}
func (st *Stack) swap3() {
	st.inner.data[st.bottom+st.size-4], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-4]
}
func (st *Stack) swap4() {
	st.inner.data[st.bottom+st.size-5], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-5]
}
func (st *Stack) swap5() {
	st.inner.data[st.bottom+st.size-6], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-6]
}
func (st *Stack) swap6() {
	st.inner.data[st.bottom+st.size-7], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-7]
}
func (st *Stack) swap7() {
	st.inner.data[st.bottom+st.size-8], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-8]
}
func (st *Stack) swap8() {
	st.inner.data[st.bottom+st.size-9], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-9]
}
func (st *Stack) swap9() {
	st.inner.data[st.bottom+st.size-10], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-10]
}
func (st *Stack) swap10() {
	st.inner.data[st.bottom+st.size-11], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-11]
}
func (st *Stack) swap11() {
	st.inner.data[st.bottom+st.size-12], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-12]
}
func (st *Stack) swap12() {
	st.inner.data[st.bottom+st.size-13], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-13]
}
func (st *Stack) swap13() {
	st.inner.data[st.bottom+st.size-14], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-14]
}
func (st *Stack) swap14() {
	st.inner.data[st.bottom+st.size-15], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-15]
}
func (st *Stack) swap15() {
	st.inner.data[st.bottom+st.size-16], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-16]
}
func (st *Stack) swap16() {
	st.inner.data[st.bottom+st.size-17], st.inner.data[st.bottom+st.size-1] = st.inner.data[st.bottom+st.size-1], st.inner.data[st.bottom+st.size-17]
}

func (st *Stack) dup(n int) {
	// TODO: check size of inner
	st.inner.data[st.bottom+st.size] = st.inner.data[st.bottom+st.size-n]
	st.size++
	st.inner.top++
}

func (st *Stack) peek() *uint256.Int {
	return &st.inner.data[st.bottom+st.size-1]
}

// Back returns the n'th item in stack
func (st *Stack) Back(n int) *uint256.Int {
	return &st.inner.data[st.bottom+st.size-n-1]
}
