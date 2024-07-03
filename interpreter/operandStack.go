package interpreter

import "math"

type OperandStack struct {
	slots []uint64
}

// pushU64
func (s *OperandStack) pushU64(val uint64) {
	s.slots = append(s.slots, val)
}

// popU64
func (s *OperandStack) popU64() uint64 {
	if len(s.slots) == 0 {
		panic("operand stack is empty")
	}
	val := s.slots[len(s.slots)-1]
	s.slots = s.slots[:len(s.slots)-1]
	return val
}

// pushS64
func (s *OperandStack) pushS64(val int64) {
	s.pushU64(uint64(val))
}

// pushU32
func (s *OperandStack) pushU32(val uint32) {
	s.pushU64(uint64(val))
}

// pushS32
func (s *OperandStack) pushS32(val int32) {
	s.pushU64(uint64(val))
}

// pushF64
func (s *OperandStack) pushF64(val float64) {
	s.pushU64(math.Float64bits(val))
}

// pushF32
func (s *OperandStack) pushF32(val float32) {
	s.pushU32(math.Float32bits(val))
}

// pushBool
func (s *OperandStack) pushBool(val bool) {
	if val {
		s.pushU64(1)
	} else {
		s.pushU64(0)
	}
}

// popS64
func (s *OperandStack) popS64() int64 {
	return int64(s.popU64())
}

// popU32
func (s *OperandStack) popU32() uint32 {
	return uint32(s.popU64())
}

// popS32
func (s *OperandStack) popS32() int32 {
	return int32(s.popU64())
}

// popF64
func (s *OperandStack) popF64() float64 {
	return math.Float64frombits(s.popU64())
}

// popF32
func (s *OperandStack) popF32() float32 {
	return math.Float32frombits(s.popU32())
}

// popBool
func (s *OperandStack) popBool() bool {
	return s.popU64() != 0
}
