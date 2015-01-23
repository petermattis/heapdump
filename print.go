// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math"
	"strings"

	"golang.org/x/debug/dwarf"
	"golang.org/x/debug/ogle/arch"
)

// address is a type denoting addresses in the tracee.
type address uintptr

// typeAndAddress associates an address in the target with a DWARF type.
type typeAndAddress struct {
	Type    dwarf.Type
	Address address
}

// Routines to print a value using DWARF type descriptions.
// TODO: Does this deserve its own package? It has no dependencies on Server.

// A Printer pretty-prints a values in the target address space.
// It can be reused after each printing operation to avoid unnecessary
// allocations. However, it is not safe for concurrent access.
type Printer struct {
	err      error // Sticky error value.
	peeker   Peeker
	dwarf    *dwarf.Data
	arch     *arch.Architecture
	printBuf bytes.Buffer            // Accumulates the output.
	tmp      []byte                  // Temporary used for I/O.
	visited  map[typeAndAddress]bool // Prevents looping on cyclic data.
	types    map[string]dwarf.Type
}

// printf prints to printBuf.
func (p *Printer) printf(format string, args ...interface{}) {
	fmt.Fprintf(&p.printBuf, format, args...)
}

// errorf prints the error to printBuf, then sets the sticky error for the
// printer, if not already set.
func (p *Printer) errorf(format string, args ...interface{}) {
	fmt.Fprintf(&p.printBuf, "<"+format+">", args...)
	if p.err != nil {
		return
	}
	p.err = fmt.Errorf(format, args...)
}

// peek reads len bytes at addr, leaving p.tmp with the data and sized appropriately.
func (p *Printer) peek(addr address, length int64) bool {
	p.tmp = p.tmp[:length]
	err := p.peeker.peek(uintptr(addr), p.tmp)
	return err == nil
}

// peekPtr reads a pointer at addr.
func (p *Printer) peekPtr(addr address) (address, bool) {
	if p.peek(addr, int64(p.arch.PointerSize)) {
		return address(p.arch.Uintptr(p.tmp)), true
	}
	return 0, false
}

// peekUint8 reads a uint8 at addr.
func (p *Printer) peekUint8(addr address) (uint8, bool) {
	if p.peek(addr, 1) {
		return p.tmp[0], true
	}
	return 0, false
}

// peekInt reads an int of size s at addr.
func (p *Printer) peekInt(addr address, s int64) (int64, bool) {
	if p.peek(addr, s) {
		return p.arch.IntN(p.tmp), true
	}
	return 0, false
}

// peekUint reads a uint of size s at addr.
func (p *Printer) peekUint(addr address, s int64) (uint64, bool) {
	if p.peek(addr, s) {
		return p.arch.UintN(p.tmp), true
	}
	return 0, false
}

func (p *Printer) peekAddrStructField(t *dwarf.StructType, addr address, fieldName string) (address, bool) {
	f, err := getField(t, fieldName)
	if err != nil {
		p.errorf("%s", err)
		return 0, false
	}
	_, ok := f.Type.(*dwarf.PtrType)
	if !ok {
		p.errorf("struct field %s is not a pointer", fieldName)
		return 0, false
	}
	return addr + address(f.ByteOffset), true
}

// peekPtrStructField reads a pointer in the field fieldName of the struct
// of type t at address addr.
func (p *Printer) peekPtrStructField(t *dwarf.StructType, addr address, fieldName string) (address, bool) {
	f, err := getField(t, fieldName)
	if err != nil {
		p.errorf("%s", err)
		return 0, false
	}
	_, ok := f.Type.(*dwarf.PtrType)
	if !ok {
		p.errorf("struct field %s is not a pointer", fieldName)
		return 0, false
	}
	return p.peekPtr(addr + address(f.ByteOffset))
}

// peekUintStructField reads a uint in the field fieldName of the struct
// of type t at address addr.  The size of the uint is determined by the field.
func (p *Printer) peekUintStructField(t *dwarf.StructType, addr address, fieldName string) (uint64, bool) {
	f, err := getField(t, fieldName)
	if err != nil {
		p.errorf("%s", err)
		return 0, false
	}
	ut, ok := f.Type.(*dwarf.UintType)
	if !ok {
		p.errorf("struct field %s is not a uint", fieldName)
		return 0, false
	}
	return p.peekUint(addr+address(f.ByteOffset), ut.ByteSize)
}

// peekIntStructField reads an int in the field fieldName of the struct
// of type t at address addr.  The size of the int is determined by the field.
func (p *Printer) peekIntStructField(t *dwarf.StructType, addr address, fieldName string) (int64, bool) {
	f, err := getField(t, fieldName)
	if f == nil {
		p.errorf("%s", err)
		return 0, false
	}
	it, ok := f.Type.(*dwarf.IntType)
	if !ok {
		p.errorf("struct field %s is not an int", fieldName)
		return 0, false
	}
	return p.peekInt(addr+address(f.ByteOffset), it.ByteSize)
}

// Peeker is like a read that probes the remote address space.
type Peeker interface {
	peek(offset uintptr, buf []byte) error
}

func makeTypeMap(d *dwarf.Data) map[string]dwarf.Type {
	m := map[string]dwarf.Type{}
	for r := d.Reader(); true; {
		e, err := r.Next()
		if err != nil || e == nil {
			break
		}

		switch e.Tag {
		case dwarf.TagArrayType,
			dwarf.TagBaseType,
			dwarf.TagClassType,
			dwarf.TagEnumerationType,
			dwarf.TagPointerType,
			dwarf.TagReferenceType,
			dwarf.TagStructType,
			dwarf.TagSubroutineType,
			dwarf.TagTypedef,
			dwarf.TagUnspecifiedType:
			name := e.Val(dwarf.AttrName).(string)
			if strings.Contains(name, "runtime") {
				break
			}
			typ, err := d.Type(e.Offset)
			if err != nil {
				break
			}
			m[name] = typ
		}
	}
	return m
}

// NewPrinter returns a printer that can use the Peeker to access and print
// values of the specified architecture described by the provided DWARF data.
func NewPrinter(arch *arch.Architecture, dwarf *dwarf.Data, peeker Peeker) *Printer {
	return &Printer{
		peeker:  peeker,
		arch:    arch,
		dwarf:   dwarf,
		visited: make(map[typeAndAddress]bool),
		tmp:     make([]byte, 100), // Enough for a largish string.
		types:   makeTypeMap(dwarf),
	}
}

// reset resets the Printer. It must be called before starting a new
// printing operation.
func (p *Printer) reset() {
	p.err = nil
	p.printBuf.Reset()
	// Just wipe the map rather than reallocating. It's almost always tiny.
	for k := range p.visited {
		delete(p.visited, k)
	}
}

// Sprint returns the pretty-printed value of the item with the given name, such as "main.global".
func (p *Printer) Sprint(name string) (string, error) {
	entry, err := p.dwarf.LookupEntry(name)
	if err != nil {
		return "", err
	}
	p.reset()
	switch entry.Tag {
	case dwarf.TagVariable: // TODO: What other entries have global location attributes?
		var a address
		iface := entry.Val(dwarf.AttrLocation)
		if iface != nil {
			a = p.decodeLocation(iface.([]byte))
		}
		p.printEntryValueAt(entry, a)
	default:
		p.errorf("unrecognized entry type %s", entry.Tag)
	}
	return p.printBuf.String(), p.err
}

// Figure 24 of DWARF v4.
const (
	locationAddr = 0x03
)

// decodeLocation decodes the dwarf data describing an address.
func (p *Printer) decodeLocation(data []byte) address {
	switch data[0] {
	case locationAddr:
		return address(p.arch.Uintptr(data[1:]))
	default:
		p.errorf("unimplemented location type %#x", data[0])
	}
	return 0
}

// SprintEntry returns the pretty-printed value of the item with the specified DWARF Entry and address.
func (p *Printer) SprintEntry(entry *dwarf.Entry, a address) (string, error) {
	p.reset()
	p.printEntryValueAt(entry, a)
	return p.printBuf.String(), p.err
}

// printEntryValueAt pretty-prints the data at the specified addresss
// using the type information in the Entry.
func (p *Printer) printEntryValueAt(entry *dwarf.Entry, a address) {
	if a == 0 {
		p.printf("<nil>")
		return
	}
	switch entry.Tag {
	case dwarf.TagVariable, dwarf.TagFormalParameter:
		// OK
	default:
		p.errorf("unrecognized entry type %s", entry.Tag)
		return
	}
	iface := entry.Val(dwarf.AttrType)
	if iface == nil {
		p.errorf("no type")
		return
	}
	typ, err := p.dwarf.Type(iface.(dwarf.Offset))
	if err != nil {
		p.errorf("type lookup: %v", err)
		return
	}
	p.printValueAt(typ, a)
}

// printValueAt pretty-prints the data at the specified addresss
// using the provided type information.
func (p *Printer) printValueAt(typ dwarf.Type, a address) {
	if a != 0 {
		// Check if we are repeating the same type and address.
		ta := typeAndAddress{typ, a}
		if p.visited[ta] {
			p.printf("(%v %#x)", typ, a)
			return
		}
		p.visited[ta] = true
	}
	switch typ := typ.(type) {
	case *dwarf.BoolType:
		if typ.ByteSize != 1 {
			p.errorf("unrecognized bool size %d", typ.ByteSize)
			return
		}
		if b, ok := p.peekUint8(a); ok {
			p.printf("%t", b != 0)
		} else {
			p.errorf("couldn't read bool")
		}
	case *dwarf.PtrType:
		if ptr, ok := p.peekPtr(a); ok {
			if ptr == 0 {
				p.printf("<nil>")
			} else {
				name := typ.Type.String()
				if strings.Contains(name, "runtime") || name == "void" {
					p.printf("%#x", ptr)
				} else {
					p.printf("&")
					p.printValueAt(typ.Type, ptr)
				}
			}
		} else {
			p.errorf("couldn't read pointer")
		}
	case *dwarf.IntType:
		// Sad we can't tell a rune from an int32.
		if i, ok := p.peekInt(a, typ.ByteSize); ok {
			p.printf("%d", i)
		} else {
			p.errorf("couldn't read int")
		}
	case *dwarf.UintType:
		if u, ok := p.peekUint(a, typ.ByteSize); ok {
			p.printf("%d", u)
		} else {
			p.errorf("couldn't read uint")
		}
	case *dwarf.FloatType:
		if !p.peek(a, typ.ByteSize) {
			p.errorf("couldn't read float")
			return
		}
		switch typ.ByteSize {
		case 4:
			p.printf("%g", math.Float32frombits(uint32(p.arch.UintN(p.tmp))))
		case 8:
			p.printf("%g", math.Float64frombits(p.arch.UintN(p.tmp)))
		default:
			p.errorf("unrecognized float size %d", typ.ByteSize)
		}
	case *dwarf.ComplexType:
		if !p.peek(a, typ.ByteSize) {
			p.errorf("couldn't read complex")
			return
		}
		switch typ.ByteSize {
		case 8:
			r := math.Float32frombits(uint32(p.arch.UintN(p.tmp[:4])))
			i := math.Float32frombits(uint32(p.arch.UintN(p.tmp[4:8])))
			p.printf("%g", complex(r, i))
		case 16:
			r := math.Float64frombits(p.arch.UintN(p.tmp[:8]))
			i := math.Float64frombits(p.arch.UintN(p.tmp[8:16]))
			p.printf("%g", complex(r, i))
		default:
			p.errorf("unrecognized complex size %d", typ.ByteSize)
		}
	case *dwarf.StructType:
		if typ.Kind != "struct" {
			// Could be "class" or "union".
			p.errorf("can't handle struct type %s", typ.Kind)
			return
		}
		p.printf("%s {", strings.TrimPrefix(typ.String(), "struct "))
		for i, field := range typ.Field {
			if i != 0 {
				p.printf(", ")
			}
			p.printValueAt(field.Type, a+address(field.ByteOffset))
		}
		p.printf("}")
	case *dwarf.ArrayType:
		p.printArrayAt(typ, a)
	case *dwarf.InterfaceType:
		p.printInterfaceAt(typ, a)
	case *dwarf.MapType:
		p.printMapAt(typ, a)
	case *dwarf.ChanType:
		p.printChannelAt(typ, a)
	case *dwarf.SliceType:
		p.printSliceAt(typ, a)
	case *dwarf.StringType:
		p.printStringAt(typ, a)
	case *dwarf.TypedefType:
		p.printValueAt(typ.Type, a)
	case *dwarf.FuncType:
		p.printf("%v @%#x ", typ, a)
	case *dwarf.VoidType:
		p.printf("void")
	default:
		p.errorf("unimplemented type %v", typ)
	}
}

func (p *Printer) printArrayAt(typ *dwarf.ArrayType, a address) {
	elemType := typ.Type
	length := typ.Count
	stride, ok := p.arrayStride(typ)
	if !ok {
		p.errorf("can't determine element size")
	}
	p.printf("%s{", typ)
	n := length
	if n > 100 {
		n = 100 // TODO: Have a way to control this?
	}
	for i := int64(0); i < n; i++ {
		if i != 0 {
			p.printf(", ")
		}
		p.printValueAt(elemType, a)
		a += address(stride) // TODO: Alignment and padding - not given by Type
	}
	if n < length {
		p.printf(", ...")
	}
	p.printf("}")
}

func (p *Printer) printInterfaceAt(t *dwarf.InterfaceType, a address) {
	// t should be a typedef binding a struct.
	st, ok := t.TypedefType.Type.(*dwarf.StructType)
	if !ok {
		p.errorf("bad interface type: not a typedef")
		return
	}
	p.printf("(")
	tab, ok := p.peekPtrStructField(st, a, "tab")
	var typename string
	if ok {
		f, err := getField(st, "tab")
		if err != nil {
			p.errorf("%s", err)
		} else {
			start := p.printBuf.Len()
			p.printTypeOfInterface(f.Type, tab)
			end := p.printBuf.Len()
			typename = string(p.printBuf.Bytes()[start+1 : end-1])
		}
	} else {
		p.errorf("couldn't read interface type")
	}
	p.printf(", ")
	addr, ok := p.peekAddrStructField(st, a, "data")
	if !ok {
		p.errorf("couldn't read interface value")
	} else {
		if typ, ok := p.types[typename]; ok {
			p.printValueAt(typ, addr)
		} else {
			data, ok := p.peekPtr(addr)
			if !ok {
				p.errorf("couldn't read interface value")
			} else {
				p.printf("%#x", data)
			}
		}
	}
	p.printf(")")
}

// printTypeOfInterface prints the type of the given tab pointer.
func (p *Printer) printTypeOfInterface(t dwarf.Type, a address) {
	if a == 0 {
		p.printf("<nil>")
		return
	}
	// t should be a pointer to a typedef binding a struct which contains a field _type.
	// _type should be a pointer to a typedef binding a struct which contains a field _string.
	// _string is the name of the type.
	t1, ok := t.(*dwarf.PtrType)
	if !ok {
		p.errorf("bad type")
		return
	}
	t2, ok := t1.Type.(*dwarf.TypedefType)
	if !ok {
		p.errorf("bad type")
		return
	}
	t3, ok := t2.Type.(*dwarf.StructType)
	if !ok {
		p.errorf("bad type")
		return
	}
	typeField, err := getField(t3, "_type")
	if err != nil {
		p.errorf("%s", err)
		return
	}
	t4, ok := typeField.Type.(*dwarf.PtrType)
	if !ok {
		p.errorf("bad type")
		return
	}
	t5, ok := t4.Type.(*dwarf.TypedefType)
	if !ok {
		p.errorf("bad type")
		return
	}
	t6, ok := t5.Type.(*dwarf.StructType)
	if !ok {
		p.errorf("bad type")
		return
	}
	stringField, err := getField(t6, "_string")
	if err != nil {
		p.errorf("%s", err)
		return
	}
	t7, ok := stringField.Type.(*dwarf.PtrType)
	if !ok {
		p.errorf("bad type")
		return
	}
	stringType, ok := t7.Type.(*dwarf.StringType)
	if !ok {
		p.errorf("bad type")
		return
	}
	typeAddr, ok := p.peekPtrStructField(t3, a, "_type")
	if !ok {
		p.errorf("couldn't read type structure pointer")
		return
	}
	stringAddr, ok := p.peekPtrStructField(t6, typeAddr, "_string")
	if !ok {
		p.errorf("couldn't read type name")
		return
	}
	p.printStringAt(stringType, stringAddr)
}

// maxMapValuesToPrint values are printed for each map; any remaining values are
// truncated to "...".
const maxMapValuesToPrint = 8

func (p *Printer) printMapAt(typ *dwarf.MapType, a address) {
	// Maps are pointers to structs.
	pt, ok := typ.Type.(*dwarf.PtrType)
	if !ok {
		p.errorf("bad map type: not a pointer")
		return
	}
	st, ok := pt.Type.(*dwarf.StructType)
	if !ok {
		p.errorf("bad map type: not a pointer to a struct")
		return
	}
	a, ok = p.peekPtr(a)
	if !ok {
		p.errorf("couldn't read map pointer")
		return
	}
	if a == 0 {
		p.printf("<nil>")
		return
	}
	b, ok := p.peekUintStructField(st, a, "B")
	if !ok {
		p.errorf(`couldn't read map field "B"`)
		return
	}
	buckets, ok := p.peekPtrStructField(st, a, "buckets")
	if !ok {
		p.errorf(`couldn't read map field "buckets"`)
		return
	}
	oldbuckets, ok := p.peekPtrStructField(st, a, "oldbuckets")
	if !ok {
		p.errorf(`couldn't read map field "oldbuckets"`)
		return
	}

	p.printf("{")
	// Limit how many values are printed per map.
	numValues := address(0)
	{
		bf, err := getField(st, "buckets")
		if err != nil {
			p.errorf("%s", err)
		} else {
			p.printMapBucketsAt(bf.Type, buckets, 1<<b, &numValues)
		}
	}
	if b > 0 {
		bf, err := getField(st, "oldbuckets")
		if err != nil {
			p.errorf("%s", err)
		} else {
			p.printMapBucketsAt(bf.Type, oldbuckets, 1<<(b-1), &numValues)
		}
	}
	p.printf("}")
}

func (p *Printer) printMapBucketsAt(t dwarf.Type, a, numBuckets address, numValues *address) {
	if *numValues > maxMapValuesToPrint {
		return
	}
	if a == 0 {
		return
	}
	// From runtime/hashmap.go
	const minTopHash = 4
	// t is a pointer to a struct.
	bucketPtrType, ok := t.(*dwarf.PtrType)
	if !ok {
		p.errorf("bad map bucket type: not a pointer")
		return
	}
	bt, ok := bucketPtrType.Type.(*dwarf.StructType)
	if !ok {
		p.errorf("bad map bucket type: not a pointer to a struct")
		return
	}
	bucketSize, ok := p.sizeof(bucketPtrType.Type)
	if !ok {
		p.errorf("can't get bucket size")
		return
	}
	tophashField, err := getField(bt, "tophash")
	if err != nil {
		p.errorf("%s", err)
		return
	}
	bucketCnt, ok := p.sizeof(tophashField.Type)
	if !ok {
		p.errorf("can't get tophash size")
		return
	}
	keysField, err := getField(bt, "keys")
	if err != nil {
		p.errorf("%s", err)
		return
	}
	keysType, ok := keysField.Type.(*dwarf.ArrayType)
	if !ok {
		p.errorf(`bad map bucket type: "keys" is not an array`)
		return
	}
	keysStride, ok := p.arrayStride(keysType)
	if !ok {
		p.errorf("unknown key size")
		keysStride = 1
	}
	valuesField, err := getField(bt, "values")
	if err != nil {
		p.errorf("%s", err)
		return
	}
	valuesType, ok := valuesField.Type.(*dwarf.ArrayType)
	if !ok {
		p.errorf(`bad map bucket type: "values" is not an array`)
		return
	}
	valuesStride, ok := p.arrayStride(valuesType)
	if !ok {
		p.errorf("unknown value size")
		valuesStride = 1
	}

	for i := address(0); i < numBuckets; i++ {
		bucketAddr := a + i*bucketSize
		// TODO: check for repeated bucket pointers.
		for bucketAddr != 0 {
			for j := address(0); j < bucketCnt; j++ {
				tophash, ok := p.peekUint8(bucketAddr + address(tophashField.ByteOffset) + j)
				if !ok {
					p.errorf("couldn't read map")
					return
				}
				if tophash < minTopHash {
					continue
				}

				// Limit how many values are printed per map.
				*numValues++
				if *numValues > maxMapValuesToPrint {
					p.printf(", ...")
					return
				}
				if *numValues > 1 {
					p.printf(", ")
				}

				p.printValueAt(keysType.Type,
					bucketAddr+address(keysField.ByteOffset)+j*keysStride)
				p.printf(":")
				p.printValueAt(valuesType.Type,
					bucketAddr+address(valuesField.ByteOffset)+j*valuesStride)
			}

			var ok bool
			bucketAddr, ok = p.peekPtrStructField(bt, bucketAddr, "overflow")
			if !ok {
				p.errorf("couldn't read map")
				return
			}
		}
	}
}

func (p *Printer) printChannelAt(ct *dwarf.ChanType, a address) {
	p.printf("(chan %s ", ct.ElemType)
	defer p.printf(")")

	a, ok := p.peekPtr(a)
	if !ok {
		p.errorf("couldn't read channel")
		return
	}
	if a == 0 {
		p.printf("<nil>")
		return
	}
	p.printf("%#x", a)

	// ct is a typedef for a pointer to a struct.
	pt, ok := ct.TypedefType.Type.(*dwarf.PtrType)
	if !ok {
		p.errorf("bad channel type: not a pointer")
		return
	}
	st, ok := pt.Type.(*dwarf.StructType)
	if !ok {
		p.errorf("bad channel type: not a pointer to a struct")
		return
	}

	// Print the channel buffer's length (qcount) and capacity (dataqsiz),
	// if not 0/0.
	qcount, ok := p.peekUintStructField(st, a, "qcount")
	if !ok {
		p.errorf(`couldn't read channel field "qcount"`)
		return
	}
	dataqsiz, ok := p.peekUintStructField(st, a, "dataqsiz")
	if !ok {
		p.errorf(`couldn't read channel field "dataqsiz"`)
		return
	}
	if qcount != 0 || dataqsiz != 0 {
		p.printf(" [%d/%d]", qcount, dataqsiz)
	}
}

func (p *Printer) printSliceAt(typ *dwarf.SliceType, a address) {
	// Slices look like a struct with fields array *elemtype, len uint32/64, cap uint32/64.
	// BUG: Slice header appears to have fields with ByteSize == 0
	ptr, ok1 := p.peekPtrStructField(&typ.StructType, a, "array")
	length, ok2 := p.peekUintStructField(&typ.StructType, a, "len")
	// Capacity is not used yet.
	_, ok3 := p.peekUintStructField(&typ.StructType, a, "cap")
	if !ok1 || !ok2 || !ok3 {
		p.errorf("couldn't read slice")
		return
	}
	elemType := typ.ElemType
	size, ok := p.sizeof(typ.ElemType)
	if !ok {
		p.errorf("can't determine element size")
	}
	p.printf("%s{", typ)
	for i := uint64(0); i < length; i++ {
		if i != 0 {
			p.printf(", ")
		}
		p.printValueAt(elemType, ptr)
		ptr += address(size) // TODO: Alignment and padding - not given by Type
	}
	p.printf("}")
}

func (p *Printer) printStringAt(typ *dwarf.StringType, a address) {
	// BUG: String header appears to have fields with ByteSize == 0
	ptr, ok := p.peekPtrStructField(&typ.StructType, a, "str")
	if !ok {
		p.errorf("couldn't read string")
		return
	}
	length, ok := p.peekIntStructField(&typ.StructType, a, "len")
	if !ok {
		p.errorf("couldn't read string")
		return
	}
	if length > int64(cap(p.tmp)) {
		if p.peek(address(ptr), int64(cap(p.tmp))) {
			p.printf("%q...", p.tmp)
		} else {
			p.errorf("couldn't read string")
			return
		}
	} else {
		if p.peek(address(ptr), int64(length)) {
			p.printf("%q", p.tmp[:length])
		} else {
			p.errorf("couldn't read string")
			return
		}
	}
}

// sizeof returns the byte size of the type.
func (p *Printer) sizeof(typ dwarf.Type) (address, bool) {
	size := typ.Size() // Will be -1 if ByteSize is not set.
	if size >= 0 {
		return address(size), true
	}
	switch typ.(type) {
	case *dwarf.PtrType:
		// This is the only one we know of, but more may arise.
		return address(p.arch.PointerSize), true
	}
	return 0, false
}

// arrayStride returns the stride of a dwarf.ArrayType in bytes.
func (p *Printer) arrayStride(t *dwarf.ArrayType) (address, bool) {
	stride := t.StrideBitSize
	if stride > 0 {
		return address(stride / 8), true
	}
	return p.sizeof(t.Type)
}

// getField finds the *dwarf.StructField in a dwarf.StructType with name fieldName.
func getField(t *dwarf.StructType, fieldName string) (*dwarf.StructField, error) {
	var r *dwarf.StructField
	for _, f := range t.Field {
		if f.Name == fieldName {
			if r != nil {
				return nil, fmt.Errorf("struct definition repeats field %s", fieldName)
			}
			r = f
		}
	}
	if r == nil {
		return nil, fmt.Errorf("struct field %s missing", fieldName)
	}
	return r, nil
}
