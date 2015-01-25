// TODO(pmattis): Web UI for navigating heap dump
//   - Source navigator (ala godoc)
//     - Find code via gosym.Table.Files.
//     - Detect if the source is newer than the binary.
//   - List of goroutines (jump to source location)
//     - Filter by regex.
//   - Ability to walk up and down stacks.
//   - Display of local variables and parameters.
//   - Data structure navigator.
//     - Display structure contents.
//     - Expand/collapse pointers and interfaces.
//   - Utilize multiple heap dumps taken in a single run of a program
//     to step through time.
//
// TODO(pmattis): Small library to ease heap dump creation and write
// heap dumps to files suffixed with process id:
//   heapdump.<pid>.<timestamp>
//
// TODO(pmattis): Support both coredumps and heapdumps. Note that the
// go runtime disables coredumps on Mac OS X (darwin) because of
// extremely naive behavior from the kernel.

package main

import (
	"bufio"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"go/parser"
	"go/token"

	"golang.org/x/debug/dwarf"
	"golang.org/x/debug/elf"
	"golang.org/x/debug/macho"
	"golang.org/x/debug/ogle/arch"
)

// Objfile ...
type Objfile struct {
	architecture *arch.Architecture
	dwarfData    *dwarf.Data
	rodata       *Data
	noptrdata    *Data
	noptrbss     *Data
	symtab       *gosym.Table
}

func loadObjfile(path string) (*Objfile, error) {
	f := &Objfile{}
	if obj, err := elf.Open(path); err == nil {
		f.dwarfData, err = obj.DWARF()
		if err != nil {
			return nil, err
		}

		// TODO(pmattis): rodata, noptrbss, noptrdata sections.

		switch obj.Machine {
		case elf.EM_ARM:
			f.architecture = &arch.ARM
		case elf.EM_386:
			switch obj.Class {
			case elf.ELFCLASS32:
				f.architecture = &arch.X86
			case elf.ELFCLASS64:
				f.architecture = &arch.AMD64
			}
		case elf.EM_X86_64:
			f.architecture = &arch.AMD64
		}
		if f.architecture == nil {
			return nil, fmt.Errorf("unrecognized ELF architecture")
		}
		return f, nil
	}

	if obj, err := macho.Open(os.Args[0]); err == nil {
		f.dwarfData, err = obj.DWARF()
		if err != nil {
			return nil, err
		}

		// TODO(pmattis): Reduce duplicated code in handling of __rodata,
		// __noptrdata and __noptrbss.

		if s := obj.Section("__rodata"); s != nil {
			f.rodata = &Data{}
			f.rodata.Start = s.Addr
			f.rodata.End = s.Addr + s.Size
			f.rodata.Data, err = s.Data()
			if err != nil {
				return nil, err
			}
		}

		if s := obj.Section("__noptrdata"); s != nil {
			f.noptrdata = &Data{}
			f.noptrdata.Start = s.Addr
			f.noptrdata.End = s.Addr + s.Size
			f.noptrdata.Data, err = s.Data()
			if err != nil {
				return nil, err
			}
		}

		if s := obj.Section("__noptrbss"); s != nil {
			f.noptrbss = &Data{}
			f.noptrbss.Start = s.Addr
			f.noptrbss.End = s.Addr + s.Size
			f.noptrbss.Data, err = s.Data()
			if err != nil {
				return nil, err
			}
		}

		var (
			symdat  []byte
			pclndat []byte
			err     error
		)

		if s := obj.Section("__gosymtab"); s != nil {
			symdat, err = s.Data()
			if err != nil {
				return nil, err
			}
		}

		if s := obj.Section("__gopclntab"); s != nil {
			pclndat, err = s.Data()
			if err != nil {
				return nil, err
			}
		}

		pcln := gosym.NewLineTable(pclndat, obj.Section("__text").Addr)
		f.symtab, err = gosym.NewTable(symdat, pcln)
		if err != nil {
			return nil, err
		}

		switch obj.Cpu {
		case macho.Cpu386:
			f.architecture = &arch.X86
		case macho.CpuAmd64:
			f.architecture = &arch.AMD64
		}
		if f.architecture == nil {
			return nil, fmt.Errorf("unrecognized Mach-O architecture")
		}
		return f, nil
	}

	return nil, fmt.Errorf("unrecognized binary format")
}

func dumpDwarf(d *dwarf.Data, r *dwarf.Reader, indent string) error {
	for {
		entry, err := r.Next()
		if err != nil {
			return err
		}
		if entry == nil || entry.Tag == 0 {
			break
		}

		// fmt.Printf("%s%d: %s: %+v\n", indent, entry.Offset, entry.Tag, entry.Field)

		switch entry.Tag {
		case dwarf.TagCompileUnit, dwarf.TagSubprogram:
			fmt.Printf("%s%d: %s: %v: %#08x-%#08x\n", indent, entry.Offset, entry.Tag,
				entry.Val(dwarf.AttrName), entry.Val(dwarf.AttrLowpc), entry.Val(dwarf.AttrHighpc))
		case dwarf.TagFormalParameter, dwarf.TagVariable:
			typ, err := d.Type(entry.Val(dwarf.AttrType).(dwarf.Offset))
			if err != nil {
				return err
			}
			fmt.Printf("%s%d: %s: %v: %s %+v\n", indent, entry.Offset, entry.Tag,
				entry.Val(dwarf.AttrName), typ, entry.Val(dwarf.AttrLocation))
		case dwarf.TagArrayType,
			dwarf.TagBaseType,
			dwarf.TagClassType,
			dwarf.TagEnumerationType,
			dwarf.TagMember,
			dwarf.TagPointerType,
			dwarf.TagReferenceType,
			dwarf.TagStructType,
			dwarf.TagSubrangeType,
			dwarf.TagSubroutineType,
			dwarf.TagTypedef,
			dwarf.TagUnspecifiedType:
		default:
			log.Fatalf("%s%d: %s: %+v\n", indent, entry.Offset, entry.Tag, entry.Field)
		}

		if entry.Children {
			err := dumpDwarf(d, r, indent+"  ")
			if err != nil {
				return err
			}
		}
	}
	return nil
}

//go:generate stringer -type=kind
type kind int

const (
	kindEol   kind = 0
	kindPtr   kind = 1
	kindIface kind = 2
	kindEface kind = 3
)

//go:generate stringer -type=tag
type tag int

const (
	tagEOF             tag = 0
	tagObject          tag = 1
	tagOtherRoot       tag = 2
	tagType            tag = 3
	tagGoroutine       tag = 4
	tagStackFrame      tag = 5
	tagParams          tag = 6
	tagFinalizer       tag = 7
	tagItab            tag = 8
	tagOSThread        tag = 9
	tagMemStats        tag = 10
	tagQueuedFinalizer tag = 11
	tagData            tag = 12
	tagBSS             tag = 13
	tagDefer           tag = 14
	tagPanic           tag = 15
	tagMemProf         tag = 16
	tagAllocSample     tag = 17
)

// Field ...
type Field struct {
	kind   kind
	offset uint64
}

func readUint64(r *bufio.Reader) uint64 {
	x, err := binary.ReadUvarint(r)
	if err != nil {
		log.Fatal(err)
	}
	return x
}

func readNBytes(r *bufio.Reader, n uint64) []byte {
	s := make([]byte, n)
	_, err := io.ReadFull(r, s)
	if err != nil {
		log.Fatal(err)
	}
	return s
}

func readBytes(r *bufio.Reader) []byte {
	n := readUint64(r)
	return readNBytes(r, n)
}

func readString(r *bufio.Reader) string {
	return string(readBytes(r))
}

func readBool(r *bufio.Reader) bool {
	b, err := r.ReadByte()
	if err != nil {
		log.Fatal(err)
	}
	return b != 0
}

func readFields(r *bufio.Reader) []Field {
	var x []Field
	for {
		k := kind(readUint64(r))
		if k == kindEol {
			return x
		}
		x = append(x, Field{kind: k, offset: readUint64(r)})
	}
}

// Dump ...
type Dump struct {
	byteOrder    binary.ByteOrder
	ptrSize      uint64
	heapStart    uint64
	heapEnd      uint64
	theChar      byte
	experiment   string
	ncpu         uint
	data         Data
	rodata       Data
	noptrdata    Data
	noptrbss     Data
	bss          Data
	objects      map[uint64]Object
	goroutines   []*Goroutine
	threads      []Thread
	memprof      map[uint64]*MemProfEntry
	allocSamples []AllocSample
	types        map[uint64]Type
	itabs        map[uint64]Type
	memStats     *runtime.MemStats
}

// Type ...
type Type struct {
	Addr uint64
	Size uint64
	Name string
	Ptr  bool
}

// Data ...
type Data struct {
	Start  uint64
	End    uint64
	Data   []byte
	Fields []Field
}

// Finalizer ...
type Finalizer struct {
	fn   uint64
	fnfn uint64
	fint uint64
	ot   uint64
}

// MemProfFrame ...
type MemProfFrame struct {
	Func string
	File string
	Line uint64
}

// MemProfEntry ...
type MemProfEntry struct {
	addr   uint64
	size   uint64
	stack  []MemProfFrame
	allocs uint64
	frees  uint64
}

// AllocSample ...
type AllocSample struct {
	Addr uint64
	Prof *MemProfEntry
}

// Object ...
type Object struct {
	addr        uint64
	contents    []byte
	fields      []Field
	finalizers  []Finalizer
	qfinalizers []Finalizer
}

// Goroutine ...
type Goroutine struct {
	addr         uint64
	sp           uint64
	goid         uint64
	gopc         uint64
	status       uint64
	isSystem     bool
	isBackground bool
	waitSince    uint64
	waitReason   string
	ctxtaddr     uint64
	maddr        uint64
	deferaddr    uint64
	panicaddr    uint64
	frames       []StackFrame
	defers       []Defer
	panics       []Panic
}

// Thread ...
type Thread struct {
	Addr   uint64
	ID     uint64
	ProcID uint64
}

// StackFrame ...
type StackFrame struct {
	sp       uint64
	depth    uint64
	childsp  uint64
	contents []byte
	entry    uint64
	pc       uint64
	continpc uint64
	name     string
	fields   []Field
}

// Defer ...
type Defer struct {
	addr uint64
	gp   uint64
	argp uint64
	pc   uint64
	fn   uint64
	code uint64
	link uint64
}

// Panic ...
type Panic struct {
	addr uint64
	gp   uint64
	typ  uint64
	data uint64
	defr uint64
	link uint64
}

func read(f *os.File, exename string) (*Dump, error) {
	r := bufio.NewReader(f)

	hdr, _, err := r.ReadLine()
	if err != nil {
		return nil, err
	}
	if string(hdr) != "go1.4 heap dump" {
		return nil, fmt.Errorf("unexpected heap dump format: %s", hdr)
	}

	d := &Dump{
		objects: map[uint64]Object{},
		memprof: map[uint64]*MemProfEntry{},
		types:   map[uint64]Type{},
		itabs:   map[uint64]Type{},
	}
	if err := d.readTags(r); err != nil {
		return nil, err
	}

	if err := d.link(exename); err != nil {
		return nil, err
	}

	return d, nil
}

func (d *Dump) readTags(r *bufio.Reader) error {
	gmap := map[uint64]*Goroutine{}

	for {
		t := tag(readUint64(r))
		switch t {
		case tagEOF:
			// fmt.Printf("%v\n", t)
			return nil

		case tagObject:
			o := Object{}
			o.addr = readUint64(r)
			o.contents = readBytes(r)
			o.fields = readFields(r)
			d.objects[o.addr] = o
			// fmt.Printf("%v: %#08x: %d %d\n", t, o.addr, len(o.contents), len(o.fields))

		case tagOtherRoot:
			_ = readString(r)
			_ = readUint64(r)
			// fmt.Printf("%v: %s", t, desc)

		case tagType:
			typ := Type{}
			typ.Addr = readUint64(r)
			typ.Size = readUint64(r)
			typ.Name = readString(r)
			typ.Ptr = readBool(r)
			d.types[typ.Addr] = typ
			// fmt.Printf("%v: %#08x %d %s %v\n", t, typ.Addr, typ.Size, typ.Name, typ.Ptr)

		case tagGoroutine:
			g := &Goroutine{}
			g.addr = readUint64(r)
			g.sp = readUint64(r)
			g.goid = readUint64(r)
			g.gopc = readUint64(r)
			g.status = readUint64(r)
			g.isSystem = readBool(r)
			g.isBackground = readBool(r)
			g.waitSince = readUint64(r)
			g.waitReason = readString(r)
			g.ctxtaddr = readUint64(r)
			g.maddr = readUint64(r)
			g.deferaddr = readUint64(r)
			g.panicaddr = readUint64(r)
			d.goroutines = append(d.goroutines, g)
			gmap[g.sp] = g
			gmap[g.addr] = g
			// fmt.Printf("%v: %d %#08x %#08x\n", t, g.goid, g.sp, g.addr)

		case tagStackFrame:
			f := StackFrame{}
			f.sp = readUint64(r)
			f.depth = readUint64(r)
			f.childsp = readUint64(r)
			f.contents = readBytes(r)
			f.entry = readUint64(r)
			f.pc = readUint64(r)
			f.continpc = readUint64(r)
			f.name = readString(r)
			f.fields = readFields(r)
			g, ok := gmap[f.sp]
			if !ok {
				g, ok = gmap[f.childsp]
				if !ok {
					fmt.Printf("ERROR %v: unable to find goroutine: %#08x\n", t, f.childsp)
					break
				}
			}
			if len(g.frames) != int(f.depth) {
				fmt.Printf("ERROR %v: unexpected frame for gorouting %d: %d != %d",
					t, g.goid, len(g.frames), f.depth)
				break
			}
			gmap[f.sp] = g
			g.frames = append(g.frames, f)
			// fmt.Printf("%v: %d %s %#08x %#08x %d\n", t, g.goid, f.name, f.sp, f.childsp, f.depth)

		case tagParams:
			if readBool(r) {
				d.byteOrder = binary.BigEndian
			} else {
				d.byteOrder = binary.LittleEndian
			}
			d.ptrSize = readUint64(r)
			d.heapStart = readUint64(r)
			d.heapEnd = readUint64(r)
			d.theChar = byte(readUint64(r))
			d.experiment = readString(r)
			d.ncpu = uint(readUint64(r))
			// fmt.Printf("%v: ptrSize=%d heap=%#08x-%#08x\n", t, d.ptrSize, d.heapStart, d.heapEnd)

		case tagFinalizer, tagQueuedFinalizer:
			f := Finalizer{}
			addr := readUint64(r)
			f.fn = readUint64(r)
			f.fnfn = readUint64(r)
			f.fint = readUint64(r)
			f.ot = readUint64(r)
			obj, ok := d.objects[addr]
			if !ok {
				fmt.Printf("ERROR %v: unable to find object: %#08x\n", t, addr)
				break
			}
			if t == tagFinalizer {
				obj.finalizers = append(obj.finalizers, f)
			} else {
				obj.qfinalizers = append(obj.qfinalizers, f)
			}
			// fmt.Printf("%v: %#08x\n", t, addr)

		case tagItab:
			addr := readUint64(r)
			typeAddr := readUint64(r)
			typ, ok := d.types[typeAddr]
			if !ok {
				fmt.Printf("ERROR %v: unable to find type for address: %#08x", t, typeAddr)
				break
			}
			d.itabs[addr] = typ
			// fmt.Printf("%v: %#08x %#08x (%s)\n", t, addr, typeAddr, typ.Name)

		case tagOSThread:
			thr := Thread{}
			thr.Addr = readUint64(r)
			thr.ID = readUint64(r)
			thr.ProcID = readUint64(r)
			d.threads = append(d.threads, thr)
			// fmt.Printf("%v: %#08x %d %d\n", t, thr.Addr, thr.ID, thr.ProcID)

		case tagMemStats:
			s := &runtime.MemStats{}
			s.Alloc = readUint64(r)
			s.TotalAlloc = readUint64(r)
			s.Sys = readUint64(r)
			s.Lookups = readUint64(r)
			s.Mallocs = readUint64(r)
			s.Frees = readUint64(r)
			s.HeapAlloc = readUint64(r)
			s.HeapSys = readUint64(r)
			s.HeapIdle = readUint64(r)
			s.HeapInuse = readUint64(r)
			s.HeapReleased = readUint64(r)
			s.HeapObjects = readUint64(r)
			s.StackInuse = readUint64(r)
			s.StackSys = readUint64(r)
			s.MSpanInuse = readUint64(r)
			s.MSpanSys = readUint64(r)
			s.MCacheInuse = readUint64(r)
			s.MCacheSys = readUint64(r)
			s.BuckHashSys = readUint64(r)
			s.GCSys = readUint64(r)
			s.OtherSys = readUint64(r)
			s.NextGC = readUint64(r)
			s.LastGC = readUint64(r)
			s.PauseTotalNs = readUint64(r)
			for i := 0; i < 256; i++ {
				s.PauseNs[i] = readUint64(r)
			}
			s.NumGC = uint32(readUint64(r))
			d.memStats = s
			// fmt.Printf("%v: %+v\n", t, s)

		case tagData, tagBSS:
			var dat *Data
			if t == tagData {
				dat = &d.data
			} else {
				dat = &d.bss
			}
			dat.Start = readUint64(r)
			dat.Data = readBytes(r)
			dat.Fields = readFields(r)
			dat.End = dat.Start + uint64(len(dat.Data))
			// fmt.Printf("%v: %#08x %d %d\n", t, dat.Addr, len(dat.Data), len(dat.Fields))

		case tagDefer:
			q := Defer{}
			q.addr = readUint64(r)
			q.gp = readUint64(r)
			q.argp = readUint64(r)
			q.pc = readUint64(r)
			q.fn = readUint64(r)
			q.code = readUint64(r)
			q.link = readUint64(r)
			g, ok := gmap[q.gp]
			if !ok {
				fmt.Printf("ERROR %v: unable to find goroutine: %#08x\n", t, q.gp)
				break
			}
			g.defers = append(g.defers, q)
			// fmt.Printf("%v: %d\n", t, g.goid)

		case tagPanic:
			q := Panic{}
			q.addr = readUint64(r)
			q.gp = readUint64(r)
			q.typ = readUint64(r)
			q.data = readUint64(r)
			q.defr = readUint64(r)
			q.link = readUint64(r)
			g, ok := gmap[q.gp]
			if !ok {
				fmt.Printf("ERROR %v: unable to find goroutine: %#08x\n", t, q.gp)
				break
			}
			g.panics = append(g.panics, q)
			// fmt.Printf("%v: %d\n", t, g.goid)

		case tagMemProf:
			e := &MemProfEntry{}
			e.addr = readUint64(r)
			e.size = readUint64(r)
			nstk := readUint64(r)
			for i := uint64(0); i < nstk; i++ {
				fn := readString(r)
				file := readString(r)
				line := readUint64(r)
				e.stack = append(e.stack, MemProfFrame{fn, file, line})
			}
			e.allocs = readUint64(r)
			e.frees = readUint64(r)
			d.memprof[e.addr] = e
			// fmt.Printf("%v: %#08x\n", t, e.addr)

		case tagAllocSample:
			s := AllocSample{}
			s.Addr = readUint64(r)
			profAddr := readUint64(r)
			prof, ok := d.memprof[profAddr]
			if !ok {
				fmt.Printf("ERROR %v: unable to find profile for address: %#08x", t, profAddr)
				break
			}
			s.Prof = prof
			d.allocSamples = append(d.allocSamples, s)
			// fmt.Printf("%v: %#08x %+v\n", t, s.Addr, s.Prof)
		}
	}
}

const (
	opCallFrameCFA = 0x9c
	opConsts       = 0x11
	opPlus         = 0x22
	opAddr         = 0x03
)

func readUleb(b []byte) ([]byte, uint64) {
	r := uint64(0)
	s := uint(0)
	for {
		x := b[0]
		b = b[1:]
		r |= uint64(x&127) << s
		if x&128 == 0 {
			break
		}
		s += 7

	}
	return b, r
}

func readSleb(b []byte) ([]byte, int64) {
	c, v := readUleb(b)
	// sign extend
	k := (len(b) - len(c)) * 7
	return c, int64(v) << uint(64-k) >> uint(64-k)
}

// func (d *Dump) initGlobalVars() error {
// 	const opAddr = 0x03
// 	for r := d.dwarf.Reader(); true; {
// 		entry, err := r.Next()
// 		if err != nil {
// 			return err
// 		}
// 		if entry == nil {
// 			break
// 		}
// 		if entry.Tag != dwarf.TagVariable {
// 			continue
// 		}
// 		typ, err := d.dwarf.Type(entry.Val(dwarf.AttrType).(dwarf.Offset))
// 		if err != nil {
// 			fmt.Printf("ERROR: unable to find type: %s\n", entry.Val(dwarf.AttrName))
// 			continue
// 		}
// 		locexpr, ok := entry.Val(dwarf.AttrLocation).([]byte)
// 		if !ok {
// 			continue
// 		}
// 		if len(locexpr) == 0 || locexpr[0] != opAddr {
// 			continue
// 		}
// 		addr := d.uintptr(locexpr[1:])
// 		d.globalVars[addr] = typ
// 		fmt.Printf("%#08x: %s: %v\n", addr, entry.Val(dwarf.AttrName), typ)
// 	}
// 	return nil
// }

type localValue struct {
	name   string
	offset int64
	entry  *dwarf.Entry
}

type localsMap map[string][]localValue

func makeLocalsMap(d *dwarf.Data) (localsMap, error) {
	m := localsMap{}
	var funcname string
	var vals []localValue
	for r := d.Reader(); true; {
		e, err := r.Next()
		if err != nil {
			return nil, err
		}
		if e == nil {
			break
		}
		switch e.Tag {
		case 0:
			m[funcname] = vals
			funcname = ""
		case dwarf.TagSubprogram:
			funcname = e.Val(dwarf.AttrName).(string)
			vals = m[funcname]
		case dwarf.TagVariable, dwarf.TagFormalParameter:
			name, ok := e.Val(dwarf.AttrName).(string)
			if !ok {
				break
			}
			loc := e.Val(dwarf.AttrLocation).([]uint8)
			if len(loc) == 0 || loc[0] != opCallFrameCFA {
				break
			}
			var offset int64
			if len(loc) == 1 {
				offset = 0
			} else if len(loc) >= 3 && loc[1] == opConsts && loc[len(loc)-1] == opPlus {
				loc, offset = readSleb(loc[2 : len(loc)-1])
				if len(loc) != 0 {
					break
				}
			}
			vals = append(vals, localValue{name, offset, e})
		}
	}
	return m, nil
}

func (d *Dump) peek(offset uintptr, buf []byte) error {
	// TODO(pmattis): This is currently inefficient and could be
	// significantly improved by putting all of the "data" into a single
	// array sorted by address and using binary search to find the
	// desired address.

	if offset == 0 {
		for i := range buf {
			buf[i] = 0
		}
		return nil
	}
	off64 := uint64(offset)
	len64 := uint64(len(buf))
	for _, data := range []*Data{&d.data, &d.rodata, &d.bss, &d.noptrdata, &d.noptrbss} {
		if off64 >= data.Start && off64 < data.End {
			off64 -= data.Start
			copy(buf, data.Data[off64:off64+len64])
			// fmt.Printf("peek(data): %#08x %d: %v\n", offset, len(buf), buf)
			return nil
		}
	}
	for _, obj := range d.objects {
		if off64 >= obj.addr && off64 < obj.addr+uint64(len(obj.contents)) {
			off64 -= obj.addr
			copy(buf, obj.contents[off64:off64+len64])
			// fmt.Printf("peek(obj): %#08x %d: %v\n", offset, len(buf), buf)
			return nil
		}
	}
	for _, g := range d.goroutines {
		for _, f := range g.frames {
			if off64 >= f.sp && off64 < f.sp+uint64(len(f.contents)) {
				off64 -= f.sp
				copy(buf, f.contents[off64:off64+len64])
				// fmt.Printf("peek(%d/%s): %#08x %d: %v\n", g.goid, f.name, offset, len(buf), buf)
				return nil
			}
		}
	}
	if len(buf) == int(d.ptrSize) {
		for addr, typ := range d.itabs {
			if off64 == addr+d.ptrSize {
				switch d.ptrSize {
				case 4:
					d.byteOrder.PutUint32(buf, uint32(typ.Addr))
				case 8:
					d.byteOrder.PutUint64(buf, typ.Addr)
				}
				return nil
			}
		}
	}
	// fmt.Printf("ERROR: %#08x %d: not found\n", offset, len(buf))
	return fmt.Errorf("%#08x %d: not found\n", offset, len(buf))
	// for i := range buf {
	// 	buf[i] = 0
	// }
	// return nil
}

func (d *Dump) link(exename string) error {
	obj, err := loadObjfile(exename)
	if err != nil {
		return err
	}
	// dumpDwarf(obj.dwarfData, obj.dwarfData.Reader(), "")

	if obj.rodata != nil {
		d.rodata = *obj.rodata
	}
	if obj.noptrdata != nil {
		d.noptrdata = *obj.noptrdata
	}
	if obj.noptrbss != nil {
		d.noptrbss = *obj.noptrbss
	}

	printer := NewPrinter(obj.architecture, obj.dwarfData, d)

	locals, err := makeLocalsMap(obj.dwarfData)
	if err != nil {
		return err
	}

	// fmt.Printf("data:        %d\n", len(d.data.Data))
	// fmt.Printf("rodata:      %d\n", len(d.rodata.Data))
	// fmt.Printf("noptrdata:   %d\n", len(d.noptrdata.Data))
	// fmt.Printf("bss:         %d\n", len(d.bss.Data))
	// fmt.Printf("noptrbss:    %d\n", len(d.noptrbss.Data))

	for _, g := range d.goroutines {
		fmt.Printf("goroutine %d [%s]\n", g.goid, g.waitReason)
		for _, f := range g.frames {
			fmt.Printf("%s\n", f.name)
			if file, line, fn := obj.symtab.PCToLine(f.pc - 1); fn != nil {
				fmt.Printf("\t%s:%d\n", file, line)
			}
			vals, ok := locals[f.name]
			if !ok {
				continue
			}
			for _, v := range vals {
				typ, err := obj.dwarfData.Type(v.entry.Val(dwarf.AttrType).(dwarf.Offset))
				if err != nil {
					continue
				}
				addr := address(int64(f.sp) + int64(len(f.contents)) + v.offset)
				// TODO(pmattis): We currently can't print values in the
				// "first" function invoked by a goroutine because the
				// arguments are stored in the parent frame but the parent
				// frame isn't properly sized.
				s, _ := printer.SprintEntry(v.entry, addr)
				fmt.Printf("\t%4d %s %v %s\n", v.offset, v.name, typ, s)
			}
		}
		if file, line, fn := obj.symtab.PCToLine(g.gopc); fn != nil {
			fmt.Printf("created by %s\n\t%s:%d\n", fn.Name, file, line)
		}
		fmt.Println()
	}

	for r := obj.dwarfData.Reader(); true; {
		e, err := r.Next()
		if err != nil || e == nil {
			break
		}
		if e.Tag == dwarf.TagCompileUnit {
			continue
		}
		if e.Tag == dwarf.TagVariable {
			name, ok := e.Val(dwarf.AttrName).(string)
			if !ok {
				continue
			}
			if strings.HasPrefix(name, "main.") {
				loc, ok := e.Val(dwarf.AttrLocation).([]byte)
				if !ok {
					continue
				}
				if len(loc) == 0 || loc[0] != opAddr {
					continue
				}
				addr := d.uintptr(loc[1:])
				typ, err := obj.dwarfData.Type(e.Val(dwarf.AttrType).(dwarf.Offset))
				if err != nil {
					fmt.Printf("ERROR: unable to find type: %s\n", name)
					continue
				}
				if _, ok := typ.(*dwarf.UnspecifiedType); ok {
					continue
				}
				s, err := printer.SprintEntry(e, address(addr))
				if err != nil {
					fmt.Printf("%#08x: %s %s [%s]\n", addr, e.Val(dwarf.AttrName), s, err)
				} else {
					fmt.Printf("%#08x: %s %s\n", addr, e.Val(dwarf.AttrName), s)
				}
			}
		}
		if e.Children {
			r.SkipChildren()
		}
	}

	files := token.NewFileSet()
	for p := range obj.symtab.Files {
		if path.Ext(p) == ".go" {
			f, err := parser.ParseFile(files, p, nil, parser.ParseComments)
			if err != nil {
				log.Fatalf("unable to parse: %s: %s\n", p, err)
			}
			fmt.Printf("%s: %s\n", f.Name.Name, p)
		}
	}

	return nil
}

func (d *Dump) uintptr(buf []byte) uint64 {
	switch d.ptrSize {
	case 4:
		return uint64(d.byteOrder.Uint32(buf[:4]))
	case 8:
		return d.byteOrder.Uint64(buf[:8])
	}
	panic(fmt.Errorf("invalid pointer size: %d", d.ptrSize))
}

func baz(a error, b int, c string) {
	select {}
}

func bar(a error, b int) {
	baz(a, b, "world")
}

func foo(a error) {
	bar(a, 1)
}

func boo() {
	foo(errors.New("hello"))
}

func main() {
	// go foo(errors.New("hello"))
	go boo()
	time.Sleep(1)

	f, err := ioutil.TempFile(".", "heapdump.")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err := os.Remove(f.Name()); err != nil {
		log.Fatal(err)
	}

	debug.WriteHeapDump(f.Fd())

	if _, err := f.Seek(0, 0); err != nil {
		log.Fatal(err)
	}
	if _, err := read(f, os.Args[0]); err != nil {
		log.Fatal(err)
	}
}
