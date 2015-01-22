package main

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"runtime/debug"
)

func loadDwarf(path string) (d *dwarf.Data, err error) {
	if obj, err := elf.Open(path); err == nil {
		d, err = obj.DWARF()
		if err != nil {
			return nil, err
		}
		return d, nil
	}

	if obj, err := macho.Open(os.Args[0]); err == nil {
		d, err = obj.DWARF()
		if err != nil {
			return nil, err
		}
		return d, nil
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
	bss          Data
	objects      map[uint64]Object
	goroutines   []*Goroutine
	threads      []Thread
	memprof      map[uint64]*MemProfEntry
	allocSamples []AllocSample
	types        map[uint64]Type
	itabs        map[uint64]Type
	memStats     *runtime.MemStats
	dwarf        *dwarf.Data
	globalVars   map[uint64]dwarf.Type
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
	Addr   uint64
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
	fmt.Printf("%s\n", hdr)
	if string(hdr) != "go1.4 heap dump" {
		return nil, fmt.Errorf("unexpected heap dump format: %s", hdr)
	}

	d := &Dump{
		objects:    map[uint64]Object{},
		memprof:    map[uint64]*MemProfEntry{},
		types:      map[uint64]Type{},
		itabs:      map[uint64]Type{},
		globalVars: map[uint64]dwarf.Type{},
	}
	d.dwarf, err = loadDwarf(exename)
	if err != nil {
		return nil, err
	}

	if err := d.readTags(r); err != nil {
		return nil, err
	}

	// if err := d.initGlobalVars(); err != nil {
	// 	return nil, err
	// }

	if err := d.link(); err != nil {
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
			fmt.Printf("%v\n", t)
			return nil

		case tagObject:
			o := Object{}
			o.addr = readUint64(r)
			o.contents = readBytes(r)
			o.fields = readFields(r)
			d.objects[o.addr] = o
			fmt.Printf("%v: %#08x: %d %d\n", t, o.addr, len(o.contents), len(o.fields))

		case tagOtherRoot:
			desc := readString(r)
			_ = readUint64(r)
			fmt.Printf("%v: %s", t, desc)

		case tagType:
			typ := Type{}
			typ.Addr = readUint64(r)
			typ.Size = readUint64(r)
			typ.Name = readString(r)
			typ.Ptr = readBool(r)
			d.types[typ.Addr] = typ
			fmt.Printf("%v: %#08x %d %s %v\n", t, typ.Addr, typ.Size, typ.Name, typ.Ptr)

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
			fmt.Printf("%v: %d %#08x %#08x\n", t, g.goid, g.sp, g.addr)

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
			fmt.Printf("%v: %d %s %#08x %#08x %d\n", t, g.goid, f.name, f.sp, f.childsp, f.depth)

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
			fmt.Printf("%v: ptrSize=%d heap=%#08x-%#08x\n", t, d.ptrSize, d.heapStart, d.heapEnd)

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
			fmt.Printf("%v: %#08x\n", t, addr)

		case tagItab:
			addr := readUint64(r)
			typeAddr := readUint64(r)
			typ, ok := d.types[typeAddr]
			if !ok {
				fmt.Printf("ERROR %v: unable to find type for address: %#08x", t, typeAddr)
				break
			}
			d.itabs[addr] = typ
			fmt.Printf("%v: %#08x %#08x (%s)\n", t, addr, typeAddr, typ.Name)

		case tagOSThread:
			thr := Thread{}
			thr.Addr = readUint64(r)
			thr.ID = readUint64(r)
			thr.ProcID = readUint64(r)
			d.threads = append(d.threads, thr)
			fmt.Printf("%v: %#08x %d %d\n", t, thr.Addr, thr.ID, thr.ProcID)

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
			fmt.Printf("%v: %+v\n", t, s)

		case tagData, tagBSS:
			var dat *Data
			if t == tagData {
				dat = &d.data
			} else {
				dat = &d.bss
			}
			dat.Addr = readUint64(r)
			dat.Data = readBytes(r)
			dat.Fields = readFields(r)
			fmt.Printf("%v: %#08x %d %d\n", t, dat.Addr, len(dat.Data), len(dat.Fields))

			// TODO(pmattis): Instead of walking over the fields, we should
			// walk over the global variables and print out the contents
			// using ogle/printer.go.
			// for _, f := range dat.Fields {
			// 	addr := dat.Addr + f.offset
			// 	typ, ok := d.globalVars[addr]
			// 	if !ok {
			// 		continue
			// 	}
			// 	fmt.Printf("  %#08x: %v\n", addr, typ)
			// }

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
			fmt.Printf("%v: %d\n", t, g.goid)

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
			fmt.Printf("%v: %d\n", t, g.goid)

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
			fmt.Printf("%v: %#08x\n", t, e.addr)

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
			fmt.Printf("%v: %#08x %+v\n", t, s.Addr, s.Prof)
		}
	}
}

func (d *Dump) initGlobalVars() error {
	const opAddr = 0x03
	for r := d.dwarf.Reader(); true; {
		entry, err := r.Next()
		if err != nil {
			return err
		}
		if entry == nil {
			break
		}
		if entry.Tag != dwarf.TagVariable {
			continue
		}
		typ, err := d.dwarf.Type(entry.Val(dwarf.AttrType).(dwarf.Offset))
		if err != nil {
			fmt.Printf("ERROR: unable to find type: %s\n", entry.Val(dwarf.AttrName))
			continue
		}
		locexpr, ok := entry.Val(dwarf.AttrLocation).([]byte)
		if !ok {
			continue
		}
		if len(locexpr) == 0 || locexpr[0] != opAddr {
			continue
		}
		addr := d.uintptr(locexpr[1:])
		d.globalVars[addr] = typ
		fmt.Printf("%#08x: %s: %v\n", addr, entry.Val(dwarf.AttrName), typ)
	}
	return nil
}

func (d *Dump) link() error {
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

func main() {
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

	// d, err := loadDwarf(os.Args[0])
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// dumpDwarf(d, d.Reader(), "")
}
