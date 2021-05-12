package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/iovisor/gobpf/bcc"
)

//go:embed bcc/resolve.c
var resolveBccSource string

type symbolResolveEvent struct {
	Pid        uint32
	LAddr      uint64
	RelocIdx   uint64
	RelocAddr  uint64
	InitAddr   uint64
	SymbolAddr uint64
	LoadAddr   uint64
	Symbol     [256]byte
	Version    [80]byte
	Flags      uint64
}

var interpPath string
var outputPath string

func init() {
	flag.Usage = usage
	flag.StringVar(&interpPath, "i", "/usr/lib/ld-linux-x86-64.so.2", "interp path")
	flag.StringVar(&outputPath, "o", "out.csv", "output csv file")
}

//nolint:funlen
func main() {
	flag.Parse()

	csvFile, err := os.Create(outputPath)
	if err != nil {
		log.Panicf("can't create file %q, %v", outputPath, err)
	}
	// 修改权限，普通用户可以执行写操作
	_ = csvFile.Chmod(0666)
	defer func() {
		_ = csvFile.Close()
	}()
	csvWriter := csv.NewWriter(csvFile)

	var m = bcc.NewModule(resolveBccSource, []string{""})
	defer m.Close()

	// Load
	dlFixupUprobeFd, err := m.LoadUprobe("uprobe__x_dl_fixup")
	if err != nil {
		log.Panicf("Load error, %v", err)
	}
	dlFixupUretprobeFd, err := m.LoadUprobe("uretprobe__x_dl_fixup")
	if err != nil {
		log.Panicf("Load error, %v", err)
	}
	dlLookupSymbolUprobeFd, err := m.LoadUprobe("uprobe__x_dl_lookup_symbol_x")
	if err != nil {
		log.Panicf("Load error, %v", err)
	}
	dlLookupSymbolUretprobeFd, err := m.LoadUprobe("uretprobe__x_dl_lookup_symbol_x")
	if err != nil {
		log.Panicf("Load error, %v", err)
	}

	// Attach
	if err := m.AttachUprobe(interpPath, "_dl_fixup", dlFixupUprobeFd, -1); err != nil {
		log.Panicf("Attach error, %v", err)
	}
	if err := m.AttachUretprobe(interpPath, "_dl_fixup", dlFixupUretprobeFd, -1); err != nil {
		log.Panicf("Attach error, %v", err)
	}
	if err := m.AttachUprobe(interpPath, "_dl_lookup_symbol_x", dlLookupSymbolUprobeFd, -1); err != nil {
		log.Panicf("Attach error, %v", err)
	}
	if err := m.AttachUretprobe(interpPath, "_dl_lookup_symbol_x", dlLookupSymbolUretprobeFd, -1); err != nil {
		log.Panicf("Attach error, %v", err)
	}

	table := bcc.NewTable(m.TableId("resolve_event_output"), m)

	channel := make(chan []byte)
	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		log.Printf("Failed to init perf map: %s\n", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	_ = csvWriter.Write([]string{"pid", "symbol", "version", "flags", "symbol_addr", "load_addr", "symbol_load_addr",
		"symbol_rel_idx", "reloc_addr", "before_reloc_addr"})

	fmt.Printf("%-6s\t%-30s\t%-15s\t%-15s\t%-15s\t%-15s\t%-15s\t%-15s\t%-15s\t%-15s\n", "PID", "SYMBOL", "VERSION", "FLAG", "ADDR",
		"L_ADDR", "LOAD_ADDR", "RELOC_IDX", "RELOC_ADDR", "RELOC_INIT_ADDR")

	go func() {
		var event symbolResolveEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), bcc.GetHostByteOrder(), &event)
			if err != nil {
				log.Printf("failed to decode received data: %s\n", err)
				continue
			}

			sym := string(event.Symbol[:bytes.IndexByte(event.Symbol[:], 0)])
			ver := string(event.Version[:bytes.IndexByte(event.Version[:], 0)])

			simpleSym := sym
			if len(simpleSym) > 30 {
				simpleSym = simpleSym[:26] + "..."
			}

			fmt.Printf("%-6d\t%-30s\t%-15s\t%-15d\t0X%-15X\t0X%-15X\t0X%-15X\t%-15X\t0X%-15X\t0X%-15X\n", event.Pid, simpleSym,
				ver, event.Flags, event.SymbolAddr,
				event.LAddr, event.LoadAddr, event.RelocIdx, event.RelocAddr, event.InitAddr)

			_ = csvWriter.Write([]string{
				strconv.Itoa(int(event.Pid)),
				sym, ver,
				"0x" + strconv.FormatUint(event.Flags, 16),
				"0x" + strconv.FormatUint(event.SymbolAddr, 16),
				"0x" + strconv.FormatUint(event.LAddr, 16),
				"0x" + strconv.FormatUint(event.LoadAddr, 16),
				strconv.FormatUint(event.RelocIdx, 10),
				"0x" + strconv.FormatUint(event.RelocAddr, 16),
				"0x" + strconv.FormatUint(event.InitAddr, 16),
			})
			csvWriter.Flush()
		}
	}()
	perfMap.Start()
	<-sig
	perfMap.Stop()
}

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, `dynamic-symbol-resolve
version: 0.0.1
 author: xcphoenix root@xcphoenix.top

Usage: dynamic-symbol-resolve [-i interp path] [-o csv path]
 Desc: monitor dynamic lazy binding events

Csv File Format: 
    "pid", "symbol", "version", "flags", "symbol_addr", "load_addr", 
    "symbol_load_addr", "symbol_rel_idx", "reloc_addr", "before_reloc_addr"
    -----------------------------------------------------------------------
    进程pid、符号、符号版本、标志位、符号真实地址、程序加载地址、
    符号加载地址、符号在动态链接重定位表的索引、要重定位的地址(.got.plt中对应的项)、延迟绑定前对应位置的值

Options:
`)
	flag.PrintDefaults()
}
