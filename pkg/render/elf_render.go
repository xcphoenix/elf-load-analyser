package render

import (
	"debug/elf"
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"os"
	"strconv"

	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	"github.com/xcphoenix/elf-load-analyser/pkg/xsys/xelf"
)

type ElfRender struct {
	filepath string
	f        *elf.File
}

func NewElfRender(filepath string) (*ElfRender, error) {
	// file header
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	eFile, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	return &ElfRender{filepath: filepath, f: eFile}, nil
}

func (e *ElfRender) elfData() (elf.FileHeader, bool, string) {
	fHeader := e.f.FileHeader
	isDyn := !xelf.IsNotDynamic(e.f)
	interp, err := xelf.GetInterp(e.f)
	if err != nil {
		log.Errorf("Read elf interp error: %v", err)
	}
	return fHeader, isDyn, interp
}

func (e *ElfRender) Render() (d *data.AnalyseData, err error) {
	renderRes := data.NewSet(
		form.NewTitleMarkdown(form.H2, "ELF File Header"),
		e.buildHeader(),
		form.NewTitleMarkdown(form.H2, "ELF Prog Header"),
		e.buildProgHeader(),
		e.buildDynamicData(),
	)

	t := e.Type()
	d = data.NewAnalyseData(renderRes).WithName(t.Name).WithID(t.ID)
	return
}

func (e *ElfRender) Type() Type {
	return ElfType
}

func (e *ElfRender) Release() {
	_ = e.f.Close()
}

func (e *ElfRender) buildHeader() data.Content {
	header := e.f.FileHeader

	table := form.NewTable("MEMBER", "VALUE").
		WithDesc(fmt.Sprintf("table 1: file %q header, for more information, see: %q", e.filepath, "readelf -h ..."))
	table.AddRow("Class", header.Class).
		AddRow("data", header.Data).
		AddRow("ByteOrder", header.ByteOrder).
		AddRow("Version", header.Version).
		AddRow("Os/ABI", header.OSABI).
		AddRow("ABI Version", strconv.Itoa(int(header.ABIVersion))).
		AddRow("Type", header.Type).
		AddRow("Machine", header.Machine).
		AddRow("Version", header.Version).
		AddRow("Entry", convertAddr(header.Entry))
	return table
}

func (e *ElfRender) buildProgHeader() data.Content {
	ph := e.f.Progs

	table := form.NewTable("Type", "Offset", "FileSize", "VirtAddr", "MemSize", "PhysAddr", "Flags", "Align").
		WithDesc(fmt.Sprintf("table 2: file %q program headers, for more information, see: %q", e.filepath, "readelf -l ...")).
		SetHandler(convertRow)
	for _, prog := range ph {
		table.AddRow(prog.Type, prog.Off, prog.Filesz, prog.Vaddr, prog.Memsz, prog.Paddr, prog.Flags, prog.Align)
	}

	return table
}

func (e *ElfRender) buildStaticData() data.Content {
	sectionRels, err := xelf.BuildRelIf(e.f, false)
	if err != nil {
		log.Warnf("Get static rel data from elf file failed: %v", err)
		return data.EmptyContent
	}
	if len(sectionRels) == 0 {
		return data.EmptyContent
	}

	mk := data.NewSet(form.NewTitleMarkdown(form.H3, "Static relocation info"))
	for _, rel := range sectionRels {
		mk.Combine(relSecToMarkdown(rel))
	}
	return mk
}

func (e *ElfRender) buildDynamicData() data.Content { //nolint:funlen
	dynInfo, err := xelf.BuildDynamicInfo(e.f)
	if err != nil {
		log.Warnf("Get static rel data from elf file failed: %v", err)
		return data.EmptyContent
	}
	if helper.IsNil(dynInfo) {
		return data.EmptyContent
	}

	resContent := data.NewSet()

	// info
	resContent.Combine(form.NewTitleMarkdown(form.H2, "Dynamic info").
		Append(form.NewTitleMarkdown(form.H3, "interp").WithContents(dynInfo.Interp)))

	// dynamic symbol
	symContent := form.NewTitleMarkdown(form.H3, "dynamic symbols")
	if syms := dynInfo.Symbols; len(syms) == 0 {
		resContent.Combine(symContent.WithContents("no data"))
	} else {
		symTable := form.NewTable("Name", "Section", "Value", "Size", "Library", "Version").SetHandler(convertRow)
		for _, symbol := range syms {
			symTable.AddRow(symbol.Name, symbol.Section, symbol.Value, symbol.Size, symbol.Library, symbol.Version)
		}
		resContent.Combine(symContent, symTable)
	}

	// dyn
	tag2DynContent := form.NewTitleMarkdown(form.H3, "dyn string")
	if t2d := dynInfo.Tag2Dyn; len(dynInfo.Tag2Dyn) == 0 {
		resContent.Combine(tag2DynContent.WithContents("No data"))
	} else {
		tag2DynTable := form.NewTable("Tag", "Data")
		for tag, strList := range t2d {
			if len(strList) == 0 {
				continue
			}
			tagStr := tag.String()
			for _, str := range strList {
				tag2DynTable.AddRow(tagStr, str)
			}
		}
		resContent.Combine(tag2DynContent, tag2DynTable)
	}

	// import symbol
	importSymsContent := form.NewTitleMarkdown(form.H3, "import symbols")
	if iSym := dynInfo.ImportedSymbols; len(iSym) == 0 {
		resContent.Combine(importSymsContent.WithContents("no data"))
	} else {
		importSymsTable := form.NewTable("Name", "Version", "Library")
		for _, symbol := range iSym {
			importSymsTable.AddRow(symbol.Name, symbol.Version, symbol.Library)
		}
		resContent.Combine(importSymsContent, importSymsTable)
	}

	relSecs := form.NewTitleMarkdown(form.H3, "Dynamic relocation sections")
	if rss := dynInfo.RelSections; len(rss) == 0 {
		resContent.Combine(relSecs.WithContents("No data"))
	} else {
		resContent.Combine(relSecs)
		for _, rel := range rss {
			resContent.Combine(relSecToMarkdown(rel))
		}
	}

	return resContent
}

func relSecToMarkdown(rSec xelf.RelSection) data.Content {
	sec := rSec.Section
	mk := data.NewSet(form.NewTitleMarkdown(form.H4, "Relocation Section ["+sec.Name+"]"))
	secTable := form.NewTable("Name", "Type", "Flags", "Addr", "Offset",
		"Size", "Link", "Info", "Addralign", "Entsize", "FileSize").SetHandler(convertRow)
	secTable.AddRow(sec.Name, sec.Type, sec.Flags, sec.Addr, sec.Offset, sec.Size, sec.Link, sec.Info,
		sec.Addralign, sec.Entsize, sec.FileSize)
	mk.Combine(secTable, relsToMarkdown(rSec.Rels))
	return mk
}

func relsToMarkdown(rels []xelf.RelDecoded) data.Content {
	if len(rels) == 0 {
		return data.EmptyContent
	}
	relTable := form.NewTable("Offset", "Type", "Value")
	for _, rel := range rels {
		relTable.AddRow(convertAddr(rel.Offset), rel.XType, rel.Value)
	}
	return relTable
}

func convertRow(val interface{}) (string, bool) {
	switch val := val.(type) {
	case uint64:
		return convertAddr(val), true
	case uint32:
		return convertAddr(uint64(val)), true
	case string:
		return val, true
	case fmt.Stringer:
		return val.String(), true
	}
	return "", false
}

func convertAddr(addr uint64) string {
	return "0X" + strconv.FormatUint(addr, 16)
}
