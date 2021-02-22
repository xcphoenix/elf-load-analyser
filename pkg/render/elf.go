package render

import (
    "debug/elf"
    "fmt"
    "github.com/phoenixxc/elf-load-analyser/pkg/data"
    "os"
    "strconv"
)

// 文件路径
// ELF 格式

type ElfRender struct {
    filepath string
}

func NewElfRender(filepath string) *ElfRender {
    return &ElfRender{filepath: filepath}
}

func (e *ElfRender) Render() (*data.AnalyseData, error) {
    // file header
    f, err := os.Open(e.filepath)
    if err != nil {
        return nil, err
    }
    eFile, err := elf.NewFile(f)
    if err != nil {
        return nil, err
    }

    fHeader := data.NewItem(data.H3Level, "ELF File Header", e.buildHeader(eFile))
    fProgHeader := data.NewItem(data.H3Level, "ELF Prog Header", e.buildProgramHeader(eFile))
    h2 := data.NewItem(data.H2Level, "ELF", fHeader.String(), fProgHeader.String())

    // program header
    return data.NewAnalyseData(string(e.Type()), data.NewData(data.MarkdownType, h2.String())), nil
}

func (e *ElfRender) Type() Type {
    return ElfType
}

func (e *ElfRender) buildHeader(f *elf.File) string {
    header := f.FileHeader

    table := data.NewTable("MEMBER", "VALUE").
        WithDesc(fmt.Sprintf("table 1: file %q header, for more information, see: %q", e.filepath, "readelf -h ..."))
    table.AddRow("Class", header.Class.String()).
        AddRow("Data", header.Data.String()).
        AddRow("ByteOrder", header.ByteOrder.String()).
        AddRow("Version", header.Version.String()).
        AddRow("Os/ABI", header.OSABI.String()).
        AddRow("ABI Version", string(header.ABIVersion)).
        AddRow("Type", header.Type.String()).
        AddRow("Machine", header.Machine.String()).
        AddRow("Version", header.Version.String()).
        AddRow("Entry", addrConvert(header.Entry))
    return table.String()
}

func (e *ElfRender) buildProgramHeader(f *elf.File) string {
    ph := f.Progs

    table := data.NewTable("Type", "Offset", "FileSize", "VirtAddr", "MemSize", "PhysAddr", "Flags", "Align").
        WithDesc(fmt.Sprintf("table 2: file %q program headers, for more information, see: %q", e.filepath, "readelf -l ..."))
    for _, prog := range ph {
        table.AddRow(prog.Type.String(), addrConvert(prog.Off), addrConvert(prog.Filesz), addrConvert(prog.Vaddr),
            addrConvert(prog.Memsz), addrConvert(prog.Paddr), prog.Flags.String(), addrConvert(prog.Align))
    }
    return table.String()
}

func addrConvert(addr uint64) string {
    return "0X" + strconv.FormatUint(addr, 16)
}