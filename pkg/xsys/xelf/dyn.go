package xelf

import (
	"debug/elf"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
)

type DynamicInfo struct {
	Interp          string
	Symbols         []elf.Symbol
	Tag2Dyn         map[elf.DynTag][]string
	ImportedSymbols []elf.ImportedSymbol
	RelSections     []RelSection
}

func BuildDynamicInfo(f *elf.File) (dynamicInfo *DynamicInfo, err error) {
	if IsNotDynamic(f) {
		return nil, nil
	}
	dynamicInfo = &DynamicInfo{}
	if dynamicInfo.Interp, err = GetInterp(f); err != nil {
		return nil, err
	}

	if dynamicInfo.Symbols, err = f.DynamicSymbols(); err != nil {
		return nil, err
	}

	if dynamicInfo.Tag2Dyn, err = getDynTagSymbols(f); err != nil {
		return nil, err
	}

	if dynamicInfo.ImportedSymbols, err = f.ImportedSymbols(); err != nil {
		return nil, err
	}

	if dynamicInfo.RelSections, err = BuildRelIf(f, true); err != nil {
		return nil, err
	}

	return
}

func IsNotDynamic(f *elf.File) bool {
	return f.Type != elf.ET_DYN
}

func GetInterp(f *elf.File) (string, error) {
	for i := range f.Progs {
		if f.Progs[i].Type == elf.PT_INTERP {
			d, err := readBytes(f.Progs[i].Open(), 1024)
			if err != nil {
				return "", err
			}
			return helper.TrimBytes2Str(d), nil
		}
	}
	// 共享对象可以没有解释器
	return "", nil
}

func getDynTagSymbols(f *elf.File) (map[elf.DynTag][]string, error) {
	res := make(map[elf.DynTag][]string)
	tarDynTag := [...]elf.DynTag{elf.DT_NEEDED, elf.DT_SONAME, elf.DT_RPATH, elf.DT_RUNPATH}
	for i := range tarDynTag {
		syms, err := f.DynString(tarDynTag[i])
		if err != nil {
			return nil, err
		}
		res[tarDynTag[i]] = syms
	}
	return res, nil
}
