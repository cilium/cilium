package btf

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"

	"golang.org/x/xerrors"
)

type btfExtHeader struct {
	Magic   uint16
	Version uint8
	Flags   uint8
	HdrLen  uint32

	FuncInfoOff uint32
	FuncInfoLen uint32
	LineInfoOff uint32
	LineInfoLen uint32
}

func parseExtInfos(r io.ReadSeeker, bo binary.ByteOrder, strings stringTable) (funcInfo, lineInfo map[string]extInfo, err error) {
	var header btfExtHeader
	if err := binary.Read(r, bo, &header); err != nil {
		return nil, nil, xerrors.Errorf("can't read header: %v", err)
	}

	if header.Magic != btfMagic {
		return nil, nil, xerrors.Errorf("incorrect magic value %v", header.Magic)
	}

	if header.Version != 1 {
		return nil, nil, xerrors.Errorf("unexpected version %v", header.Version)
	}

	if header.Flags != 0 {
		return nil, nil, xerrors.Errorf("unsupported flags %v", header.Flags)
	}

	remainder := int64(header.HdrLen) - int64(binary.Size(&header))
	if remainder < 0 {
		return nil, nil, xerrors.New("header is too short")
	}

	// Of course, the .BTF.ext header has different semantics than the
	// .BTF ext header. We need to ignore non-null values.
	_, err = io.CopyN(ioutil.Discard, r, remainder)
	if err != nil {
		return nil, nil, xerrors.Errorf("header padding: %v", err)
	}

	if _, err := r.Seek(int64(header.HdrLen+header.FuncInfoOff), io.SeekStart); err != nil {
		return nil, nil, xerrors.Errorf("can't seek to function info section: %v", err)
	}

	funcInfo, err = parseExtInfo(io.LimitReader(r, int64(header.FuncInfoLen)), bo, strings)
	if err != nil {
		return nil, nil, xerrors.Errorf("function info: %w", err)
	}

	if _, err := r.Seek(int64(header.HdrLen+header.LineInfoOff), io.SeekStart); err != nil {
		return nil, nil, xerrors.Errorf("can't seek to line info section: %v", err)
	}

	lineInfo, err = parseExtInfo(io.LimitReader(r, int64(header.LineInfoLen)), bo, strings)
	if err != nil {
		return nil, nil, xerrors.Errorf("line info: %w", err)
	}

	return funcInfo, lineInfo, nil
}

type btfExtInfoSec struct {
	SecNameOff uint32
	NumInfo    uint32
}

type extInfoRecord struct {
	InsnOff uint64
	Opaque  []byte
}

type extInfo struct {
	recordSize uint32
	records    []extInfoRecord
}

func (ei extInfo) append(other extInfo, offset uint64) (extInfo, error) {
	if other.recordSize != ei.recordSize {
		return extInfo{}, xerrors.Errorf("ext_info record size mismatch, want %d (got %d)", ei.recordSize, other.recordSize)
	}

	records := make([]extInfoRecord, 0, len(ei.records)+len(other.records))
	records = append(records, ei.records...)
	for _, info := range other.records {
		records = append(records, extInfoRecord{
			InsnOff: info.InsnOff + offset,
			Opaque:  info.Opaque,
		})
	}
	return extInfo{ei.recordSize, records}, nil
}

func (ei extInfo) MarshalBinary() ([]byte, error) {
	if len(ei.records) == 0 {
		return nil, nil
	}

	buf := bytes.NewBuffer(make([]byte, 0, int(ei.recordSize)*len(ei.records)))
	for _, info := range ei.records {
		// The kernel expects offsets in number of raw bpf instructions,
		// while the ELF tracks it in bytes.
		insnOff := uint32(info.InsnOff / asm.InstructionSize)
		if err := binary.Write(buf, internal.NativeEndian, insnOff); err != nil {
			return nil, xerrors.Errorf("can't write instruction offset: %v", err)
		}

		buf.Write(info.Opaque)
	}

	return buf.Bytes(), nil
}

func parseExtInfo(r io.Reader, bo binary.ByteOrder, strings stringTable) (map[string]extInfo, error) {
	var recordSize uint32
	if err := binary.Read(r, bo, &recordSize); err != nil {
		return nil, xerrors.Errorf("can't read record size: %v", err)
	}

	if recordSize < 4 {
		// Need at least insnOff
		return nil, xerrors.New("record size too short")
	}

	result := make(map[string]extInfo)
	for {
		var infoHeader btfExtInfoSec
		if err := binary.Read(r, bo, &infoHeader); err == io.EOF {
			return result, nil
		} else if err != nil {
			return nil, xerrors.Errorf("can't read ext info header: %v", err)
		}

		secName, err := strings.Lookup(infoHeader.SecNameOff)
		if err != nil {
			return nil, xerrors.Errorf("can't get section name: %w", err)
		}

		if infoHeader.NumInfo == 0 {
			return nil, xerrors.Errorf("section %s has invalid number of records", secName)
		}

		var records []extInfoRecord
		for i := uint32(0); i < infoHeader.NumInfo; i++ {
			var byteOff uint32
			if err := binary.Read(r, bo, &byteOff); err != nil {
				return nil, xerrors.Errorf("section %v: can't read extended info offset: %v", secName, err)
			}

			buf := make([]byte, int(recordSize-4))
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, xerrors.Errorf("section %v: can't read record: %v", secName, err)
			}

			if byteOff%asm.InstructionSize != 0 {
				return nil, xerrors.Errorf("section %v: offset %v is not aligned with instruction size", secName, byteOff)
			}

			records = append(records, extInfoRecord{uint64(byteOff), buf})
		}

		result[secName] = extInfo{
			recordSize,
			records,
		}
	}
}
