package verifierlog

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
)

// ParseVerifierLog parses the verbose output of the kernel eBPF verifier. It simply returns all statements in the order
// they appeared in the verifier output.
func ParseVerifierLog(log string) []VerifierStatement {
	scan := bufio.NewScanner(strings.NewReader(log))
	statements := make([]VerifierStatement, 0)
	for scan.Scan() {
		parsed := parseStatement(scan)
		if parsed != nil {
			statements = append(statements, parsed)
		}
	}
	return statements
}

// MergedPerInstruction takes and parses the verifier log. It then merges the observed register and stack states seen
// for each permutation the verifier considers. The resulting state isn't useful for its values, just to see which
// registers are never used and which stack slots/offsets are never used.
func MergedPerInstruction(log string) []VerifierState {
	scan := bufio.NewScanner(strings.NewReader(log))
	states := make([]VerifierState, 0)

	var curState VerifierState

	mergeCurState := func(state VerifierState) {
		curState.Unknown = false

		for _, reg := range state.Registers {
			found := false
			for i, curReg := range curState.Registers {
				if reg.Register == curReg.Register {
					curState.Registers[i] = reg
					found = true
					break
				}
			}
			if !found {
				curState.Registers = append(curState.Registers, reg)
			}
		}

		for _, slot := range state.Stack {
			found := false
			for i, curSlot := range curState.Stack {
				if slot.Offset == curSlot.Offset {
					curState.Stack[i] = slot
					found = true
					break
				}
			}
			if !found {
				curState.Stack = append(curState.Stack, slot)
			}
		}
	}

	applyCurState := func(instNum int) {
		if instNum >= len(states) {
			newStates := make([]VerifierState, 1+instNum-len(states))
			for i := range newStates {
				newStates[i].Unknown = true
			}
			states = append(states, newStates...)
		}

		// Apply current state to `states`
		for _, curReg := range curState.Registers {
			states[instNum].Unknown = false

			found := false
			for i, reg := range states[instNum].Registers {
				if reg.Register == curReg.Register {
					states[instNum].Registers[i] = reg
					found = true
					break
				}
			}
			if !found {
				states[instNum].Registers = append(states[instNum].Registers, curReg)
			}
		}

		for _, curSlot := range curState.Stack {
			found := false
			for i, slot := range states[instNum].Stack {
				if slot.Offset == curSlot.Offset {
					states[instNum].Stack[i] = slot
					found = true
					break
				}
			}
			if !found {
				states[instNum].Stack = append(states[instNum].Stack, curSlot)
			}
		}
	}

	for scan.Scan() {
		parsed := parseStatement(scan)
		if parsed != nil {
			switch parsed := parsed.(type) {
			case *RecapState:
				// RecapState only show relevant values not all of them, so apply the diff
				mergeCurState(parsed.State)

			case *ReturnFunctionCall:
				curState = *parsed.CallerState

			case *BranchEvaluation:
				curState = *parsed.State

			case *Instruction:
				// Apply current state to `states`
				applyCurState(parsed.InstructionNumber)

			case *InstructionState:
				// Apply current state to `states`
				applyCurState(parsed.InstructionNumber)

				// InstructionState only show relevant values not all of them, so apply the diff
				mergeCurState(parsed.State)

			default:
				continue
			}
		}
	}

	return states
}

func parseStatement(scan *bufio.Scanner) VerifierStatement {
	line := scan.Text()
	// Skip empty lines
	if line == "" {
		return nil
	}

	if strings.HasPrefix(line, ";") {
		return parseComment(line)
	}

	if strings.HasPrefix(line, "func#") {
		return parseSubProgLocation(line)
	}

	if strings.HasPrefix(line, "propagating") {
		return parsePropagatePrecision(line)
	}

	if strings.HasPrefix(line, "last_idx") {
		return parseBackTrackingHeader(line)
	}

	if strings.HasPrefix(line, "caller") {
		return parseFunctionCall(line, scan)
	}

	if strings.HasPrefix(line, "returning from callee") {
		return parseReturnFunctionCall(line, scan)
	}

	if statePrunedRegex.MatchString(line) {
		return parseStatePruned(line)
	}

	if instructionStateRegex.MatchString(line) {
		return parseInstructionState(line)
	}

	if instructionRegex.MatchString(line) {
		return parseInstruction(line)
	}

	if recapStateRegex.MatchString(line) {
		return parseRecapState(line)
	}

	if branchEvaluationRegex.MatchString(line) {
		return parseBranchEvaluation(line)
	}

	if backTrackInstructionRegex.MatchString(line) {
		return parseBackTrackInstruction(line)
	}

	if backTrackingTrailerRegex.MatchString(line) {
		return parseBacktrackingTrailer(line)
	}

	if loadSuccessRegex.MatchString(line) {
		return parseLoadSuccess(line)
	}

	return &Unknown{Log: line}
}

// VerifierStatement is often a single line of the log.
type VerifierStatement interface {
	fmt.Stringer
	verifierStmt()
}

// For when we have no clue what a line is or means
type Unknown struct {
	Log string
}

func (u *Unknown) String() string {
	return u.Log
}

func (u *Unknown) verifierStmt() {}

// An error, something went wrong
type Error struct {
	Msg string
}

func (e *Error) String() string {
	return e.Msg
}

func (e *Error) Error() string {
	return e.Msg
}

func (e *Error) verifierStmt() {}

func parseComment(line string) *Comment {
	return &Comment{
		Comment: strings.TrimPrefix(line, "; "),
	}
}

// A comment, usually contains the original line of the source code
// Example: "; if (data + nh_off > data_end)"
type Comment struct {
	Comment string
}

func (c *Comment) String() string {
	return fmt.Sprintf("; %s", c.Comment)
}

func (c *Comment) verifierStmt() {}

var recapStateRegex = regexp.MustCompile(`^(\d+): ?(.*)`)

func parseRecapState(line string) VerifierStatement {
	match := recapStateRegex.FindStringSubmatch(line)
	if len(match) == 0 {
		return &Error{Msg: "recap state: no match"}
	}

	instNr, err := strconv.Atoi(match[1])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("recap state: inst nr atoi: %s", err)}
	}

	verifierState, err := parseVerifierState(match[2])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("recap state: parse verifier state: %s", err)}
	}
	if verifierState == nil {
		return &Error{Msg: "recap state: nil verifier state"}
	}

	return &RecapState{
		InstructionNumber: instNr,
		State:             *verifierState,
	}
}

// A recap of the current state of the verifier and its location, without indicating it evaluated an expression.
// This happens when the verifier switches state to evaluate another permutation.
// Example: "0: R1=ctx(id=0,off=0,imm=0) R10=fp0"
type RecapState struct {
	InstructionNumber int
	State             VerifierState
}

func (is *RecapState) String() string {
	return fmt.Sprintf("%d: %s", is.InstructionNumber, is.State.String())
}

func (is *RecapState) verifierStmt() {}

var instructionStateRegex = regexp.MustCompile(`^(\d+): \(([0-9a-f]{2})\)([^;]+);(.*)`)

func parseInstructionState(line string) VerifierStatement {
	match := instructionStateRegex.FindStringSubmatch(line)
	if len(match) == 0 {
		return &Error{Msg: "instruction state: no match"}
	}

	instNr, err := strconv.Atoi(match[1])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("inst nr atoi: %s", err)}
	}

	opcode, err := hex.DecodeString(match[2])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("decode opcode hex: %s", err)}
	}

	verifierState, err := parseVerifierState(match[4])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("parse verifier state: %s", err)}
	}
	if verifierState == nil {
		return &Error{Msg: "bad or missing verifier state"}
	}

	return &InstructionState{
		Instruction: Instruction{
			InstructionNumber: instNr,
			Opcode:            asm.OpCode(opcode[0]),
			Assembly:          match[3],
		},
		State: *verifierState,
	}
}

// Instruction and verifier state. Logged when the verifier evaluates an instruction. The state is the state after the
// instruction was evaluated.
// Example: "0: (b7) r6 = 1; R6_w=invP1"
type InstructionState struct {
	Instruction
	State VerifierState
}

func (is *InstructionState) String() string {
	return fmt.Sprintf("%d: (%02x)%s; %s", is.InstructionNumber, byte(is.Opcode), is.Assembly, is.State.String())
}

func (is *InstructionState) verifierStmt() {}

var instructionRegex = regexp.MustCompile(`^(\d+): \(([0-9a-f]{2})\)([^;]+)`)

func parseInstruction(line string) VerifierStatement {
	match := instructionRegex.FindStringSubmatch(line)
	if len(match) == 0 {
		return &Error{Msg: "instruction state: no match"}
	}

	instNr, err := strconv.Atoi(match[1])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("inst nr atoi: %s", err)}
	}

	opcode, err := hex.DecodeString(match[2])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("decode opcode hex: %s", err)}
	}
	return &Instruction{
		InstructionNumber: instNr,
		Opcode:            asm.OpCode(opcode[0]),
		Assembly:          match[3],
	}
}

func (is *Instruction) String() string {
	return fmt.Sprintf("%d: (%02x)%s", is.InstructionNumber, byte(is.Opcode), is.Assembly)
}

func (is *Instruction) verifierStmt() {}

// Instruction describes an instruction, is used by multiple statements.
// Example: "22: (85) call pc+4"
type Instruction struct {
	InstructionNumber int
	Opcode            asm.OpCode
	Assembly          string
}

func parseVerifierState(line string) (*VerifierState, error) {
	var state VerifierState
	line = strings.TrimSpace(line)

	if strings.HasPrefix(line, "frame") {
		line = strings.TrimPrefix(line, "frame")
		colon := strings.Index(line, ":")
		if colon == -1 {
			return nil, nil
		}

		var err error
		state.FrameNumber, err = strconv.Atoi(line[:colon])
		if err != nil {
			return nil, fmt.Errorf("frame number atoi: %s", err)
		}

		line = strings.TrimSpace(line[colon+1:])
	}

	for {
		equal := strings.Index(line, "=")
		if equal == -1 {
			break
		}

		key := line[:equal]
		var value string

		line = line[equal+1:]
		// If there are chars left after '=' find the end of the current value.
		// If not, the current key may not have a value (R1=) which is also valid.
		if len(line) > 1 {
			bktDepth := 0
			i := 0
			for {
				i++
				if i >= len(line) {
					value = line
					line = line[i:]
					break
				}

				if line[i] == '(' {
					bktDepth++
					continue
				}

				if line[i] == ')' {
					bktDepth--
					continue
				}

				if line[i] == ' ' && bktDepth == 0 {
					value = line[:i]
					line = line[i+1:]
					break
				}
			}
		}

		if strings.HasPrefix(key, "fp") {
			stackState, err := parseStackState(key, value)
			if err != nil {
				return nil, fmt.Errorf("parse stack state: %w", err)
			}

			if stackState != nil {
				state.Stack = append(state.Stack, *stackState)
			}
		} else {
			regState, err := parseRegisterState(key, value)
			if err != nil {
				return nil, fmt.Errorf("parse register state: %w", err)
			}
			if regState != nil {
				state.Registers = append(state.Registers, *regState)
			}
		}
	}

	return &state, nil
}

// VerifierState contains a description of the state of the verifier at a certain point. Used by a number of statements.
// Example: "frame1: R2_w=invP(id=0) R10=fp0 fp-16_w=mmmmmmmm"
type VerifierState struct {
	FrameNumber int
	Registers   []RegisterState
	Stack       []StackState
	// If true, the struct was initialized as filler, but no actual state info is known
	Unknown bool
}

func parseRegisterState(key, value string) (*RegisterState, error) {
	var state RegisterState

	if idx := strings.Index(key, "_"); idx != -1 {
		livenessStr := key[idx+1:]
		if strings.Contains(livenessStr, "r") {
			state.Liveness = state.Liveness | LivenessRead
		}
		if strings.Contains(livenessStr, "w") {
			state.Liveness = state.Liveness | LivenessWritten
		}
		if strings.Contains(livenessStr, "D") {
			state.Liveness = state.Liveness | LivenessDone
		}

		key = key[:idx]
	}

	key = strings.Trim(key, "R")
	keyNum, err := strconv.Atoi(key)
	if err != nil {
		return nil, fmt.Errorf("reg num atoi: %w", err)
	}
	state.Register = asm.Register(keyNum)

	val, err := parseRegisterValue(value)
	if err != nil {
		return nil, fmt.Errorf("parse register value: %w", err)
	}
	if val != nil {
		state.Value = *val
	}

	return &state, err
}

func (is *VerifierState) String() string {
	if is.Unknown {
		return "unknown"
	}

	var sb strings.Builder

	if is.FrameNumber != 0 {
		fmt.Fprintf(&sb, "frame%d: ", is.FrameNumber)
	}

	for i, reg := range is.Registers {
		fmt.Fprint(&sb, reg)

		if i+1 < len(is.Registers) || len(is.Stack) > 0 {
			sb.WriteString(" ")
		}
	}

	for i, stackSlot := range is.Stack {
		fmt.Fprint(&sb, stackSlot.String())

		if i+1 < len(is.Stack) {
			sb.WriteString(" ")
		}
	}

	return sb.String()
}

// Liveness indicates the liveness of a register.
type Liveness int

const (
	LivenessNone Liveness = 0
	LivenessRead          = 1 << (iota - 1)
	LivenessWritten
	LivenessDone
)

// RegType indicates the data type contained in a register
type RegType int

const (
	RegTypeNotInit RegType = iota
	RegTypeScalarValue
	RegTypePtrToCtx
	RegTypeConstPtrToMap
	RegTypeMapValue
	RegTypePtrToStack
	RegTypePtrToPacket
	RegTypePtrToPacketMeta
	RegTypePtrToPacketEnd
	RegTypePtrToFlowKeys
	RegTypePtrToSock
	RegTypePtrToSockCommon
	RegTypePtrToTCPSock
	RegTypePtrToTPBuf
	RegTypePtrToXDPSock
	RegTypePtrToBTFID
	RegTypePtrToMem
	RegTypePtrToBuf
	RegTypePtrToFunc
	RegTypePtrToMapKey
)

const (
	RegTypeBaseType RegType = 0xFF

	RegTypePtrMaybeNull RegType = 1 << (8 + iota)
	RegTypeMemReadonly
	RegTypeMemAlloc
	RegTypeMemUser
	RegTypeMemPreCPU
)

var rtToString = map[RegType]string{
	RegTypeNotInit:         "?",
	RegTypeScalarValue:     "scalar",
	RegTypePtrToCtx:        "ctx",
	RegTypeConstPtrToMap:   "map_ptr",
	RegTypePtrToMapKey:     "map_key",
	RegTypeMapValue:        "map_value",
	RegTypePtrToStack:      "fp",
	RegTypePtrToPacket:     "pkt",
	RegTypePtrToPacketMeta: "pkt_meta",
	RegTypePtrToPacketEnd:  "pkt_end",
	RegTypePtrToFlowKeys:   "flow_keys",
	RegTypePtrToSock:       "sock",
	RegTypePtrToSockCommon: "sock_common",
	RegTypePtrToTCPSock:    "tcp_sock",
	RegTypePtrToTPBuf:      "tp_buffer",
	RegTypePtrToXDPSock:    "xdp_sock",
	RegTypePtrToBTFID:      "ptr_",
	RegTypePtrToMem:        "mem",
	RegTypePtrToBuf:        "buf",
	RegTypePtrToFunc:       "func",
}

var stringToRT = map[string]RegType{
	"inv":         RegTypeScalarValue,
	"scalar":      RegTypeScalarValue,
	"ctx":         RegTypePtrToCtx,
	"map_ptr":     RegTypeConstPtrToMap,
	"map_key":     RegTypePtrToMapKey,
	"map_value":   RegTypeMapValue,
	"fp":          RegTypePtrToStack,
	"pkt":         RegTypePtrToPacket,
	"pkt_meta":    RegTypePtrToPacketMeta,
	"pkt_end":     RegTypePtrToPacketEnd,
	"flow_keys":   RegTypePtrToFlowKeys,
	"sock":        RegTypePtrToSock,
	"sock_common": RegTypePtrToSockCommon,
	"tcp_sock":    RegTypePtrToTCPSock,
	"tp_buffer":   RegTypePtrToTPBuf,
	"xdp_sock":    RegTypePtrToXDPSock,
	"ptr_":        RegTypePtrToBTFID,
	"mem":         RegTypePtrToMem,
	"buf":         RegTypePtrToBuf,
	"func":        RegTypePtrToFunc,
}

func (rt RegType) String() string {
	var sb strings.Builder

	if rt&RegTypeMemReadonly != 0 {
		sb.WriteString("rdonly_")
	}
	if rt&RegTypeMemAlloc != 0 {
		sb.WriteString("alloc_")
	}
	if rt&RegTypeMemUser != 0 {
		sb.WriteString("user_")
	}
	if rt&RegTypeMemPreCPU != 0 {
		sb.WriteString("per_cpu_")
	}

	sb.WriteString(rtToString[rt&RegTypeBaseType])

	if rt&RegTypePtrMaybeNull != 0 {
		if rt&RegTypeBaseType == RegTypePtrToBTFID {
			sb.WriteString("or_null_")
		} else {
			sb.WriteString("_or_null_")
		}
	}

	return sb.String()
}

// TNum is a tracked (or tristate) number. Relevant parts ported from linux kernel.
// https://elixir.bootlin.com/linux/v5.18.3/source/include/linux/tnum.h
// https://elixir.bootlin.com/linux/v5.18.3/source/kernel/bpf/tnum.c
type TNum struct {
	Value uint64
	Mask  uint64
}

func (t TNum) isConst() bool {
	return t.Mask == 0
}

func (t TNum) isUnknown() bool {
	return t.Mask == math.MaxInt64
}

func parseRegisterType(line string) (RegType, bool, string) {
	var typ RegType
	precise := false

	if strings.HasPrefix(line, "rdonly_") {
		typ = typ | RegTypeMemReadonly
		line = strings.TrimPrefix(line, "rdonly_")
	}

	if strings.HasPrefix(line, "alloc_") {
		typ = typ | RegTypeMemAlloc
		line = strings.TrimPrefix(line, "alloc_")
	}

	if strings.HasPrefix(line, "user_") {
		typ = typ | RegTypeMemUser
		line = strings.TrimPrefix(line, "user_")
	}

	if strings.HasPrefix(line, "per_cpu_") {
		typ = typ | RegTypeMemPreCPU
		line = strings.TrimPrefix(line, "per_cpu_")
	}

	if strings.HasPrefix(line, "P") {
		precise = true
		line = strings.TrimPrefix(line, "P")
	}

	// Process names from longest to shortest to avoid exiting early on a shorter match
	names := make([]string, 0, len(stringToRT))
	for name := range stringToRT {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return len(names[i]) > len(names[j])
	})

	for _, name := range names {
		if strings.HasPrefix(line, name) {
			typ = typ | stringToRT[name]
			line = strings.TrimPrefix(line, name)
			break
		}
	}

	if strings.HasPrefix(line, "or_null_") {
		typ = typ | RegTypePtrMaybeNull
		line = strings.TrimPrefix(line, "or_null_")
	}

	if strings.HasPrefix(line, "_or_null_") {
		typ = typ | RegTypePtrMaybeNull
		line = strings.TrimPrefix(line, "_or_null_")
	}

	if strings.HasPrefix(line, "P") {
		precise = true
		line = strings.TrimPrefix(line, "P")
	}

	return typ, precise, line
}

func parseRegisterValue(line string) (*RegisterValue, error) {
	var val RegisterValue

	line = strings.TrimSpace(line)

	val.Type, val.Precise, line = parseRegisterType(line)

	if val.Type == RegTypeScalarValue {
		varOff, err := strconv.Atoi(line)
		if err == nil {
			val.VarOff.Value = uint64(varOff)
			return &val, nil
		}
	}

	line = strings.TrimSuffix(strings.TrimPrefix(line, "("), ")")
	for _, pair := range strings.Split(line, ",") {
		eq := strings.Index(pair, "=")
		if eq == -1 {
			continue
		}

		key := pair[:eq]
		valStr := pair[eq+1:]

		//nolint:errcheck // one of these will always fail, doesn't matter since the default value is 0
		intVal, _ := strconv.ParseInt(valStr, 10, 64)
		//nolint:errcheck // one of these will always fail, doesn't matter since the default value is 0
		uintVal, _ := strconv.ParseUint(valStr, 10, 64)

		switch key {
		case "id":
			val.ID = int(intVal)
		case "ref_obj_id":
			val.RefObjID = int(intVal)
		case "off":
			val.Off = int32(intVal)
		case "r":
			val.Range = int(intVal)
		case "ks":
			val.KeySize = int(intVal)
		case "vs":
			val.ValueSize = int(intVal)
		case "imm":
			val.VarOff.Value = uint64(intVal)
		case "smin", "smin_value":
			val.SMinValue = intVal
		case "smax", "smax_value":
			val.SMaxValue = intVal
		case "umin", "umin_value":
			val.UMinValue = uintVal
		case "umax", "umax_value":
			val.UMaxValue = uintVal
		case "s32_min", "s32_min_value":
			val.S32MinValue = int32(intVal)
		case "s32_max", "s32_max_value":
			val.S32MaxValue = int32(intVal)
		case "u32_min", "u32_min_value":
			val.U32MinValue = uint32(uintVal)
		case "u32_max", "u32_max_value":
			val.U32MaxValue = uint32(uintVal)
		case "var_off":
			semicolon := strings.Index(valStr, ";")
			closeBrace := strings.Index(valStr, ")")

			if semicolon < 1 {
				return nil, fmt.Errorf("bad var_off, semicolon missing or misplaced")
			}

			if closeBrace < semicolon {
				return nil, fmt.Errorf("bad var_off, closing brace must come after semicolon")
			}

			hexVal := strings.TrimSpace(valStr[1:semicolon])
			hexMask := strings.TrimSpace(valStr[semicolon+1 : closeBrace])

			var err error
			val.VarOff.Value, err = strconv.ParseUint(hexVal, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("parse hex val: %w", err)
			}

			val.VarOff.Value, err = strconv.ParseUint(hexMask, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("parse hex mask: %w", err)
			}
		}
	}

	return &val, nil
}

// RegisterValue is the value part of the register state, the part after the =
// Example: "invP(id=2,umax_value=255,var_off=(0x0; 0xff))"
type RegisterValue struct {
	Type      RegType
	Off       int32
	ID        int
	RefObjID  int
	Range     int
	KeySize   int
	ValueSize int
	// if (!precise && SCALAR_VALUE) min/max/tnum don't affect safety
	Precise bool
	/* For scalar types (SCALAR_VALUE), this represents our knowledge of
	 * the actual value.
	 * For pointer types, this represents the variable part of the offset
	 * from the pointed-to object, and is shared with all bpf_reg_states
	 * with the same id as us.
	 */
	VarOff TNum
	/* Used to determine if any memory access using this register will
	 * result in a bad access.
	 * These refer to the same value as var_off, not necessarily the actual
	 * contents of the register.
	 */
	SMinValue   int64  /* minimum possible (s64)value */
	SMaxValue   int64  /* maximum possible (s64)value */
	UMinValue   uint64 /* minimum possible (u64)value */
	UMaxValue   uint64 /* maximum possible (u64)value */
	S32MinValue int32  /* minimum possible (s32)value */
	S32MaxValue int32  /* maximum possible (s32)value */
	U32MinValue uint32 /* minimum possible (u32)value */
	U32MaxValue uint32 /* maximum possible (u32)value */

	BTFName string
}

func (rv RegisterValue) String() string {
	var sb strings.Builder
	baseType := rv.Type & RegTypeBaseType

	// TODO make setting to determine to print the P before or after the inv
	if rv.Type == RegTypeScalarValue && rv.Precise {
		sb.WriteString("P")
	}

	if (rv.Type == RegTypeScalarValue || rv.Type == RegTypePtrToStack) && rv.VarOff.isConst() {
		if rv.Type == RegTypeScalarValue {
			fmt.Fprintf(&sb, "%d", rv.VarOff.Value+uint64(rv.Off))
		} else {
			sb.WriteString(rv.Type.String())
		}
		return sb.String()
	}

	sb.WriteString(rv.Type.String())
	if baseType == RegTypePtrToBTFID {
		sb.WriteString(rv.BTFName)
	}
	sb.WriteString("(")

	var args []string
	if rv.ID != 0 {
		args = append(args, fmt.Sprintf("id=%d", rv.ID))
	}

	// reg_type_may_be_refcounted_or_null
	if baseType == RegTypePtrToSock || baseType == RegTypePtrToTCPSock || baseType == RegTypePtrToMem {
		args = append(args, fmt.Sprintf("ref_obj_id=%d", rv.RefObjID))
	}

	if baseType != RegTypeScalarValue {
		args = append(args, fmt.Sprintf("off=%d", rv.Off))
	}

	// type_is_pkt_pointer
	if baseType == RegTypePtrToPacket || baseType == RegTypePtrToPacketMeta {
		args = append(args, fmt.Sprintf("r=%d", rv.Range))
	} else if baseType == RegTypeConstPtrToMap || baseType == RegTypePtrToMapKey || baseType == RegTypeMapValue {
		args = append(args, fmt.Sprintf("ks=%d,vs=%d", rv.KeySize, rv.ValueSize))
	}

	if rv.VarOff.isConst() {
		args = append(args, fmt.Sprintf("imm=%d", rv.VarOff.Value))
	} else {
		if rv.SMinValue != int64(rv.UMinValue) && rv.SMinValue != math.MinInt64 {
			args = append(args, fmt.Sprintf("smin=%d", rv.SMinValue))
		}

		if rv.SMaxValue != int64(rv.UMaxValue) && rv.SMaxValue != math.MaxInt64 {
			args = append(args, fmt.Sprintf("smax=%d", rv.SMaxValue))
		}

		if rv.UMinValue != 0 {
			args = append(args, fmt.Sprintf("umin=%d", rv.SMaxValue))
		}

		if rv.UMaxValue != math.MaxUint64 {
			args = append(args, fmt.Sprintf("umin=%d", rv.SMaxValue))
		}

		if !rv.VarOff.isUnknown() {
			args = append(args, fmt.Sprintf("var_off=(%x; %x)", rv.VarOff.Value, rv.VarOff.Mask))
		}

		if int64(rv.S32MinValue) != rv.SMinValue && rv.S32MinValue != math.MinInt32 {
			args = append(args, fmt.Sprintf("s32_min=%d", rv.S32MinValue))
		}

		if int64(rv.S32MaxValue) != rv.SMaxValue && rv.S32MaxValue != math.MaxInt32 {
			args = append(args, fmt.Sprintf("s32_max=%d", rv.S32MaxValue))
		}

		if uint64(rv.U32MinValue) != rv.UMinValue && rv.U32MinValue != 0 {
			args = append(args, fmt.Sprintf("u32_min=%d", rv.S32MinValue))
		}

		if uint64(rv.U32MaxValue) != rv.UMaxValue && rv.U32MaxValue != math.MaxUint32 {
			args = append(args, fmt.Sprintf("u32_max=%d", rv.U32MaxValue))
		}
	}

	sb.WriteString(strings.Join(args, ","))
	sb.WriteString(")")

	return sb.String()
}

// RegisterState describes a single register and its state.
// Example: "R1_w=invP(id=2,umax_value=255,var_off=(0x0; 0xff))"
type RegisterState struct {
	Register asm.Register
	Liveness Liveness
	Value    RegisterValue
}

func (r RegisterState) String() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "R%d", r.Register)
	if r.Liveness != LivenessNone {
		fmt.Fprint(&sb, "_")
		if r.Liveness&^LivenessRead > 0 {
			fmt.Fprint(&sb, "r")
		}
		if r.Liveness&^LivenessWritten > 0 {
			fmt.Fprint(&sb, "w")
		}
		if r.Liveness&^LivenessDone > 0 {
			fmt.Fprint(&sb, "D")
		}
	}

	fmt.Fprintf(&sb, "=%s", r.Value.String())

	return sb.String()
}

func parseStackState(key, value string) (*StackState, error) {
	var state StackState

	if idx := strings.Index(key, "_"); idx != -1 {
		livenessStr := key[idx+1:]
		if strings.Contains(livenessStr, "r") {
			state.Liveness = state.Liveness | LivenessRead
		}
		if strings.Contains(livenessStr, "w") {
			state.Liveness = state.Liveness | LivenessWritten
		}
		if strings.Contains(livenessStr, "D") {
			state.Liveness = state.Liveness | LivenessDone
		}

		key = key[:idx]
	}

	key = strings.Trim(key, "fp-")
	keyNum, err := strconv.Atoi(key)
	if err != nil {
		return nil, fmt.Errorf("fp offset atoi: %s", err)
	}

	state.Offset = keyNum

	state.SpilledRegister.Type, state.SpilledRegister.Precise, value = parseRegisterType(value)
	if state.SpilledRegister.Type != RegTypeNotInit {
		// TODO Scalar value?
	} else {
		for i := 0; i < 8; i++ {
			if i >= len(value) {
				break
			}

			state.Slots[i] = StackSlot(value[i])
		}
	}

	// TODO refs
	// TODO callback

	return &state, nil
}

// StackSlot describes the contents of a single byte within a stack slot
type StackSlot byte

const (
	StackSlotInvalid = '?'
	StackSlotSpill   = 'r'
	StackSlotMisc    = 'm'
	StackSlotZero    = '0'
)

// StackState describes the state of a single stack slot.
// Example: `fp-8=m???????`
type StackState struct {
	Offset            int
	Liveness          Liveness
	SpilledRegister   RegisterValue
	Slots             [8]StackSlot
	AcquiredRefs      []string
	InCallbackFn      bool
	InAsyncCallbackFn bool
}

func (ss *StackState) String() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "fp-%d", ss.Offset)

	if ss.Liveness != LivenessNone {
		fmt.Fprint(&sb, "_")
		if ss.Liveness&^LivenessRead > 0 {
			fmt.Fprint(&sb, "r")
		}
		if ss.Liveness&^LivenessWritten > 0 {
			fmt.Fprint(&sb, "w")
		}
		if ss.Liveness&^LivenessDone > 0 {
			fmt.Fprint(&sb, "D")
		}
	}

	fmt.Fprint(&sb, "=")

	if ss.SpilledRegister.Type != RegTypeNotInit {
		// TODO Scalar type
		fmt.Fprint(&sb, rtToString[ss.SpilledRegister.Type])
		// TODO refs
		// TODO callback
	} else {
		fmt.Fprint(&sb, string(ss.Slots[:]))
	}

	return sb.String()
}

var subProgLocRegex = regexp.MustCompile(`^func#(\d+) @(\d+)`)

func parseSubProgLocation(line string) VerifierStatement {
	match := subProgLocRegex.FindStringSubmatch(line)
	if len(match) != 3 {
		return nil
	}

	progID, err := strconv.Atoi(match[1])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("sub prog loc: atoi prog ID: %s", err)}
	}

	instNum, err := strconv.Atoi(match[2])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("sub prog loc: atoi inst num: %s", err)}
	}

	return &SubProgLocation{
		ProgID:           progID,
		StartInstruction: instNum,
	}
}

// SubProgLocation states the location of a sub program.
// Example: "func#3 @85"
type SubProgLocation struct {
	ProgID           int
	StartInstruction int
}

func (spl *SubProgLocation) String() string {
	return fmt.Sprintf("func#%d @%d", spl.ProgID, spl.StartInstruction)
}

func (spl *SubProgLocation) verifierStmt() {}

func parsePropagatePrecision(line string) VerifierStatement {
	line = strings.TrimPrefix(line, "propagating ")
	if strings.HasPrefix(line, "r") {
		regInt, err := strconv.Atoi(strings.TrimPrefix(line, "r"))
		if err != nil {
			return &Error{Msg: fmt.Sprintf("register number atoi: %s", err)}
		}

		reg := asm.Register(regInt)
		return &PropagatePrecision{
			Register: &reg,
		}
	}

	offset, err := strconv.Atoi(strings.TrimPrefix(line, "fp-"))
	if err != nil {
		return &Error{Msg: fmt.Sprintf("offset atoi: %s", err)}
	}
	return &PropagatePrecision{
		Offset: offset,
	}
}

// PropagatePrecision indicates that the verifier is propagating the precision of a register or stack slot to another
// state. Example: "propagating r6"
type PropagatePrecision struct {
	Register *asm.Register
	Offset   int
}

func (pp *PropagatePrecision) String() string {
	if pp.Register != nil {
		return fmt.Sprintf("propagating r%d", uint8(*pp.Register))
	}

	return fmt.Sprintf("propagating fp-%d", pp.Offset)
}

func (pp *PropagatePrecision) verifierStmt() {}

var statePrunedRegex = regexp.MustCompile(`^(?:from )?(\d+)(?: to (\d+))?: safe`)

func parseStatePruned(line string) VerifierStatement {
	match := statePrunedRegex.FindStringSubmatch(line)
	var (
		from int
		to   int
		err  error
	)
	from, err = strconv.Atoi(match[1])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("from atoi: %s", err)}
	}

	if match[2] != "" {
		to, err = strconv.Atoi(match[2])
		if err != nil {
			return &Error{Msg: fmt.Sprintf("to atoi: %s", err)}
		}

		return &StatePruned{
			From: from,
			To:   to,
		}
	}

	return &StatePruned{
		From: from,
		To:   from,
	}
}

// StatePruned means that the verifier considers a specific permutation to be safe and will prune the state from memory.
// Example: "25: safe" or "from 42 to 57: safe"
type StatePruned struct {
	From int
	To   int
}

func (sp *StatePruned) String() string {
	if sp.From == sp.To {
		return fmt.Sprintf("%d: safe", sp.From)
	}

	return fmt.Sprintf("from %d to %d: safe", sp.From, sp.To)
}

func (sp *StatePruned) verifierStmt() {}

var branchEvaluationRegex = regexp.MustCompile(`^from (\d+) to (\d+): (.*)`)

func parseBranchEvaluation(line string) VerifierStatement {
	match := branchEvaluationRegex.FindStringSubmatch(line)
	from, err := strconv.Atoi(match[1])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("from atoi: %s", err)}
	}

	to, err := strconv.Atoi(match[2])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("to atoi: %s", err)}
	}

	verifierState, err := parseVerifierState(match[3])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("branch eval: parse verifier state: %s", err)}
	}

	return &BranchEvaluation{
		From:  from,
		To:    to,
		State: verifierState,
	}
}

// BranchEvaluation means that the verifier switch state and is now evaluating another permutation.
// Example: "from 84 to 40: frame1: R0=invP(id=0) R6=pkt(id=0,off=38,r=38,imm=0) R7=pkt(id=0,off=0,r=38,imm=0)
// R8=invP18 R9=invP(id=2,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=pkt_end fp-16=mmmmmmmm"
type BranchEvaluation struct {
	From  int
	To    int
	State *VerifierState
}

func (be *BranchEvaluation) String() string {
	return fmt.Sprintf("from %d to %d: %s", be.From, be.To, be.State.String())
}

func (be *BranchEvaluation) verifierStmt() {}

var backTrackingHeaderRegex = regexp.MustCompile(`^last_idx (\d+) first_idx (\d+)`)

func parseBackTrackingHeader(line string) VerifierStatement {
	match := backTrackingHeaderRegex.FindStringSubmatch(line)
	last, err := strconv.Atoi(match[1])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("last atoi: %s", err)}
	}

	first, err := strconv.Atoi(match[2])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("first atoi: %s", err)}
	}

	return &BackTrackingHeader{
		Last:  last,
		First: first,
	}
}

// BackTrackingHeader indicates that the verifier is back tracking, and is followed by BackTrackInstruction and
// BackTrackingTrailer statements. Example: "last_idx 26 first_idx 20"
type BackTrackingHeader struct {
	Last  int
	First int
}

func (bt *BackTrackingHeader) String() string {
	return fmt.Sprintf("last_idx %d first_idx %d", bt.Last, bt.First)
}

func (bt *BackTrackingHeader) verifierStmt() {}

var backTrackInstructionRegex = regexp.MustCompile(`^regs=([0-9a-fA-F]+) stack=(\d+) before (.*)`)

func parseBackTrackInstruction(line string) VerifierStatement {
	match := backTrackInstructionRegex.FindStringSubmatch(line)
	regsStr := match[1]
	if len(regsStr)%2 == 1 {
		regsStr = "0" + regsStr
	}
	regs, err := hex.DecodeString(regsStr)
	if err != nil {
		return &Error{Msg: fmt.Sprint("hex decode regs: ", err)}
	}

	var stack int64
	stack, err = strconv.ParseInt(match[2], 10, 64)
	if err != nil {
		return &Error{Msg: fmt.Sprint("parse int stack: ", err)}
	}

	instruction := parseInstruction(match[3])

	return &BackTrackInstruction{
		Regs:        regs,
		Stack:       stack,
		Instruction: instruction.(*Instruction),
	}
}

// BackTrackInstruction indicates the verifier has back tracked an instruction.
// Example: "regs=4 stack=0 before 25: (bf) r1 = r0"
type BackTrackInstruction struct {
	Regs        []byte
	Stack       int64
	Instruction *Instruction
}

func (bt *BackTrackInstruction) String() string {
	return fmt.Sprintf("regs=%x stack=%d before %s", bt.Regs, bt.Stack, bt.Instruction.String())
}

func (bt *BackTrackInstruction) verifierStmt() {}

var backTrackingTrailerRegex = regexp.MustCompile(
	`parent (didn't have|already had) regs=([0-9a-fA-F]+) stack=(\d+) marks:? ?(.*)?`,
)

func parseBacktrackingTrailer(line string) VerifierStatement {
	match := backTrackingTrailerRegex.FindStringSubmatch(line)
	regsStr := match[2]
	if len(regsStr)%2 == 1 {
		regsStr = "0" + regsStr
	}
	regs, err := hex.DecodeString(regsStr)
	if err != nil {
		return &Error{Msg: fmt.Sprint("hex decode regs: ", err)}
	}

	var stack int64
	stack, err = strconv.ParseInt(match[3], 10, 64)
	if err != nil {
		return &Error{Msg: fmt.Sprint("parse int stack: ", err)}
	}

	state, err := parseVerifierState(match[4])
	if err != nil {
		return &Error{Msg: fmt.Sprint("parse verifier state: ", err)}
	}

	return &BackTrackingTrailer{
		ParentMatch:   match[1] == "already had",
		Regs:          regs,
		Stack:         stack,
		VerifierState: state,
	}
}

// BackTrackingTrailer indicates the verifier is done backtracking.
// Example: `parent didn't have regs=4 stack=0 marks` or `parent already had regs=2a stack=0 marks`
type BackTrackingTrailer struct {
	ParentMatch   bool
	Regs          []byte
	Stack         int64
	VerifierState *VerifierState
}

func (bt *BackTrackingTrailer) String() string {
	if bt.ParentMatch {
		return fmt.Sprintf(
			"parent already had regs=%x stack=%d marks: %s", bt.Regs, bt.Stack, bt.VerifierState.String())
	}

	return fmt.Sprintf("parent didn't have regs=%x stack=%d marks: %s", bt.Regs, bt.Stack, bt.VerifierState.String())
}

func (bt *BackTrackingTrailer) verifierStmt() {}

var loadSuccessRegex = regexp.MustCompile(
	`processed (\d+) insns \(limit (\d+)\) max_states_per_insn (\d+) total_states (\d+) peak_states ` +
		`(\d+) mark_read (\d+)`,
)

func parseLoadSuccess(line string) VerifierStatement {
	match := loadSuccessRegex.FindStringSubmatch(line)
	instProcessed, err := strconv.Atoi(match[1])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("inst processed atoi: %s", err)}
	}

	instLimit, err := strconv.Atoi(match[2])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("inst limit atoi: %s", err)}
	}

	maxStatesPerInst, err := strconv.Atoi(match[3])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("max states atoi: %s", err)}
	}

	totalStates, err := strconv.Atoi(match[4])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("total states atoi: %s", err)}
	}

	peekStates, err := strconv.Atoi(match[5])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("peek states atoi: %s", err)}
	}

	markRead, err := strconv.Atoi(match[6])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("mark read atoi: %s", err)}
	}

	return &VerifierDone{
		InstructionsProcessed: instProcessed,
		InstructionLimit:      instLimit,
		MaxStatesPerInst:      maxStatesPerInst,
		TotalStates:           totalStates,
		PeakStates:            peekStates,
		MarkRead:              markRead,
	}
}

// VerifierDone indicates the verifier is done and has failed or succeeded.
// Example: "processed 520 insns (limit 1000000) max_states_per_insn 1 total_states 46 peak_states 46 mark_read 7"
type VerifierDone struct {
	InstructionsProcessed int
	InstructionLimit      int
	MaxStatesPerInst      int
	TotalStates           int
	PeakStates            int
	MarkRead              int
}

func (ls *VerifierDone) String() string {
	return fmt.Sprintf(
		"processed %d insns (limit %d) max_states_per_insn %d total_states %d peak_states %d mark_read %d",
		ls.InstructionsProcessed,
		ls.InstructionLimit,
		ls.MaxStatesPerInst,
		ls.TotalStates,
		ls.PeakStates,
		ls.MarkRead,
	)
}

func (ls *VerifierDone) verifierStmt() {}

func parseFunctionCall(firstLine string, scan *bufio.Scanner) VerifierStatement {
	if strings.TrimSpace(firstLine) != "caller:" {
		return &Error{Msg: "func call: bad initial line"}
	}

	if !scan.Scan() {
		return &Error{Msg: "func call: no caller state"}
	}

	callerState, err := parseVerifierState(scan.Text())
	if err != nil {
		return &Error{Msg: fmt.Sprintf("parse caller verifier state: %s", err)}
	}

	if !scan.Scan() {
		return &Error{Msg: "func call: no callee state header"}
	}

	if strings.TrimSpace(scan.Text()) != "callee:" {
		return &Error{Msg: "func call: bad callee state header"}
	}

	if !scan.Scan() {
		return &Error{Msg: "func call: no callee state"}
	}

	calleeState, err := parseVerifierState(scan.Text())
	if err != nil {
		return &Error{Msg: fmt.Sprintf("parse callee verifier state: %s", err)}
	}

	return &FunctionCall{
		CallerState: callerState,
		CalleeState: calleeState,
	}
}

// FunctionCall indicates the verifier is following a bpf-to-bpf function call.
// For example:
// caller:
//
//	 frame1: R6=pkt(id=0,off=54,r=74,imm=0) R7=pkt(id=0,off=0,r=74,imm=0) R8_w=pkt(id=0,off=74,r=74,imm=0) R9=invP6
//	 R10=fp0 fp-8=pkt_end fp-16=mmmmmmmm
//	callee:
//	 frame2: R1_w=pkt(id=0,off=54,r=74,imm=0) R2_w=invP(id=0) R10=fp0
type FunctionCall struct {
	CallerState *VerifierState
	CalleeState *VerifierState
}

func (fc *FunctionCall) String() string {
	return fmt.Sprintf("caller:\n%s\ncallee:\n%s", fc.CallerState.String(), fc.CalleeState.String())
}

func (fc *FunctionCall) verifierStmt() {}

var returnFuncCallRegex = regexp.MustCompile(`^to caller at (\d+):`)

func parseReturnFunctionCall(firstLine string, scan *bufio.Scanner) VerifierStatement {
	if strings.TrimSpace(firstLine) != "returning from callee:" {
		return &Error{Msg: "return func call: bad initial line"}
	}

	if !scan.Scan() {
		return &Error{Msg: "return func call: no callee state"}
	}

	calleeState, err := parseVerifierState(scan.Text())
	if err != nil {
		return &Error{Msg: fmt.Sprintf("parse callee verifier state: %s", err)}
	}

	if !scan.Scan() {
		return &Error{Msg: "return func call: no call site line"}
	}

	match := returnFuncCallRegex.FindStringSubmatch(scan.Text())
	callsite, err := strconv.Atoi(match[1])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("callsite atoi: %s", err)}
	}

	if !scan.Scan() {
		return &Error{Msg: "return func call: no caller state"}
	}

	callerState, err := parseVerifierState(scan.Text())
	if err != nil {
		return &Error{Msg: fmt.Sprintf("parse caller verifier state: %s", err)}
	}

	return &ReturnFunctionCall{
		CalleeState: calleeState,
		CallSite:    callsite,
		CallerState: callerState,
	}
}

// ReturnFunctionCall indicates the verifier is evaluating returning from a function call.
// Example:
// returning from callee:
//
//	frame2: R0=map_value(id=0,off=0,ks=1,vs=16,imm=0) R1_w=invP(id=0) R6=invP(id=31) R10=fp0 fp-8=m???????
//
// to caller at 156:
//
//	frame1: R0=map_value(id=0,off=0,ks=1,vs=16,imm=0) R6=pkt(id=0,off=54,r=54,imm=0) R7=pkt(id=0,off=0,r=54,imm=0)
//	R8=invP14 R9=invP(id=30,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=pkt_end fp-16=mmmmmmmm
type ReturnFunctionCall struct {
	CallerState *VerifierState
	CallSite    int
	CalleeState *VerifierState
}

func (rfc *ReturnFunctionCall) String() string {
	return fmt.Sprintf(
		"returning from callee:\n%s\nto caller at %d:\n%s",
		rfc.CalleeState.String(),
		rfc.CallSite,
		rfc.CallerState.String(),
	)
}

func (rfc *ReturnFunctionCall) verifierStmt() {}
