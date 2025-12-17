#!/usr/bin/env python3
"""
RISC-V Side-Channel Vulnerability Static Analyzer
Complete with 100 benign + 125 vulnerable test cases + 100000 random sequences
"""

import re
import random
import json
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from datetime import datetime
import os


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    NONE = 0


class VulnerabilityType(Enum):
    """Types of detected vulnerabilities"""
    SPECTRE_V1 = "Spectre V1 (Bounds Check Bypass)"
    SPECTRE_V2 = "Spectre V2 (Branch Target Injection)"
    SPECTRE_V4 = "Spectre V4 (Speculative Store Bypass)"
    FLUSH_RELOAD = "Flush+Reload Cache Attack"
    PRIME_PROBE = "Prime+Probe Cache Attack"
    CACHE_CONFLICT = "Cache Set Conflict Pattern"
    TIMING_CHANNEL = "Timing Side-Channel"
    PASSWORD_TIMING = "Password Timing Attack"
    SECRET_DEPENDENT_CONTROL = "Secret-Dependent Control Flow"
    UNALIGNED_ACCESS = "Unaligned Memory Access"


@dataclass
class Instruction:
    """Parsed RISC-V instruction"""
    line_num: int
    raw: str
    opcode: str
    operands: List[str]
    rd: Optional[str] = None
    rs1: Optional[str] = None
    rs2: Optional[str] = None
    imm: Optional[int] = None
    label: Optional[str] = None
    is_branch: bool = False
    is_jump: bool = False
    is_load: bool = False
    is_store: bool = False
    is_compare: bool = False
    is_fence: bool = False
    
    def __post_init__(self):
        self._classify_instruction()
    
    def _classify_instruction(self):
        """Classify instruction type"""
        branch_opcodes = {'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu', 'beqz', 'bnez', 'blez', 'bgez', 'bltz', 'bgtz'}
        jump_opcodes = {'jal', 'jalr', 'j', 'jr', 'ret', 'call'}
        load_opcodes = {'lb', 'lh', 'lw', 'ld', 'lbu', 'lhu', 'lwu'}
        store_opcodes = {'sb', 'sh', 'sw', 'sd'}
        compare_opcodes = {'slt', 'sltu', 'slti', 'sltiu', 'seq', 'sne'}
        fence_opcodes = {'fence', 'fence.i', 'fence.tso'}
        
        self.is_branch = self.opcode in branch_opcodes
        self.is_jump = self.opcode in jump_opcodes
        self.is_load = self.opcode in load_opcodes
        self.is_store = self.opcode in store_opcodes
        self.is_compare = self.opcode in compare_opcodes
        self.is_fence = self.opcode in fence_opcodes


@dataclass
class Vulnerability:
    """Detected vulnerability"""
    vuln_type: VulnerabilityType
    risk_level: RiskLevel
    line_start: int
    line_end: int
    description: str
    pattern: List[str]
    affected_registers: Set[str]
    recommendations: List[str]
    confidence: float
    details: Dict = field(default_factory=dict)
    sequence_length: int = 0


class DataFlowAnalyzer:
    """Tracks data flow and taint propagation"""
    
    def __init__(self):
        self.taint_map: Dict[str, Set[str]] = defaultdict(set)
        self.secret_sources: Set[str] = set()
        self.register_definitions: Dict[str, int] = {}
    
    def mark_secret(self, register: str, source: str):
        """Mark a register as containing secret data"""
        self.secret_sources.add(register)
        self.taint_map[register].add(source)
    
    def propagate_taint(self, dest: str, sources: List[str]):
        """Propagate taint from source registers to destination"""
        for src in sources:
            if src in self.taint_map or src in self.secret_sources:
                self.taint_map[dest].update(self.taint_map.get(src, {src}))
                if src in self.secret_sources:
                    self.secret_sources.add(dest)
    
    def is_tainted(self, register: str) -> bool:
        """Check if a register is tainted with secret data"""
        return register in self.secret_sources or register in self.taint_map
    
    def get_taint_sources(self, register: str) -> Set[str]:
        """Get the sources of taint for a register"""
        return self.taint_map.get(register, set())


class RISCVParser:
    """Parse RISC-V assembly code"""
    
    REG_PATTERN = r'(zero|ra|sp|gp|tp|t[0-6]|s[0-9]|s1[0-1]|a[0-7]|x[0-9]|x[12][0-9]|x3[01])'
    
    def __init__(self):
        self.labels: Dict[str, int] = {}
        self.instructions: List[Instruction] = []
    
    def parse(self, code: str) -> List[Instruction]:
        """Parse RISC-V assembly code"""
        lines = code.strip().split('\n')
        self.instructions = []
        
        for line_num, line in enumerate(lines, 1):
            line = re.sub(r'[#;].*$', '', line).strip()
            if not line:
                continue
            
            label_match = re.match(r'^(\w+):\s*(.*)', line)
            if label_match:
                label, rest = label_match.groups()
                self.labels[label] = line_num
                if not rest:
                    continue
                line = rest
            
            instr = self._parse_instruction(line_num, line)
            if instr:
                self.instructions.append(instr)
        
        return self.instructions
    
    
    def _parse_instruction(self, line_num: int, line: str) -> Optional[Instruction]:
        """Parse a single instruction"""
        parts = re.split(r'[\s,()]+', line)
        parts = [p for p in parts if p]
        
        if not parts:
            return None
        
        opcode = parts[0].lower()
        operands = parts[1:]
        
        instr = Instruction(
            line_num=line_num,
            raw=line,
            opcode=opcode,
            operands=operands
        )
        
        # Special handling for different instruction types
        if instr.is_load or instr.
        :
            if len(operands) >= 2:
                instr.rd = operands[0]
                if len(operands) >= 3:
                    # Parse offset(rs1) format
                    imm_part = operands[1]
                    if '(' in imm_part and ')' in imm_part:
                        # Format: offset(rs1)
                        imm_str = imm_part.split('(')[0]
                        rs1_str = imm_part.split('(')[1].rstrip(')')
                        instr.imm = self._parse_immediate(imm_str)
                        instr.rs1 = rs1_str
                    else:
                        # Format: rd, offset, rs1
                        instr.imm = self._parse_immediate(operands[1])
                        instr.rs1 = operands[2]
        elif instr.is_branch:
            if len(operands) >= 2:
                instr.rs1 = operands[0]
                if len(operands) >= 3:
                    instr.rs2 = operands[1]
                    instr.label = operands[2]
                else:
                    instr.label = operands[1]
        else:
            # Handle arithmetic and other instructions
            if len(operands) >= 1:
                instr.rd = operands[0]
                if len(operands) >= 2:
                    instr.rs1 = operands[1]
                    if len(operands) >= 3:
                        # Check if it's an immediate instruction
                        # I-type instructions: addi, andi, ori, xori, slti, sltiu
                        if opcode.endswith('i') or opcode in ['addi', 'andi', 'ori', 'xori', 'slti', 'sltiu', 'slli', 'srli', 'srai']:
                            instr.imm = self._parse_immediate(operands[2])
                        else:
                            instr.rs2 = operands[2]
        
        return instr
    
    def _parse_immediate(self, imm_str: str) -> Optional[int]:
        """Parse immediate value"""
        try:
            if imm_str.startswith('0x'):
                return int(imm_str, 16)
            return int(imm_str)
        except ValueError:
            return None


class VulnerabilityDetector:
    """Main vulnerability detection engine"""
    
    def __init__(self):
        self.parser = RISCVParser()
        self.dataflow = DataFlowAnalyzer()
        self.vulnerabilities: List[Vulnerability] = []
        self.instructions: List[Instruction] = []
        
        self.cache_line_size = 64
        self.cache_set_count = 64
    
    def analyze(self, code: str) -> Dict:
        """Main analysis entry point"""
        self.instructions = self.parser.parse(code)
        self.vulnerabilities = []
        
        # Run all detection passes
        self._detect_spectre_v1()
        self._detect_spectre_v2()
        self._detect_spectre_v4()
        self._detect_flush_reload()
        self._detect_prime_probe()
        self._detect_cache_conflicts()
        self._detect_timing_channels()
        self._detect_password_timing()
        self._detect_secret_dependent_control()
        self._detect_unaligned_access()
        
        overall_risk = self._calculate_overall_risk()
        
        return {
            'vulnerabilities': [self._vuln_to_dict(v) for v in self.vulnerabilities],
            'summary': self._generate_summary(),
            'overall_risk': overall_risk.name,
            'overall_score': self._calculate_vulnerability_score(),
            'statistics': self._calculate_statistics(),
            'total_instructions': len(self.instructions),
            'is_vulnerable': len(self.vulnerabilities) > 0
        }
    
    def _detect_spectre_v1(self):
        """Detect Spectre V1 (Bounds Check Bypass) patterns"""
        # Pattern 1: compare -> branch -> load (3 instructions)
        for i in range(len(self.instructions) - 2):
            instr1 = self.instructions[i]
            instr2 = self.instructions[i + 1]
            instr3 = self.instructions[i + 2]
            
            if (instr1.is_compare and instr2.is_branch and instr3.is_load):
                confidence = 0.85
                risk = RiskLevel.CRITICAL
                
                if instr1.opcode in {'sltu', 'sltiu'}:
                    confidence = 0.95
                
                affected_regs = {r for r in [instr1.rd, instr1.rs1, instr1.rs2, 
                                            instr2.rs1, instr2.rs2, instr3.rd, instr3.rs1] if r}
                
                self.vulnerabilities.append(Vulnerability(
                    vuln_type=VulnerabilityType.SPECTRE_V1,
                    risk_level=risk,
                    line_start=instr1.line_num,
                    line_end=instr3.line_num,
                    description="CRITICAL Spectre V1: bounds check, branch, speculative load",
                    pattern=[instr1.raw, instr2.raw, instr3.raw],
                    affected_registers=affected_regs,
                    recommendations=["Insert fence after bounds check", "Use constant-time bounds checking"],
                    confidence=confidence,
                    sequence_length=3,
                    details={'pattern': 'compare-branch-load'}
                ))
            
            # Pattern 2: compare -> branch -> arithmetic(s) -> load (4+ instructions)
            # Check for patterns up to 5 instructions total
            for seq_length in range(3, 6):  # Check for 3, 4, or 5 instruction sequences
                if i + seq_length - 1 < len(self.instructions):
                    # Build the sequence
                    sequence = self.instructions[i:i+seq_length]
                    
                    # Check if first is compare, second is branch, last is load
                    if (sequence[0].is_compare and 
                        sequence[1].is_branch and 
                        sequence[-1].is_load):
                        
                        # Check that all middle instructions are arithmetic/address calculations
                        all_arithmetic = True
                        for j in range(2, len(sequence)-1):
                            if sequence[j].opcode not in {'add', 'addi', 'slli', 'sll', 'mul', 'sub'}:
                                all_arithmetic = False
                                break
                        
                        if all_arithmetic:
                            confidence = 0.92 if seq_length == 3 else 0.88
                            risk = RiskLevel.CRITICAL
                            
                            if sequence[0].opcode in {'sltu', 'sltiu'}:
                                confidence = 0.95 if seq_length == 3 else 0.92
                            
                            # Collect all registers from all instructions in sequence
                            affected_regs = set()
                            for instr in sequence:
                                for reg in [instr.rd, instr.rs1, instr.rs2]:
                                    if reg:
                                        affected_regs.add(reg)
                            
                            pattern_texts = [instr.raw for instr in sequence]
                            
                            self.vulnerabilities.append(Vulnerability(
                                vuln_type=VulnerabilityType.SPECTRE_V1,
                                risk_level=risk,
                                line_start=sequence[0].line_num,
                                line_end=sequence[-1].line_num,
                                description=f"CRITICAL Spectre V1: bounds check, branch, {seq_length-3} address calc(s), load",
                                pattern=pattern_texts,
                                affected_registers=affected_regs,
                                recommendations=["Insert fence immediately after bounds check"],
                                confidence=confidence,
                                sequence_length=seq_length,
                                details={
                                    'pattern': f'compare-branch-{seq_length-3}-arithmetic-load',
                                    'total_instructions': seq_length
                                }
                            ))
    
    def _detect_spectre_v2(self):
        """Detect Spectre V2 patterns"""
        for i in range(len(self.instructions)):
            instr = self.instructions[i]
            
            if instr.opcode == 'jalr':
                risk = RiskLevel.HIGH
                confidence = 0.8
                
                if i > 0:
                    prev = self.instructions[i - 1]
                    if prev.is_load and prev.rd == instr.rs1:
                        risk = RiskLevel.CRITICAL
                        confidence = 0.95
                
                affected_regs = {r for r in [instr.rd, instr.rs1] if r}
                
                self.vulnerabilities.append(Vulnerability(
                    vuln_type=VulnerabilityType.SPECTRE_V2,
                    risk_level=risk,
                    line_start=instr.line_num,
                    line_end=instr.line_num,
                    description="Indirect jump vulnerable to Branch Target Injection",
                    pattern=[instr.raw],
                    affected_registers=affected_regs,
                    recommendations=["Use retpoline technique", "Insert IBPB barrier"],
                    confidence=confidence,
                    sequence_length=1,
                    details={'jump_type': 'indirect'}
                ))
    
    def _detect_spectre_v4(self):
        """Detect Spectre V4 patterns"""
        for i in range(len(self.instructions) - 1):
            instr1 = self.instructions[i]
            instr2 = self.instructions[i + 1]
            
            if instr1.is_store and instr2.is_load:
                if self._addresses_may_overlap(instr1, instr2):
                    confidence = 0.75
                    risk = RiskLevel.MEDIUM
                    
                    if instr1.rs1 == instr2.rs1:
                        confidence = 0.85
                        risk = RiskLevel.HIGH
                    
                    affected_regs = {r for r in [instr1.rs1, instr2.rd, instr2.rs1] if r}
                    
                    self.vulnerabilities.append(Vulnerability(
                        vuln_type=VulnerabilityType.SPECTRE_V4,
                        risk_level=risk,
                        line_start=instr1.line_num,
                        line_end=instr2.line_num,
                        description="Speculative Store Bypass: load may bypass store",
                        pattern=[instr1.raw, instr2.raw],
                        affected_registers=affected_regs,
                        recommendations=["Insert fence between store and load"],
                        confidence=confidence,
                        sequence_length=2,
                        details={'store_load_overlap': True}
                    ))
    
    def _detect_flush_reload(self):
        """Detect Flush+Reload patterns"""
        for i in range(len(self.instructions) - 1):
            instr1 = self.instructions[i]
            instr2 = self.instructions[i + 1]
            
            if instr1.opcode == 'fence.i' and (instr2.is_jump or instr2.is_load):
                confidence = 0.7
                risk = RiskLevel.MEDIUM
                
                if self._has_timing_measurement(i + 2, 5):
                    confidence = 0.9
                    risk = RiskLevel.HIGH
                
                affected_regs = {r for r in [instr2.rd, instr2.rs1] if r}
                
                self.vulnerabilities.append(Vulnerability(
                    vuln_type=VulnerabilityType.FLUSH_RELOAD,
                    risk_level=risk,
                    line_start=instr1.line_num,
                    line_end=instr2.line_num,
                    description="Flush+Reload cache attack pattern detected",
                    pattern=[instr1.raw, instr2.raw],
                    affected_registers=affected_regs,
                    recommendations=["Avoid explicit cache flushes", "Use constant-time code"],
                    confidence=confidence,
                    sequence_length=2,
                    details={'has_timing': self._has_timing_measurement(i + 2, 5)}
                ))
    
    def _detect_prime_probe(self):
        """Detect Prime+Probe cache attack patterns"""
        # Look for loop patterns: label -> memory access -> addi 64/128 -> backward branch
        for i, instr in enumerate(self.instructions):
            # Only consider branch instructions
            if not instr.is_branch:
                continue
                
            # Get the branch target label
            if not instr.label:
                continue
                
            # Get the line number for the label
            label_line = self.parser.labels.get(instr.label, -1)
            if label_line == -1:
                continue
                
            # Check if it's a backward branch (loop)
            # Label should be before the branch instruction
            if label_line < instr.line_num:
                # Find the start of the loop (instruction at or after label_line)
                loop_start_idx = -1
                for j, search_instr in enumerate(self.instructions):
                    if search_instr.line_num >= label_line:
                        loop_start_idx = j
                        break
                
                if loop_start_idx == -1 or loop_start_idx >= i:
                    continue
                    
                # Get loop body (from label to branch)
                loop_body = self.instructions[loop_start_idx:i+1]
                
                # Now check for Prime+Probe pattern in the loop body
                # Pattern: memory access -> addi by 64 or 128 -> (other ops) -> backward branch
                for j in range(len(loop_body) - 1):
                    # Look for a memory access
                    if loop_body[j].is_load or loop_body[j].is_store:
                        base_reg = loop_body[j].rs1
                        
                        # Look for an addi that increments the base register by cache-line size
                        for k in range(j+1, min(j+4, len(loop_body))):
                            next_instr = loop_body[k]
                            
                            # Check if it's an addi that increments the same register by 64 or 128
                            if (next_instr.opcode == 'addi' and
                                next_instr.rs1 == base_reg and
                                next_instr.rd in [base_reg, next_instr.rs1] and
                                next_instr.imm in [64, 128]):  # FIXED: Check for both 64 and 128
                                
                                # Found Prime+Probe pattern!
                                confidence = 0.9
                                risk = RiskLevel.HIGH
                                
                                # If the base register is being incremented and used in the next iteration
                                if next_instr.rd == base_reg:
                                    risk = RiskLevel.CRITICAL
                                    confidence = 0.95
                                
                                affected_regs = {base_reg}
                                if loop_body[j].rd:
                                    affected_regs.add(loop_body[j].rd)
                                
                                # Get the pattern instructions (3-5 of them)
                                pattern_start = max(0, j-1)
                                pattern_end = min(len(loop_body), k+2)
                                pattern_instrs = [instr.raw for instr in loop_body[pattern_start:pattern_end]]
                                
                                self.vulnerabilities.append(Vulnerability(
                                    vuln_type=VulnerabilityType.PRIME_PROBE,
                                    risk_level=risk,
                                    line_start=loop_body[j].line_num,
                                    line_end=loop_body[k].line_num,
                                    description=(
                                        f"Prime+Probe cache attack: loop with cache-line stride ({next_instr.imm} bytes). "
                                        "Attackers can evict and monitor cache sets to infer access patterns."
                                    ),
                                    pattern=pattern_instrs,
                                    affected_registers=affected_regs,
                                    recommendations=[
                                        "Use non-deterministic memory access patterns",
                                        "Add random delays between memory accesses",
                                        "Use cache partitioning to isolate sensitive data",
                                        "Consider scatter-gather techniques"
                                    ],
                                    confidence=confidence,
                                    sequence_length=pattern_end - pattern_start,
                                    details={
                                        'base_register': base_reg,
                                        'increment_amount': next_instr.imm,
                                        'is_loop': True,
                                        'branch_target': instr.label,
                                        'cache_lines_per_stride': next_instr.imm // 64
                                    }
                                ))
                                break  # Found pattern for this memory access
        
        # Also check for simpler patterns without explicit loop labels
        # Pattern: memory access -> addi 64/128 -> branch (any)
        for i in range(len(self.instructions) - 2):
            instr1 = self.instructions[i]
            instr2 = self.instructions[i + 1] if i + 1 < len(self.instructions) else None
            instr3 = self.instructions[i + 2] if i + 2 < len(self.instructions) else None
            
            if (instr1 and instr2 and instr3 and
                (instr1.is_load or instr1.is_store) and
                instr2.opcode == 'addi' and
                instr2.imm in [64, 128] and  # FIXED: Check for both 64 and 128
                instr2.rs1 == instr1.rs1 and
                instr3.is_branch):
                
                # Check if it's likely a loop (backward branch)
                is_loop = False
                if instr3.label:
                    label_line = self.parser.labels.get(instr3.label, -1)
                    if label_line < instr3.line_num:
                        is_loop = True
                
                risk = RiskLevel.HIGH if is_loop else RiskLevel.MEDIUM
                confidence = 0.85 if is_loop else 0.7
                
                affected_regs = {instr1.rs1}
                if instr1.rd:
                    affected_regs.add(instr1.rd)
                
                self.vulnerabilities.append(Vulnerability(
                    vuln_type=VulnerabilityType.PRIME_PROBE,
                    risk_level=risk,
                    line_start=instr1.line_num,
                    line_end=instr3.line_num,
                    description=(
                        f"Prime+Probe pattern: cache-line stride access ({instr2.imm} bytes) "
                        f"{'in loop' if is_loop else 'followed by branch'}."
                    ),
                    pattern=[instr1.raw, instr2.raw, instr3.raw],
                    affected_registers=affected_regs,
                    recommendations=["Break deterministic stride patterns"],
                    confidence=confidence,
                    sequence_length=3,
                    details={
                        'base_register': instr1.rs1,
                        'increment': instr2.imm,
                        'is_loop': is_loop,
                        'cache_lines_per_stride': instr2.imm // 64
                    }
                ))
        
        # Add detection for fence.i followed by timing measurement in loops
        # This catches patterns like VULN_ADVANCED_02
        for i in range(len(self.instructions) - 4):
            # Look for fence.i, then loop with memory access and timing
            if (self.instructions[i].opcode == 'fence.i' and
                i + 4 < len(self.instructions)):
                
                # Check if there's a timing measurement instruction nearby
                for j in range(i, min(i + 10, len(self.instructions))):
                    if self.instructions[j].opcode in {'rdcycle', 'rdtime', 'rdinstret'}:
                        # Found timing measurement, now look for loop patterns
                        for k in range(i, j):
                            if self.instructions[k].is_branch and self.instructions[k].label:
                                # This might be a timing loop with cache attacks
                                label_line = self.parser.labels.get(self.instructions[k].label, -1)
                                if label_line < self.instructions[k].line_num:
                                    # Found a backward branch (loop) near fence.i and timing
                                    confidence = 0.8
                                    risk = RiskLevel.HIGH
                                    
                                    affected_regs = set()
                                    # Add registers from fence.i to timing instruction
                                    for m in range(i, j+1):
                                        for reg in [self.instructions[m].rd, 
                                                self.instructions[m].rs1, 
                                                self.instructions[m].rs2]:
                                            if reg:
                                                affected_regs.add(reg)
                                    
                                    pattern_instrs = [instr.raw for instr in self.instructions[i:j+1]]
                                    
                                    self.vulnerabilities.append(Vulnerability(
                                        vuln_type=VulnerabilityType.FLUSH_RELOAD,
                                        risk_level=risk,
                                        line_start=self.instructions[i].line_num,
                                        line_end=self.instructions[j].line_num,
                                        description=(
                                            "Flush+Reload/Timing attack: cache flush followed by loop with timing measurement"
                                        ),
                                        pattern=pattern_instrs,
                                        affected_registers=affected_regs,
                                        recommendations=[
                                            "Avoid explicit cache flushes before timing loops",
                                            "Use constant-time implementations",
                                            "Add noise to timing measurements"
                                        ],
                                        confidence=confidence,
                                        sequence_length=j - i + 1,
                                        details={
                                            'has_fence_i': True,
                                            'has_timing': True,
                                            'timing_op': self.instructions[j].opcode,
                                            'has_loop': True
                                        }
                                    ))
                                    break
                        break
    
    def _detect_cache_conflicts(self):
        """Detect cache set conflict patterns"""
        # Only flag patterns that are clearly cache-line aligned and suspicious
        suspicious_patterns = []
        
        # Look for sequences of 3+ loads/stores with cache-line stride
        for i in range(len(self.instructions) - 2):
            window = self.instructions[i:i+3]
            
            # Check if all are memory accesses
            memory_instrs = [instr for instr in window if instr.is_load or instr.is_store]
            if len(memory_instrs) < 3:
                continue
            
            # Check if they use the same base register
            base_regs = {instr.rs1 for instr in memory_instrs if instr.rs1}
            if len(base_regs) != 1:
                continue  # Different base registers, less suspicious
            
            # Get offsets
            offsets = []
            for instr in memory_instrs:
                if instr.imm is not None:
                    offsets.append(instr.imm)
            
            if len(offsets) < 2:
                continue
            
            # Check stride
            sorted_offsets = sorted(offsets)
            diffs = [sorted_offsets[j+1] - sorted_offsets[j] for j in range(len(sorted_offsets)-1)]
            
            if len(set(diffs)) == 1:
                stride = abs(diffs[0])
                
                # Only flag if stride is exactly cache-line size (64) or double (128)
                # This avoids false positives for small strides
                if stride in [64, 128]:
                    # Don't flag if it looks like normal stack operations (using sp)
                    base_reg = next(iter(base_regs))
                    if base_reg == 'sp':
                        # Stack operations with regular stride might be normal
                        # Only flag if in a loop
                        if not self._is_in_loop(window[0].line_num):
                            continue
                    
                    affected_regs = set()
                    for instr in memory_instrs:
                        affected_regs.update({r for r in [instr.rd, instr.rs1] if r})
                    
                    suspicious_patterns.append({
                        'window': window,
                        'stride': stride,
                        'affected_regs': affected_regs,
                        'base_reg': base_reg,
                        'is_loop': self._is_in_loop(window[0].line_num)
                    })
        
        # Filter out likely false positives
        for pattern in suspicious_patterns:
            # Skip if it looks like normal array access (small number of fixed offsets)
            if pattern['stride'] == 64 and not pattern['is_loop']:
                # Might be normal struct/array access, reduce confidence
                confidence = 0.6
                risk = RiskLevel.LOW
            else:
                confidence = 0.8
                risk = RiskLevel.MEDIUM
            
            self.vulnerabilities.append(Vulnerability(
                vuln_type=VulnerabilityType.CACHE_CONFLICT,
                risk_level=risk,
                line_start=pattern['window'][0].line_num,
                line_end=pattern['window'][-1].line_num,
                description=f"Cache conflict pattern: stride {pattern['stride']} bytes",
                pattern=[instr.raw for instr in pattern['window']],
                affected_registers=pattern['affected_regs'],
                recommendations=["Consider randomizing memory layout"],
                confidence=confidence,
                sequence_length=len(pattern['window']),
                details={
                    'stride': pattern['stride'],
                    'base_register': pattern['base_reg'],
                    'in_loop': pattern['is_loop']
                }
            ))
    
    def _detect_timing_channels(self):
        """Detect timing side-channels"""
        for i in range(len(self.instructions) - 1):
            instr1 = self.instructions[i]
            instr2 = self.instructions[i + 1]
            
            if self._is_variable_time_op(instr1):
                if instr2.is_load or instr2.is_store or instr2.is_branch:
                    confidence = 0.65
                    risk = RiskLevel.LOW
                    
                    if self.dataflow.is_tainted(instr1.rs1 or ''):
                        confidence = 0.85
                        risk = RiskLevel.HIGH
                    
                    affected_regs = {r for r in [instr1.rd, instr1.rs1, instr2.rd] if r}
                    
                    self.vulnerabilities.append(Vulnerability(
                        vuln_type=VulnerabilityType.TIMING_CHANNEL,
                        risk_level=risk,
                        line_start=instr1.line_num,
                        line_end=instr2.line_num,
                        description=f"Timing channel: variable-time {instr1.opcode}",
                        pattern=[instr1.raw, instr2.raw],
                        affected_registers=affected_regs,
                        recommendations=["Use constant-time implementations"],
                        confidence=confidence,
                        sequence_length=2,
                        details={'variable_op': instr1.opcode}
                    ))
    
    def _detect_password_timing(self):
        """Detect password timing attacks"""
        for i in range(len(self.instructions) - 2):
            load1 = self.instructions[i]
            load2 = self.instructions[i + 1]
            branch = self.instructions[i + 2]
            
            if (load1.is_load and load1.opcode in {'lb', 'lbu'} and
                load2.is_load and load2.opcode in {'lb', 'lbu'} and
                branch.is_branch and branch.opcode in {'bne', 'beq'}):
                
                if (branch.rs1 in {load1.rd, load2.rd} or branch.rs2 in {load1.rd, load2.rd}):
                    affected_regs = {r for r in [load1.rd, load2.rd, branch.rs1, branch.rs2] if r}
                    
                    self.vulnerabilities.append(Vulnerability(
                        vuln_type=VulnerabilityType.PASSWORD_TIMING,
                        risk_level=RiskLevel.CRITICAL,
                        line_start=load1.line_num,
                        line_end=branch.line_num,
                        description="CRITICAL: Password timing attack - byte-by-byte comparison with early exit",
                        pattern=[load1.raw, load2.raw, branch.raw],
                        affected_registers=affected_regs,
                        recommendations=["Use constant-time comparison", "Compare all bytes before checking"],
                        confidence=0.95,
                        sequence_length=3,
                        details={'attack': 'early_exit_comparison'}
                    ))
    
    def _detect_secret_dependent_control(self):
        """Detect secret-dependent control flow"""
        for instr in self.instructions:
            if instr.is_branch or instr.is_jump:
                condition_regs = {r for r in [instr.rs1, instr.rs2] if r}
                
                for reg in condition_regs:
                    if self.dataflow.is_tainted(reg):
                        sources = self.dataflow.get_taint_sources(reg)
                        
                        self.vulnerabilities.append(Vulnerability(
                            vuln_type=VulnerabilityType.SECRET_DEPENDENT_CONTROL,
                            risk_level=RiskLevel.CRITICAL,
                            line_start=instr.line_num,
                            line_end=instr.line_num,
                            description=f"Secret-dependent branch on tainted register {reg}",
                            pattern=[instr.raw],
                            affected_registers=condition_regs,
                            recommendations=["Convert to branchless code"],
                            confidence=0.9,
                            sequence_length=1,
                            details={'tainted_reg': reg}
                        ))
    
    def _detect_unaligned_access(self):
        """Detect unaligned memory access"""
        for instr in self.instructions:
            if instr.is_load or instr.is_store:
                if instr.imm is not None:
                    access_size = self._get_access_size(instr.opcode)
                    if instr.imm % access_size != 0:
                        affected_regs = {r for r in [instr.rd, instr.rs1] if r}
                        
                        self.vulnerabilities.append(Vulnerability(
                            vuln_type=VulnerabilityType.UNALIGNED_ACCESS,
                            risk_level=RiskLevel.LOW,
                            line_start=instr.line_num,
                            line_end=instr.line_num,
                            description=f"Unaligned {instr.opcode} at offset {instr.imm}",
                            pattern=[instr.raw],
                            affected_registers=affected_regs,
                            recommendations=["Align data to natural boundaries"],
                            confidence=0.8,
                            sequence_length=1,
                            details={'offset': instr.imm, 'alignment': access_size}
                        ))
    
    # Helper methods
    
    def _addresses_may_overlap(self, store: Instruction, load: Instruction) -> bool:
        if store.rs1 == load.rs1:
            if store.imm is not None and load.imm is not None:
                offset_diff = abs(store.imm - load.imm)
                store_size = self._get_access_size(store.opcode)
                return offset_diff < store_size
            return True
        return False
    
    def _has_timing_measurement(self, start_idx: int, window: int) -> bool:
        timing_opcodes = {'rdcycle', 'rdtime', 'rdinstret', 'csrr'}
        end_idx = min(start_idx + window, len(self.instructions))
        for i in range(start_idx, end_idx):
            if self.instructions[i].opcode in timing_opcodes:
                return True
        return False
    
    def _find_loop_body(self, branch_instr: Instruction) -> List[Instruction]:
        """Find the body of a loop given a backward branch"""
        if not branch_instr.label:
            return []
        
        label_line = self.parser.labels.get(branch_instr.label, -1)
        if label_line == -1:
            return []
        
        # Find loop start index
        loop_start = None
        for i, instr in enumerate(self.instructions):
            if instr.line_num == label_line:
                loop_start = i
                break
        
        if loop_start is None:
            return []
        
        # Find loop end (the branch instruction)
        loop_end = None
        for i, instr in enumerate(self.instructions):
            if instr.line_num == branch_instr.line_num:
                loop_end = i
                break
        
        if loop_end is None or loop_start >= loop_end:
            return []
        
        return self.instructions[loop_start:loop_end + 1]
    
    def _detect_stride_pattern(self, memory_instrs: List[Instruction]) -> Optional[int]:
        """Detect constant stride in memory access pattern"""
        if len(memory_instrs) < 2:
            return None
        
        # Extract offsets from instructions
        offsets = []
        for instr in memory_instrs:
            if instr.imm is not None:
                offsets.append(instr.imm)
        
        if len(offsets) < 2:
            return None
        
        # Sort offsets to find consistent stride
        sorted_offsets = sorted(offsets)
        diffs = [sorted_offsets[i+1] - sorted_offsets[i] for i in range(len(sorted_offsets)-1)]
        
        # Check if all diffs are the same (consistent stride)
        if len(set(diffs)) == 1:
            return abs(diffs[0])
        
        return None
    
    def _is_power_of_two(self, n: int) -> bool:
        return n > 0 and (n & (n - 1)) == 0
    
    def _is_variable_time_op(self, instr: Instruction) -> bool:
        variable_time_ops = {'div', 'divu', 'rem', 'remu', 'mul', 'mulh', 'mulhu', 'mulhsu'}
        return instr.opcode in variable_time_ops
    
    def _get_access_size(self, opcode: str) -> int:
        if opcode in {'lb', 'lbu', 'sb'}:
            return 1
        elif opcode in {'lh', 'lhu', 'sh'}:
            return 2
        elif opcode in {'lw', 'lwu', 'sw'}:
            return 4
        elif opcode in {'ld', 'sd'}:
            return 8
        return 4
    
    def _calculate_overall_risk(self) -> RiskLevel:
        if not self.vulnerabilities:
            return RiskLevel.NONE
        max_risk_value = max(v.risk_level.value for v in self.vulnerabilities)
        for risk in RiskLevel:
            if risk.value == max_risk_value:
                return risk
        return RiskLevel.NONE
    
    def _calculate_vulnerability_score(self) -> float:
        if not self.vulnerabilities:
            return 0.0
        
        total_score = 0.0
        for vuln in self.vulnerabilities:
            risk_weight = vuln.risk_level.value / 4.0
            total_score += risk_weight * vuln.confidence
        
        import math
        normalized = 1 - math.exp(-total_score / 3)
        return min(normalized, 1.0)
    
    def _calculate_statistics(self) -> Dict:
        stats = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_risk_level': defaultdict(int),
            'by_type': defaultdict(int),
            'by_sequence_length': defaultdict(int),
            'average_confidence': 0.0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
        
        if not self.vulnerabilities:
            return stats
        
        for vuln in self.vulnerabilities:
            stats['by_risk_level'][vuln.risk_level.name] += 1
            stats['by_type'][vuln.vuln_type.value] += 1
            stats['by_sequence_length'][vuln.sequence_length] += 1
            
            if vuln.risk_level == RiskLevel.CRITICAL:
                stats['critical_count'] += 1
            elif vuln.risk_level == RiskLevel.HIGH:
                stats['high_count'] += 1
            elif vuln.risk_level == RiskLevel.MEDIUM:
                stats['medium_count'] += 1
            elif vuln.risk_level == RiskLevel.LOW:
                stats['low_count'] += 1
        
        stats['average_confidence'] = sum(v.confidence for v in self.vulnerabilities) / len(self.vulnerabilities)
        
        return dict(stats)
    
    def _generate_summary(self) -> str:
        if not self.vulnerabilities:
            return "✅ BENIGN - No vulnerabilities detected"
        
        critical = sum(1 for v in self.vulnerabilities if v.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for v in self.vulnerabilities if v.risk_level == RiskLevel.HIGH)
        medium = sum(1 for v in self.vulnerabilities if v.risk_level == RiskLevel.MEDIUM)
        low = sum(1 for v in self.vulnerabilities if v.risk_level == RiskLevel.LOW)
        
        summary = f"❌ VULNERABLE - Found {len(self.vulnerabilities)} vulnerabilities: "
        parts = []
        if critical: parts.append(f"{critical} CRITICAL")
        if high: parts.append(f"{high} HIGH")
        if medium: parts.append(f"{medium} MEDIUM")
        if low: parts.append(f"{low} LOW")
        
        summary += ", ".join(parts)
        return summary
    
    def _vuln_to_dict(self, vuln: Vulnerability) -> Dict:
        return {
            'type': vuln.vuln_type.value,
            'risk_level': vuln.risk_level.name,
            'line_start': vuln.line_start,
            'line_end': vuln.line_end,
            'sequence_length': vuln.sequence_length,
            'description': vuln.description,
            'pattern': vuln.pattern,
            'affected_registers': list(vuln.affected_registers),
            'recommendations': vuln.recommendations,
            'confidence': vuln.confidence,
            'details': vuln.details
        }

    def _are_consecutive_lines(self, line_nums: List[int]) -> bool:
        """Check if line numbers are consecutive (no gaps)"""
        if len(line_nums) <= 1:
            return True
        
        # Check if they're consecutive in the source code
        for i in range(len(line_nums) - 1):
            if line_nums[i+1] - line_nums[i] > 3:  # Allow small gaps for labels/blank lines
                return False
        
        return True

    def _is_in_loop(self, line_num: int) -> bool:
        """Check if instruction is inside a loop"""
        # Look for backward branches
        for i, instr in enumerate(self.instructions):
            if instr.is_branch and instr.label:
                # Check if this branch jumps back to before our line
                label_line = self.parser.labels.get(instr.label, -1)
                if label_line < instr.line_num and label_line <= line_num <= instr.line_num:
                    return True
        
        return False

class RandomRISCVGenerator:
    """Generate random RISC-V sequences"""
    
    def __init__(self, seed=None):
        if seed:
            random.seed(seed)
        
        self.registers = ['t0', 't1', 't2', 't3', 't4', 't5', 't6',
                         's0', 's1', 'a0', 'a1', 'a2', 'a3']
        
        self.opcodes = {
            'arithmetic': ['add', 'sub', 'addi', 'and', 'or', 'xor'],
            'compare': ['slt', 'sltu', 'slti', 'sltiu'],
            'load': ['lw', 'lh', 'lb'],
            'store': ['sw', 'sh', 'sb'],
            'branch': ['beq', 'bne', 'blt', 'bge', 'beqz', 'bnez'],
            'jump': ['jal', 'jalr']
        }
    
    def generate_random_instruction(self, category=None) -> str:
        if category is None:
            category = random.choice(list(self.opcodes.keys()))
        
        opcode = random.choice(self.opcodes[category])
        
        if category in ['load', 'store']:
            rd = random.choice(self.registers)
            rs1 = random.choice(self.registers)
            offset = random.randint(-64, 63) * 4
            return f"{opcode} {rd}, {offset}({rs1})"
        
        elif category == 'branch':
            rs1 = random.choice(self.registers)
            if opcode in ['beqz', 'bnez']:
                return f"{opcode} {rs1}, label_{random.randint(1, 5)}"
            rs2 = random.choice(self.registers)
            return f"{opcode} {rs1}, {rs2}, label_{random.randint(1, 5)}"
        
        elif category == 'jump':
            if opcode == 'jal':
                return f"{opcode} ra, label_{random.randint(1, 5)}"
            rs1 = random.choice(self.registers)
            return f"{opcode} {rs1}"
        
        else:
            rd = random.choice(self.registers)
            rs1 = random.choice(self.registers)
            
            if opcode.endswith('i'):
                imm = random.randint(-32, 31)
                return f"{opcode} {rd}, {rs1}, {imm}"
            
            rs2 = random.choice(self.registers)
            return f"{opcode} {rd}, {rs1}, {rs2}"
    
    def generate_random_program(self, num_instructions=10) -> str:
        instructions = []
        for i in range(num_instructions):
            category = random.choice(['arithmetic', 'load', 'store', 'compare'])
            instructions.append(self.generate_random_instruction(category))
        return "\n".join(instructions)


def save_report_to_file(report: str, filename: str):
    with open(filename, 'w') as f:
        f.write(report)


def analyze_custom_code():
    """Interactive mode for analyzing custom RISC-V code"""
    print("\n" + "=" * 100)
    print("📝 CUSTOM RISC-V CODE ANALYSIS MODE")
    print("=" * 100)
    
    # Show instruction format examples
    print("\n📋 INSTRUCTION FORMAT EXAMPLES:")
    print("-" * 50)
    print("1. Arithmetic:    add t0, t1, t2")
    print("2. Load:          lw t0, 0(sp)")
    print("3. Store:         sw t0, 4(sp)")
    print("4. Load with offset: lw t0, 8(t1)")
    print("5. Branch:        beq t0, t1, label_name")
    print("6. Jump:          jal ra, function_name")
    print("7. Immediate:     addi t0, t1, 10")
    print("8. Compare:       slt t0, t1, t2")
    print("9. Memory access: lb t0, 0(a0)")
    print("10. Unconditional: j loop_start")
    print("\n📝 You can use labels (e.g., 'loop:' on its own line)")
    print("📝 Comments start with # or ;")
    print("=" * 100)
    
    print("\n📥 Enter your RISC-V assembly code (press Enter twice to finish):")
    print("   (Type 'END' on a new line to finish)")
    print("-" * 80)
    
    lines = []
    line_count = 0
    
    while True:
        try:
            line = input(f"   Line {line_count + 1}: ").strip()
            
            if line.upper() == 'END':
                break
            
            if line:  # Only add non-empty lines
                lines.append(line)
                line_count += 1
            elif line_count > 0:  # Allow empty line only if we have some content
                # Check if user wants to finish
                confirm = input("   Finish input? (y/n): ").strip().lower()
                if confirm == 'y':
                    break
        
        except EOFError:
            print("\n   Input complete.")
            break
    
    if not lines:
        print("❌ No code provided. Exiting...")
        return
    
    code = "\n".join(lines)
    
    print("\n📊 ANALYZING YOUR CODE...")
    print("-" * 80)
    
    detector = VulnerabilityDetector()
    result = detector.analyze(code)
    
    print(f"\n📈 ANALYSIS RESULTS:")
    print(f"   Instructions analyzed: {result['total_instructions']}")
    print(f"   Overall Status: {result['summary']}")
    print(f"   Overall Risk Level: {result['overall_risk']}")
    print(f"   Vulnerability Score: {result['overall_score']:.2f}/1.0")
    
    if result['is_vulnerable']:
        print(f"\n⚠️  VULNERABILITIES DETECTED ({result['statistics']['total_vulnerabilities']} total):")
        print("-" * 80)
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in result['vulnerabilities']:
            vuln_type = vuln['type']
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Print vulnerabilities by type
        for vuln_type, vulns in vuln_by_type.items():
            print(f"\n🔴 {vuln_type} ({len(vulns)} instances):")
            for i, vuln in enumerate(vulns, 1):
                print(f"   {i}. Lines {vuln['line_start']}-{vuln['line_end']}:")
                print(f"      Description: {vuln['description']}")
                print(f"      Risk Level: {vuln['risk_level']}")
                print(f"      Confidence: {vuln['confidence']:.2f}")
                print(f"      Affected Registers: {', '.join(vuln['affected_registers'])}")
                print(f"      Pattern: {' → '.join(vuln['pattern'])}")
                print(f"      Recommendations:")
                for rec in vuln['recommendations']:
                    print(f"        • {rec}")
        
        # Statistics
        print(f"\n📊 VULNERABILITY STATISTICS:")
        print(f"   Critical: {result['statistics']['critical_count']}")
        print(f"   High: {result['statistics']['high_count']}")
        print(f"   Medium: {result['statistics']['medium_count']}")
        print(f"   Low: {result['statistics']['low_count']}")
        print(f"   Average Confidence: {result['statistics']['average_confidence']:.2f}")
    
    else:
        print(f"\n✅ NO VULNERABILITIES DETECTED")
        print("   Your code appears to be secure against side-channel attacks.")
    
    # Save to file option
    save_option = input("\n💾 Save analysis to file? (y/n): ").strip().lower()
    if save_option == 'y':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"custom_analysis_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("RISC-V SIDE-CHANNEL VULNERABILITY ANALYSIS\n")
            f.write("=" * 80 + "\n")
            f.write(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Instructions Analyzed: {result['total_instructions']}\n")
            f.write(f"Overall Status: {result['summary']}\n")
            f.write(f"Overall Risk Level: {result['overall_risk']}\n")
            f.write(f"Vulnerability Score: {result['overall_score']:.2f}/1.0\n\n")
            
            f.write("CODE ANALYZED:\n")
            f.write("-" * 80 + "\n")
            f.write(code + "\n")
            f.write("-" * 80 + "\n\n")
            
            if result['is_vulnerable']:
                f.write("DETECTED VULNERABILITIES:\n")
                f.write("-" * 80 + "\n")
                for i, vuln in enumerate(result['vulnerabilities'], 1):
                    f.write(f"{i}. {vuln['type']}\n")
                    f.write(f"   Lines: {vuln['line_start']}-{vuln['line_end']}\n")
                    f.write(f"   Description: {vuln['description']}\n")
                    f.write(f"   Risk Level: {vuln['risk_level']}\n")
                    f.write(f"   Confidence: {vuln['confidence']:.2f}\n")
                    f.write(f"   Affected Registers: {', '.join(vuln['affected_registers'])}\n")
                    f.write(f"   Pattern: {' → '.join(vuln['pattern'])}\n")
                    f.write(f"   Recommendations:\n")
                    for rec in vuln['recommendations']:
                        f.write(f"      • {rec}\n")
                    f.write("\n")
                
                f.write("STATISTICS:\n")
                f.write(f"   Total Vulnerabilities: {result['statistics']['total_vulnerabilities']}\n")
                f.write(f"   Critical: {result['statistics']['critical_count']}\n")
                f.write(f"   High: {result['statistics']['high_count']}\n")
                f.write(f"   Medium: {result['statistics']['medium_count']}\n")
                f.write(f"   Low: {result['statistics']['low_count']}\n")
                f.write(f"   Average Confidence: {result['statistics']['average_confidence']:.2f}\n")
            else:
                f.write("NO VULNERABILITIES DETECTED\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("ANALYSIS COMPLETE\n")
            f.write("=" * 80 + "\n")
        
        print(f"✅ Analysis saved to: {filename}")
    
    print("\n" + "=" * 100)
    print("ANALYSIS COMPLETE")
    print("=" * 100)


def test_mode():
    """Run the comprehensive test suite"""
    print("=" * 100)
    print("RISC-V SIDE-CHANNEL VULNERABILITY STATIC ANALYZER - TEST MODE")
    print("=" * 100)
    print()
    
    # 100 BENIGN SEQUENCES (50 existing + 50 new)
    benign_sequences = [
        ("BENIGN_01", "add t0, t1, t2"),
        ("BENIGN_02", "sub t0, t1, t2"),
        ("BENIGN_03", "lw t0, 0(sp)"),
        ("BENIGN_04", "sw t0, 0(sp)"),
        ("BENIGN_05", "addi t0, t1, 10"),
        ("BENIGN_06", "and t0, t1, t2"),
        ("BENIGN_07", "or t0, t1, t2"),
        ("BENIGN_08", "xor t0, t1, t2"),
        ("BENIGN_09", "slli t0, t1, 2"),
        ("BENIGN_10", "srli t0, t1, 2"),
        ("BENIGN_11", "add t0, t1, t2\nlw t3, 0(sp)"),
        ("BENIGN_12", "addi s0, sp, 16\nlw a0, 0(s0)"),
        ("BENIGN_13", "li t0, 100\naddi t0, t0, 50"),
        ("BENIGN_14", "mv a0, t0\nret"),
        ("BENIGN_15", "sw t0, 0(sp)\nlw t1, 4(sp)"),
        ("BENIGN_16", "jal label_1\nlabel_1:\nret"),
        ("BENIGN_17", "add t0, t1, t2\nadd t3, t4, t5"),
        ("BENIGN_18", "lw t0, 0(a0)\nlw t1, 8(a0)"),
        ("BENIGN_19", "beq t0, zero, done\ndone:\nret"),
        ("BENIGN_20", "li t0, 0\nloop:\naddi t0, t0, 1\nblt t0, a0, loop"),
        ("BENIGN_21", "fence\nlw t0, 0(a0)\nlw t1, 0(a1)"),
        ("BENIGN_22", "and t0, t1, t2\nor t3, t4, t5"),
        ("BENIGN_23", "slt t0, t1, t2\nadd t3, t0, zero"),
        ("BENIGN_24", "lw t0, 0(sp)\nsw t0, 4(sp)\nlw t1, 8(sp)"),
        ("BENIGN_25", "addi sp, sp, -16\nsw ra, 12(sp)"),
        ("BENIGN_26", "lw ra, 12(sp)\naddi sp, sp, 16\nret"),
        ("BENIGN_27", "li a0, 42\nmv a1, a0\nret"),
        ("BENIGN_28", "add t0, a0, a1\nadd t1, a2, a3"),
        ("BENIGN_29", "lw t0, 0(a0)\nadd t1, t0, zero"),
        ("BENIGN_30", "beq a0, zero, skip\naddi a0, a0, 1\nskip:\nret"),
        ("BENIGN_31", "and t0, t1, 0xFF\nor t2, t3, t4"),
        ("BENIGN_32", "slli t0, t1, 3\nsrli t2, t3, 2"),
        ("BENIGN_33", "lw t0, 0(a0)\nlw t1, 16(a0)\nlw t2, 32(a0)"),
        ("BENIGN_34", "sw t0, 0(a0)\nsw t1, 16(a0)"),
        ("BENIGN_35", "li t0, 1000\nloop2:\naddi t0, t0, -1\nbnez t0, loop2"),
        ("BENIGN_36", "add t0, t1, t2\nsub t3, t4, t5\nand t6, t0, t3"),
        ("BENIGN_37", "lw a0, 0(sp)\nlw a1, 4(sp)\ncall func"),
        ("BENIGN_38", "addi t0, zero, 5\naddi t1, zero, 10"),
        ("BENIGN_39", "fence\nsw t0, 0(a0)"),
        ("BENIGN_40", "lw t0, 0(a0)\nfence\nlw t1, 0(a1)"),
        ("BENIGN_41", "beq t0, t1, equal\nli a0, 0\nj done\nequal:\nli a0, 1\ndone:"),
        ("BENIGN_42", "slt t0, a0, a1\nbeqz t0, skip2\naddi a2, a2, 1\nskip2:"),
        ("BENIGN_43", "add t0, t1, t2\nadd t0, t0, t3\nadd t0, t0, t4"),
        ("BENIGN_44", "lw t0, 0(a0)\nlw t1, 20(a0)\nlw t2, 40(a0)"),
        ("BENIGN_45", "li t0, 0\nli t1, 0\nli t2, 0"),
        ("BENIGN_46", "mv t0, a0\nmv t1, a1\nmv t2, a2"),
        ("BENIGN_47", "sw zero, 0(a0)\nsw zero, 4(a0)"),
        ("BENIGN_48", "addi a0, a0, 4\naddi a1, a1, 4"),
        ("BENIGN_49", "and t0, t1, t2\nxor t3, t4, t5\nor t6, t0, t3"),
        ("BENIGN_50", "lw t0, 0(sp)\naddi sp, sp, 4\nret"),
        ("BENIGN_51", "lui t0, 0x10000\naddi t0, t0, 0x100"),
        ("BENIGN_52", "sltiu t0, a0, 1000\nbeqz t0, large_value\naddi a1, a1, 1\nlarge_value:"),
        ("BENIGN_53", "lw t0, 0(a0)\nlw t1, 4(a0)\nlw t2, 8(a0)"),
        ("BENIGN_54", "add t0, a0, a1\nsub t1, a2, a3\nmul t2, t0, t1"),
        ("BENIGN_55", "sw t0, 0(sp)\nsw t1, 4(sp)\nlw t2, 8(sp)"),
        ("BENIGN_56", "li t0, 0\nli t1, 10\nbgt t0, t1, error\naddi t0, t0, 1"),
        ("BENIGN_57", "srl t0, a0, a1\nsll t1, a2, a3\nor t2, t0, t1"),
        ("BENIGN_58", "fence.i\naddi t0, t0, 1\nsw t0, 0(a0)"),
        ("BENIGN_59", "lbu t0, 0(a0)\nlbu t1, 1(a0)\nadd t2, t0, t1"),
        ("BENIGN_60", "xor t0, a0, a1\nxor t1, a2, a3\nand t2, t0, t1"),
        ("BENIGN_61", "lw t0, 0(a0)\naddi t0, t0, 1\nsw t0, 0(a0)"),
        ("BENIGN_62", "srai t0, a0, 4\nsrli t1, a1, 4\nadd t2, t0, t1"),
        ("BENIGN_63", "beqz a0, zero_case\naddi a1, a1, 10\nj end\nzero_case:\naddi a1, a1, 5\nend:"),
        ("BENIGN_64", "lw t0, 0(a0)\nlw t1, 0(a1)\nadd t2, t0, t1\nsw t2, 0(a2)"),
        ("BENIGN_65", "addi sp, sp, -32\nsw ra, 28(sp)\nsw s0, 24(sp)\nsw s1, 20(sp)"),
        ("BENIGN_66", "lw ra, 28(sp)\nlw s0, 24(sp)\nlw s1, 20(sp)\naddi sp, sp, 32\nret"),
        ("BENIGN_67", "mv a0, zero\nmv a1, zero\ncall memset"),
        ("BENIGN_68", "slt t0, a0, a1\nslt t1, a2, a3\nor t2, t0, t1"),
        ("BENIGN_69", "lw t0, 0(a0)\nlw t1, 12(a0)\nlw t2, 24(a0)"),
        ("BENIGN_70", "addi t0, zero, 1\nslli t0, t0, 10\nsw t0, 0(a0)"),
        ("BENIGN_71", "lb t0, 0(a0)\nlb t1, 1(a0)\nadd t2, t0, t1"),
        ("BENIGN_72", "sw t0, 0(a0)\nfence\nlw t1, 0(a1)"),
        ("BENIGN_73", "sltu t0, a0, a1\nbeqz t0, error\naddi a0, a0, 1"),
        ("BENIGN_74", "lw t0, 0(a0)\nlw t1, 0(a1)\nmul t2, t0, t1"),
        ("BENIGN_75", "addi t0, zero, 64\naddi t1, zero, 128\nadd t2, t0, t1"),
        ("BENIGN_76", "lw t0, 0(sp)\nlw t1, 16(sp)\nlw t2, 32(sp)"),
        ("BENIGN_77", "sw zero, 0(a0)\nsw zero, 8(a0)\nsw zero, 16(a0)"),
        ("BENIGN_78", "add t0, a0, a1\nsub t1, a2, a3\nand t2, t0, t1"),
        ("BENIGN_79", "li t0, 0\nli t1, 100\nloop3:\naddi t0, t0, 1\nblt t0, t1, loop3"),
        ("BENIGN_80", "sll t0, a0, a1\nsrl t1, a2, a3\nxor t2, t0, t1"),
        ("BENIGN_81", "lw t0, 0(a0)\naddi a0, a0, 4\nsw t0, 0(a1)\naddi a1, a1, 4"),
        ("BENIGN_82", "addi t0, zero, 0xFF\nand t1, a0, t0\nsrli t2, a0, 8"),
        ("BENIGN_83", "beq a0, a1, match\nli a0, 0\nret\nmatch:\nli a0, 1\nret"),
        ("BENIGN_84", "lw t0, 0(a0)\nlw t1, 4(a0)\nadd t2, t0, t1\nsw t2, 8(a0)"),
        ("BENIGN_85", "slli t0, a0, 2\nadd t1, a1, t0\nlw t2, 0(t1)"),
        ("BENIGN_86", "addi t0, zero, 10\naddi t1, zero, 20\nbge t0, t1, skip3\naddi t0, t0, 5\nskip3:"),
        ("BENIGN_87", "lw t0, 0(a0)\nsw t0, 0(a1)\nlw t1, 4(a0)\nsw t1, 4(a1)"),
        ("BENIGN_88", "andi t0, a0, 0xF\nandi t1, a1, 0xF\nadd t2, t0, t1"),
        ("BENIGN_89", "lui t0, 0x20000\naddi t0, t0, 0x400\nsw a0, 0(t0)"),
        ("BENIGN_90", "bnez a0, non_zero\naddi a1, a1, 1\nj end2\nnon_zero:\naddi a1, a1, 2\nend2:"),
        ("BENIGN_91", "lw t0, 0(a0)\nlw t1, 0(a1)\nsub t2, t0, t1\nsw t2, 0(a2)"),
        ("BENIGN_92", "slti t0, a0, 100\nbeqz t0, big_value\naddi a1, a1, 10\nbig_value:"),
        ("BENIGN_93", "addi sp, sp, -64\nsw ra, 60(sp)\nsw s0, 56(sp)\nsw s1, 52(sp)"),
        ("BENIGN_94", "lw t0, 0(a0)\nlw t1, 64(a0)\nlw t2, 128(a0)"),
        ("BENIGN_95", "li t0, 0\nli t1, 0\nli t2, 0\nli t3, 0"),
        ("BENIGN_96", "add t0, a0, a1\nslli t1, t0, 1\naddi t2, t1, 10"),
        ("BENIGN_97", "lw t0, 0(a0)\nlw t1, 256(a0)\nlw t2, 512(a0)"),
        ("BENIGN_98", "beqz a0, case1\nbeqz a1, case2\nj default\ncase1:\ncase2:\ndefault:"),
        ("BENIGN_99", "slli t0, a0, 3\nadd t1, a1, t0\nsw a2, 0(t1)"),
        ("BENIGN_100", "lw t0, 0(a0)\naddi t0, t0, 1\nsw t0, 0(a0)\nret"),
    ]
    
    vulnerable_sequences = [
        ("VULN_SPECTRE_V1_01", "sltu t0, a1, a2\nbeqz t0, safe\nlw t2, 0(a0)\nsafe:"),
        ("VULN_SPECTRE_V1_02", "slt t0, a1, a2\nbnez t0, ok\nlw t2, 0(a0)\nok:"),
        ("VULN_SPECTRE_V1_03", "sltu t0, t1, t2\nbeqz t0, bounds_fail\nslli t3, t1, 3\nadd t4, a0, t3\nlw t5, 0(t4)\nbounds_fail:"),
        ("VULN_SPECTRE_V1_04", "sltiu t0, a1, 100\nbeqz t0, out\nlw t2, 0(a0)\nout:"),
        ("VULN_SPECTRE_V1_05", "sltu t0, s1, s2\nbeqz t0, skip\nlw t1, 0(s3)\nskip:"),
        ("VULN_SPECTRE_V2_01", "jalr t0"),
        ("VULN_SPECTRE_V2_02", "lw t0, 0(sp)\njalr t0"),
        ("VULN_SPECTRE_V2_03", "lw t1, 8(sp)\njalr t1"),
        ("VULN_SPECTRE_V2_04", "lw ra, 0(sp)\njalr ra"),
        ("VULN_SPECTRE_V2_05", "ld t2, 0(a0)\njalr t2"),
        ("VULN_SPECTRE_V4_01", "sw t0, 0(a0)\nlw t1, 0(a0)"),
        ("VULN_SPECTRE_V4_02", "sw t0, 4(sp)\nlw t1, 4(sp)"),
        ("VULN_SPECTRE_V4_03", "sd t0, 0(a1)\nld t1, 0(a1)"),
        ("VULN_SPECTRE_V4_04", "sw t2, 8(sp)\nlw t3, 8(sp)"),
        ("VULN_SPECTRE_V4_05", "sb t0, 0(a0)\nlb t1, 0(a0)"),
        ("VULN_FLUSH_RELOAD_01", "fence.i\nlw t0, 0(a0)"),
        ("VULN_FLUSH_RELOAD_02", "fence.i\njalr t1"),
        ("VULN_FLUSH_RELOAD_03", "fence.i\nlw t0, 0(sp)\nrdcycle t1"),
        ("VULN_FLUSH_RELOAD_04", "fence.i\nld t0, 0(a0)\nrdtime t1"),
        ("VULN_FLUSH_RELOAD_05", "fence.i\nlw t1, 0(a1)\nrdinstret t2"),
        ("VULN_PASSWORD_01", "lbu t1, 0(a0)\nlbu t2, 0(a1)\nbne t1, t2, fail"),
        ("VULN_PASSWORD_02", "lb t1, 0(a0)\nlb t2, 0(a1)\nbeq t1, t2, ok\nli a0, 0\nret\nok:"),
        ("VULN_PASSWORD_03", "lbu t3, 0(s0)\nlbu t4, 0(s1)\nbne t3, t4, mismatch"),
        ("VULN_PASSWORD_04", "lb t1, 0(a0)\nlb t2, 0(a1)\nbne t1, t2, fail\naddi a0, a0, 1\naddi a1, a1, 1"),
        ("VULN_PASSWORD_05", "lbu t5, 0(a0)\nlbu t6, 0(a1)\nbeq t5, t6, match\nj fail\nmatch:"),
        ("VULN_CACHE_01", "lw t0, 0(a0)\nlw t1, 64(a0)\nlw t2, 128(a0)\nlw t3, 192(a0)"),
        ("VULN_CACHE_02", "lw t0, 0(t1)\nlw t2, 64(t1)\nlw t3, 128(t1)"),
        ("VULN_CACHE_03", "ld t0, 0(a0)\nld t1, 64(a0)\nld t2, 128(a0)\nld t3, 192(a0)"),
        ("VULN_CACHE_04", "lw t0, 0(s0)\nlw t1, 128(s0)\nlw t2, 256(s0)\nlw t3, 384(s0)"),
        ("VULN_CACHE_05", "lb t0, 0(a0)\nlb t1, 64(a0)\nlb t2, 128(a0)\nlb t3, 192(a0)"),
        ("VULN_TIMING_01", "div t0, a0, a1\nlw t1, 0(sp)"),
        ("VULN_TIMING_02", "rem t0, a0, a1\nbeq t0, zero, done"),
        ("VULN_TIMING_03", "divu t0, t1, t2\nsw t0, 0(a0)"),
        ("VULN_TIMING_04", "mul t0, a0, a1\nbne t0, zero, skip"),
        ("VULN_TIMING_05", "remu t0, s0, s1\nlw t1, 0(sp)"),
        ("VULN_PRIME_PROBE_01", "loop:\nlw t0, 0(a0)\naddi a0, a0, 64\nbne a0, a1, loop"),
        ("VULN_PRIME_PROBE_02", "li t0, 0x1000\np_loop:\nlw t1, 0(t0)\naddi t0, t0, 64\nblt t0, a0, p_loop"),
        ("VULN_PRIME_PROBE_03", "probe:\nld t0, 0(s0)\naddi s0, s0, 64\nbnez t1, probe"),
        ("VULN_PRIME_PROBE_04", "li a0, 0\nprobe_loop:\nlw t0, 0(a0)\naddi a0, a0, 64\nbne a0, t2, probe_loop"),
        ("VULN_PRIME_PROBE_05", "cache_loop:\nlw t2, 0(t3)\naddi t3, t3, 64\nbltu t3, t4, cache_loop"),
        ("VULN_UNALIGNED_01", "lw t0, 3(a0)"),
        ("VULN_UNALIGNED_02", "lw t0, 5(sp)"),
        ("VULN_UNALIGNED_03", "ld t0, 7(a0)"),
        ("VULN_UNALIGNED_04", "lh t0, 1(sp)"),
        ("VULN_UNALIGNED_05", "sw t0, 6(a0)"),
        ("VULN_MIXED_01", "sltu t0, a1, a2\nbeqz t0, fail\njalr t1"),
        ("VULN_MIXED_02", "fence.i\nlbu t0, 0(a0)\nlbu t1, 0(a1)\nbne t0, t1, fail"),
        ("VULN_MIXED_03", "lw t0, 0(sp)\njalr t0\nlw t1, 0(a0)"),
        ("VULN_MIXED_04", "div t0, a0, a1\nsltu t1, t0, a2\nbeqz t1, skip\nlw t2, 0(a3)"),
        ("VULN_MIXED_05", "sw t0, 0(a0)\nlw t1, 0(a0)\nfence.i\njalr t2"),
        
        ("VULN_SPECTRE_V1_06", "sltiu t0, s0, 256\nbeqz t0, overflow\nlw t1, 0(s1)\noverflow:"),
        ("VULN_SPECTRE_V1_07", "sltu t0, a2, a3\nbnez t0, in_bounds\nlw t1, 0(a4)\nin_bounds:"),
        ("VULN_SPECTRE_V1_08", "slt t0, t2, t3\nbeqz t0, exit\naddi t4, t2, 4\nlw t5, 0(t4)\nexit:"),
        ("VULN_SPECTRE_V1_09", "sltiu t0, a5, 1024\nbnez t0, valid\nlw t6, 0(a6)\nvalid:"),
        ("VULN_SPECTRE_V1_10", "sltu t0, s3, s4\nbeqz t0, stop\nslli t1, s3, 2\nadd t2, s5, t1\nlw t3, 0(t2)\nstop:"),
        ("VULN_SPECTRE_V2_06", "ld ra, 0(sp)\njalr ra"),
        ("VULN_SPECTRE_V2_07", "lw t3, 16(sp)\njalr t3"),
        ("VULN_SPECTRE_V2_08", "lw a0, 0(t0)\njalr a0"),
        ("VULN_SPECTRE_V2_09", "ld t4, 8(a0)\njalr t4"),
        ("VULN_SPECTRE_V2_10", "lw t5, 24(sp)\njalr t5"),
        ("VULN_SPECTRE_V4_06", "sd s0, 0(a0)\nld s1, 0(a0)"),
        ("VULN_SPECTRE_V4_07", "sw s2, 16(sp)\nlw s3, 16(sp)"),
        ("VULN_SPECTRE_V4_08", "sb a0, 0(t0)\nlb a1, 0(t0)"),
        ("VULN_SPECTRE_V4_09", "sh t0, 0(a1)\nlh t1, 0(a1)"),
        ("VULN_SPECTRE_V4_10", "sw t2, -8(sp)\nlw t3, -8(sp)"),
        ("VULN_FLUSH_RELOAD_06", "fence.i\nlw t2, 64(a0)\nrdcycle t3"),
        ("VULN_FLUSH_RELOAD_07", "fence.i\njalr ra"),
        ("VULN_FLUSH_RELOAD_08", "fence.i\nlbu t0, 0(a0)\nrdtime t1"),
        ("VULN_FLUSH_RELOAD_09", "fence.i\nlh t0, 0(a1)\nrdinstret t1"),
        ("VULN_FLUSH_RELOAD_10", "fence.i\nlw t0, 128(sp)\nrdcycle t1"),
        ("VULN_PASSWORD_06", "lbu s0, 0(a0)\nlbu s1, 0(a1)\nbeq s0, s1, next\nj mismatch"),
        ("VULN_PASSWORD_07", "lb t0, 0(s2)\nlb t1, 0(s3)\nbne t0, t1, diff"),
        ("VULN_PASSWORD_08", "lbu a2, 0(t0)\nlbu a3, 0(t1)\nbeq a2, a3, equal2\nli a0, 0"),
        ("VULN_PASSWORD_09", "lb s4, 0(a4)\nlb s5, 0(a5)\nbne s4, s5, not_equal"),
        ("VULN_PASSWORD_10", "lbu t2, 0(t3)\nlbu t4, 0(t5)\nbeq t2, t4, success\nj failure"),
        ("VULN_CACHE_06", "lw t4, 0(a0)\nlw t5, 64(a0)\nlw t6, 128(a0)\nlw s0, 192(a0)"),
        ("VULN_CACHE_07", "lw s1, 0(a1)\nlw s2, 64(a1)\nlw s3, 128(a1)"),
        ("VULN_CACHE_08", "ld s4, 0(a2)\nld s5, 64(a2)\nld s6, 128(a2)\nld s7, 192(a2)"),
        ("VULN_CACHE_09", "lw t0, 0(t1)\nlw t1, 128(t1)\nlw t2, 256(t1)\nlw t3, 384(t1)"),
        ("VULN_CACHE_10", "lb s0, 0(s1)\nlb s1, 64(s1)\nlb s2, 128(s1)\nlb s3, 192(s1)"),
        ("VULN_TIMING_06", "mulh t0, a0, a1\nbeqz t0, zero_result"),
        ("VULN_TIMING_07", "div t0, s0, s1\nsw t0, 0(sp)"),
        ("VULN_TIMING_08", "remu t0, a2, a3\nlw t1, 0(a0)"),
        ("VULN_TIMING_09", "mulhu t0, t1, t2\nbnez t0, non_zero"),
        ("VULN_TIMING_10", "divu t0, s2, s3\nlw t1, 4(sp)"),
        ("VULN_PRIME_PROBE_06", "start:\nlw t0, 0(s0)\naddi s0, s0, 64\nblt s0, s1, start"),
        ("VULN_PRIME_PROBE_07", "li s0, 0x2000\nloop4:\nld t1, 0(s0)\naddi s0, s0, 64\nbne s0, s2, loop4"),
        ("VULN_PRIME_PROBE_08", "ptr = a0\nrepeat:\nlw t2, 0(ptr)\naddi ptr, ptr, 64\nbne ptr, a1, repeat"),
        ("VULN_PRIME_PROBE_09", "li t0, 0\nscan:\nlw t1, 0(t0)\naddi t0, t0, 64\nbltu t0, t2, scan"),
        ("VULN_PRIME_PROBE_10", "move a0, zero\nexamine:\nlw t3, 0(a0)\naddi a0, a0, 64\nbne a0, t4, examine"),
        ("VULN_UNALIGNED_06", "lw t0, 2(a0)"),
        ("VULN_UNALIGNED_07", "lh t0, 3(sp)"),
        ("VULN_UNALIGNED_08", "lw t0, 1(a1)"),
        ("VULN_UNALIGNED_09", "sh t0, 3(a0)"),
        ("VULN_UNALIGNED_10", "lwu t0, 5(a0)"),
        ("VULN_MIXED_06", "sltu t0, a0, a1\nbeqz t0, end\njalr t2\nlw t3, 0(a2)"),
        ("VULN_MIXED_07", "fence.i\nlb t0, 0(a0)\nlb t1, 0(a1)\nbeq t0, t1, same"),
        ("VULN_MIXED_08", "lw ra, 8(sp)\njalr ra\nsw t0, 0(a0)"),
        ("VULN_MIXED_09", "mul t0, a0, a1\nsltiu t1, t0, 100\nbeqz t1, large\nlw t2, 0(a2)"),
        ("VULN_MIXED_10", "sw t0, 4(a0)\nlw t1, 4(a0)\nfence.i\njalr t3"),
        ("VULN_COMPLEX_01", "sltu t0, a1, a2\nbeqz t0, out_of_range\nslli t1, a1, 2\nadd t2, a0, t1\nlw t3, 0(t2)\nsw t3, 0(a3)\nout_of_range:"),
        ("VULN_COMPLEX_02", "fence.i\nli t0, 0\nattack_loop:\nlw t1, 0(t0)\naddi t0, t0, 64\nblt t0, a0, attack_loop\nrdcycle t2"),
        ("VULN_COMPLEX_03", "lbu t0, 0(a0)\nlbu t1, 0(a1)\nbne t0, t1, mismatch2\nlw t2, 0(sp)\njalr t2"),
        ("VULN_COMPLEX_04", "div t0, a0, a1\nsltu t1, t0, a2\nbeqz t1, skip_all\nlw t2, 0(a3)\nsw t2, 0(a4)"),
        ("VULN_COMPLEX_05", "sltiu t0, s0, 100\nbnez t0, valid_index\nlw t1, 0(s1)\naddi t1, t1, 1\nsw t1, 0(s1)\nvalid_index:"),
        ("VULN_COMPLEX_06", "loop5:\nlw t0, 0(a0)\naddi a0, a0, 64\nbne a0, a1, loop5\nfence.i\njalr ra"),
        ("VULN_COMPLEX_07", "sw t0, 0(a0)\nlw t1, 0(a0)\nlb t2, 0(a1)\nlb t3, 0(a2)\nbne t2, t3, fail2"),
        ("VULN_COMPLEX_08", "sltu t0, a1, a2\nbeqz t0, end3\nmul t1, a1, a2\nlw t2, 0(a3)\nend3:"),
        ("VULN_COMPLEX_09", "fence.i\nlw t0, 0(a0)\nrem t1, t0, a1\nbeqz t1, divisible\nlw t2, 0(a2)"),
        ("VULN_COMPLEX_10", "li t0, 0x1000\nloop6:\nld t1, 0(t0)\naddi t0, t0, 64\nblt t0, a0, loop6\nsw t1, 0(a1)"),
        ("VULN_TAINT_01", "lw t0, 0(sp)  # secret loaded\nsltu t1, t0, a1\nbeqz t1, safe_zone\nlw t2, 0(a0)\nsafe_zone:"),
        ("VULN_TAINT_02", "lw t0, 4(sp)  # secret\nadd t1, t0, a0\njalr t1"),
        ("VULN_TAINT_03", "lw s0, 8(sp)  # secret key\nrem t0, s0, a0\nbeqz t0, exact_multiple\nlw t1, 0(a1)"),
        ("VULN_TAINT_04", "lw a0, 12(sp)  # secret\nsw a0, 0(t0)\nlw t1, 0(t0)"),
        ("VULN_TAINT_05", "lw t0, 16(sp)  # secret data\nfence.i\nlw t1, 0(t0)\nrdcycle t2"),
        ("VULN_ADVANCED_01", "sltu t0, a1, a2\nbnez t0, bounds_ok\nlw t1, 0(a0)\naddi t1, t1, 1\nsw t1, 0(a0)\nbounds_ok:"),
        ("VULN_ADVANCED_02", "fence.i\nli t0, 0\nprobe2:\nlw t1, 0(t0)\naddi t0, t0, 128\nblt t0, a0, probe2\nrdtime t2"),
        ("VULN_ADVANCED_03", "lw t0, 0(sp)\njalr t0\nlbu t1, 0(a0)\nlbu t2, 0(a1)\nbeq t1, t2, match2"),
        ("VULN_ADVANCED_04", "div t0, a0, a1\nsltiu t1, t0, 256\nbeqz t1, overflow2\nlw t2, 0(a2)\nsw t2, 0(a3)"),
        ("VULN_ADVANCED_05", "loop7:\nlw t0, 0(a0)\naddi a0, a0, 64\nsw t0, 0(a1)\naddi a1, a1, 64\nbne a0, a2, loop7"),
        ("VULN_ADVANCED_06", "sltu t0, s0, s1\nbeqz t0, exit2\nslli t1, s0, 3\nadd t2, s2, t1\nld t3, 0(t2)\nsd t3, 0(s3)\nexit2:"),
        ("VULN_ADVANCED_07", "fence.i\nlw t0, 0(a0)\nmul t1, t0, a1\nbeqz t1, zero_val\nlw t2, 0(a2)"),
        ("VULN_ADVANCED_08", "lw t0, 20(sp)\njalr t0\nsw t1, 0(a0)\nlw t2, 0(a0)"),
        ("VULN_ADVANCED_09", "slti t0, a0, 1000\nbnez t0, small\nlw t1, 0(a1)\nadd t2, t1, a2\nsw t2, 0(a3)\nsmall:"),
        ("VULN_ADVANCED_10", "li t0, 0x3000\nattack2:\nld t1, 0(t0)\naddi t0, t0, 64\nbne t0, a0, attack2\nfence.i\njalr ra"),
    ]
    
    # Analyze all sequences
    detector = VulnerabilityDetector()
    
    results = {
        'benign': {'total': 0, 'correct': 0, 'false_positives': []},
        'vulnerable': {'total': 0, 'correct': 0, 'false_negatives': []}
    }

    print("📊 ANALYZING 100 BENIGN SEQUENCES")
    print("-" * 100)
    for idx, (name, code) in enumerate(benign_sequences, 1):
        result = detector.analyze(code)
        results['benign']['total'] += 1
        
        if not result['is_vulnerable']:
            results['benign']['correct'] += 1
            status = "✅ PASS"
        else:
            results['benign']['false_positives'].append(name)
            vuln_count = result['statistics']['total_vulnerabilities']
            status = f"❌ FALSE POSITIVE ({vuln_count} vulns)"
        
        # Print in similar format to random sequences
        instr_count = len(code.strip().split('\n'))
        print(f"  FIXED_{idx:03d} ({name}): {status:<25} length={instr_count}")
        
        
    print()
    print("📊 ANALYZING 100 VULNERABLE SEQUENCES")
    print("-" * 100)
    for idx, (name, code) in enumerate(vulnerable_sequences, 1):
        result = detector.analyze(code)
        results['vulnerable']['total'] += 1
        
        if result['is_vulnerable']:
            results['vulnerable']['correct'] += 1
            vuln_count = result['statistics']['total_vulnerabilities']
            risk = result['overall_risk']
            status = f"✅ DETECTED ({vuln_count} vulns, {risk})"
        else:
            results['vulnerable']['false_negatives'].append(name)
            status = "❌ MISSED"
        
        # Print in similar format to random sequences
        instr_count = len(code.strip().split('\n'))
        print(f"  FIXED_{idx+100:03d} ({name}): {status:<25} length={instr_count}")
                    
    print()
        # Save fixed sequences to file in the same format as random sequences
    print("💾 SAVING FIXED SEQUENCES TO FILE...")
    
    fixed_sequences_file = "FIXED_SEQUENCES_REPORT.txt"
    with open(fixed_sequences_file, 'w') as f:
        f.write("=" * 100 + "\n")
        f.write("FIXED RISC-V SEQUENCES REPORT (BENIGN + VULNERABLE)\n")
        f.write("=" * 100 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Sequences: {len(benign_sequences) + len(vulnerable_sequences)}\n")
        f.write(f"Benign Sequences: {len(benign_sequences)}\n")
        f.write(f"Vulnerable Sequences: {len(vulnerable_sequences)}\n")
        f.write("=" * 100 + "\n\n")
        
        sequence_id = 1
        
        # Save benign sequences
        f.write("BENIGN SEQUENCES\n")
        f.write("-" * 80 + "\n")
        for name, code in benign_sequences:
            result = detector.analyze(code)
            status = "BENIGN" if not result['is_vulnerable'] else "VULNERABLE (False Positive)"
            vuln_count = result['statistics']['total_vulnerabilities']
            risk = result['overall_risk']
            
            f.write(f"SEQUENCE {sequence_id} ({name}):\n")
            f.write(f"Status: {status}\n")
            f.write(f"Sequence Type: BENIGN\n")
            f.write(f"Instruction Count: {len(code.strip().split('\\n'))}\n")
            
            if result['is_vulnerable']:
                f.write(f"Vulnerability Suspected/Detected: YES (False Positive)\n")
                f.write(f"Number of Vulnerabilities: {vuln_count}\n")
                f.write(f"Overall Risk Level: {risk}\n")
                if vuln_count > 0:
                    f.write("Vulnerability Details:\n")
                    for vuln in result['vulnerabilities']:
                        f.write(f"  - Type: {vuln['type']}\n")
                        f.write(f"    Risk: {vuln['risk_level']}\n")
                        f.write(f"    Recommendations: {vuln['recommendations']}\n")
                        f.write(f"    Confidence: {vuln['confidence']:.2f}\n")
                        f.write(f"    Pattern: {vuln['pattern']}\n")
            else:
                f.write(f"Vulnerability Suspected/Detected: NO\n")
                f.write(f"Recommendations: No vulnerabilities detected. Code appears secure.\n")
            
            f.write(f"Code:\n{code}\n")
            f.write("-" * 80 + "\n\n")
            sequence_id += 1
        
        # Save vulnerable sequences
        f.write("\n" + "=" * 80 + "\n")
        f.write("VULNERABLE SEQUENCES\n")
        f.write("-" * 80 + "\n")
        
        for name, code in vulnerable_sequences:
            result = detector.analyze(code)
            status = "VULNERABLE" if result['is_vulnerable'] else "BENIGN (False Negative)"
            vuln_count = result['statistics']['total_vulnerabilities']
            risk = result['overall_risk']
            
            f.write(f"SEQUENCE {sequence_id} ({name}):\n")
            f.write(f"Status: {status}\n")
            f.write(f"Sequence Type: VULNERABLE\n")
            f.write(f"Instruction Count: {len(code.strip().split('\\n'))}\n")
            
            if result['is_vulnerable']:
                f.write(f"Vulnerability Suspected/Detected: YES\n")
                f.write(f"Number of Vulnerabilities: {vuln_count}\n")
                f.write(f"Overall Risk Level: {risk}\n")
                if vuln_count > 0:
                    f.write("Vulnerability Details:\n")
                    for vuln in result['vulnerabilities']:
                        f.write(f"  - Type: {vuln['type']}\n")
                        f.write(f"    Risk: {vuln['risk_level']}\n")
                        f.write(f"    Recommendations: {vuln['recommendations']}\n")
                        f.write(f"    Confidence: {vuln['confidence']:.2f}\n")
                        f.write(f"    Pattern: {vuln['pattern']}\n")
            else:
                f.write(f"Vulnerability Suspected/Detected: NO (False Negative)\n")
                f.write(f"Recommendations: Vulnerabilities were missed. Review code manually.\n")
            
            f.write(f"Code:\n{code}\n")
            f.write("-" * 80 + "\n\n")
            sequence_id += 1
    
    print(f"💾 Fixed sequences saved to: {fixed_sequences_file}")    

    # Generate 100000 random sequences
    print()
    print("📊 ANALYZING 100000 RANDOM SEQUENCES")
    print("-" * 100)
    
    generator = RandomRISCVGenerator(seed=42)
    random_results = []
    
    # Create a file to save random sequences
    random_sequences_file = "RANDOM_SEQUENCES_REPORT.txt"
    with open(random_sequences_file, 'w') as f:
        f.write("=" * 100 + "\n")
        f.write("RANDOM RISC-V SEQUENCES REPORT\n")
        f.write("=" * 100 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Sequences: 100000\n")
        f.write("=" * 100 + "\n\n")
        
        for i in range(1, 100001):
            # Generate sequence length between 2 and 5
            seq_length = random.randint(2, 5)
            code = generator.generate_random_program(seq_length)
            result = detector.analyze(code)
            
            status = "VULNERABLE" if result['is_vulnerable'] else "BENIGN"
            vuln_count = result['statistics']['total_vulnerabilities']
            risk = result['overall_risk']
            
            # Save sequence information
            sequence_info = {
                'id': i,
                'status': status,
                'vuln_count': vuln_count,
                'risk': risk,
                'code': code,
                'sequence_length': seq_length
            }
            random_results.append(sequence_info)
            
            # Write to file
            f.write(f"SEQUENCE {i}:\n")
            f.write(f"Status: {status}\n")
            f.write(f"Sequence Length: {seq_length}\n")
            if result['is_vulnerable']:
                f.write(f"Vulnerability Suspected/Detected: YES\n")
                f.write(f"Number of Vulnerabilities: {vuln_count}\n")
                f.write(f"Overall Risk Level: {risk}\n")
                if vuln_count > 0:
                    f.write("Vulnerability Details:\n")
                    for vuln in result['vulnerabilities']:
                        f.write(f"  - Type: {vuln['type']}\n")
                        f.write(f"    Risk: {vuln['risk_level']}\n")
                        f.write(f"    Recommendations: {vuln['recommendations']}\n")
                        f.write(f"    Confidence: {vuln['confidence']:.2f}\n")
                        f.write(f"    Pattern: {vuln['pattern']}\n")
            else:
                f.write(f"Vulnerability Suspected/Detected: NO\n")
            f.write(f"Code:\n{code}\n")
            f.write("-" * 80 + "\n\n")
            
            # Print first 10 sequences to console as sample
            if i <= 10:
                print(f"  RANDOM_{i:04d}: {status:<12} vulns={vuln_count:<3} risk={risk:<10} length={seq_length}")
            elif i == 100000:
                print(f"  RANDOM_100000: {status:<12} vulns={vuln_count:<3} risk={risk:<10} length={seq_length}")
    
    print(f"  ... (sequences 11-9999 saved to file)")
    
    # Generate comprehensive report
    print()
    print("=" * 100)
    print("📈 FINAL RESULTS")
    print("=" * 100)
    
    benign_accuracy = (results['benign']['correct'] / results['benign']['total']) * 100
    vuln_accuracy = (results['vulnerable']['correct'] / results['vulnerable']['total']) * 100
    overall_accuracy = ((results['benign']['correct'] + results['vulnerable']['correct']) / 
                       (results['benign']['total'] + results['vulnerable']['total'])) * 100
    
    vuln_random = sum(1 for r in random_results if r['status'] == 'VULNERABLE')
    avg_seq_length = sum(r['sequence_length'] for r in random_results) / len(random_results)
    
    print(f"\n🎯 BENIGN SEQUENCES:")
    print(f"   Total:            {results['benign']['total']}")
    print(f"   Correctly ID'd:   {results['benign']['correct']}")
    print(f"   False Positives:  {len(results['benign']['false_positives'])}")
    print(f"   Accuracy:         {benign_accuracy:.1f}%")
    
    print(f"\n🎯 VULNERABLE SEQUENCES:")
    print(f"   Total:            {results['vulnerable']['total']}")
    print(f"   Correctly ID'd:   {results['vulnerable']['correct']}")
    print(f"   False Negatives:  {len(results['vulnerable']['false_negatives'])}")
    print(f"   Accuracy:         {vuln_accuracy:.1f}%")
    
    print(f"\n🎯 OVERALL:")
    print(f"   Total Tested:     {results['benign']['total'] + results['vulnerable']['total']}")
    print(f"   Correct:          {results['benign']['correct'] + results['vulnerable']['correct']}")
    print(f"   Overall Accuracy: {overall_accuracy:.1f}%")
    
    print(f"\n🎯 RANDOM SEQUENCES:")
    print(f"   Total Generated:  100000")
    print(f"   Vulnerable:       {vuln_random}")
    print(f"   Benign:           {100000 - vuln_random}")
    print(f"   Average Length:   {avg_seq_length:.1f} instructions")
    print(f"   Vulnerability Rate: {(vuln_random/100000)*100:.1f}%")
    
    # Save detailed report
    report = []
    report.append("=" * 100)
    report.append("RISC-V VULNERABILITY ANALYZER - COMPREHENSIVE TEST REPORT")
    report.append("=" * 100)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    report.append(f"Benign Accuracy:      {benign_accuracy:.1f}%")
    report.append(f"Vulnerable Accuracy:  {vuln_accuracy:.1f}%")
    report.append(f"Overall Accuracy:     {overall_accuracy:.1f}%")
    report.append("")
    
    if results['benign']['false_positives']:
        report.append("FALSE POSITIVES (Benign marked as Vulnerable):")
        for name in results['benign']['false_positives']:
            report.append(f"  - {name}")
        report.append("")
    
    if results['vulnerable']['false_negatives']:
        report.append("FALSE NEGATIVES (Vulnerable marked as Benign):")
        for name in results['vulnerable']['false_negatives']:
            report.append(f"  - {name}")
        report.append("")
    
    report.append("=" * 100)
    report.append("RANDOM SEQUENCE SUMMARY")
    report.append("=" * 100)
    report.append(f"Total Random Sequences: 100000")
    report.append(f"Vulnerable Sequences:   {vuln_random}")
    report.append(f"Benign Sequences:       {100000 - vuln_random}")
    report.append(f"Vulnerability Rate:     {(vuln_random/100000)*100:.1f}%")
    report.append(f"Average Sequence Length: {avg_seq_length:.1f}")
    report.append("")
    report.append("Random sequences saved to: RANDOM_SEQUENCES_REPORT.txt")
    
    report_text = "\n".join(report)
    save_report_to_file(report_text, "FINAL_VERIFICATION_REPORT.txt")
    
    print(f"\n💾 Random sequences saved to: {random_sequences_file}")
    print(f"💾 Report saved to: FINAL_VERIFICATION_REPORT.txt")
    print("=" * 100)


def main():
    """Main entry point with interactive mode selection"""
    print("=" * 100)
    print("🔐 RISC-V SIDE-CHANNEL VULNERABILITY STATIC ANALYZER")
    print("=" * 100)
    print()
    
    # Display mode selection
    print("SELECT ANALYSIS MODE:")
    print("1. 🧪 Test Mode - Run comprehensive tests (100 benign + 100 vulnerable + 100000 random sequences)")
    print("2. 📝 Custom Code Mode - Analyze your own RISC-V assembly code")
    print("3. ❌ Exit")
    print()
    
    while True:
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == '1':
            test_mode()
            break
        elif choice == '2':
            analyze_custom_code()
            break
        elif choice == '3':
            print("\nExiting program. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
    
    # Ask if user wants to return to main menu
    if choice != '3':
        while True:
            again = input("\nReturn to main menu? (y/n): ").strip().lower()
            if again == 'y':
                print("\n" + "=" * 100 + "\n")
                main()
                break
            elif again == 'n':
                print("\nExiting program. Goodbye!")
                break
            else:
                print("Please enter 'y' or 'n'.")


if __name__ == "__main__":
    main()