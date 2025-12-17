## Key Features Added:

### 1. Interactive Mode Selection
- When you run the program, it now asks you to choose between:
  - Test Mode (runs the comprehensive test suite)
  - Custom Code Mode (analyzes your own RISC-V code)
  - Exit

### 2. Custom Code Analysis Mode
- User can input their own RISC-V assembly code line by line
- Shows examples of proper instruction formats
- Provides detailed analysis results with:
  - Overall risk assessment
  - Specific vulnerabilities found
  - Recommendations for fixes
  - Option to save results to a file

### 3. Instruction Format Examples
The program shows examples of how to write RISC-V instructions:

```
📋 INSTRUCTION FORMAT EXAMPLES:
1. Arithmetic:    add t0, t1, t2
2. Load:          lw t0, 0(sp)
3. Store:         sw t0, 4(sp)
4. Load with offset: lw t0, 8(t1)
5. Branch:        beq t0, t1, label_name
6. Jump:          jal ra, function_name
7. Immediate:     addi t0, t1, 10
8. Compare:       slt t0, t1, t2
9. Memory access: lb t0, 0(a0)
10. Unconditional: j loop_start
```

### 4. How to Use:

Example 1: Test Mode
```
python riscv_analyzer.py
> Select mode: 1
```
This runs the comprehensive test suite with all 200+ test cases.

Example 2: Custom Code Mode
```
python riscv_analyzer.py
> Select mode: 2
> Enter your code line by line:
> Line 1: sltu t0, a1, a2
> Line 2: beqz t0, safe
> Line 3: lw t2, 0(a0)
> Line 4: safe:
> Line 5: END
```

### 5. Sample Vulnerable Code to Test:
Try these examples in custom mode:

Spectre V1 Pattern:
```
sltu t0, a1, a2
beqz t0, safe
lw t2, 0(a0)
safe:
```

Prime+Probe Pattern:
```
loop:
lw t0, 0(a0)
addi a0, a0, 64
bne a0, a1, loop
```

Password Timing Attack:
```
lbu t1, 0(a0)
lbu t2, 0(a1)
bne t1, t2, fail
```
