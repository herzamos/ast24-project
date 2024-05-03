/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 memAccesses = 0;
BOOL countAccess = true;
uintptr_t upper = 0x401198;
uintptr_t lower = 0x401126;
FILE *trace;

VOID RecordMemRead(VOID *ip, VOID *addr, REG reg) { 
    if (countAccess) { 
        fprintf(trace, "%p: READ %p %s\n", ip, addr, REG_StringShort(reg).c_str());
    }
}

VOID RecordMemWrite (VOID *ip, VOID *addr, REG reg) { 
    if (countAccess) {
        fprintf(trace, "%p: WRITE %s %p\n", ip, REG_StringShort(reg).c_str(), addr);
    }
}

VOID RecordBinOp(VOID *ip, OPCODE op, REG reg1, REG reg2) {
    std::string reg1s = REG_StringShort(reg1);
    std::string reg2s = REG_StringShort(reg2);
    std::string ops;
    if (op == XED_ICLASS_ADD) {
        ops = "+";
    } else if (op == XED_ICLASS_SUB) {
        ops = "-";
    } else if (op == XED_ICLASS_MUL) {
        ops = "*";
    } else if (op == XED_ICLASS_DIV) {
        ops = "/";
    }
    fprintf(trace, "%p: BinOp %s %s %s\n", ip, ops.c_str(), reg2s.c_str(), reg1s.c_str());
}


VOID Instruction(INS ins, VOID *v) {

    if (!(lower <= INS_Address(ins) && INS_Address(ins) <= upper)) return;

    if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {

        UINT32 mem_operands = INS_MemoryOperandCount(ins);
        /* skip reads and writes to the stack */
        if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) return;

        for (UINT32 memop = 0; memop < mem_operands; ++memop) {

            if (INS_MemoryOperandIsRead(ins, memop)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memop, IARG_UINT32, INS_RegW(ins, 0), IARG_END);

            }

            if (INS_MemoryOperandIsWritten(ins, memop)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, memop, IARG_UINT32, INS_RegR(ins, 1), IARG_END);
            }
        }
    }
    UINT32 op = INS_Opcode(ins);
    if (op == XED_ICLASS_ADD || op == XED_ICLASS_SUB || op == XED_ICLASS_MUL || op == XED_ICLASS_DIV) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordBinOp, 
            IARG_INST_PTR, 
            IARG_UINT32, op, 
            IARG_UINT32, INS_OperandReg(ins, 0), 
            IARG_UINT32, INS_OperandReg(ins, 1), 
            IARG_END
        );
    }

}


/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID* v)
{
    cerr << "===============================================" << endl;
    cerr << "MyPinTool analysis results: " << endl;
    cerr << "===============================================" << endl;

    cerr << "Memory accesses in main: " << memAccesses << std::endl;
    fclose(trace);
}

INT32 Usage() {
    cerr << "Wrong arguments\n" << endl;
    return -1;
}

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    /* Create trace file */
    trace = fopen("out.trace", "w");


    /* Add instrumentation */
    INS_AddInstrumentFunction(Instruction, NULL);
    PIN_AddFiniFunction(Fini, NULL);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
