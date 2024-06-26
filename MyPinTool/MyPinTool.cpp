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

BOOL should_trace = false;
FILE *trace;

VOID RecordMemRead(VOID *ip, VOID *addr, REG reg) { 
    if (!should_trace) return;

    fprintf(trace, "%p: READ %p %s\n", ip, addr, REG_StringShort(reg).c_str());
}

VOID RecordMemWrite (VOID *ip, VOID *addr, REG reg) { 
    if (!should_trace) return;

    fprintf(trace, "%p: WRITE %s %p\n", ip, REG_StringShort(reg).c_str(), addr);
}

VOID RecordBinOp(VOID *ip, VOID *op, REG reg1, REG reg2, UINT64 imm, BOOL is_imm) {
    if (!should_trace) return;

    std::string reg1s = REG_StringShort(reg1);
    std::string reg2s = REG_StringShort(reg2);
    if (is_imm) {
        fprintf(trace, "%p: BinOp %s #%ld %s %s\n", ip, (char *)op, imm, reg1s.c_str(), reg1s.c_str());
    } else {
        fprintf(trace, "%p: BinOp %s %s %s %s\n", ip, (char *)op, reg2s.c_str(), reg1s.c_str(), reg1s.c_str());
    }
}
VOID RecordAVXBinOp(VOID *ip, VOID *op, REG reg1, REG reg2, REG reg3) {
    if (!should_trace) return;

    std::string reg1s = REG_StringShort(reg1);
    std::string reg2s = REG_StringShort(reg2);
    std::string reg3s = REG_StringShort(reg3);
    fprintf(trace, "%p: BinOp %s %s %s %s\n", ip, (char *)op, reg3s.c_str(), reg2s.c_str(), reg1s.c_str());
}

VOID marker() {
    should_trace = !should_trace;
}


VOID Instruction(INS ins, VOID *v) {
    if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {

        UINT32 mem_operands = INS_MemoryOperandCount(ins);
        /* skip reads and writes to the stack */
        if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) return;
        for (UINT32 memop = 0; memop < mem_operands; ++memop) {

            if (INS_MemoryOperandIsRead(ins, memop)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memop, IARG_UINT32, INS_OperandReg(ins, memop), IARG_END);
                // cerr << "READ regs:" << endl;
                // for (UINT32 i = 0; i < mem_operands; ++i) {
                //     cerr << "\t" << i << "\t" << REG_StringShort(INS_RegW(ins, i)) << endl;
                // }
            }

            if (INS_MemoryOperandIsWritten(ins, memop)) {
                // FIXME: This is hacky as fuck is there a better way to do it???
                int i = 0;
                while (INS_RegR(ins, i) != REG_INVALID()) {
                    if (should_trace) cerr << i << REG_StringShort(INS_RegR(ins, i)) << endl;
                    ++i;
                }
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, memop, IARG_UINT32, INS_RegR(ins, i-1), IARG_END);
                // cerr << "WRITE regs:" << endl;
                // for (UINT32 i = 0; i < 4; ++i) {
                //     cerr << "\t" << i << "\t" << REG_StringShort(INS_RegR(ins, i)) << endl;
                // }
            }
        }
    }
    // Trace binary operations
    if (INS_OperandCount(ins) < 2) return;
    UINT32 op = INS_Opcode(ins);

    // we leak le memory
    const char *mnemonic = INS_Mnemonic(ins).c_str();
    void *ptr = calloc(strlen(mnemonic) + 1, 1);
    strcpy((char *)ptr, mnemonic);

    // Check if AVX
    if (should_trace) cerr << "IP: " << std::hex << INS_Address(ins) << endl;
    xed_extension_enum_t ext = xed_inst_extension(xed_decoded_inst_inst(INS_XedDec(ins)));
    if (ext == XED_EXTENSION_AVX || ext == XED_EXTENSION_AVX2 || ext == XED_EXTENSION_AVX2GATHER) {
        cerr << "AVX instruction" << endl;
        // If we have less than 3 operands it's a memory operation
        if (INS_OperandCount(ins) < 3) return;

        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordAVXBinOp,
        IARG_INST_PTR,
            IARG_PTR, ptr, 
            IARG_UINT32, INS_OperandReg(ins, 0), 
            IARG_UINT32, INS_OperandReg(ins, 1), 
            IARG_UINT32, INS_OperandReg(ins, 2), 
            IARG_END
        );

    } else {
        if (op == XED_ICLASS_ADD || op == XED_ICLASS_SUB || op == XED_ICLASS_MUL || op == XED_ICLASS_IMUL || op == XED_ICLASS_DIV) {
            BOOL is_imm = INS_OperandIsImmediate(ins, 1);
            UINT64 imm = is_imm ? INS_OperandImmediate(ins, 1) : 0;

            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordBinOp, 
                IARG_INST_PTR,
                IARG_PTR, ptr, 
                IARG_UINT32, INS_OperandReg(ins, 0), 
                IARG_UINT32, INS_OperandReg(ins, 1), 
                IARG_UINT64, imm,
                IARG_BOOL, is_imm,
                IARG_END
            );

        } else {
            if (should_trace) cerr << "Mnemonic: " << INS_Mnemonic(ins) << endl;
        }
    }
}

VOID Function(RTN rtn, VOID *v) {
    RTN_Open(rtn);
    if (RTN_Name(rtn) == "markerf") {
        cerr << "found marker" << endl;
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)marker, IARG_END);
    }
    RTN_Close(rtn);
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

    PIN_InitSymbols();
    /* Add instrumentation */
    RTN_AddInstrumentFunction(Function, NULL);
    INS_AddInstrumentFunction(Instruction, NULL);
    PIN_AddFiniFunction(Fini, NULL);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
