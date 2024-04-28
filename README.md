# Binary Analysis Project

## How to run
 - From within `MyPinTool` run `make` to compile the PinTool.
 - Run the desired ELF with pin and the PinTool to generate a trace: `pin -t MyPinTool.so -- <ELF>`
 - From within `vecspot` run `cargo r -- ../MyPinTool/mem.out` to generate the dataflow graph
