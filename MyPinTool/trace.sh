set -e

make PIN_ROOT="../pin" obj-intel64/MyPinTool.so -j 8
../pin/pin -t obj-intel64/MyPinTool.so -- "$@"