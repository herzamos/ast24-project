void cvt_8_32(uint32_t* op, uint8_t const* ints)
{
    // When this is outlined it generates correct code
    uint32_t out[16];
    uint8_t in[16];
    memcpy(in, ints, sizeof(in));
    for (int i = 0; i < 16; ++i) {
        out[i] = in[i];
    }
    memcpy(op, out, sizeof(out));
}