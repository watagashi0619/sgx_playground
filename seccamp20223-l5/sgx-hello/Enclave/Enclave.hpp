typedef struct
{
    uint64_t a; // 8 bytes
    uint8_t b; // 1 byte
    /* 7 bytes are padded here by compiler */
    uint64_t c; // 8 bytes
} test_struct_t;