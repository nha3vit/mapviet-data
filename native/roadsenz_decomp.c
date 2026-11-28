/*
 * roadsenz_decomp.c — Decompress roadsenz.bin partition from VietMap secrect.bin.
 * Supports optional --decode flag to apply verified 256-byte cipher -> plain UTF-8 TSV.
 * Build: cc -O3 -Wall -Wextra -o roadsenz_decomp roadsenz_decomp.c
 * Usage: roadsenz_decomp <secrect.bin> <offset> <size> <out_file> [--decode]
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static int obits_for(int p) {
    if (p == 0) return 0;
    if (p == 1) return 1;
    if (p == 2) return 2;
    int v = p - 1, b = 0;
    while (v > 0) { b++; v >>= 1; }
    return b;
}

static void init_cipher_lut(uint8_t lut[256]) {
    for (int i = 0; i < 256; i++) lut[i] = (uint8_t)i;
    static const struct { uint8_t k; uint8_t v; } entries[] = {
        {1, 69}, {2, 110}, {4, 102}, {5, 43}, {6, 161}, {7, 198}, {8, 108}, {9, 178},
        {11, 172}, {12, 195}, {14, 121}, {15, 181}, {17, 80}, {18, 101}, {22, 67},
        {23, 155}, {25, 225}, {26, 65}, {30, 152}, {31, 113}, {33, 75}, {34, 169},
        {36, 187}, {39, 97}, {40, 45}, {42, 118}, {48, 70}, {51, 90}, {52, 185},
        {57, 46}, {61, 168}, {63, 151}, {64, 173}, {65, 109}, {66, 146}, {67, 160},
        {68, 77}, {70, 239}, {73, 9}, {74, 182}, {77, 73}, {79, 83}, {82, 66},
        {84, 107}, {85, 135}, {87, 86}, {88, 143}, {90, 32}, {92, 172}, {93, 131},
        {95, 99}, {96, 137}, {99, 168}, {100, 50}, {102, 189}, {103, 164}, {107, 117},
        {108, 176}, {109, 186}, {111, 170}, {113, 10}, {115, 85}, {119, 87}, {121, 139},
        {123, 148}, {126, 129}, {128, 191}, {130, 49}, {131, 13}, {132, 39}, {136, 84},
        {137, 138}, {139, 54}, {140, 79}, {141, 145}, {144, 197}, {145, 57}, {146, 106},
        {148, 72}, {150, 95}, {151, 162}, {153, 147}, {157, 182}, {159, 158}, {160, 163},
        {161, 88}, {162, 183}, {163, 44}, {164, 130}, {168, 56}, {169, 196}, {171, 167},
        {175, 55}, {176, 105}, {177, 76}, {178, 68}, {180, 53}, {181, 175}, {182, 116},
        {183, 52}, {184, 170}, {188, 112}, {189, 104}, {190, 175}, {195, 81}, {198, 89},
        {200, 103}, {202, 100}, {205, 98}, {207, 48}, {210, 74}, {212, 133}, {214, 179},
        {215, 177}, {217, 51}, {218, 144}, {219, 111}, {220, 141}, {221, 115}, {223, 71},
        {227, 119}, {228, 47}, {231, 180}, {232, 153}, {233, 165}, {234, 173}, {235, 157},
        {237, 78}, {239, 114}, {244, 82}, {248, 121}, {250, 122}, {251, 141}, {255, 154}
    };
    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        lut[entries[i].k] = entries[i].v;
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <secrect.bin> <part_offset> <part_size> <out_file> [--decode]\n", argv[0]);
        return 1;
    }
    const char *in_path = argv[1];
    long part_off = atol(argv[2]);
    long part_size = atol(argv[3]);
    const char *out_path = argv[4];
    int do_decode = (argc >= 6 && strcmp(argv[5], "--decode") == 0);

    FILE *fin = fopen(in_path, "rb");
    FILE *fout = fopen(out_path, "wb");
    if (!fin || !fout) {
        fprintf(stderr, "Failed to open input/output files\n");
        return 2;
    }

    // roadsenz.bin starts with 32-byte sub-header ("roadsen.bin\0..." + unpacked size)
    long cur_off = part_off + 32L;
    long end_off = part_off + part_size;
    if (fseek(fin, cur_off, SEEK_SET) != 0) {
        fprintf(stderr, "Seek failed at %ld\n", cur_off);
        return 2;
    }

    uint8_t lut[256];
    init_cipher_lut(lut);

    uint8_t *inbuf = malloc(262144);
    uint8_t *outbuf = malloc(65540);
    if (!inbuf || !outbuf) return 4;
    int blocks = 0;

    while (ftell(fin) + 12 <= end_off) {
        uint32_t hdr[3];
        if (fread(hdr, 4, 3, fin) != 3) break;
        uint32_t u_sz = hdr[0], c_sz = hdr[1], chk = hdr[2];
        if (c_sz == 0 || c_sz > 262144 || u_sz > 65540) {
            fprintf(stderr, "Invalid block %d sizes: u=%u c=%u\n", blocks, u_sz, c_sz);
            return 3;
        }
        if (fread(inbuf, 1, c_sz, fin) != c_sz) break;
        if (u_sz == c_sz) {
            memcpy(outbuf, inbuf, u_sz);
        } else {
            uint64_t bit_buf = 0;
            int bit_cnt = 0;
            uint32_t idx = 0, p = 0;
            while (p < u_sz) {
                int ob = obits_for((int)p);
                int lb = (p == 0) ? 4 : 5;
                int k1 = ob + lb;
                while (bit_cnt < k1) {
                    bit_buf = (bit_buf << 8) | (idx < c_sz ? inbuf[idx++] : 0);
                    bit_cnt += 8;
                }
                bit_cnt -= k1;
                uint32_t bv = (uint32_t)((bit_buf >> bit_cnt) & ((1ULL << k1) - 1));
                uint32_t off = bv >> lb;
                uint32_t ln = bv & ((1U << lb) - 1);
                if (off > 0 && off <= p) {
                    uint32_t start = p - off;
                    for (uint32_t i = 0; i < ln && p < u_sz; i++) {
                        outbuf[p++] = outbuf[start + i];
                    }
                }
                if (p < u_sz) {
                    while (bit_cnt < 8) {
                        bit_buf = (bit_buf << 8) | (idx < c_sz ? inbuf[idx++] : 0);
                        bit_cnt += 8;
                    }
                    bit_cnt -= 8;
                    outbuf[p++] = (uint8_t)((bit_buf >> bit_cnt) & 0xFF);
                }
            }
            uint32_t s = 0;
            for (uint32_t i = 0; i < u_sz; i++) s += outbuf[i];
            if (s != chk) {
                fprintf(stderr, "Checksum mismatch block %d: %u != %u\n", blocks, s, chk);
                return 3;
            }
        }
        if (do_decode) {
            for (uint32_t i = 0; i < u_sz; i++) outbuf[i] = lut[outbuf[i]];
        }
        fwrite(outbuf, 1, u_sz, fout);
        blocks++;
    }
    fprintf(stderr, "OK: %d blocks decompressed\n", blocks);
    free(inbuf);
    free(outbuf);
    fclose(fin);
    fclose(fout);
    return 0;
}
