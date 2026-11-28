/*
 * enrich_tiles.c — Enrich MapViet tiles.bin speed limits & missing street names from decoded roadsen TSV.
 * Updates tiles.bin, names.bin, and seg_names.bin in dst_dir while preserving segId & geometry/index.
 *
 * Build: cc -O3 -Wall -Wextra -o enrich_tiles enrich_tiles.c -lm
 * Usage: enrich_tiles <src_dir> <roadsen_decoded.tsv> <dst_dir>
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#define PI 3.14159265358979323846
#define M_PER_LAT 111320.0
#define GLAT 3200
#define GLON 1600
#define GSTEP 0.005

static inline double deg2rad(double d) { return d * PI / 180.0; }

static double pt_seg_dist_and_hd(double pla, double plo, double la1, double lo1, double la2, double lo2, double *out_hd) {
    double c = cos(deg2rad(pla));
    double ax = (lo1 - plo) * M_PER_LAT * c, ay = (la1 - pla) * M_PER_LAT;
    double bx = (lo2 - plo) * M_PER_LAT * c, by = (la2 - pla) * M_PER_LAT;
    double dx = bx - ax, dy = by - ay;
    double l2 = dx * dx + dy * dy;
    double u = (l2 == 0.0) ? 0.0 : -(ax * dx + ay * dy) / l2;
    if (u < 0.0) u = 0.0; else if (u > 1.0) u = 1.0;
    double px = ax + u * dx, py = ay + u * dy;
    if (out_hd) {
        double a = atan2(dx, dy) * 180.0 / PI;
        if (a < 0.0) a += 360.0;
        *out_hd = a;
    }
    return sqrt(px * px + py * py);
}

static double angle_diff(double a, double b) {
    double d = fabs(a - b);
    while (d >= 360.0) d -= 360.0;
    return d > 180.0 ? 360.0 - d : d;
}

static inline int gcell(double la, double lo) {
    int r = (int)((la - 8.0) / GSTEP), c = (int)((lo - 102.0) / GSTEP);
    if (r < 0 || r >= GLAT || c < 0 || c >= GLON) return -1;
    return r * GLON + c;
}

#pragma pack(push, 1)
typedef struct {
    uint32_t segId;
    int32_t sLatE7, sLonE7, eLatE7, eLonE7;
    uint16_t headingDeg;
    uint8_t roadClass, direction;
    int16_t speedLimit;
    uint8_t speedSrc, flags;
} TileSeg;

typedef struct {
    char magic[4];
    uint16_t version;
    uint32_t count;
    uint32_t poolBytes;
    uint16_t reserved;
} NameHdr;
#pragma pack(pop)

typedef struct {
    double la1, lo1, la2, lo2;
    uint8_t spda, spdb;
    uint32_t name_off;
} RSeg;

static RSeg *rsegs;
static uint32_t n_rsegs = 0;
static uint32_t rcap = 8000000;
static uint32_t *rcell_head;
static uint32_t *rseg_next;
static char *rname_pool;
static size_t rname_pool_len = 1;
static size_t rname_pool_cap = 32 * 1024 * 1024;

typedef struct NameEntry {
    char *s;
    uint32_t id;
    struct NameEntry *next;
} NameEntry;
#define NH_SIZE (1 << 18)
static NameEntry *nh[NH_SIZE];
static uint32_t next_name_id = 1;
static char **ordered_names;
static uint32_t ordered_cap = 131072;

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261U;
    while (*s) { h ^= (uint8_t)(*s++); h *= 16777619U; }
    return h;
}

static uint32_t intern_name(const char *s) {
    if (!s || !s[0]) return 0;
    uint32_t b = fnv1a(s) & (NH_SIZE - 1);
    for (NameEntry *e = nh[b]; e; e = e->next) {
        if (strcmp(e->s, s) == 0) return e->id;
    }
    NameEntry *ne = malloc(sizeof(NameEntry));
    ne->s = strdup(s);
    ne->id = next_name_id++;
    ne->next = nh[b];
    nh[b] = ne;
    if (ne->id >= ordered_cap) {
        ordered_cap *= 2;
        ordered_names = realloc(ordered_names, ordered_cap * sizeof(char *));
    }
    ordered_names[ne->id] = ne->s;
    return ne->id;
}

static void add_rseg(double la1, double lo1, double la2, double lo2, uint8_t spda, uint8_t spdb, uint32_t noff) {
    if (n_rsegs >= rcap) {
        rcap *= 2;
        rsegs = realloc(rsegs, (size_t)rcap * sizeof(RSeg));
        rseg_next = realloc(rseg_next, (size_t)rcap * sizeof(uint32_t));
    }
    RSeg rs = { la1, lo1, la2, lo2, spda, spdb, noff };
    rsegs[n_rsegs] = rs;
    int c = gcell((la1 + la2) * 0.5, (lo1 + lo2) * 0.5);
    if (c >= 0) {
        rseg_next[n_rsegs] = rcell_head[c];
        rcell_head[c] = n_rsegs;
    } else {
        rseg_next[n_rsegs] = 0xFFFFFFFFU;
    }
    n_rsegs++;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <src_speedmap_dir> <roadsen_decoded.tsv> <dst_dir>\n", argv[0]);
        return 1;
    }
    const char *src_dir = argv[1], *road_tsv = argv[2], *dst_dir = argv[3];
    char path[1024];

    ordered_names = calloc(ordered_cap, sizeof(char *));
    snprintf(path, sizeof(path), "%s/names.bin", src_dir);
    FILE *fn = fopen(path, "rb");
    if (!fn) { fprintf(stderr, "Cannot open %s\n", path); return 2; }
    NameHdr nhdr;
    if (fread(&nhdr, sizeof(NameHdr), 1, fn) != 1) return 2;
    uint32_t *old_offs = malloc((nhdr.count + 1) * sizeof(uint32_t));
    if (nhdr.count > 0 && fread(old_offs, sizeof(uint32_t), nhdr.count, fn) != nhdr.count) return 2;
    char *old_pool = malloc(nhdr.poolBytes + 1);
    if (nhdr.poolBytes > 0 && fread(old_pool, 1, nhdr.poolBytes, fn) != nhdr.poolBytes) return 2;
    fclose(fn);
    for (uint32_t i = 0; i < nhdr.count; i++) {
        intern_name(old_pool + old_offs[i]);
    }
    free(old_offs);
    free(old_pool);

    snprintf(path, sizeof(path), "%s/seg_names.bin", src_dir);
    FILE *fsn = fopen(path, "rb");
    if (!fsn) { fprintf(stderr, "Cannot open %s\n", path); return 2; }
    fseek(fsn, 0, SEEK_END); long snsz = ftell(fsn); fseek(fsn, 0, SEEK_SET);
    uint32_t n_seg_names = (uint32_t)(snsz / 4);
    uint32_t *seg_names = malloc(snsz > 0 ? snsz : 4);
    if (snsz > 0 && fread(seg_names, 4, n_seg_names, fsn) != n_seg_names) return 2;
    fclose(fsn);

    snprintf(path, sizeof(path), "%s/tiles.bin", src_dir);
    FILE *ft = fopen(path, "rb");
    if (!ft) { fprintf(stderr, "Cannot open %s\n", path); return 2; }
    fseek(ft, 0, SEEK_END); long tsz = ftell(ft); fseek(ft, 0, SEEK_SET);
    uint32_t n_segs = (uint32_t)(tsz / sizeof(TileSeg));
    TileSeg *segs = malloc(tsz > 0 ? tsz : 1);
    if (n_segs > 0 && fread(segs, sizeof(TileSeg), n_segs, ft) != n_segs) return 2;
    fclose(ft);

    FILE *fr = fopen(road_tsv, "r");
    if (!fr) { fprintf(stderr, "Cannot open %s\n", road_tsv); return 2; }
    rsegs = malloc((size_t)rcap * sizeof(RSeg));
    rcell_head = malloc((size_t)GLAT * GLON * sizeof(uint32_t));
    memset(rcell_head, 0xFF, (size_t)GLAT * GLON * sizeof(uint32_t));
    rseg_next = malloc((size_t)rcap * sizeof(uint32_t));
    rname_pool = malloc(rname_pool_cap);
    rname_pool[0] = 0;

    char *line = malloc(131072);
    double *lons = malloc(4096 * sizeof(double));
    double *lats = malloc(4096 * sizeof(double));
    long rlines = 0;
    while (fgets(line, 131072, fr)) {
        char *p = line, *f[9];
        int fi = 0;
        f[fi++] = p;
        while (*p && fi < 9) {
            if (*p == '\t') { *p = 0; f[fi++] = p + 1; }
            else if (*p == '\r' || *p == '\n') { *p = 0; break; }
            p++;
        }
        if (fi < 9) continue;
        rlines++;
        uint32_t noff = 0;
        if (f[2][0] != 0) {
            size_t nl = strlen(f[2]) + 1;
            if (rname_pool_len + nl > rname_pool_cap) {
                rname_pool_cap *= 2;
                rname_pool = realloc(rname_pool, rname_pool_cap);
            }
            noff = (uint32_t)rname_pool_len;
            memcpy(rname_pool + noff, f[2], nl);
            rname_pool_len += nl;
        }
        int spda = atoi(f[5]), spdb = atoi(f[6]);
        int nv = 0;
        lons[0] = atof(f[7]);
        char *cur = f[8];
        int is_lat = 1;
        while (*cur && nv < 4096) {
            char *next = cur;
            while (*next && *next != '\t' && *next != '\r' && *next != '\n') next++;
            char saved = *next;
            *next = 0;
            double v = atof(cur);
            if (is_lat) { lats[nv++] = v; is_lat = 0; }
            else { if (nv < 4096) lons[nv] = v; is_lat = 1; }
            if (saved == 0 || saved == '\r' || saved == '\n') break;
            cur = next + 1;
        }
        for (int k = 0; k < nv - 1; k++) {
            add_rseg(lats[k], lons[k], lats[k + 1], lons[k + 1], (uint8_t)spda, (uint8_t)spdb, noff);
        }
    }
    free(lons);
    free(lats);
    free(line);
    fclose(fr);

    long cnt_def_updated = 0, cnt_unk_filled = 0, cnt_osm_kept_low = 0, cnt_osm_updated = 0;
    long cnt_def_same = 0, cnt_name_added = 0, cnt_unmatched = 0;
    for (uint32_t i = 0; i < n_segs; i++) {
        TileSeg *ts = &segs[i];
        if (ts->roadClass > 3 || (ts->flags & 0x20)) continue;
        double midla = ((double)ts->sLatE7 + (double)ts->eLatE7) * 0.5e-7;
        double midlo = ((double)ts->sLonE7 + (double)ts->eLonE7) * 0.5e-7;
        int r0 = (int)((midla - 8.0) / GSTEP), c0 = (int)((midlo - 102.0) / GSTEP);

        double best_score = 1e9, best_d = 1e9, best_rhd = 0;
        RSeg best_rs = {0};
        for (int dr = -1; dr <= 1; dr++) {
            int r = r0 + dr; if (r < 0 || r >= GLAT) continue;
            for (int dc = -1; dc <= 1; dc++) {
                int c = c0 + dc; if (c < 0 || c >= GLON) continue;
                uint32_t idx = rcell_head[r * GLON + c];
                while (idx != 0xFFFFFFFFU) {
                    RSeg *rs = &rsegs[idx];
                    double rhd = 0;
                    double d = pt_seg_dist_and_hd(midla, midlo, rs->la1, rs->lo1, rs->la2, rs->lo2, &rhd);
                    if (d <= 15.0) {
                        double df = angle_diff((double)ts->headingDeg, rhd);
                        double axis_df = (df <= 30.0) ? df : (df >= 150.0 ? 180.0 - df : 999.0);
                        if (axis_df <= 30.0) {
                            double score = d + axis_df * 0.3;
                            if (score < best_score) {
                                best_score = score; best_d = d; best_rs = *rs; best_rhd = rhd;
                            }
                        }
                    }
                    idx = rseg_next[idx];
                }
            }
        }
        if (best_score >= 1e8) { cnt_unmatched++; continue; }

        double df = angle_diff((double)ts->headingDeg, best_rhd);
        int is_fwd = (df <= 30.0);
        int vm_spd = 0;
        if (ts->direction == 1) {
            vm_spd = is_fwd ? best_rs.spda : best_rs.spdb;
            if (vm_spd == 0) vm_spd = best_rs.spda > 0 ? best_rs.spda : best_rs.spdb;
        } else if (ts->direction == 2) {
            vm_spd = is_fwd ? best_rs.spdb : best_rs.spda;
            if (vm_spd == 0) vm_spd = best_rs.spda > 0 ? best_rs.spda : best_rs.spdb;
        } else {
            int s_match = is_fwd ? best_rs.spda : best_rs.spdb;
            int s_opp   = is_fwd ? best_rs.spdb : best_rs.spda;
            if (s_match > 0 && s_opp > 0) vm_spd = (s_match < s_opp) ? s_match : s_opp;
            else vm_spd = s_match > 0 ? s_match : s_opp;
        }

        if (vm_spd >= 20 && vm_spd <= 120) {
            if (ts->speedSrc == 0 || ts->speedLimit == -1) {
                ts->speedLimit = (int16_t)vm_spd;
                ts->speedSrc = 1;
                cnt_unk_filled++;
            } else if (ts->speedSrc == 4) {
                if (ts->speedLimit != vm_spd) cnt_def_updated++;
                else cnt_def_same++;
                ts->speedLimit = (int16_t)vm_spd;
                ts->speedSrc = 1;
            } else if (ts->speedSrc >= 1 && ts->speedSrc <= 3) {
                if (ts->speedLimit <= 40) {
                    cnt_osm_kept_low++;
                } else if (ts->speedLimit != vm_spd) {
                    ts->speedLimit = (int16_t)vm_spd;
                    cnt_osm_updated++;
                }
            }
        }

        if (best_rs.name_off > 0 && best_d <= 12.0 && ts->segId < n_seg_names && seg_names[ts->segId] == 0) {
            uint32_t nid = intern_name(rname_pool + best_rs.name_off);
            if (nid > 0) {
                seg_names[ts->segId] = nid;
                cnt_name_added++;
            }
        }
    }

    printf("{\"polylines\": %ld, \"subsegments\": %u, \"total_segs\": %u, \"unmatched\": %ld, "
           "\"unknown_filled\": %ld, \"default_changed\": %ld, \"default_confirmed\": %ld, "
           "\"osm_kept_low\": %ld, \"osm_updated\": %ld, \"names_added\": %ld, "
           "\"unique_names_before\": %u, \"unique_names_after\": %u}\n",
           rlines, n_rsegs, n_segs, cnt_unmatched,
           cnt_unk_filled, cnt_def_updated, cnt_def_same,
           cnt_osm_kept_low, cnt_osm_updated, cnt_name_added,
           nhdr.count, next_name_id - 1);

    snprintf(path, sizeof(path), "%s/tiles.bin", dst_dir);
    FILE *fo = fopen(path, "wb"); fwrite(segs, sizeof(TileSeg), n_segs, fo); fclose(fo);

    uint32_t new_cnt = next_name_id - 1;
    uint32_t *new_offs = malloc((new_cnt + 1) * sizeof(uint32_t));
    size_t new_pool_cap = nhdr.poolBytes + 8 * 1024 * 1024 + 4096;
    char *new_pool = malloc(new_pool_cap);
    size_t new_plen = 0;
    for (uint32_t k = 1; k <= new_cnt; k++) {
        size_t sl = strlen(ordered_names[k]) + 1;
        while (new_plen + sl > new_pool_cap) {
            new_pool_cap *= 2;
            new_pool = realloc(new_pool, new_pool_cap);
        }
        new_offs[k - 1] = (uint32_t)new_plen;
        memcpy(new_pool + new_plen, ordered_names[k], sl);
        new_plen += sl;
    }
    NameHdr out_nh = { {'V','N','N','M'}, 2, new_cnt, (uint32_t)new_plen, 0 };
    snprintf(path, sizeof(path), "%s/names.bin", dst_dir);
    FILE *fno = fopen(path, "wb");
    fwrite(&out_nh, sizeof(NameHdr), 1, fno);
    if (new_cnt > 0) fwrite(new_offs, sizeof(uint32_t), new_cnt, fno);
    if (new_plen > 0) fwrite(new_pool, 1, new_plen, fno);
    fclose(fno);

    snprintf(path, sizeof(path), "%s/seg_names.bin", dst_dir);
    FILE *fsno = fopen(path, "wb");
    if (n_seg_names > 0) fwrite(seg_names, 4, n_seg_names, fsno);
    fclose(fsno);

    return 0;
}
