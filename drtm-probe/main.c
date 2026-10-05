/*
 * NOVA root PD: DRTM attestation probe
 *
 * Runs as the root protection domain on top of the NOVA microhypervisor
 * (upstream udosteinberg/NOVA, x86_64) after an Intel TXT measured launch and:
 *
 *   1. takes the NOVA Host/PIO space capabilities into its own object space
 *   2. maps a legacy 16550 UART (I/O ports) for output
 *   3. maps TPM locality 0 (0xfed40000) and reads PCR 17/18/19 (SHA-256 bank)
 *   4. maps the DRTM TCG event log (location conveyed via the HIP), prints it
 *      and replays the SHA-256 digests to recompute PCR 17/18/19
 *   5. prints a verdict and blocks forever
 *
 * Output lines are prefixed with "ROOT-PD:".
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------ */
/* libc bits the compiler may emit calls to                                 */
/* ------------------------------------------------------------------------ */

void *memcpy (void *d, void const *s, size_t n)
{
    uint8_t *dp = d; uint8_t const *sp = s;
    while (n--) *dp++ = *sp++;
    return d;
}

void *memset (void *d, int c, size_t n)
{
    uint8_t *dp = d;
    while (n--) *dp++ = (uint8_t) c;
    return d;
}

static int memeq (void const *a, void const *b, size_t n)
{
    uint8_t const *x = a, *y = b;
    while (n--) if (*x++ != *y++) return 0;
    return 1;
}

/* ------------------------------------------------------------------------ */
/* NOVA ABI (x86_64)                                                        */
/* ------------------------------------------------------------------------ */

enum { HC_CREATE_SM = 0x6, HC_CTRL_PD = 0x8, HC_CTRL_SM = 0xc };

enum { SUCCESS = 0 };

static char const *const status_str[] =
{
    "SUCCESS", "TIMEOUT", "ABORTED", "OVRFLOW", "BAD_HYP", "BAD_CAP",
    "BAD_PAR", "BAD_FTR", "BAD_CPU", "BAD_DEV", "MEM_OBJ", "MEM_CAP",
};

/*
 * p0 = RDI: [3:0] hypercall number, [7:4] flags, [63:8] selector
 * p1 = RSI, p2 = RDX, p3 = RAX, p4 = R8. Status returns in RDI.
 * SYSCALL clobbers RCX/R11; NOVA restores all other GPRs.
 */
static unsigned long hypercall (unsigned long p0, unsigned long p1, unsigned long p2, unsigned long p3, unsigned long p4)
{
    register unsigned long r8 asm ("r8") = p4;
    asm volatile ("syscall" : "+D" (p0), "+S" (p1), "+d" (p2), "+a" (p3), "+r" (r8) : : "rcx", "r11", "memory");
    return p0;
}

/* ctrl_pd: delegate [ssb, ssb + 2^ord) from space src to [dsb, ...) in space dst */
static unsigned long ctrl_pd (unsigned long src, unsigned long dst, unsigned long ssb, unsigned long dsb, unsigned ord, unsigned pmm, unsigned ma)
{
    return hypercall (src << 8 | HC_CTRL_PD, dst, ssb << 12 | ord, dsb << 12 | pmm, ma);
}

/* Memory capability permissions / memory attributes (x86 MAD cache field) */
enum { PERM_R = 1, PERM_W = 2 };
enum { MA_WB = 0, MA_UC = 3 };

/* Hypervisor Information Page (inc/hip.hpp, inc/x86_64/hip_arch.hpp) */
struct hip
{
    uint32_t signature;
    uint16_t checksum, length;
    uint64_t nova_p_addr, nova_e_addr;
    uint64_t mbuf_p_addr, mbuf_e_addr;
    uint64_t root_p_addr, root_e_addr;
    uint64_t acpi_rsdp_addr;
    uint64_t fbuf_addr, fbuf_size;
    uint32_t fbuf_pixel, fbuf_pitch, fbuf_res_x, fbuf_res_y;
    uint64_t uefi_mmap_addr;
    uint32_t uefi_mmap_size;
    uint16_t uefi_desc_size, uefi_desc_vers;
    uint64_t tmr_frq;
    uint8_t  sbw_obj, sbw_hst, sbw_gst, sbw_dma, sbw_pio, sbw_msr, sbw_r[2];
    uint8_t  mco_obj, mco_hst, mco_gst, mco_dma, mco_pio, mco_msr, mco_r[2];
    uint16_t cpu_bsp, cpu_max, kid_max, reserved;
    uint16_t sel_hst_arch, sel_hst_nova, sel_gst_arch, sel_gst_nova;
    uint64_t features;
    /* arch (x86_64) */
    uint8_t  num_vec;
    uint16_t num_pin;
    uint32_t num_gsi;
    uint64_t elog_phys;
    uint32_t elog_size;
    uint32_t elog_offs;
};

_Static_assert (sizeof (struct hip) == 0xa0 + 24, "HIP layout");
_Static_assert (offsetof (struct hip, elog_phys) == 0xa8, "HIP layout");

/*
 * Object selectors. Root object space (spec 6.2.3.1): top 5 slots are
 * preinstalled. NOVA object space (inc/space_obj.hpp): top 9 slots.
 */
static unsigned long SEL_MAX;               /* 2^SBW_OBJ */
#define ROOT_SEL_NOVA_OBJ   (SEL_MAX - 1)
#define ROOT_SEL_ROOT_OBJ   (SEL_MAX - 2)
#define ROOT_SEL_ROOT_PD    (SEL_MAX - 3)
#define NOVA_SEL_NOVA_HST   (SEL_MAX - 3)
#define NOVA_SEL_NOVA_PIO   (SEL_MAX - 5)
#define NOVA_SEL_ROOT_HST   (SEL_MAX - 8)
#define NOVA_SEL_ROOT_PIO   (SEL_MAX - 9)

/* Where we put things in our own object space / address space */
enum { SEL_NOVA_HST = 16, SEL_ROOT_HST, SEL_NOVA_PIO, SEL_ROOT_PIO, SEL_SM };

#define VA_TPM  0x20000000UL                /* 2 pages: localities 0 and 1 */
#define VA_ELOG 0x20100000UL                /* event log */

/* ------------------------------------------------------------------------ */
/* UART (legacy 16550 via I/O ports)                                        */
/* ------------------------------------------------------------------------ */

#ifndef UART_PIO
#define UART_PIO 0x3f8
#endif

static int uart_ok;

static inline uint8_t inb (uint16_t p) { uint8_t v; asm volatile ("inb %1, %0" : "=a" (v) : "Nd" (p)); return v; }
static inline void outb (uint16_t p, uint8_t v) { asm volatile ("outb %0, %1" : : "a" (v), "Nd" (p)); }

static void putc_ (char c)
{
    if (!uart_ok)
        return;
    if (c == '\n')
        putc_ ('\r');
    for (unsigned i = 0; i < 1000000 && !(inb (UART_PIO + 5) & 0x20); i++)
        asm volatile ("pause");
    outb (UART_PIO, (uint8_t) c);
}

static void puts_ (char const *s) { while (*s) putc_ (*s++); }

static void puthex (uint64_t v, int digits)
{
    for (int i = digits - 1; i >= 0; i--)
        putc_ ("0123456789abcdef"[v >> (4 * i) & 0xf]);
}

static void putdec (uint64_t v)
{
    char b[21]; int i = 0;
    do b[i++] = (char) ('0' + v % 10); while (v /= 10);
    while (i--) putc_ (b[i]);
}

static void putbytes (uint8_t const *p, size_t n) { while (n--) puthex (*p++, 2); }

static void pfx (void) { puts_ ("ROOT-PD: "); }

static void putstatus (unsigned long s)
{
    puts_ (s < sizeof status_str / sizeof *status_str ? status_str[s] : "?");
}

/* ------------------------------------------------------------------------ */
/* SHA-256                                                                  */
/* ------------------------------------------------------------------------ */

struct sha256 { uint32_t h[8]; uint8_t buf[64]; uint64_t len; unsigned fill; };

static uint32_t const K256[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t ror (uint32_t x, unsigned n) { return x >> n | x << (32 - n); }

static void sha256_block (struct sha256 *s, uint8_t const *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t) p[4 * i] << 24 | (uint32_t) p[4 * i + 1] << 16 | (uint32_t) p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++)
        w[i] = w[i - 16] + (ror (w[i - 15], 7) ^ ror (w[i - 15], 18) ^ (w[i - 15] >> 3)) +
               w[i - 7]  + (ror (w[i - 2], 17) ^ ror (w[i - 2], 19)  ^ (w[i - 2] >> 10));

    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ror (e, 6) ^ ror (e, 11) ^ ror (e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ror (a, 2) ^ ror (a, 13) ^ ror (a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256_init (struct sha256 *s)
{
    static uint32_t const iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy (s->h, iv, sizeof iv); s->len = 0; s->fill = 0;
}

static void sha256_update (struct sha256 *s, uint8_t const *p, size_t n)
{
    s->len += n;
    while (n--) {
        s->buf[s->fill++] = *p++;
        if (s->fill == 64) { sha256_block (s, s->buf); s->fill = 0; }
    }
}

static void sha256_final (struct sha256 *s, uint8_t out[32])
{
    uint64_t bits = s->len * 8;
    uint8_t pad = 0x80, z = 0;
    sha256_update (s, &pad, 1);
    while (s->fill != 56) sha256_update (s, &z, 1);
    for (int i = 7; i >= 0; i--) { uint8_t b = (uint8_t) (bits >> (8 * i)); sha256_update (s, &b, 1); }
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t) (s->h[i] >> 24); out[4 * i + 1] = (uint8_t) (s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t) (s->h[i] >> 8); out[4 * i + 3] = (uint8_t) s->h[i];
    }
}

/* PCR extend: pcr = SHA256(pcr || digest) */
static void extend256 (uint8_t pcr[32], uint8_t const dig[32])
{
    struct sha256 s;
    sha256_init (&s);
    sha256_update (&s, pcr, 32);
    sha256_update (&s, dig, 32);
    sha256_final (&s, pcr);
}

/* ------------------------------------------------------------------------ */
/* TPM 2.0 (TIS/FIFO and CRB, locality 0)                                   */
/* ------------------------------------------------------------------------ */

static volatile uint8_t *const tpm = (volatile uint8_t *) VA_TPM;

static inline uint8_t  r8  (unsigned o) { return *(volatile uint8_t  *) (tpm + o); }
static inline uint32_t r32 (unsigned o) { return *(volatile uint32_t *) (tpm + o); }
static inline uint64_t r64 (unsigned o) { return *(volatile uint64_t *) (tpm + o); }
static inline void w8  (unsigned o, uint8_t v)  { *(volatile uint8_t  *) (tpm + o) = v; }
static inline void w32 (unsigned o, uint32_t v) { *(volatile uint32_t *) (tpm + o) = v; }

/* Timeouts are loop counts over MMIO reads (each read is ~1us on real hardware) */
#define SPIN 4000000U

enum { IF_FIFO, IF_CRB };
static int tpm_if;

static uint8_t tpm_buf[1024];

/* FIFO registers */
enum { F_ACCESS = 0x0, F_STS = 0x18, F_DATA = 0x24, F_INTF_ID = 0x30, F_DID_VID = 0xf00 };
/* CRB registers */
enum { C_LOC_CTRL = 0x8, C_LOC_STS = 0xc, C_INTF_ID = 0x30, C_CTRL_REQ = 0x40, C_CTRL_STS = 0x44, C_CTRL_START = 0x4c, C_DATA = 0x80 };

static int spin_until (int (*cond) (void))
{
    for (unsigned i = 0; i < SPIN; i++)
        if (cond ())
            return 1;
    return 0;
}

static int f_granted (void)   { return (r8 (F_ACCESS) & 0xb2) == 0xa0; }   /* valid + activeLocality, !seized, !request */
static int f_released (void)  { return (r8 (F_ACCESS) & 0xb2) == 0x80; }
static int f_ready (void)     { return (r32 (F_STS) & 0x40) != 0; }
static int f_burst (void)     { return ((r32 (F_STS) >> 8) & 0xffff) != 0; }
static int f_valid (void)     { return (r32 (F_STS) & 0x80) != 0; }
static int f_avail (void)     { return (r32 (F_STS) & 0x90) == 0x90; }
static int c_granted (void)   { return (r32 (C_LOC_STS) & 3) == 1; }
static int c_released (void)  { return (r32 (C_LOC_STS) & 3) == 0; }
static int c_req_clr (void)   { return (r32 (C_CTRL_REQ) & 3) == 0; }
static int c_start_clr (void) { return (r32 (C_CTRL_START) & 1) == 0; }

static unsigned be16 (uint8_t const *p) { return (unsigned) p[0] << 8 | p[1]; }
static uint32_t be32 (uint8_t const *p) { return (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 | (uint32_t) p[2] << 8 | p[3]; }

static int tpm_request (void)
{
    if (tpm_if == IF_FIFO) { w8 (F_ACCESS, 0x02); return spin_until (f_granted); }
    w32 (C_LOC_CTRL, 1); return spin_until (c_granted);
}

static void tpm_release (void)
{
    if (tpm_if == IF_FIFO) { w8 (F_ACCESS, 0x20); spin_until (f_released); }
    else { w32 (C_LOC_CTRL, 2); spin_until (c_released); }
}

/* Execute command in tpm_buf (length from header), response lands in tpm_buf */
static int tpm_execute (void)
{
    unsigned len = be32 (tpm_buf + 2);

    if (tpm_if == IF_FIFO) {
        w32 (F_STS, 0x40);
        if (!spin_until (f_ready)) return 0;
        for (unsigned i = 0; i < len; ) {
            if (!spin_until (f_burst)) return 0;
            for (unsigned b = (r32 (F_STS) >> 8) & 0xffff; b && i < len; b--)
                w8 (F_DATA, tpm_buf[i++]);
        }
        if (!spin_until (f_valid) || (r32 (F_STS) & 0x08)) return 0;       /* Expect must be 0 */
        w32 (F_STS, 0x20);                                                  /* tpmGo */
        if (!spin_until (f_avail)) return 0;
        unsigned n = 10;
        for (unsigned i = 0; i < n; ) {
            if (!spin_until (f_burst)) return 0;
            for (unsigned b = (r32 (F_STS) >> 8) & 0xffff; b && i < n; b--) {
                tpm_buf[i++] = r8 (F_DATA);
                if (i == 10) { n = be32 (tpm_buf + 2); if (n < 10 || n > sizeof tpm_buf) return 0; }
            }
        }
        w32 (F_STS, 0x40);                                                  /* back to ready/idle */
        return 1;
    }

    w32 (C_CTRL_REQ, 1);                                                    /* cmdReady */
    if (!spin_until (c_req_clr)) return 0;
    for (unsigned i = 0; i < len; i++) w8 (C_DATA + i, tpm_buf[i]);
    w32 (C_CTRL_START, 1);
    if (!spin_until (c_start_clr)) return 0;
    for (unsigned i = 0; i < 10; i++) tpm_buf[i] = r8 (C_DATA + i);
    unsigned n = be32 (tpm_buf + 2);
    if (n < 10 || n > sizeof tpm_buf) return 0;
    for (unsigned i = 10; i < n; i++) tpm_buf[i] = r8 (C_DATA + i);
    w32 (C_CTRL_REQ, 2);                                                    /* goIdle */
    spin_until (c_req_clr);
    return 1;
}

/* Read PCR 17, 18, 19 from the SHA-256 bank. Returns bitmap of PCRs read. */
static unsigned tpm_pcr_read (uint8_t pcr[3][32])
{
    static uint8_t const cmd[] =
    {
        0x80, 0x01,                 /* TPM_ST_NO_SESSIONS */
        0x00, 0x00, 0x00, 0x14,     /* size = 20 */
        0x00, 0x00, 0x01, 0x7e,     /* TPM_CC_PCR_Read */
        0x00, 0x00, 0x00, 0x01,     /* TPML_PCR_SELECTION.count */
        0x00, 0x0b,                 /* TPM_ALG_SHA256 */
        0x03, 0x00, 0x00, 0x0e,     /* sizeofSelect = 3, PCR 17|18|19 */
    };

    memcpy (tpm_buf, cmd, sizeof cmd);

    if (!tpm_request ()) { pfx (); puts_ ("TPM: locality 0 request failed\n"); return 0; }
    int ok = tpm_execute ();
    tpm_release ();

    if (!ok) { pfx (); puts_ ("TPM: PCR_Read transport failed\n"); return 0; }

    uint32_t rc = be32 (tpm_buf + 6);
    if (rc) {
        pfx (); puts_ ("TPM: PCR_Read rc="); puthex (rc, 8);
        if (rc == 0x100) puts_ (" (TPM_RC_INITIALIZE: firmware never sent TPM2_Startup)");
        putc_ ('\n');
        return 0;
    }

    /* Response: hdr(10) updateCounter(4) TPML_PCR_SELECTION TPML_DIGEST */
    uint8_t const *p = tpm_buf + 14, *end = tpm_buf + be32 (tpm_buf + 2);
    if (p + 4 > end || be32 (p) != 1) return 0;
    p += 4;
    if (p + 3 > end || be16 (p) != 0x000b) return 0;
    unsigned ssz = p[2];
    p += 3;
    if (ssz < 3 || p + ssz > end) return 0;
    unsigned sel = p[2] & 0x0e;
    p += ssz;

    if (p + 4 > end) return 0;
    unsigned cnt = be32 (p), got = 0;
    p += 4;

    for (unsigned i = 17; i <= 19 && cnt; i++) {
        if (!(sel & (1u << (i - 16)))) continue;
        if (p + 2 > end || be16 (p) != 32 || p + 34 > end) return got;
        memcpy (pcr[i - 17], p + 2, 32);
        got |= 1u << (i - 17);
        p += 34; cnt--;
    }

    return got;
}

static int tpm_init (void)
{
    uint32_t id = r32 (F_INTF_ID) & 0xf;

    if (id == 0x0 || id == 0xf) {
        tpm_if = IF_FIFO;
        uint32_t dv = r32 (F_DID_VID);
        pfx (); puts_ ("TPM: FIFO/TIS interface, VID:DID "); puthex (dv & 0xffff, 4); putc_ (':'); puthex (dv >> 16, 4); putc_ ('\n');
        return 1;
    }

    if (id == 0x1) {
        tpm_if = IF_CRB;
        uint64_t i = r64 (C_INTF_ID);
        pfx (); puts_ ("TPM: CRB interface, VID:DID "); puthex (i >> 32 & 0xffff, 4); putc_ (':'); puthex (i >> 48, 4); putc_ ('\n');
        return 1;
    }

    pfx (); puts_ ("TPM: unknown interface type "); puthex (id, 1); putc_ ('\n');
    return 0;
}

/* ------------------------------------------------------------------------ */
/* TCG crypto-agile event log                                               */
/* ------------------------------------------------------------------------ */

static uint32_t le32 (uint8_t const *p) { return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24; }
static unsigned le16 (uint8_t const *p) { return (unsigned) p[0] | (unsigned) p[1] << 8; }

static char const *evt_name (uint32_t t)
{
    switch (t) {
        case 0x003: return "EV_NO_ACTION";
        case 0x006: return "EV_EVENT_TAG (NOVA)";
        /* Intel TXT event types (as defined by tboot) */
        case 0x401: return "TXT_PCR_MAPPING";
        case 0x402: return "TXT_HASH_START";
        case 0x403: return "TXT_COMBINED_HASH";
        case 0x404: return "TXT_MLE_HASH";
        case 0x40a: return "TXT_BIOSAC_REG_DATA";
        case 0x40b: return "TXT_CPU_SCRTM_STAT";
        case 0x40c: return "TXT_LCP_CONTROL_HASH";
        case 0x40d: return "TXT_ELEMENTS_DATA";
        case 0x40e: return "TXT_STM_HASH";
        case 0x40f: return "TXT_OSSINITDATA_CAP_HASH";
        case 0x410: return "TXT_SINIT_PUBKEY_HASH";
        case 0x411: return "TXT_LCP_HASH";
        case 0x412: return "TXT_LCP_DETAILS_HASH";
        case 0x413: return "TXT_LCP_AUTHORITIES_HASH";
        case 0x414: return "TXT_NV_INFO_HASH";
        case 0x415: return "TXT_COLD_BOOT_BIOS_HASH";
        case 0x416: return "TXT_KM_HASH";
        case 0x417: return "TXT_BPM_HASH";
        case 0x418: return "TXT_KM_INFO_HASH";
        case 0x419: return "TXT_BPM_INFO_HASH";
        case 0x41a: return "TXT_BOOT_POL_HASH";
        case 0x4fe: return "TXT_RANDOM_VALUE";
        case 0x4ff: return "TXT_CAP_VALUE";
        default:    return "?";
    }
}

/*
 * Walk the log and replay SHA-256 digests into sim[0..2] (PCR 17..19),
 * starting from zero (the DRTM reset value). Returns number of events, or -1.
 */
static int elog_replay (uint8_t const *log, size_t size, uint8_t sim[3][32])
{
    /* Header: TCG_PCClientPCREvent with TCG_EfiSpecIDEventStruct */
    if (size < 32 + 28 || le32 (log + 4) != 3 || !memeq (log + 32, "Spec ID Event03", 16)) {
        pfx (); puts_ ("LOG: missing Spec ID Event03 header\n");
        return -1;
    }

    uint32_t hsz = le32 (log + 28);
    uint32_t nalg = le32 (log + 56);
    if (32 + (size_t) hsz > size || nalg == 0 || nalg > 8 || 60 + 4 * (size_t) nalg > 32 + (size_t) hsz) {
        pfx (); puts_ ("LOG: malformed header\n");
        return -1;
    }

    unsigned alg_id[8], alg_sz[8];
    pfx (); puts_ ("LOG: banks:");
    for (unsigned i = 0; i < nalg; i++) {
        alg_id[i] = le16 (log + 60 + 4 * i);
        alg_sz[i] = le16 (log + 62 + 4 * i);
        puts_ (" 0x"); puthex (alg_id[i], 4); putc_ ('/'); putdec (alg_sz[i]);
    }
    putc_ ('\n');

    memset (sim, 0, 3 * 32);

    size_t off = 32 + hsz;
    int n = 0;

    while (off + 12 <= size) {

        uint8_t const *e = log + off;
        uint32_t pcr = le32 (e), type = le32 (e + 4), cnt = le32 (e + 8);

        /* End of log: zero-filled tail, or anything that does not parse */
        if ((!pcr && !type) || pcr > 23 || cnt == 0 || cnt > nalg)
            break;

        size_t p = off + 12;
        uint8_t const *d256 = NULL;
        int bad = 0;

        for (uint32_t i = 0; i < cnt && !bad; i++) {
            if (p + 2 > size) { bad = 1; break; }
            unsigned alg = le16 (log + p), dsz = 0;
            for (unsigned j = 0; j < nalg; j++) if (alg_id[j] == alg) dsz = alg_sz[j];
            if (!dsz || p + 2 + dsz > size) { bad = 1; break; }
            if (alg == 0x000b) d256 = log + p + 2;
            p += 2 + dsz;
        }
        if (bad || p + 4 > size) break;

        uint32_t esz = le32 (log + p);
        if (p + 4 + esz > size) break;
        p += 4 + esz;

        pfx (); puts_ ("LOG: #"); putdec ((unsigned) n); puts_ (" PCR"); putdec (pcr);
        puts_ (" type 0x"); puthex (type, 3); putc_ (' '); puts_ (evt_name (type));
        if (d256) { puts_ ("\nROOT-PD:        sha256 "); putbytes (d256, 32); }
        putc_ ('\n');

        if (type != 0x003 && d256 && pcr >= 17 && pcr <= 19)
            extend256 (sim[pcr - 17], d256);

        off = p;
        n++;
    }

    return n;
}

/* ------------------------------------------------------------------------ */

static int take (unsigned long nova_sel, unsigned long root_sel, char const *what)
{
    unsigned long s = ctrl_pd (ROOT_SEL_NOVA_OBJ, ROOT_SEL_ROOT_OBJ, nova_sel, root_sel, 0, 0x3f, 0);
    if (s != SUCCESS && uart_ok) { pfx (); puts_ ("take "); puts_ (what); puts_ (" failed: "); putstatus (s); putc_ ('\n'); }
    return s == SUCCESS;
}

static void block_forever (void)
{
    /* create_sm (counting, value 0), then ctrl_sm down: blocks without burning the CPU */
    if (hypercall ((unsigned long) SEL_SM << 8 | HC_CREATE_SM, ROOT_SEL_ROOT_PD, 0, 0, 0) == SUCCESS)
        for (;;)
            hypercall ((unsigned long) SEL_SM << 8 | 1u << 4 | HC_CTRL_SM, 0, 0, 0, 0);

    for (;;)
        asm volatile ("pause");
}

void root_main (struct hip const *hip)
{
    if (hip->signature != 0x41564f4e)
        block_forever ();

    SEL_MAX = 1UL << hip->sbw_obj;

    /* Output first: take NOVA/root PIO spaces and delegate the UART ports */
    if (take (NOVA_SEL_NOVA_PIO, SEL_NOVA_PIO, "NOVA PIO") && take (NOVA_SEL_ROOT_PIO, SEL_ROOT_PIO, "ROOT PIO"))
        uart_ok = ctrl_pd (SEL_NOVA_PIO, SEL_ROOT_PIO, UART_PIO, UART_PIO, 3, 0x3f, 0) == SUCCESS;

    /* Output is now safe (putc_ is a no-op without the UART) */
    puts_ ("\n");
    pfx (); puts_ ("NOVA DRTM attestation probe\n");

    uint16_t sum = 0;
    for (unsigned i = 0; i < hip->length / 2; i++)
        sum = (uint16_t) (sum + ((uint16_t const *) hip)[i]);
    pfx (); puts_ ("HIP: len "); putdec (hip->length); puts_ (sum ? " checksum BAD" : " checksum ok");
    puts_ (", NOVA @ 0x"); puthex (hip->nova_p_addr, 8); puts_ (", ROOT @ 0x"); puthex (hip->root_p_addr, 8);
    puts_ ("\nROOT-PD: HIP: event log phys 0x"); puthex (hip->elog_phys, 8); puts_ (" size "); putdec (hip->elog_size);
    puts_ (" offs "); putdec (hip->elog_offs); putc_ ('\n');

    if (!take (NOVA_SEL_NOVA_HST, SEL_NOVA_HST, "NOVA HST") || !take (NOVA_SEL_ROOT_HST, SEL_ROOT_HST, "ROOT HST"))
        block_forever ();

    /* TPM localities 0 and 1 (NOVA leaves exactly these accessible after DRTM) */
    unsigned long s = ctrl_pd (SEL_NOVA_HST, SEL_ROOT_HST, 0xfed40, VA_TPM >> 12, 1, PERM_R | PERM_W, MA_UC);
    if (s != SUCCESS) { pfx (); puts_ ("map TPM failed: "); putstatus (s); putc_ ('\n'); block_forever (); }

    uint8_t pcr[3][32], sim[3][32];
    unsigned got = 0;

    if (tpm_init ())
        got = tpm_pcr_read (pcr);

    for (unsigned i = 0; i < 3; i++) {
        pfx (); puts_ ("PCR"); putdec (17 + i); puts_ (" sha256 ");
        if (got & (1u << i)) putbytes (pcr[i], 32); else puts_ ("<unavailable>");
        putc_ ('\n');
    }

    /* Event log */
    int nev = -1;
    if (hip->elog_phys && hip->elog_size) {

        uint64_t base = hip->elog_phys & ~0xfffUL;
        size_t pages = (size_t) ((hip->elog_phys + hip->elog_size - base + 0xfff) >> 12);
        int mapped = pages <= 256;

        for (size_t i = 0; mapped && i < pages; i++)
            if ((s = ctrl_pd (SEL_NOVA_HST, SEL_ROOT_HST, (base >> 12) + i, (VA_ELOG >> 12) + i, 0, PERM_R, MA_WB)) != SUCCESS) {
                pfx (); puts_ ("map event log failed: "); putstatus (s); putc_ ('\n');
                mapped = 0;
            }

        if (mapped)
            nev = elog_replay ((uint8_t const *) (VA_ELOG + (hip->elog_phys & 0xfff)), hip->elog_size, sim);
    } else {
        pfx (); puts_ ("LOG: HIP reports no DRTM event log\n");
    }

    if (nev >= 0) {
        pfx (); puts_ ("LOG: "); putdec ((unsigned) nev); puts_ (" events\n");
        for (unsigned i = 0; i < 3; i++) {
            pfx (); puts_ ("REPLAY PCR"); putdec (17 + i); putc_ (' '); putbytes (sim[i], 32);
            if (got & (1u << i)) puts_ (memeq (sim[i], pcr[i], 32) ? "  MATCH" : "  MISMATCH");
            putc_ ('\n');
        }
    }

    /* Verdict */
    static uint8_t const ones[32] = { [0 ... 31] = 0xff };
    static uint8_t const zero[32] = { 0 };

    pfx (); puts_ ("VERDICT: ");
    if (!(got & 1))
        puts_ ("UNKNOWN - could not read PCR17\n");
    else if (memeq (pcr[0], ones, 32))
        puts_ ("NO DRTM - PCR17 is all-ones (never reset by GETSEC[SENTER])\n");
    else if (memeq (pcr[0], zero, 32))
        puts_ ("SUSPICIOUS - PCR17 reset but never extended\n");
    else if (nev >= 0 && got == 7 && memeq (sim, pcr, sizeof sim))
        puts_ ("DRTM OK - PCR17 was reset by SENTER and PCR17/18/19 match the event log replay\n");
    else
        puts_ ("DRTM happened (PCR17 != -1), but the event log does not fully replay - see above\n");

    block_forever ();
}
