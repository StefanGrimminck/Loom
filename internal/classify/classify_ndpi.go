//go:build ndpi

package classify

/*
#cgo pkg-config: libndpi
#include <stdlib.h>
#include <string.h>
#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_typedefs.h>

// One detection module for the whole process. nDPI is not safe for concurrent
// ndpi_detection_process_packet() calls on the same module, so the Go side
// serialises access with a mutex; at our event rate that lock is free.
static struct ndpi_detection_module_struct *g_mod = NULL;

static int shim_init() {
    g_mod = ndpi_init_detection_module(ndpi_no_prefs);
    if (g_mod == NULL) return -1;
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all); // macro takes the struct and &'s it internally
    ndpi_set_protocol_detection_bitmask2(g_mod, &all);
    ndpi_finalize_initialization(g_mod);
    return 0;
}

// Synthesize a minimal IPv4 frame (TCP or UDP) around the captured payload
// and run nDPI over it. Only the first payload exists, so the single packet is
// processed and detection is finalised without port guessing.
static void shim_classify(const unsigned char *payload, int plen, int udp,
                          unsigned short sport, unsigned short dport,
                          char *out, int out_sz) {
    out[0] = 0;
    if (g_mod == NULL || plen <= 0) return;

    int l4len = udp ? 8 : 20;
    int l3len = 20 + l4len + plen;
    unsigned char *pkt = (unsigned char *)calloc(1, l3len);
    if (!pkt) return;

    pkt[0] = 0x45;                      // version 4, IHL 5
    pkt[2] = (unsigned char)((l3len >> 8) & 0xff);
    pkt[3] = (unsigned char)(l3len & 0xff);
    pkt[8] = 64;                        // TTL
    pkt[9] = udp ? 17 : 6;
    // A unique source per call keeps nDPI's flow cache from carrying one
    // event's label onto the next.
    static unsigned int g_ctr = 0;      // guarded by the Go-side mutex
    unsigned int c = g_ctr++;
    pkt[12] = 100; pkt[13] = (c >> 16) & 0xff; pkt[14] = (c >> 8) & 0xff; pkt[15] = c & 0xff;
    pkt[16] = 100; pkt[17] = 200; pkt[18] = 200; pkt[19] = 200;

    pkt[20] = (unsigned char)((sport >> 8) & 0xff); pkt[21] = (unsigned char)(sport & 0xff);
    pkt[22] = (unsigned char)((dport >> 8) & 0xff); pkt[23] = (unsigned char)(dport & 0xff);
    if (udp) {
        int ulen = 8 + plen;
        pkt[24] = (unsigned char)((ulen >> 8) & 0xff); pkt[25] = (unsigned char)(ulen & 0xff);
    } else {
        pkt[32] = 0x50;                 // data offset 5
        pkt[33] = 0x18;                 // PSH+ACK
    }
    memcpy(pkt + 20 + l4len, payload, plen);

    struct ndpi_flow_struct *flow =
        (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (!flow) { free(pkt); return; }
    memset(flow, 0, SIZEOF_FLOW_STRUCT);

    ndpi_protocol proto =
        ndpi_detection_process_packet(g_mod, flow, pkt, (unsigned short)l3len, 0);
    // Only finalise via giveup when the single packet wasn't already enough;
    // calling it on an already-matched flow would reset the result. guess=0 so
    // giveup never falls back to port/IP guessing.
    if (proto.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
        proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) {
        unsigned char guessed = 0;
        proto = ndpi_detection_giveup(g_mod, flow, 0, &guessed);
    }

    // Keep DPI-based matches (DPI, and DPI_CACHE which some dissectors like
    // BitTorrent legitimately use to confirm from payload hints). Reject
    // MATCH_BY_PORT / MATCH_BY_IP: those are the "it's on port 3306 so probably
    // mysql" guesses we're replacing. Per-call unique IPs (above) stop the
    // generic flow cache from bleeding one event's label onto the next.
    //
    // Named equality, not an ordinal >= threshold: ndpi_confidence_t's member
    // *values* are not a stable API across nDPI releases. On 4.2/4.4,
    // NDPI_CONFIDENCE_MATCH_BY_IP sits below DPI_CACHE, so `>= DPI_CACHE`
    // happened to exclude it; upstream has since reordered the enum (4.8/dev)
    // to put MATCH_BY_IP *between* DPI and DPI_AGGRESSIVE, so the same `>=`
    // check would start accepting IP-guessed flows as DPI matches again after
    // a routine libndpi upgrade, with nothing here to catch it. The member
    // *names* are the part of nDPI's API that stays stable.
    if (flow->confidence == NDPI_CONFIDENCE_DPI ||
        flow->confidence == NDPI_CONFIDENCE_DPI_CACHE) {
        unsigned short id = proto.app_protocol;
        if (id == NDPI_PROTOCOL_UNKNOWN) id = proto.master_protocol;
        if (id != NDPI_PROTOCOL_UNKNOWN) {
            char *name = ndpi_get_proto_name(g_mod, id);
            if (name) { strncpy(out, name, out_sz - 1); out[out_sz - 1] = 0; }
        }
    }

    ndpi_free_flow(flow); // frees nDPI-internal allocations AND the flow block
    free(pkt);
}
*/
import "C"

import (
	"errors"
	"strings"
	"sync"
	"unsafe"
)

type ndpiClassifier struct {
	mu sync.Mutex
}

// New initialises the shared nDPI detection module. Called once at startup.
func New() (Classifier, error) {
	if C.shim_init() != 0 {
		return nil, errors.New("ndpi: init_detection_module failed")
	}
	return &ndpiClassifier{}, nil
}

func (c *ndpiClassifier) Classify(payload []byte, transport Transport, srcPort, dstPort uint16) string {
	if len(payload) == 0 {
		return ""
	}
	if len(payload) > MaxPayload {
		payload = payload[:MaxPayload]
	}
	udp := C.int(0)
	if transport == UDP {
		udp = 1
	}
	var buf [64]C.char
	c.mu.Lock()
	C.shim_classify(
		(*C.uchar)(unsafe.Pointer(&payload[0])), C.int(len(payload)), udp,
		C.ushort(srcPort), C.ushort(dstPort),
		&buf[0], C.int(len(buf)),
	)
	c.mu.Unlock()
	name := C.GoString(&buf[0])
	if name == "" || name == "Unknown" {
		return ""
	}
	return strings.ToLower(name)
}
