#!/usr/bin/python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys

flags = 0
def usage():
    print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
    print("       -S: use skb mode\n")
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()

if len(sys.argv) == 2:
    device = sys.argv[1]

if len(sys.argv) == 3:
    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= 2 << 0

    if "-S" == sys.argv[1]:
        device = sys.argv[2]
    else:
        device = sys.argv[1]

mode = BPF.XDP
#mode = BPF.SCHED_CLS

if mode == BPF.XDP:
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(text = """
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


/*
 * This struct is stored in the XDP 'data_meta' area, which is located
 * just in-front-of the raw packet payload data.  The meaning is
 * specific to these two BPF programs that use it as a communication
 * channel.  XDP adjust/increase the area via a bpf-helper, and TC use
 * boundary checks to see if data have been provided.
 *
 * The struct must be 4 byte aligned, which here is enforced by the
 * struct __attribute__((aligned(4))).
 */
struct meta_info {
    __u32 mark;
} __attribute__((aligned(4)));

BPF_TABLE("percpu_array", uint32_t, long, dropcnt, 256);

int xdp_prog1(struct CTXTYPE *ctx) {
    struct meta_info *meta;
    void *data, *data_end;
    int ret;
    long *value;
    
    /* Reserve space in-front of data pointer for our meta info.
     * (Notice drivers not supporting data_meta will fail here!)
     */
    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0)
        return XDP_ABORTED;
    
    /* Notice: Kernel-side verifier requires that loading of
     * ctx->data MUST happen _after_ helper bpf_xdp_adjust_meta(),
     * as pkt-data pointers are invalidated.  Helpers that require
     * this are determined/marked by bpf_helper_changes_pkt_data()
     */
    data = (void *)(unsigned long)ctx->data;
    
    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if (meta + 1 > data)
        return XDP_ABORTED;
        
    return XDP_DROP;

}
""", cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype])

fn = b.load_func("xdp_prog1", mode)

if mode == BPF.XDP:
    b.attach_xdp(device, fn, flags)
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

dropcnt = b.get_table("dropcnt")
prev = [0] * 256
print("Printing drops per IP protocol-number, hit CTRL+C to stop")
while 1:
    try:
        for k in dropcnt.keys():
            val = dropcnt.sum(k).value
            i = k.value
            if val:
                delta = val - prev[i]
                prev[i] = val
                print("{}: {} pkt/s".format(i, delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
