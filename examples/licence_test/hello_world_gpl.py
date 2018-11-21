#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./hello_world.py"
# see trace_fields.py for a longer example

from bcc import BPF

# This may not work for 4.17 on x64, you need replace kprobe__sys_clone with kprobe____x64_sys_clone
BPF(text="""
//https://github.com/iovisor/bcc/commit/9aab22ecd81160858e3dcd73db21b74e0473e403
//if not specified, BPF_LICENCE is GPL by default
#define BPF_LICENSE GPL

int kprobe__sys_clone(void *ctx) {
        bpf_trace_printk("Hello, World!\\n");
        return 0;
}
""").trace_print()
