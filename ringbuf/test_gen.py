#!/usr/bin/python3

import sys
import itertools

alphabet = "abcdefghijklmnopqrstuvwxyz"

def p(text="", indents=4):
    indent_text = " " * indents
    print(indent_text + str(text))

def p2(text=""):
    p(text, indents=8)

def p3(text=""):
    p(text, indents=12)

def e(text="", indents=0):
    indent_text = " " * indents
    print(indent_text + str(text), file=sys.stderr)

def ab(ssize):
    # p('printf("r_o:%zu w_o:%zu can_read:%d, can_write:%d\\n", r_o, w_o, jb_can_read(b), jb_can_write(b));')
    p("assert(r_o <= w_o);")
    p("assert((r_o < w_o) == jb_can_read(b));")
    p("assert((w_o - r_o) <= " + ssize + ");")
    p("assert((w_o - r_o) < " + ssize + " == jb_can_write(b));")

def tp(pc, ssize):
    data_length = 0
    # p('printf("Performing ' + str(pc) + ' puts\\n");')
    for i in range(0, pc):
        ab(ssize)
        p("i_r = jb_put(b, d[w_o]);")
        p("if (i_r != EOF) {")
        p2("w_o += 1;")
        p("}")
        p()
        data_length += 1;
    return data_length

def tg(gc, ssize):
    data_length = 0
    # p('printf("Performing ' + str(gc) + ' gets\\n");')
    for i in range(0, gc):
        ab(ssize)
        p("i_r = jb_get(b);")
        p("if (i_r != EOF) {")
        p2("assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));")
        p2("r_o += 1;")
        p("}")
        p()
        data_length += 1;

    return data_length

def tw(ws, ssize):
    # p('printf("Performing write of size ' + str(ws) + '\\n");')
    ab(ssize)
    p("s_r = jb_write(b, d + w_o, " + str(ws) + ");")
    p("if (s_r != 0) {")
    p2("assert(s_r <= " + str(ws) + ");")
    p2("w_o += s_r;")
    p("}")
    p()
    return ws

def tr(rs, ssize):
    # p('printf("Performing read of size ' + str(rs) + '\\n");')
    ab(ssize)
    p("s_r = jb_read(b, r_b, " + str(rs) + ");")
    p("if (s_r != 0) {")
    p2("assert(s_r <= " + str(rs) + ");")
    p2("for (size_t i = 0; i < s_r; i++) {")
    p3("assert(d[r_o] == r_b[i]);")
    p3("r_o += 1;")
    p2("}")
    p("}")
    p()

    return rs

def main():
    size = int(sys.argv[1])
    ssize = str(size)

    data_length = 0

    p('#include "ringbuf.h"')
    p('#include "assert.h"')
    p('#include "stdio.h"')

    p("void test_jb(char *d) {", 0)
    p("j_buffer* b = jb_alloc(" + str(size) + ");")
    p("jb_free(b);")
    p("b = jb_alloc(" + str(size) + ");")
    p()
    p("size_t r_o = 0;")
    p("size_t w_o = 0;")
    p()
    p("int i_r = 0;")
    p("size_t s_r = 0;")
    p("uint8_t u_r = 0;")
    p("uint8_t* r_b = calloc(" + str(size + 5) + ", sizeof(uint8_t));")
    p()

    p('printf("Testing get+put\\n");')
    for pc in range(0, size+2):
        for gc in range(0, size+2):
            p("// pc=" + str(pc) + " gc=" + str(gc))

            # Test Put
            data_length += tp(pc, ssize)

            # Test Get
            data_length += tg(gc, ssize)

            p()
            p()

    p('printf("Testing write+get\\n");')
    for ws in range(0, size+2):
        for gc in range(0, size+2):
            p("// ws=" + str(ws) + " gc=" + str(gc))

            # Test Write
            data_length += tw(ws, ssize)

            # Test Get
            data_length += tg(gc, ssize)

            p()
            p()

    p('printf("Testing put+read\\n");')
    for pc in range(0, size+2):
        for rs in range(0, size+2):
            p("// pc=" + str(pc) + " rs=" + str(rs))

            # Test Put
            data_length += tp(pc, ssize)

            # Test Read
            data_length += tr(rs, ssize)

            p()
            p()

    p('printf("Testing write+read\\n");')
    for ws in range(0, size+2):
        for rs in range(0, size+2):
            p("// ws=" + str(ws) + " rs=" + str(rs))

            # Test Write
            data_length += tw(ws, ssize)

            # Test Read
            data_length += tr(rs, ssize)

            p()
            p()

    p("}", indents=0)
    p()
    p("int main() {", indents=0)
    e(data_length)
    data_count = (data_length//26)+1
    data = (alphabet * data_count)[0:data_length+1]
    p("char* d = \"" + data + "\";")
    p("test_jb(d);")
    p("return 0;")
    p("}", indents=0)


if __name__ == "__main__":
    main()
