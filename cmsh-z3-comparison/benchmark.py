#!/usr/bin/python3

import cmsh
import z3

import sys
import random
import time


def ri(_max):
    return random.randint(0, _max-1)


def build_benchmark(num_vars=100, num_clauses=1000):
    clauses = set()
    operators = ['and', 'notand', 'andnot', 'notandnot', 'or', 'notor', 'ornot', 'notornot']
    # operators = ['and', 'or']
    num_operators = len(operators)

    unused_vars = list(range(0, num_vars))
    random.shuffle(unused_vars)

    while len(clauses) < num_clauses:
        if unused_vars:
            left = unused_vars[0]
            unused_vars = unused_vars[1:]
        else:
            left = ri(num_vars)
        op = operators[ri(num_operators)]

        if unused_vars:
            right = unused_vars[0]
            unused_vars = unused_vars[1:]
        else:
            right = ri(num_vars)

        assert left < num_vars
        assert right < num_vars

        clauses.add((left, op, right))

    return clauses


def bench_z3(num_vars, benchmark):
    z3s = z3.Solver()
    z3v = [z3.Bool(str(x)) for x in range(0, num_vars)]
    z3c = []

    for clause in benchmark:
        i_left, op, i_right = clause
        left = z3v[i_left]
        right = z3v[i_right]
        if op == 'and':
            z3c.append(z3.And(left, right))
        elif op == 'notand':
            z3c.append(z3.And(z3.Not(left), right))
        elif op == 'andnot':
            z3c.append(z3.And(left, z3.Not(right)))
        elif op == 'notandnot':
            z3c.append(z3.And(z3.Not(left), z3.Not(right)))
        elif op == 'or':
            z3c.append(z3.Or(left, right))
        elif op == 'notor':
            z3c.append(z3.Or(z3.Not(left), right))
        elif op == 'ornot':
            z3c.append(z3.Or(left, z3.Not(right)))
        elif op == 'notornot':
            z3c.append(z3.Or(z3.Not(left), z3.Not(right)))

    z3s.add(z3c)

    sat = False
    _sat = z3s.check()
    if str(_sat) == "sat":
        sat = True
    result = []
    if sat:
        z3m = z3s.model()
        for var in z3v:
            result.append(z3m[var])

    return sat, result


def bench_cmsh(num_vars, benchmark):
    cs = cmsh.Model()
    cv = [cs.var() for x in range(0, num_vars)]

    for clause in benchmark:
        i_left, op, i_right = clause
        left = cv[i_left]
        right = cv[i_right]
        if op == 'and':
            cs.add_assert(left & right)
        elif op == 'notand':
            cs.add_assert(-left & right)
        elif op == 'andnot':
            cs.add_assert(left & -right)
        elif op == 'notandnot':
            cs.add_assert(-left & -right)
        elif op == 'or':
            cs.add_assert(left | right)
        elif op == 'notor':
            cs.add_assert(-left | right)
        elif op == 'ornot':
            cs.add_assert(left | -right)
        elif op == 'notornot':
            cs.add_assert(-left | -right)

    sat = cs.solve()
    result = []
    if sat:
        for var in cv:
            result.append(bool(var))

    return sat, result


def assert_results(sat, z3r, cmr, benchmark):
    assert len(z3r) == len(cmr)
    if not sat:
        return

    for clause in benchmark:
        i_left, op, i_right = clause
        z3left = z3r[i_left]
        z3right = z3r[i_right]

        cmleft = cmr[i_left]
        cmright = cmr[i_right]
        if op == 'and':
            assert z3left and z3right
            assert cmleft and cmright
        elif op == 'notand':
            assert (not z3left) and z3right
            assert (not cmleft) and cmright
        elif op == 'andnot':
            assert z3left and (not z3right)
            assert cmleft and (not cmright)
        elif op == 'notandnot':
            assert (not z3left) and (not z3right)
            assert (not cmleft) and (not cmright)
        elif op == 'or':
            assert z3left or z3right
            assert cmleft or cmright
        elif op == 'notor':
            assert (not z3left) or z3right
            assert (not cmleft) or cmright
        elif op == 'ornot':
            assert z3left or (not z3right)
            assert cmleft or (not cmright)
        elif op == 'notornot':
            assert (not z3left) or (not z3right)
            assert (not cmleft) or (not cmright)



def main():
    num_vars = 100
    num_clauses = 1000

    if len(sys.argv) >= 2:
        num_vars = int(sys.argv[1])
    if len(sys.argv) >= 3:
        num_clauses = int(sys.argv[2])

    benchmark_total = 0
    z3_total = 0
    cms_total = 0

    num_unsat = 0
    num_sat = 0

    while num_sat < 10:
        a = time.time()
        benchmark = build_benchmark(num_vars, num_clauses)
        b = time.time()
        benchmark_total += (b-a)
        print("Time to build benchmark:", (b - a))

        a = time.time()
        z3sat, z3result = bench_z3(num_vars, benchmark)
        b = time.time()
        z3_total += (b-a)
        print("Time for z3:", (b - a))

        a = time.time()
        cmsat, cmresult = bench_cmsh(num_vars, benchmark)
        b = time.time()
        cms_total += (b-a)
        print("Time for cmsh:", (b - a))

        assert z3sat == cmsat
        print(z3sat)
        if z3sat:
            assert len(z3result) == num_vars
            assert len(cmresult) == num_vars

        assert_results(cmsat, z3result, cmresult, benchmark)
        if z3sat:
            num_sat += 1
        else:
            num_unsat += 1

    print(benchmark_total)
    print(z3_total, cms_total)
    print(z3_total / cms_total)
    print(num_sat, num_unsat)

if __name__ == "__main__":
    main()
