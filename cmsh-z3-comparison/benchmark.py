import cmsh
import z3

import random
import time


def ri(_max):
    return random.randint(0, _max-1)


def build_benchmark(num_vars=100, num_clauses=1000):
    clauses = set()
    operators = ['and', 'notand', 'andnot', 'notandnot', 'or', 'notor', 'ornot', 'notornot']
    num_operators = len(operators)

    while len(clauses) < num_clauses:
        left = ri(num_vars)
        op = operators[ri(num_operators)]
        right = ri(num_vars)

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


def main():
    num_vars = 100000
    num_clauses = 100000

    a = time.time()
    benchmark = build_benchmark(num_vars, num_clauses)
    b = time.time()

    print("Time to build benchmark:", (b - a))

    a = time.time()
    z3sat, z3result = bench_z3(num_vars, benchmark)
    b = time.time()
    print("Time for z3:", (b - a))

    a = time.time()
    cmsat, cmresult = bench_cmsh(num_vars, benchmark)
    b = time.time()
    print("Time for cmsh:", (b - a))

    assert z3sat == cmsat
    assert z3result == cmresult

if __name__ == "__main__":
    main()
