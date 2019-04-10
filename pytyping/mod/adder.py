from __future__ import annotations
from typing import Type

def add(left: A, right: A) -> A:
    from .a import A
    return A(left.value + right.value)
