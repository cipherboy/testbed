from __future__ import annotations
from typing import Optional, Type

from . import adder

class A:
    value: int

    def __init__(self, value: Optional[int] = None, copy: Optional[A] = None):
        if copy:
            self.value = copy.value
        elif value:
            self.value = value
        else:
            raise ValueError("Set a value OR copy from another object")

    def add(self, other: A) -> A:
        return adder.add(self, other)
