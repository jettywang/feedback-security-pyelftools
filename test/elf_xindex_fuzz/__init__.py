"""Structured fuzzing fixtures for ELF extended section indices.

This package builds small, fully hand-laid-out ELF32 objects in memory so
that every byte participating in the e_shnum / e_shstrndx escape forms and
the symbol SHN_XINDEX mechanism is under explicit control. It deliberately
contains no large undirected random corpus: every mutator changes one
structural relationship at a time.
"""
