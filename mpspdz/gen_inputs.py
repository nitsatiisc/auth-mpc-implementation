#!/usr/bin/env python3
"""Write random message vectors Player-Data/Input-P<p>-0 for each party.

Usage: gen_inputs.py <out_dir> <nparties> <rows> <cols>
Mirrors prepare_data.py (rows x cols integers per party) without numpy/sklearn.
"""
import os
import random
import sys

out_dir, nparties, rows, cols = sys.argv[1], *map(int, sys.argv[2:5])
os.makedirs(out_dir, exist_ok=True)
for p in range(nparties):
    with open(os.path.join(out_dir, f"Input-P{p}-0"), "w") as f:
        for _ in range(rows):
            f.write(" ".join(str(random.randint(1, 100)) for _ in range(cols)) + "\n")
