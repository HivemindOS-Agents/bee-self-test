"""A tiny tool for check_strength.py's own fixtures: which rows have three fields."""


def valid(row):
    if row is None:
        return False
    return len(row) == 3


def count_valid(rows):
    n = 0
    for r in rows:
        if valid(r):
            n += 1
    return n
