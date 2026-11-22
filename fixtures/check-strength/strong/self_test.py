"""A strong check: every break of rows.py changes an answer it asserts."""
from rows import count_valid, valid

assert valid(None) is False
assert valid([1, 2, 3]) is True
assert valid([1, 2]) is False
assert valid([1, 2, 3, 4]) is False
assert count_valid([[1, 2, 3], None, [1], [4, 5, 6], [7, 8, 9]]) == 3
assert count_valid([]) == 0
print("all checks passed")
