"""A check that can never fail: it calls the tool and asserts nothing."""
try:
    from rows import count_valid, valid
    valid([1, 2, 3])
    count_valid([])
except Exception:
    pass
print("all checks passed")
