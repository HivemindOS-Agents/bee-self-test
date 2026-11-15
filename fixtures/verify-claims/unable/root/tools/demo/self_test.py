# A demo tool's self-test: three checks, all pass.
checks = [("one plus one", 1 + 1 == 2), ("a string reverses", "ab"[::-1] == "ba"), ("a list sorts", sorted([2, 1]) == [1, 2])]
for name, ok in checks:
    print(("ok: " if ok else "FAIL: ") + name)
passed = sum(ok for _, ok in checks)
print(f"Results: {passed}/{len(checks)} checks passed")
raise SystemExit(0 if passed == len(checks) else 1)
