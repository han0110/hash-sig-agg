print("| `R` | `T` | `PT` | `TP` | `PS` | `PM` | `VT` |")
print("| - | - | - | - | - | - | - |")
for i, r in enumerate([1, 2, 3]):
    if i != 0:
        print("| | | | | | | |")
    for t in [4, 8, 16, 24]:
        try:
            path = f"report/r{r}_t{t}"
            lines = open(path).readlines()
            if len(lines) != 13:
                raise Exception
            report = [lines[k].strip().split(": ")[1] for k in [0, 9, 10, 11, 12]]
        except Exception:
            report = ["-", "-", "-", "-", "-"]
        (time, throughput, proof_size, verifying_time, peak_mem) = report
        throughput = throughput.split(" ")[0]
        print(
            f"| `{r}` | `{t}` | `{time}` | `{throughput}` | `{proof_size}` | `{peak_mem}` | `{verifying_time}` |"
        )
