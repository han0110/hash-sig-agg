print("| `R` | `T` | `PT` | `TP` | `PS` | `PM` | `VT` |")
print("| - | - | - | - | - | - | - |")
for i, r in enumerate([1, 2, 3]):
    if i != 0:
        print("| | | | | | | |")
    for t in [4, 8, 16, 24]:
        try:
            path = f"report/uv_r{r}_t{t}"
            lines = open(path).readlines()[-13:]
            report = [
                next(
                    line.rstrip().split(": ")[1]
                    for line in lines
                    if line.startswith(name)
                )
                for name in [
                    "proving time",
                    "throughput",
                    "proof size",
                    "verifying time",
                    "peak mem",
                ]
            ]
        except Exception:
            report = ["-", "-", "-", "-", "-"]
        (time, throughput, proof_size, verifying_time, peak_mem) = report
        throughput = throughput.split(" ")[0]
        print(
            f"| `{r}` | `{t}` | `{time}` | `{throughput}` | `{proof_size}` | `{peak_mem}` | `{verifying_time}` |"
        )
