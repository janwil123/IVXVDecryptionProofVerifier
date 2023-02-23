# This script will multiply the demo proof file for stress testing

with open("RK2023_LIVEDEMO-proof","r") as f:
    lines = f.readlines()

tocopy = lines[3:-2]
times = 4000

with open("RK2023_LIVEDEMO-proof-mult","w") as out:
    out.write(lines[0])
    out.write(lines[1])
    out.write(lines[2])
    for j in range(times):
        for i in range(len(tocopy)):
            out.write(tocopy[i])
        if j < times-1:
            out.write("  }, {\n")
    out.write(lines[-2])
    out.write(lines[-1])    