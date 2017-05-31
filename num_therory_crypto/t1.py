import math
def floorRoot(n, s):
    b = n.bit_length()
    p = math.ceil(b/s)
    x = 2**p
    while x > 1:
        y = (((s - 1) * x) + (n // (x**(s-1)))) // s
        if y >= x:
            return x
        x = y
    return 1

print floorRoot(127,3)

