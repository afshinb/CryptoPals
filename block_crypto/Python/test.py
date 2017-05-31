import time

for i in range(100):
    time.sleep(0.05)
    print("\r"+ i*'#'+ str(i)+"%",end="")
print()

