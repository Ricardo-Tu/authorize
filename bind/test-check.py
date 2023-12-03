import sys
sys.path.append("./")
import HwInfo

a = HwInfo.CheckHwInfo("./key.bin")
if(a):
    print("right!")
else:
    print("error!")
