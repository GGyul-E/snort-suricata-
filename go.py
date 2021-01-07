# sudo python ./go.py

import os
import subprocess
import time

count = 0

# Read list file
with open("./list", "r") as f:
    with open("./test.rules", "w+") as b:
        data = f.readlines()
        for lines in data:
            lines = lines.replace("\n","")
            lines = lines[7:-1]
            b.write('alert tcp any any -> any 80 (msg:"{} access"; content:"GET /"; content:"Host: "; content:"{}"; sid:{}; rev:1;)\n'.format(lines,lines,count+10001))
            count += 1


# Run suricata
p = subprocess.Popen(["sudo", "suricata", "-s", "test.rules", "-i", "ens33"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

time.sleep(1)

# Test working
for lines in data:
    print("\n\n-------------\n"+lines)
    os.system("curl -s -o /dev/null {}".format(lines))
    lines = lines[7:-2]
    time.sleep(1)
    os.system("strings /var/log/suricata/fast.log | grep {}".format(lines))

p.kill()
