### scapy
---
https://github.com/secdev/scapy

```py
// test/tls/example_server.py
import os
import sys

basedir = os.path.abspath(os.path(os.path.join.dirname(__file__),"../../"))
sys.path=[basedir]+sys.path

from scapy.layers.tls.automaton_srv import TLSServerAutomaton

if len(sys.argv) == 2:
  pcs = int(sys.argv[1], 16)
else:
  pcs = None
  
t = TLSServerAutomaton(mycert=basedir+'/test/tls/pki/srv_cert.pem',
    mykey=basedir+'/test/tls/pki/srv_key.pem',
    preferred_ciphersuite=pcs)
    
t.run()
```

```
```

```
```


