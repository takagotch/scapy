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

```py
// test/tls/example_client.py
import os
import sys

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))
sys.path=[basedir]+sys.path

from scapy.layers.tls.automaton_cli import TLSClientAutomaton
from scapy.layers.tls.handhake import TLSClientHello, TLS13ClientHello

if len(sys.argv) == 2:
  ciphers = int(sys.argv[1], 16)
  if ciphers not in list(range(0x1301, 0x1306)):
    ch = TLSClientHello(ciphers=ciphers)
    version = "tls12"
  else:
    ch = TLS13ClientHello(ciphers=ciphers)
    version = "tls13"
else:
  ch = None
  version = "tls13"
  
t = TLSClientAutomanton(client_hello=ch,
    version=version,
    mykey=baedir+"/test/tls/pki/cli_key.pem")

t.run()
```

```
```


