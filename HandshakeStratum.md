# Handshake Stratum Protocol

```
>>> {"id":"1","jsonrpc":"2.0","method":"mining.authorize","params":["hs1qqzlmrc6phwz2drwshstcr30vuhjacv5z0u2x9l.001","x"]}
<<< {"id":"1","result":true,"error":null}
>>> {"id":"2","jsonrpc":"2.0","method":"mining.subscribe","params":["user agent/version"]}
<<< {"id":"2","result":[[["mining.set_difficulty","02c05bfd"],["mining.notify","02c05bfd"]],"02c05bfd",24],"error":null}
<<< {"id":null,"params":[1],"method":"mining.set_difficulty"}
<<< {"id":null,"params":["gTvmBBIuLW","00000000000005a6d2c1716b4ce0077d06cf6d6337ac2392f9e75821183fdea8","791dcae1813b2cd031208efad11c8dbc735195869e126cccd9eda08674eb0b0f","2716257b59d2ec7784efa547dc9cf035b489b9349477918303952458e7bd9714","1e2b44242c8ee57154496f66e9941d20aca69a3a239cb55a622f9b5d162a53ff","0000000000000000000000000000000000000000000000000000000000000000","00000000","1a06e782","5e49aa25"],"method":"mining.notify"}
>>> {"params":["hs1qqzlmrc6phwz2drwshstcr30vuhjacv5z0u2x9l.001","gTvmBBIuLW","aa923a8b","5e49aa25","73a37ddb","0000000000000000000000000000000000000000000000000000000000000000"],"id":"3","jsonrpc":"2.0","method":"mining.submit"}
<<< {"id":"3","result":true,"error":null}
```

