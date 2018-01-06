# Curipaca

### CURIous alPACA -- decompiler exerimentation

This decompiler runs the following steps:

1. Disassembly (figuring out which bytes are code, which are data and disassembling the code bytes)
2. Function Recovery (finding out which instruction sequences make up a higher level function)
3. Prototype Recovery (find inputs and outputs of a function)
4. ...

There needs to be a comfortable way to insert corrections into each of these steps, because none of them will yield perfect results.
