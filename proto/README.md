# Compiling

First, install python3-grpcio and python3-grpcio-tools

```
$ sudo apt install python3-grpcio opython3-grpcio-tools
```

Then, you shuld be able to compile the proto with:

```
`python3 -m grpc_tools.protoc -I. --python_out=../prototype --grpc_python_out=../prototype ./openadp.proto``
```
