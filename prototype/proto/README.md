# Doesn't work with Cloudflare

Apparently, you can't write servers that handle gRPC requests behind
Cloudflare.  This seems super lame, but until this changes or until we no
longer support running bhind Cloudflare, we can't use anything but HTTP
requests.

Cloudflare _does_ support gRPC between tunnel endpoints via private networks.
Their public messaging is conofusing, saying only that they support gRPC, and
when you try to follow their docs, you don't find out you're screwed until your
server is running, and you can't connect from tthe client.

# Compiling

First, install python3-grpcio and python3-grpcio-tools

```
$ sudo apt install python3-grpcio opython3-grpcio-tools
```

Then, you shuld be able to compile the proto with:

```
`python3 -m grpc_tools.protoc -I. --python_out=../prototype --grpc_python_out=../prototype ./openadp.proto``
```
