# Dependencies.  Executed on Ubuntu 24.04

sudo apt install sqlite3

## Some database commands

To see the content of the sqlite3 table as SQL:

```
$ sqlite3 ./openadp.db
sqlite> .dump
```

you also need to build the Python files for openadp.proto.  To into ../proto and follow the README.md there.
