# Dependencies.  Executed on Ubuntu 24.04

sudo apt install sqlite3

## Some database commands

To see the content of the sqlite3 table as SQL:

```
$ sqlite3 ./openadp.db
sqlite> .dump
```

you also need to build the Python files for openadp.proto.  To into ../proto and follow the README.md there.

## Installiing openadp service for Debian based systems.

1. Run the installation script
```
cd /home/waywardgeek/projects/openadp/prototype
sudo ./install-openadp-service.sh
```
2. Start the service
```
sudo systemctl start openadp-server
```
3. Enable auto-start on boot
```
sudo systemctl enable openadp-server
```
4. Check status
```
sudo systemctl status openadp-server
```
5. View logs
```
sudo journalctl -u openadp-server -f
```

## Service management commands

Start service
```
sudo systemctl start openadp-server
```

Stop service
```
sudo systemctl stop openadp-server
```

Restart service
```
sudo systemctl restart openadp-server
```

Enable auto-start on boot
```
sudo systemctl enable openadp-server
```

Disable auto-start
```
sudo systemctl disable openadp-server
```

Check status
```
sudo systemctl status openadp-server
```

View logs (follow)
```
sudo journalctl -u openadp-server -f
```

View recent logs
```
sudo journalctl -u openadp-server --since "1 hour ago"
```
