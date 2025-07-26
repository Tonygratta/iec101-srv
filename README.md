# iec101-srv

A simple IEC60870-5-101 server library written in Python for testing purposes.

This library contains a server implementation called `server-async.py`, which implements a TCP IEC60870-5-101 server. It also includes a random telemetry generator and a data corruption imitator to test clients.

The dependencies for this library are:

- scapy
- scapy-iec101 (available at https://github.com/Tonygratta/scapy-iec101)

To install scapy, you can use the following command:

```
pip install scapy
```

After installing scapy, simply copy the `iec101.py` file from the scapy-iec101 repository to the server directory to complete the installation.

To run the server, you can run the following command from the server directory:

```python
python3 server-async.py
```
Tested on Python 3.12 on Windows.

Any questions are welcome.
