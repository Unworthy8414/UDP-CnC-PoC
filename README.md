UDP-based Command and Control (C&C) PoC
=======================================

This is a proof of concept (PoC) implementation of a UDP-based Command and Control (C&C) server and client that demonstrates a novel approach to network communication for remote code execution.

The server listens for encrypted commands on a specified UDP port, decrypts them using AES encryption, and executes them on the local machine. The client sends encrypted commands to the server using UDP packets.

This PoC uses the ASIO library for network communication and the Crypto++ library for AES encryption. The AES encryption key is read from the environment variable `AES_KEY`. The PoC has been tested on Debian Linux.

Building and Running the PoC
----------------------------

To build the PoC, first install the required dependencies:

-   ASIO
-   Crypto++

Then, compile the `sender.cpp` and `receiver.cpp` files using `g++`:

```
g++ -std=c++11 -o sender sender.cpp -I asio-1.24.0/include -I /usr/include/cryptopp -L /usr/lib/x86_64-linux-gnu -lcryptopp -lpthread
g++ -std=c++11 -o receiver receiver.cpp -I asio-1.24.0/include -I /usr/include/cryptopp -L /usr/lib/x86_64-linux-gnu -lcryptopp -lpthread
```

To run the PoC, first set the `AES_KEY` environment variable:

```export AES_KEY=<your aes key> ```

Then start the server by running:

```./receiver <ip> <port> ```

Where `<ip>` is the IP address of the network interface to bind to and `<port>` is the UDP port to listen on.

Finally, start the client by running:

```./sender <src_ip> <src_port> <dst_ip> <dst_port> <command_file> [delay] ```

Where `<src_ip>` and `<src_port>` are the IP address and port of the client, `<dst_ip>` and `<dst_port>` are the IP address and port of the server, `<command_file>` is the path to a file containing a list of commands to execute, and `[delay]` is an optional delay (in seconds) between each command.

Disclaimer
----------

This PoC is for educational and research purposes only. Use at your own risk. The authors are not responsible for any misuse or damage caused by this software.

License
-------

This PoC is licensed under the GNU General Public License v3.0.
