Sample Golang project for SSL handshake detecting.

Project is based on `libpcap` and `gopacket` go library.

Project detects SSL hanshake and print small session info into console + presents small web+websocket page for browser output.  

Building on Debian 10:
=
* Download and install Golang (for example into /opt/go/)
* Download required packages: `apt install git gcc libpcap-dev`
* Go into cmd directory
* Download related go modules `go get`
* Build binary `go build`

Here you are, you can use it now.

Run binary to get usage description.