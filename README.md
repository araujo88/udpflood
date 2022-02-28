# udpflood

UDP flood denial-of-service (DoS) attack coded in C using raw sockets. Generates random spoofed IPs at each new packet and random port number.

## Build

`make clean` <br>
`make`

## Usage

`sudo ./udpflood <target_ip_address> <number_of_threads> <payload> `

## Example

`sudo ./udpflood 1.2.3.4 1 OWNED`
