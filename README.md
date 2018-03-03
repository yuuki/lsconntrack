# lsconntrack

[![Build Status](https://travis-ci.org/yuuki/lsconntrack.png?branch=master)][travis]
[![Go Report Card](https://goreportcard.com/badge/github.com/yuuki/lsconntrack)][goreportcard]

[license]: https://github.com/yuuki/lsconntrack/blob/master/LICENSE
[travis]: https://travis-ci.org/yuuki/lsconntrack
[goreportcard]: (https://goreportcard.com/report/github.com/yuuki/lsconntrack)

lsconntrack prints aggregated connections tracked by Linux netfilter conntrack and enables you to simply grasp the network relationship between localhost and other hosts.

## Setup

- Load ip_conntrack / nf_conntrack module
- Download the binary from https://github.com/yuuki/lsconntrack/releases .

## How to use

```shell
$ lsconntrack -n
Local Address:Port	 <--> 	Peer Address:Port 		Inpkts 	Inbytes     Outpkts Outbytes
localhost:many       -->    10.0.1.10:3306		    5521792 123258667	5423865 282041045
localhost:many       -->    10.0.1.11:3306		    58800   3062451	    58813   3061627
localhost:many       -->    10.0.1.20:8080		    123     169638	    62      3580
localhost:80         <--    10.0.2.10:80			23	    6416	    25	    25460
localhost:80         <--    10.0.2.11:80			38	    8574	    34	    32752
```

```shell
# Prints active open connections from localhost to destination hosts.
$ lsconntrack --active
Local Address:Port	 <--> 	Peer Address:Port 		Inpkts 	Inbytes     Outpkts Outbytes
localhost:many       -->    10.0.1.10:3306		    5521792 123258667	5423865 282041045
localhost:many       -->    10.0.1.11:3306		    58800   3062451	    58813   3061627
localhost:many       -->    10.0.1.20:8080		    123     169638	    62      3580
...
```

```shell
# Prints passive open connections from destination hosts to localhost.
$ lsconntrack --passive
Local Address:Port	 <--> 	Peer Address:Port 		Inpkts 	Inbytes     Outpkts Outbytes
localhost:80         <--    10.0.2.10:80			23	    6416	    25	    25460
localhost:80         <--    10.0.2.11:80			38	    8574	    34	    32752
...
```

### filter by port

```shell
$ lsconntrack --active --aport 3306 --aport 11211
```

### via stdin

```shell
$ cat /proc/net/nf_conntrack | lsconntrack --stdin
```

### json format

```shell
$ lsconntrack --json
```

## License

[MIT][license]

## Author

[yuuki](https://github.com/y_uuki)
