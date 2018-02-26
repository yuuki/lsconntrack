# lsconntrack

## Setup

## How to use

```shell
# List connections source to localhost
lsconntrack -a 3306 11211
```

```shell
# List connections localhost to destination
lsconntrack -p 80 443
```

### via stdin

```shell
sudo cat /proc/net/nf_conntrack | lsconntrack --stdin -a 3306 11211
```

```shell
conntrack | lsconntrack --stdin -a 3306 11211
```

## License

[MIT][license]

## Author

[yuuki](https://github.com/y_uuki)