# lsconntrack

[license]: https://github.com/yuuki/lsconntrack/blob/master/LICENSE

## Setup

## How to use

```shell
# List connections source to localhost
lsconntrack --active 3306 11211
```

```shell
# List connections localhost to destination
lsconntrack --passive 80 443
```

### via stdin

```shell
cat /proc/net/nf_conntrack | lsconntrack --stdin --active 3306 11211
```

```shell
conntrack | lsconntrack --stdin --active 3306 11211
```

### json format

```shell
lsconntrack --json --active 3306 11211
```

## License

[MIT][license]

## Author

[yuuki](https://github.com/y_uuki)
