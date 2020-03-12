## shadowsocksr-uvw

A minimal dependency shadowsocksr implementation.


## How to build

````bash
mkdir build
cd build
cmake .. -DSSR_UVW_WITH_QT=0
make
````



## Licence

shadowsocksr-uvw is under [GPLv3](LICENSE) licence. It's based on [uvw](https://github.com/skypjack/uvw) which is a header-only, event based, tiny and easy to use
[`libuv`](https://github.com/libuv/libuv) wrapper in modern C++.

## Link dependencies

| Name                   | License        |
| ---------------------- | -------------- |
| [libuv](https://github.com/libuv/libuv)   | MIT |
| [libsodium](https://libsodium.org) | ISC |
| [openssl](https://www.openssl.org/)| Apache|


