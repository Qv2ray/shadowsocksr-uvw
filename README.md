## Shadowsocksr-uvw

A minimal dependency shadowsocksr implementation.


## How to build

````bash
mkdir build
cd build
cmake .. -DSSR_UVW_WITH_QT=0
make
````



## Licence

shadowsocksr-uvw is under [GPLv3](LICENSE) licence.

## Dependencies


| Name                   | License        |
| ---------------------- | -------------- |
| [libuv](https://github.com/libuv/libuv)   | MIT |
| [uvw](https://github.com/skypjack/uvw) | MIT|
| [libsodium](https://libsodium.org) | ISC |
| [openssl](https://www.openssl.org/)| Apache|