## shadowsocksr-uvw

A minimal dependency shadowsocksr implementation.


## How to build
If you want shadowsocksr-uvw to avoid using the system's own libuv and libsodium, the default compilation options will be helpful. The compilation options are as follows, which will link libuv and libsodium statically.
````bash
git submodule update --init --recursive
mkdir build
cd build
cmake .. -DSSR_UVW_WITH_QT=0
make
````
By default, shadowsocksr-uvw will use the libuv and libsodium in the submodule for static linking. To avoid this, you can directly specify the compilation options as shown below.
````bash
mkdir build
cd build
cmake .. -DSSR_UVW_WITH_QT=0 -DUSE_SYSTEM_SODIUM=ON -DUSE_SYSTEM_LIBUV=ON -DSTATIC_LINK_LIBUV=OFF -DSTATIC_LINK_SODIUM=OFF
make
````

## Encrypto method

|                  |                  |                 |                 |                 |                |
| -----|-|-|-|-|-------------- | 
| none | rc4 | rc4-md5-6 | rc4-md5 ||||
| aes-128-cfb | aes-192-cfb | aes-256-cfb ||||
| aes-128-ctr | aes-192-ctr | aes-256-ctr ||||
| camellia-128-cfb | camellia-192-cfb | camellia-256-cfb ||||
| bf-cfb | cast5-cfb | des-cfb | idea-cfb | rc2-cfb | seed-cfb |
| salsa20 | chacha20 | chacha20-ietf ||||

## Protocols  

| Protocols |
| --------- | 
| origin |
| auth_sha1|
| auth_sha1_v2 |
| auth_sha1_v4 |
| auth_aes128_sha1 |
| auth_aes128_md5 |
| auth_chain_a |
| auth_chain_b |
| auth_chain_c |
| auth_chain_d |
| auth_chain_e |
| auth_chain_f |

## obfuscators

| obfuscators | 
| ----------- | 
| plain |
| http_simple |
| http_post |
| tls1.2_ticket_auth |


## Licence

shadowsocksr-uvw is under [GPLv3](LICENSE) licence. It's based on [uvw](https://github.com/skypjack/uvw) which is a header-only, event based, tiny and easy to use
[`libuv`](https://github.com/libuv/libuv) wrapper in modern C++.

## Link dependencies

| Name                   | License        |
| ---------------------- | -------------- |
| [libuv](https://github.com/libuv/libuv)   | MIT |
| [libsodium](https://libsodium.org) | ISC |
| [openssl](https://www.openssl.org/)| Apache|


