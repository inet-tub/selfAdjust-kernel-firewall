# Instructions to build nftables front end tool
- checkout the commit for version 0.9.8
``` bash
git clone -n git://git.netfilter.org/nftables
cd nftables
git checkout c487209984d5d7c504255a79815e937802b4f020
cd ..
```

- apply these patches
- make sure that the paths are correct
```bash
patch -ruN -d nftables/src/ < nftables_patches/nft2_src.patch
patch -ruN -d nftables/include/ < nftables_patches/nft2_include.patch
patch -ruN -d nftables/include/linux/netfilter/ < nftables_patches/nft2_include_linux_netfilter.patch
```
- follow the install instructions documented in nftables/INSTALL