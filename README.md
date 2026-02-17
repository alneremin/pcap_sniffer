
# Install

```bash

# check if pcap is installed
dpkg -l libpcap0.8-dev
# else
sudo apt install libpcap-dev
sudo apt install libnl-genl-3-dev
# or download later in build process

git clone https://github.com/alneremin/pcap_sniffer.git
cd pcap_sniffer
mkdir -p build && cd build
cmake ..
make
```

# Run

```bash
cd pcap_sniffer
sudo ./build/pcap_sniffer wlo1 --filter ./config/tcp_filter.pcap --output ./output_\$\(time\).csv --interval 1.0 --dumphex true
```

# Additional 

To compare metrics with each other you need to align the time on each computer
> In advance you need install OpenSSH server: ```sudo apt update && sudo apt install openssh-server -y```
```bash
sudo date --set="$(ssh name@%IP_v4% date +"%Y-%m-%dT%H:%M:%S")"
```