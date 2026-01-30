
# Install

```bash

# check if pcap is installed
dpkg -l libpcap0.8-dev
# else
sudo apt install libpcap-dev

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