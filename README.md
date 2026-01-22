
# Install

```bash
sudo apt install libpcap-dev

mkdir -p ~/your_ws/src
cd ~/your_ws/src
git clone https://github.com/alneremin/pcap_sniffer.git
cd ..
catkin build
```

# Run

```bash
source your_ws/devel/setup.bash
sudo ~/your_ws/devel/.private/pcap_sniffer/lib/pcap_sniffer/pcap_sniffer lo ~/your_ws/src/pcap_sniffer/config/tcp_filter.pcap ~/your_ws/src/pcap_sniffer/output_\$\(time\).csv
```