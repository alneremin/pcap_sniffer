
#include "pcap_sniffer.h"

PcapSniffer::PcapSniffer(): dump_interval_(1.0), payload_length_(0), dump_hex_(false) {}

bool PcapSniffer::IsLoaded()
{ 
    return connected_; 
}

void PcapSniffer::Connect(std::string device)
{
    device_ = device;
    if (pcap_lookupnet(device_.c_str(), &ip_, &subnet_mask_, error_buffer_) == -1) {
        throw std::runtime_error("Could not get information for device: " + device);
    }

    handle_ = pcap_open_live(device_.c_str(), SNIFF_BUFFER, 1, 10000, error_buffer_);
    if (handle_ == NULL) {
        throw std::runtime_error("Could not open: " + device + " - " + std::string(error_buffer_));
    }
    std::cout << "Device: " << device << std::endl;
    connected_ = true;
}

void PcapSniffer::LoadFilter(std::string filter_path)
{
    if (!IsLoaded())
        throw std::runtime_error("Module has been not loaded!\n Call Load() function");

    const char* filter_exp = LoadData(filter_path).c_str();
    std::cout << "Filter: " << std::string(filter_exp) << std::endl;
    if (pcap_compile(handle_, &filter_, filter_exp, 0, ip_) == -1) {
        throw std::runtime_error("Bad filter - " + std::string(pcap_geterr(handle_)));
    }
    int status = pcap_setfilter(handle_, &filter_);

    std::cout << "Filter status: " << status << std::endl;
    if (status == -1)
        throw std::runtime_error("Error setting filter - " + std::string(pcap_geterr(handle_)));
}

std::string PcapSniffer::LoadData(std::string filter_path)
{
    std::ifstream inputFile(filter_path);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Error: Unable to open file " + filter_path);
    }

    std::string line;
    if (std::getline(inputFile, line))
        return line;
    else
        std::cout << "Configuration file in empty!" << std::endl;

    inputFile.close();
    return line;
}

void PcapSniffer::AddWriter(std::string output_path)
{
    std::string pattern = "$(time)";
    size_t pos = output_path.find("$(time)");

    if (pos != std::string::npos) {
        output_path.replace(pos, pattern.length(), get_current_time_as_string());
    }

    writer_ = std::make_shared<CsvWriter>(output_path);
    std::cout << "Writer output path: " << output_path << std::endl;
}

void PcapSniffer::Start()
{
    if (!IsLoaded())
        throw std::runtime_error("Module has been not loaded!\n Call Load() function");

    int total_packet_count = -1;
    u_char *my_arguments = NULL;

    start_time_ = get_current_time_sec();
    pcap_loop(handle_, 
              total_packet_count,
              handler,
              my_arguments);
}

void handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    return PcapSniffer::GetSniffer()->Handler(args, header, packet);
}

std::shared_ptr<PcapSniffer> PcapSniffer::GetSniffer()
{
    static std::shared_ptr<PcapSniffer> sniffer;
    if (!sniffer)
        sniffer = std::make_shared<PcapSniffer>();
    return sniffer;
}

void PcapSniffer::Handler(
            u_char *args,
            const struct pcap_pkthdr *header,
            const u_char *packet
        )
{
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        // printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    // printf("Total packet available: %d bytes\n", header->caplen);
    // printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    // printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        // printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    // printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    // printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    
    if (payload_length)
        std::cout << "Payload size: " << payload_length << " bytes" << std::endl;
    payload = packet + total_headers_size;
    // printf("Memory address where payload begins: %p\n\n", payload);

    /* Print payload in ASCII */
    // int payload_len = header->len - total_headers_size;
    if (dump_hex_)
        dump_hex(payload, payload_length);

    payload_length_ += payload_length;
    if (get_current_time_sec() - start_time_ > dump_interval_) 
    {
        std::cout << "Total payload size: " << payload_length_ << std::endl;
        start_time_ = get_current_time_sec();

        if (writer_)
            writer_->Write({
                std::to_string(get_current_time()),
                // std::to_string(total_headers_size),
                std::to_string(payload_length_),
            });

        payload_length_ = 0;
    }
    
    return;
}

void dump_hex(const void* data, size_t size)
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

int64_t get_current_time()
{
    // Get the current time point with nanosecond precision
    auto now = std::chrono::time_point_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now()
    );

    // Get the duration since the epoch (1970-01-01 00:00:00 UTC)
    std::chrono::nanoseconds ns = now.time_since_epoch();

    // Get the count as a 64-bit integer
    int64_t total_nanoseconds = ns.count();

    return total_nanoseconds;
}

double get_current_time_sec()
{
    // Get the current time point with nanosecond precision
    auto now = std::chrono::time_point_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now()
    );

    // Get the duration since the epoch (1970-01-01 00:00:00 UTC)
    std::chrono::nanoseconds ns = now.time_since_epoch();

    return get_current_time() / 1000000000;
}

std::string get_current_time_as_string() 
{
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    std::tm* local_tm = std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(local_tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}