
#pragma once

// PCAP/Net
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

// STL
#include <string>
#include <fstream>
#include <unistd.h>
#include <memory>

// manipulate date
#include <chrono>
#include <cstdint>

// write data
#include <iostream>
#include "csv_writer.h"


#define SNIFF_BUFFER BUFSIZ
void handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int64_t get_current_time();
void dump_hex(const void* data, size_t size);

// enum class DUMP_SOURCE { DUMP_FILE, DUMP_SCREEN };

class PcapSniffer 
{
    private:
        std::string device_;
        pcap_t *handle_;
        char error_buffer_[PCAP_ERRBUF_SIZE];
        struct bpf_program filter_;
        bpf_u_int32 subnet_mask_; 
        bpf_u_int32 ip_;
        pcap_handler* func_;
        bool connected_ = false;
        std::shared_ptr<CsvWriter> writer_;
    public:
        void Connect(std::string device);
        void LoadFilter(std::string filter_path);
        void AddWriter(std::string output_path);
        std::string LoadData(std::string filter_path);
        void Start();
        bool IsLoaded();
        PcapSniffer();
        void Handler(
            u_char *args,
            const struct pcap_pkthdr *header,
            const u_char *packet
        );

        static std::shared_ptr<PcapSniffer> GetSniffer();
};

