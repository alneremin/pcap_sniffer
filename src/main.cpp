
#include "pcap_sniffer.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
        throw std::runtime_error("Specify device name!");

    std::shared_ptr<PcapSniffer> ps = PcapSniffer::GetSniffer();
    std::string device = std::string(argv[1]);
    ps->Connect(device);
    
    if (argc > 2)
    {
        std::string filter = std::string(argv[2]);
        ps->LoadFilter(argv[2]);
    }
    if (argc > 3)
    {
        std::string output_path = std::string(argv[3]);
        ps->AddWriter(output_path);
    }
    ps->Start();
}