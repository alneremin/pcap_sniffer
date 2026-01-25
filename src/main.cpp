
#include "pcap_sniffer.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
        throw std::runtime_error("Specify device name!");

    std::shared_ptr<PcapSniffer> ps = PcapSniffer::GetSniffer();
    std::string device = std::string(argv[1]);
    ps->Connect(device);

    for (std::size_t i = 2; i < argc; i += 2) {
        std::string arg = argv[i];

        if (arg == "--filter" && i + 1 < argc) 
        {
            ps->LoadFilter(std::string(argv[i + 1]));
        } 
        else if (arg == "--output" && i + 1 < argc) 
        {
            ps->AddWriter(std::string(argv[i + 1]));
        }
        else if (arg == "--interval" && i + 1 < argc) 
        {
            ps->SetDumpInterval(std::atof(argv[i + 1]));
            std::cout << "Dump interval: " << ps->GetDumpInterval() << std::endl;
        }
        else if (arg == "--dumphex" && i + 1 < argc) 
        {
            ps->SetDumpHex(std::string(argv[i + 1]) == "true");
            std::cout << "Dump hex flag: " << ps->DumpHex() << std::endl;
        }
        else 
        {
            throw std::runtime_error("Unknown argument or missing value: " + arg);
        }
    }

    ps->Start();
}