#pragma once

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

class CsvWriter final
{  
    private:
        std::string output_path_;
        char delimeter_;
    public:
    
        CsvWriter(std::string path, char delimeter=';')
        : output_path_(path), delimeter_(delimeter) {
            std::ofstream file(path, std::ios::app);
            file.close();
        };

        static std::string Join(std::vector<std::string> data, char delimeter)
        {
            std::stringstream ss;
            for (std::size_t i = 0;
                 i < data.size();
                 ++i)
                ss << data[i] << delimeter;
            ss << std::endl;
            return ss.str();
        }

        bool Write(std::vector<std::string> data)
        {
            std::ofstream file(output_path_, std::ios::app);
            file << CsvWriter::Join(data, delimeter_);
            file.close();
            return true;
        }
};