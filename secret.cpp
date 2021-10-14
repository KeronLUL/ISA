#include <stdio.h>
#include <iostream>
#include <getopt.h>
#include <string>


class ArgumentParser {
    public:
        std::string file = "";
        std::string ip = "";
        bool server = false;

    int argumentParser(int argc, char *argv[]){
        const char* const opts = "r:s:l";
        int opt = 0;
        opterr = 0;
        while ((opt = getopt(argc, argv, opts)) != EOF) {
            switch(opt) {
                case 'r':
                    file = optarg;
                    break;
                case 's':
                    ip = optarg;
                    break;
                case 'l':
                    server = true;
                    break;
                case '?':
                default:
                    std::cerr << "Invalid arguments\n";
                    return 1;
            }
        }

        if ((file == "" || ip == "") && !server) {
            std::cerr << "Missing some arguments\n";
            return 1;
        }

        return 0;
    }
};



int main(int argc, char *argv[]) {
    ArgumentParser args;
    if (args.argumentParser(argc, argv)) return 1;
    return 0;
}