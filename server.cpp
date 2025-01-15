//cl server.cpp /std:c++20

#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <aclapi.h>
#include <cstdio>
#include <iostream>
#include <string>
#include <Sddl.h>
#include <format>

#pragma comment (lib, "ws2_32.lib" )
#pragma comment (lib, "mswsock.lib")
#pragma comment (lib, "Advapi32.lib")
#pragma warning (disable: 4996)

#define MAX_CLIENTS (100)

const unsigned receivingBufferSize = 512;
const unsigned sendingBufferSize = 16384;

struct clientInfo {
    int socket;
    CHAR receivingBuffer[receivingBufferSize];
    CHAR sendingBuffer[sendingBufferSize];

    unsigned int receiveDataLength;
    unsigned int sendDataLength;
    unsigned int sz_send;

    OVERLAPPED overlap_recv;
    OVERLAPPED overlap_send;
    OVERLAPPED overlap_cancel;
    DWORD flags_recv;
};

enum objectType {
    File,
    Directory,
    RegisterKey
};

struct clientInfo Clients[1 + MAX_CLIENTS];
int acceptedSocket;
HANDLE ioPort;
HCRYPTPROV descCSP[1 + MAX_CLIENTS] = {0};
HCRYPTKEY descKey[1 + MAX_CLIENTS] = {0};
HCRYPTKEY descKeyOpen[1 + MAX_CLIENTS] = {0};

int isStringReceived(DWORD idx, int* len) {
    for (DWORD i = 0; i < Clients[idx].receiveDataLength; i++)
        if (Clients[idx].receivingBuffer[i] == '\n') {
            *len = (int)(i + 1);
            return 1;
        }

    if (Clients[idx].receiveDataLength == sizeof(Clients[idx].receivingBuffer)) {
        *len = sizeof(Clients[idx].receivingBuffer);
        return 1;
    }
    return 1;
}
std::string ipToString(unsigned ip) {
    return { std::to_string((ip >> 24) & 0xff) + "." + std::to_string((ip >> 16) & 0xff) +
            "." + std::to_string((ip >> 8) & 0xff) + "." + std::to_string((ip) & 0xff) };
}

void schedule_read(DWORD idx) {
    WSABUF buf;
    buf.buf = Clients[idx].receivingBuffer + Clients[idx].receiveDataLength;
    buf.len = sizeof(Clients[idx].receivingBuffer) - Clients[idx].receiveDataLength;
    memset(&Clients[idx].overlap_recv, 0, sizeof(OVERLAPPED));
    Clients[idx].flags_recv = 0;
    WSARecv(Clients[idx].socket, &buf, 1, nullptr, &Clients[idx].flags_recv, &Clients[idx].overlap_recv, nullptr);
}

void schedule_write(DWORD idx) {
    WSABUF buf;
    buf.buf = Clients[idx].sendingBuffer + Clients[idx].sz_send;
    buf.len = Clients[idx].sendDataLength - Clients[idx].sz_send;
    memset(&Clients[idx].overlap_send, 0, sizeof(OVERLAPPED));
    WSASend(Clients[idx].socket, &buf, 1, nullptr, 0, &Clients[idx].overlap_send, nullptr);
}

void add_accepted_connection() {
    for (auto index = 0; index < sizeof(Clients) / sizeof(Clients[0]); index++) {
        if (Clients[index].socket == 0) {
            sockaddr_in* local_addr = nullptr;
            sockaddr_in* remote_addr = nullptr;

            int local_addr_sz, remote_addr_sz;
            GetAcceptExSockaddrs(
                Clients[0].receivingBuffer,
                Clients[0].receiveDataLength,
                sizeof(sockaddr_in) + 16,
                sizeof(sockaddr_in) + 16,
                (sockaddr**)&local_addr,
                &local_addr_sz,
                (sockaddr**)&remote_addr,
                &remote_addr_sz);

            unsigned int ip = 0;
            if (remote_addr)
                ip = ntohl(remote_addr->sin_addr.s_addr);

            std::cout << "Client " << (int)index << " connected: " << ipToString(ip) << std::endl;

            Clients[index].socket = acceptedSocket;

            if (CreateIoCompletionPort((HANDLE)Clients[index].socket, ioPort, index, 0) == nullptr) {
                std::cout << "CreateIoCompletionPort error: " << (int)GetLastError() << std::endl;
                return;
            }

            schedule_read(index);
            return;
        }
    }

    closesocket(acceptedSocket);
    acceptedSocket = 0;
}

void schedule_accept() {
    acceptedSocket = WSASocket(AF_INET, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);
    memset(&Clients[0].overlap_recv, 0, sizeof(OVERLAPPED));
    AcceptEx(
        Clients[0].socket,
        acceptedSocket,
        Clients[0].receivingBuffer,
        0,
        sizeof(sockaddr_in) + 16,
        sizeof(sockaddr_in) + 16,
        nullptr,
        &Clients[0].overlap_recv);
}

void Error() {
    std::cerr << "Error: " << (int)GetLastError() << std::endl;
}

void getAndSetSystem(char* buffer) {
    OSVERSIONINFOEXW osVersion;
    ZeroMemory(&osVersion, sizeof(OSVERSIONINFOEXW));

    osVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    GetVersionExW((LPOSVERSIONINFOW)&osVersion);

    switch (osVersion.dwMajorVersion) {
    case 4:
        switch (osVersion.dwMinorVersion) {
        case 0:
            strcpy(buffer, "OS: Windows 95\n\0");
            break;
        case 10:
            strcpy(buffer, "OS: Windows 98\n\0");
            break;
        case 90:
            strcpy(buffer, "OS: WindowsMe\n\0");
            break;
        default:
            strcpy(buffer, "Unknown OS\n\0");
            break;
        }
        break;
    case 5:
        switch (osVersion.dwMinorVersion) {
        case 0:
            strcpy(buffer, "OS: Windows 2000\n\0");
            break;
        case 1:
            strcpy(buffer, "OS: Windows XP\n\0");
            break;
        case 2:
            strcpy(buffer, "OS: Windows 2003\n\0");
            break;
        default:
            strcpy(buffer, "Unknown OS\n\0");
            break;
        }
        break;
    case 6:
        switch (osVersion.dwMinorVersion) {
        case 0:
            strcpy(buffer, "OS: Windows Vista\n\0");
            break;
        case 1:
            strcpy(buffer, "OS: Windows 7\n\0");
            break;
        case 2:
            strcpy(buffer, "OS: Windows 10\n\0");
            break;
        case 3:
            strcpy(buffer, "Unknown OS\n\0");
            break;
        }
        break;
    default:
        strcpy(buffer, "Unknown OS\n\0");
        break;
    }
}

void getAndSetCurrentTime(char* buffer) {
    SYSTEMTIME sysTime;
    GetLocalTime(&sysTime);

    strcpy(buffer, "Current time: ");

    auto pos = 14;
    if (sysTime.wDay < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wDay;
    }
    else {
        strncpy(buffer + pos, std::to_string(sysTime.wDay).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = '.';

    if (sysTime.wMonth < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wMonth;
    }
    else {
        strncpy(buffer + pos, std::to_string(sysTime.wMonth).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = '.';

    strncpy(buffer + pos, std::to_string(sysTime.wYear).c_str(), 4);
    pos += 4;
    buffer[pos++] = ' ';

    if (sysTime.wHour < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wHour;
    }
    else {
        strncpy(buffer + pos, std::to_string(sysTime.wHour).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = ':';

    if (sysTime.wMinute < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wMinute;
    }
    else {
        strncpy(buffer + pos, std::to_string(sysTime.wMinute).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = ':';

    if (sysTime.wSecond < 10) {
        buffer[pos++] = '0';
        buffer[pos++] = '0' + sysTime.wSecond;
    }
    else {
        strncpy(buffer + pos, std::to_string(sysTime.wSecond).c_str(), 2);
        pos += 2;
    }
    buffer[pos++] = '\n';
    buffer[pos] = 0;
}

void getAndSetTimeSinceLaunch(char* buffer) {
    auto time = GetTickCount();
    auto hours = time / (1000 * 60 * 60) ;
    auto minutes = time / (1000 * 60) % 60;
    auto seconds = (time / 1000) % 60;
    std::string tmp = "Time since the launch: " + std::to_string(hours) + ":" + std::to_string(minutes) + ":" + std::to_string(seconds) + "\n";
    strncpy(buffer, tmp.c_str(), tmp.length());
}

void getAndSetMemoryInfo(char* buffer) {
    MEMORYSTATUSEX status;

    status.dwLength = sizeof (status);

    GlobalMemoryStatusEx(&status);

    std::string text = "";

    text += std::format("RAM usage: {}%.\n", status.dwMemoryLoad);
    text += std::format("In total: {:.2f} Gb.\n", status.ullTotalPhys / 1024.0 / 1024.0 / 1024.0);
    text += std::format("Not occupied: {:.2f} Gb.\n", status.ullAvailPhys / 1024.0 / 1024.0 / 1024.0);
    text += std::format("Maximum available for programs: {:.2f} Gb.\n", status.ullTotalPageFile / 1024.0 / 1024.0 / 1024.0);
    text += std::format("Not occupied: {:.2f} Gb.\n", status.ullAvailPageFile / 1024.0 / 1024.0 / 1024.0);
    text += std::format("Maximum available virtual: {:.2f} Gb.\n", status.ullTotalVirtual / 1024.0 / 1024.0 / 1024.0);
    text += std::format("Not occupied: {:.2f} Gb.\n", status.ullAvailVirtual / 1024.0 / 1024.0 / 1024.0);

    strcpy(buffer, text.c_str());
    buffer[text.size()] = '\n';
    buffer[text.size() + 1] = 0;
}

void getAndSetDisksInfo(char* buffer) {
    static const auto mostAvailableDisks = 26;
    char disks[mostAvailableDisks][3] = { 0 };
    DWORD drives = GetLogicalDrives();
    auto pos = 0;
    for (int i = 0, count = 0; i < 26; i++)
        if (((drives >> i) & 0x00000001) == 1) {
            disks[count][0] = static_cast<char>(static_cast<int>('A') + i);
            disks[count][1] = ':';
            std::string text = std::string(1, *disks[count]) + ": ";

            switch (GetDriveTypeA(disks[count])) {
            case 0:
                text += std::string("Unknown.\n");
                break;
            case 1:
                text += std::string("Root path is invalid.\n");
                break;
            case 2:
                text += std::string("Removable.\n");
                break;
            case 3:
                text += std::string("Static.\n");
                break;
            case 4:
                text += std::string("Network.\n");
                break;
            case 5:
                text += std::string("CD-ROM.\n");
                break;
            case 6:
                text += std::string("RAM.\n");
                break;
            default:
                break;
            }
            strcpy(buffer + pos, text.c_str());
            pos += strlen(text.c_str());
            count++;
        }

}
void getAndSetAvailableDiskSpace(char* buffer) {
    std::string text = "";
    static const auto mostAvailableDisks = 26;
    char disks[mostAvailableDisks][3] = { 0 };
    DWORD drives = GetLogicalDrives();
    auto pos = 0;
    for (auto i = 0, count = 0; i < 26; i++)
        if (((drives >> i) & 0x00000001) == 1) {
            disks[count][0] = static_cast<char>(static_cast<int>('A') + i);
            disks[count][1] = ':';
            if (GetDriveTypeA(disks[count]) == DRIVE_FIXED || GetDriveTypeA(disks[count]) == DRIVE_REMOVABLE) {
                unsigned long long lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes;
                GetDiskFreeSpaceEx(
                    (LPCSTR) disks[count],
                    (PULARGE_INTEGER)&lpFreeBytesAvailable,
                    (PULARGE_INTEGER)&lpTotalNumberOfBytes,
                    (PULARGE_INTEGER)&lpTotalNumberOfFreeBytes
                );
                text += std::format("Disk {}: ", disks[count][0]);
                text += std::format("{:.2f} Gb available.\n", lpTotalNumberOfFreeBytes / 1024.0 / 1024.0 / 1024.0);
            }
            count++;
        }
    strcpy(buffer, text.c_str());
}

void getAndSetAccessRights(const std::string& filename, enum objectType type, char* buffer) {
    static const std::string pathError = "Error. Unable to find the file.";
    PACL dACL;
    ACL_SIZE_INFORMATION aclSize;
    PSECURITY_DESCRIPTOR pSD;
    ACCESS_ALLOWED_ACE* pACE;

    char objectType;
    if (type == RegisterKey) objectType = SE_REGISTRY_KEY;
    if (type == File) objectType = SE_FILE_OBJECT;
    if (type == Directory) objectType = SE_FILE_OBJECT;

    if (GetNamedSecurityInfoA(
        filename.c_str(),
        (SE_OBJECT_TYPE)objectType,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &dACL,
        nullptr,
        &pSD) != ERROR_SUCCESS) {
        strcpy(buffer, pathError.c_str());
        return;
    }

    GetAclInformation(dACL, &aclSize, sizeof(aclSize), AclSizeInformation);

    const auto size = 256;
    char user[size] = { 0 };
    char domain[size] = { 0 };

    std::string result;

    for (auto i = 0; i < aclSize.AceCount; ++i) {
        memset(user, 0, size);
        memset(domain, 0, size);

        GetAce(dACL, i, (PVOID*)&pACE);
        PSID pSID = (PSID)(&(pACE->SidStart));

        DWORD dUserSize = sizeof(user);
        DWORD dDomainSize = sizeof(domain);
        SID_NAME_USE sidName;
        LPSTR sSID = nullptr;

        if (LookupAccountSidA(
            nullptr,
            pSID,
            user,
            &dUserSize,
            domain,
            &dDomainSize,
            &sidName)) {

            ConvertSidToStringSidA(pSID, &sSID);
            result += std::string("# Account: ") + domain + " | " + user + ".\n" + "Sid: " + sSID + ".\n" + "Ace objectType: ";

            switch (pACE->Header.AceType) {
            case ACCESS_DENIED_ACE_TYPE:
                result += "access denied.\n";
                break;
            case ACCESS_ALLOWED_ACE_TYPE:
                result += "access allowed.\n";
                break;
            default:
                result += "audit.\n";
            }

            std::string mask = "Access mask: ";
            for (auto j = 0; j < 32; ++j)
                mask += static_cast<char>('0' + pACE->Mask / (1 << (31 - j)) % 2);
            result += mask + ".\nGeneric rights:\n";

            if (((ACCESS_ALLOWED_ACE*)pACE)->Mask & 1) result += "\tGeneric read.\n";
            if (((ACCESS_ALLOWED_ACE*)pACE)->Mask & 2) result += "\tGeneric write.\n";
            if (((ACCESS_ALLOWED_ACE*)pACE)->Mask & 4) result += "\tGeneric execute.\n";
            if (((ACCESS_ALLOWED_ACE*)pACE)->Mask & GENERIC_ALL) result += "\tGeneric all.\n";

            result += "Standart rights:\n";

            if ((pACE->Mask & SYNCHRONIZE) == SYNCHRONIZE) result += "\tSynchronise.\n";
            if ((pACE->Mask & WRITE_OWNER) == WRITE_OWNER) result += "\tWrite owner.\n";
            if ((pACE->Mask & WRITE_DAC) == WRITE_DAC) result += "\tWrite DAC.\n";
        }

        if ((pACE->Mask & READ_CONTROL) == READ_CONTROL) result += "\tRead control.\n";
        if ((pACE->Mask & DELETE) == DELETE) result += "\tDelete.\n";

        if (type == Directory) {
            result += "Additional rights for directory:\n";
            if ((pACE->Mask & FILE_LIST_DIRECTORY) == FILE_LIST_DIRECTORY) result += "\tFILE_LIST_DIRECTORY\n";
            if ((pACE->Mask & FILE_ADD_FILE) == FILE_ADD_FILE) result += "\tFILE_ADD_FILE\n";
            if ((pACE->Mask & FILE_ADD_SUBDIRECTORY) == FILE_ADD_SUBDIRECTORY) result += "\tFILE_ADD_SUBDIRECTORY\n";
            if ((pACE->Mask & FILE_READ_EA) == FILE_READ_EA) result += "\tFILE_READ_EA\n";
            if ((pACE->Mask & FILE_WRITE_EA) == FILE_WRITE_EA) result += "\tFILE_WRITE_EA\n";
            if ((pACE->Mask & FILE_TRAVERSE) == FILE_TRAVERSE) result += "\tFILE_TRAVERSE\n";
            if ((pACE->Mask & FILE_DELETE_CHILD) == FILE_DELETE_CHILD) result += "\tFILE_DELETE_CHILD\n";
            if ((pACE->Mask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES) result += "\tFILE_READ_ATTRIBUTES\n";
            if ((pACE->Mask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES) result += "\tFILE_WRITE_ATTRIBUTES\n";
        }

        if (type == File) {
            result += "Additional rights for file:\n";
            if ((pACE->Mask & FILE_READ_DATA) == FILE_READ_DATA) result += "\tFILE_READ_DATA\n";
            if ((pACE->Mask & FILE_WRITE_DATA) == FILE_WRITE_DATA) result += "\tFILE_WRITE_DATA\n";
            if ((pACE->Mask & FILE_APPEND_DATA) == FILE_APPEND_DATA) result += "\tFILE_APPEND_DATA\n";
            if ((pACE->Mask & FILE_READ_EA) == FILE_READ_EA) result += "\tFILE_READ_EA\n";
            if ((pACE->Mask & FILE_WRITE_EA) == FILE_WRITE_EA) result += "\tFILE_WRITE_EA\n";
            if ((pACE->Mask & FILE_EXECUTE) == FILE_EXECUTE) result += "\tFILE_EXECUTE\n";
            if ((pACE->Mask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES) result += "\tFILE_READ_ATTRIBUTES\n";
            if ((pACE->Mask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES) result += "\tFILE_WRITE_ATTRIBUTES\n";
        }

        if (type == RegisterKey) {
            result += "Register key permissions:\n";
            if ((pACE->Mask & KEY_CREATE_SUB_KEY) == KEY_CREATE_SUB_KEY) result += "\tKEY_CREATE_SUB_KEY\n ";
            if ((pACE->Mask & KEY_ENUMERATE_SUB_KEYS) == KEY_ENUMERATE_SUB_KEYS)
                result += "\tKEY_ENUMERATE_SUB_KEYS\n ";
            if ((pACE->Mask & KEY_NOTIFY) == KEY_NOTIFY) result += "\tKEY_NOTIFY\n ";
            if ((pACE->Mask & KEY_QUERY_VALUE) == KEY_QUERY_VALUE) result += "\tKEY_QUERY_VALUE\n ";
            if ((pACE->Mask & KEY_SET_VALUE) == KEY_SET_VALUE) result += "\tKEY_SET_VALUE\n ";
        }
        result += '\n';
    }
    strcpy(buffer, result.c_str());
}

void getAndSetOwner(const std::string& filename, enum objectType type, char* buffer) {
    DWORD dwRes = 0;
    PSID ownerSID;
    PSECURITY_DESCRIPTOR pSD;

    char objectType;
    if (type == RegisterKey) objectType = SE_REGISTRY_KEY;
    if (type == File) objectType = SE_FILE_OBJECT;
    if (type == Directory) objectType = SE_FILE_OBJECT;

    dwRes = GetNamedSecurityInfoA(filename.c_str(), (SE_OBJECT_TYPE)objectType,
            OWNER_SECURITY_INFORMATION, &ownerSID, nullptr, nullptr, nullptr, &pSD);

    if (dwRes != ERROR_SUCCESS) {
        std::cerr << "Error in receiving owner's information" << std::endl;
        LocalFree(pSD);
    }

    char szOwnerName[1024] = { 0 };
    char szDomainName[1024] = { 0 };
    DWORD dwUsetNameLength = sizeof(szOwnerName);
    DWORD dwDomainNameLength = sizeof(szDomainName);
    SID_NAME_USE sidUse;

    dwRes = LookupAccountSidA(nullptr, ownerSID, szOwnerName,
        &dwUsetNameLength, szDomainName, &dwDomainNameLength, &sidUse);

    if (dwRes == 0)
        std::cerr << "Error in receiving owner's information" << std::endl;

    std::string result = "Owner: " + std::string(szOwnerName) + ". Domain: " + std::string(szDomainName) + ".\n";
    strcpy(buffer, result.c_str());
}

void exitClient(unsigned clientNumber) {
    descCSP[clientNumber] = 0;
    descKey[clientNumber] = 0;
    descKeyOpen[clientNumber] = 0;
    memset(Clients[clientNumber].sendingBuffer, 0, sendingBufferSize);
    CancelIo((HANDLE)Clients[clientNumber].socket);
    PostQueuedCompletionStatus(ioPort, 0, clientNumber, &Clients[clientNumber].overlap_cancel);
}

void createCryptedConnection(int clientNumber) {
    if (!CryptAcquireContext(&descCSP[clientNumber], nullptr, MS_ENHANCED_PROV, PROV_RSA_FULL, NULL)
        && !CryptAcquireContext(&descCSP[clientNumber], nullptr, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
        Error();

    if (CryptGenKey(descCSP[clientNumber], CALG_RC4, (CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT), descKey + clientNumber) == 0)
        Error();

    auto tLen = 255;
    for (; tLen >= 0 && Clients[clientNumber].receivingBuffer[tLen] == 0; --tLen);
    unsigned int len = (unsigned char)Clients[clientNumber].receivingBuffer[tLen];
    Clients[clientNumber].receivingBuffer[tLen] = 0;

    if (!CryptImportKey(
        descCSP[clientNumber], (BYTE*)Clients[clientNumber].receivingBuffer,
        len, 0, 0, descKeyOpen + clientNumber))
        {std::cout << 3 << std::endl; Error();}

    DWORD lenExp = 256;
    if (!CryptExportKey(
        descKey[clientNumber], descKeyOpen[clientNumber], SIMPLEBLOB, NULL,
        (BYTE*)Clients[clientNumber].sendingBuffer, &lenExp))
        {std::cout << 4 << std::endl; Error();}

    Clients[clientNumber].sendingBuffer[lenExp] = lenExp;
    Clients[clientNumber].sendDataLength = lenExp + 1;
    std::cout << "Created encrypted connection for client " << clientNumber << "." << std::endl;
}

void Search(DWORD index) {
    char* rBuffer = Clients[index].receivingBuffer;
    char* sBuffer = Clients[index].sendingBuffer;
    if (descCSP[index] != 0 && descKey[index] != 0 && descKeyOpen[index] != 0 &&
        !CryptDecrypt(
            descKey[index],
            NULL,
            true,
            NULL,
            (BYTE*)rBuffer,
            (DWORD*)&(Clients[index].receiveDataLength)))
        Error();

    const char firstSym = *rBuffer;
    std::string filename = (firstSym < '7') ? "" : std::string(rBuffer).substr(2);
    enum objectType type = (firstSym < '7') ? File : objectType((rBuffer[1] - '0') % 3);

    static const std::string indent = "   - ";
    switch (firstSym) {
    case '0':
        std::cout << indent << "Client " << (int)index << " disconnected. " << std::endl;
        exitClient(index);
        return;
    case '1':
        std::cout << indent << "Client " << (int)index << " requested information about the system." << std::endl;
        getAndSetSystem(sBuffer);
        break;
    case '2':
        std::cout << indent << "Client " << (int)index << " requested current time. " << std::endl;
        getAndSetCurrentTime(sBuffer);
        break;
    case '3':
        std::cout << indent << "Client " << (int)index << " requested time since launch. " << std::endl;
        getAndSetTimeSinceLaunch(sBuffer);
        break;
    case '4':
        std::cout << indent << "Client " << (int)index << " requested info about the memory. " << std::endl;
        getAndSetMemoryInfo(sBuffer);
        break;
    case '5':
        std::cout << indent << "Client " << (int)index << " requested info about the disks. " << std::endl;
        getAndSetDisksInfo(sBuffer);
        break;
    case '6':
        std::cout << indent << "Client " << (int)index << " requested available space on the disks. " << std::endl;
        getAndSetAvailableDiskSpace(sBuffer);
        break;
    case '7':
        std::cout << indent << "Client " << (int)index << " requested access rights. " << std::endl;
        getAndSetAccessRights(filename, type, sBuffer);
        break;
    case '8':
        std::cout << indent << "Client " << (int)index << " requested information about owner. " << std::endl;
        getAndSetOwner(filename, type, sBuffer);
        break;
    default:
        createCryptedConnection(index);
        return;
    }

    DWORD count = strlen(sBuffer);
    if (!CryptEncrypt(
        descKey[index], NULL, true, NULL,
        (BYTE*)sBuffer, (DWORD*)&count, sendingBufferSize))
        Error();
    Clients[index].sendDataLength = count;
}

int main() {
    WSADATA wasData;
    if (WSAStartup(MAKEWORD(2, 2), &wasData) == 0)
        std::cout << "WSAStartup - all right" << std::endl;
    else
        std::cout << "WSAStartup - error" << std::endl;

    struct sockaddr_in addr {};
    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);

    ioPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (ioPort == nullptr)
        throw std::runtime_error("CreateIoCompletionPort error: " + std::to_string(GetLastError()));

    memset(Clients, 0, sizeof(Clients));
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
        throw std::runtime_error("Binding or listening error");

    std::cout << "Listening: " << ntohs(addr.sin_port) << std::endl;

    if (nullptr == CreateIoCompletionPort((HANDLE)s, ioPort, 0, 0))
        throw std::runtime_error("CreateIoCompletionPort error: " + std::to_string(GetLastError()));

    Clients[0].socket = static_cast<int>(s);

    schedule_accept();

    while (true) {
        DWORD transferred;
        ULONG_PTR key;
        OVERLAPPED* lp_overlap;

        BOOL b = GetQueuedCompletionStatus(ioPort, &transferred, &key, &lp_overlap, 1000);
        if (b) {
            if (key == 0) {
                Clients[0].receiveDataLength += transferred;
                add_accepted_connection();
                schedule_accept();
            }
            else {
                if (&Clients[key].overlap_recv == lp_overlap) {
                    int len;
                    if (transferred == 0) {
                        CancelIo((HANDLE)Clients[key].socket);
                        PostQueuedCompletionStatus(ioPort, 0, key,
                            &Clients[key].overlap_cancel);
                        continue;
                    }
                    Clients[key].receiveDataLength += transferred;
                    if (isStringReceived(key, &len)) {
                        Search(key);

                        Clients[key].sz_send = 0;
                        memset(Clients[key].receivingBuffer, 0, receivingBufferSize);

                        schedule_write(key);
                    }
                    else
                        schedule_read(key);

                }
                else if (&Clients[key].overlap_send == lp_overlap) {
                    Clients[key].sz_send += transferred;
                    if (Clients[key].sz_send < Clients[key].sendDataLength && transferred > 0) {
                        schedule_write(key);
                    }
                    else {
                        Clients[key].receiveDataLength = 0;
                        memset(Clients[key].sendingBuffer, 0, sendingBufferSize);
                        schedule_read(key);
                    }
                }
                else if (&Clients[key].overlap_cancel == lp_overlap) {
                    closesocket(Clients[key].socket);
                    memset(&Clients[key], 0, sizeof(Clients[key]));
                    std::cout << "Connection " << (int)key << " closed" << std::endl;
                }
            }
        }
    }

    return 0;
}