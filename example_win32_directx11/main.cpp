
#define IMGUI_DEFINE_MATH_OPERATORS
#define _CRT_SECURE_NO_WARNINGS

// --- SVG PARSING LIBRARIES ---
#define NANOSVG_IMPLEMENTATION
#include "nanosvg.h"
#define NANOSVGRAST_IMPLEMENTATION
#include "nanosvgrast.h"
#include "icons.h"

// --- ZIP LIBRARY (REQUIRED) ---
// DOWNLOAD: https://github.com/richgel999/miniz
#include "miniz.h"
#include "miniz.c"
// -----------------------------

#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <thread>
#include <random>
#include <unordered_map>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <memory>
#include <windows.h>
#include <winhttp.h>
#include <gdiplus.h>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <mutex> 
#include <cmath>
#include <cctype>
#include <cstdint>
#include <shellapi.h> 
#include <shlobj.h>   // For SHGetFolderPathA, CSIDL_DESKTOP
#include <shobjidl.h> // IShellLink
#include <objbase.h>  // COM
#include <winreg.h>
#include <fstream> 
#include <tlhelp32.h> // Process Snapshotting
#include <set>        // PID Tracking

// UI AUTOMATION
#include <UIAutomation.h>
#include <comdef.h>

// DWM API
#include <dwmapi.h>

// JSON LIBRARY
#include "nlohmann/json.hpp"
using json = nlohmann::json;

// Forward declaration for helpers that call the HTTP layer before its definition.
namespace Api {
    std::string HttpRequest(std::wstring domain, std::wstring path, std::string method, std::string body, const std::vector<std::wstring>& customHeaders = {});
}

#include <psapi.h> // For GetModuleBaseName

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "UIAutomationCore.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Shell32.lib") 
#pragma comment(lib, "dwmapi.lib") 
#pragma comment(lib, "advapi32.lib") // For Privileges
#pragma comment(lib, "psapi.lib") // For Process Info

// =========================================================
// 2. HELPERS & GLOBALS
// =========================================================

ULONG_PTR g_gdiplusToken;
std::mutex g_dataMutex;

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static IDXGIOutputDuplication* g_pDup = nullptr;

static HWND g_hwnd = NULL;
static HHOOK g_hKeyboardHook = NULL;


// --- INPUT QUEUE FOR THREAD SAFETY ---
struct QueuedInput {
    DWORD vkCode;
    DWORD scanCode;
    DWORD flags;
    bool isDown;
};
std::vector<QueuedInput> g_inputQueue;
std::mutex g_inputMutex;
// -------------------------------------

// --- CONFIG & SETTINGS ---
ImVec4 g_uiColor = ImVec4(0.0f, 0.98f, 0.60f, 1.0f);
std::string g_iconPath = "icons/";
ImFont* g_fontMono = nullptr;

// --- UI STATE ---
bool g_dimOverlay = false;
// Start hidden by default; GUI can be shown via hotkey (after login) or Telegram /gui.
bool g_isVisible = false;
bool g_isProcessing = false;
bool g_scrollToBottom = false;
float g_windowAlpha = 1.0f; // Transparency (1.0 = Opaque)


// --- VERSION CONTROL & STORAGE ---
const std::string CURRENT_APP_VERSION = "2.0.0.0.1";
bool g_blockSystemInput = false;
volatile bool g_agentExecuting = false;  // Set by AgentCore to bypass hook input swallowing
bool g_updateRequired = false;
std::string g_updateLink = "";
bool g_checkingVersion = true;

// --- CHAT HISTORY ---
bool g_chatHistoryEnabled = false;  // Toggle (default off)
int g_chatHistoryCounter = 0;       // Counter for numbered entries
std::string g_chatHistoryDate = ""; // Current date folder

// --- API KEYS ---
struct ApiKeys {
    std::string gemini = "sk-placeholder-gemini-key";
    std::string openai = "sk-placeholder-openai-key";
    std::string claude = "sk-placeholder-claude-key";
    std::string kimi = "sk-placeholder-kimi-key";
    std::string openrouter = "sk-placeholder-openrouter-key";
    std::string deepseek = "sk-placeholder-deepseek-key";
} g_apiKeys;

// --- PROVIDER STATE ---
enum class AIProvider { Gemini, OpenAI, Anthropic, DeepSeek, Moonshot, OpenRouter, Ollama };

struct ModelInfo {
    std::string id;
    std::string displayName;
};

struct ProviderDef {
    std::string name;
    AIProvider type;
    std::vector<ModelInfo> models;
    bool modelsFetched = false;
};

std::vector<ProviderDef> g_providers;
int g_currProviderIdx = 0;
int g_currModelIdx = 0;

// --- ICONS ---
struct AppIcons {
    ID3D11ShaderResourceView* Screenshot = nullptr;
    ID3D11ShaderResourceView* Inspect = nullptr;
    ID3D11ShaderResourceView* Copy = nullptr;
    ID3D11ShaderResourceView* NewChat = nullptr;
    ID3D11ShaderResourceView* Settings = nullptr;
    ID3D11ShaderResourceView* Send = nullptr;
    ID3D11ShaderResourceView* Close = nullptr;
} g_icons;

// --- HOTKEYS ---
struct HotkeyConfig {
    int vkCode = 0;
    bool alt = false;
    bool ctrl = false;
    bool shift = false;
};


HotkeyConfig g_hkToggle = { VK_OEM_2, true, false, false };
HotkeyConfig g_hkScreenshot = { 0, false, false, false };

bool g_isBindingKey = false;
HotkeyConfig* g_targetBinding = nullptr;
bool g_showSettings = false;

// --- TELEGRAM REMOTE CONTROL ---
std::string g_telegramToken = "";
std::string g_telegramChatId = "";
bool g_telegramEnabled = true;
int g_telegramLastUpdateId = 0;
bool g_telegramPolling = false;
enum class TelegramState {
    Idle,
    WaitingForAppSelection,
    WaitingForAiProvider,
    WaitingForAiModel,
};
TelegramState g_telegramState = TelegramState::Idle;
std::string g_telegramInputBuffer = "";  // Incoming user input from Telegram
bool g_telegramInputReady = false;
std::mutex g_telegramMutex;
int g_telegramAiProviderIdx = -1;
static bool g_waitingForUserInput = false;

// Request GUI visibility change from any thread.
// Uses a window message so the actual ShowWindow/SetWindowPos runs on the UI thread.
static void RequestGuiVisible(bool visible) {
    if (!g_hwnd) return;
    PostMessage(g_hwnd, WM_APP + 2, visible ? 1 : 0, 0);
}

// =========================================================
// RANDOM STRING GENERATOR (FOR WINDOW HIDING)
// =========================================================
std::wstring GenerateRandomString(int length) {
    const std::wstring chars = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, (int)chars.size() - 1);
    std::wstring random_string;
    for (int i = 0; i < length; ++i) {
        random_string += chars[distribution(generator)];
    }
    return random_string;
}

// Global variable to hold the random class name
std::wstring g_randomClassName;


// --- HOTKEY PERSISTENCE FUNCTIONS ---
void SaveHotkeys() {
    json j;
    // OMITTED OPACITY SAVING AS REQUESTED
    // j["ui"]["opacity"] = g_windowAlpha; 

    j["toggle"]["vk"] = g_hkToggle.vkCode;
    j["toggle"]["alt"] = g_hkToggle.alt;
    j["toggle"]["ctrl"] = g_hkToggle.ctrl;
    j["toggle"]["shift"] = g_hkToggle.shift;

    j["screenshot"]["vk"] = g_hkScreenshot.vkCode;
    j["screenshot"]["alt"] = g_hkScreenshot.alt;
    j["screenshot"]["ctrl"] = g_hkScreenshot.ctrl;
    j["screenshot"]["shift"] = g_hkScreenshot.shift;

    j["chatHistory"]["enabled"] = g_chatHistoryEnabled;

    // --- TELEGRAM CONFIG ---
    j["telegram"]["token"] = g_telegramToken;
    j["telegram"]["chatId"] = g_telegramChatId;
    j["telegram"]["enabled"] = g_telegramEnabled;

    std::ofstream o("hotkeys.json");
    if (o.is_open()) {
        o << std::setw(4) << j << std::endl;
    }
}

void LoadHotkeys() {
    std::ifstream i("hotkeys.json");
    if (i.is_open()) {
        try {
            json j;
            i >> j;
            if (j.contains("ui") && j["ui"].contains("opacity")) {
                g_windowAlpha = j["ui"]["opacity"].get<float>();
            }

            if (j.contains("toggle")) {
                g_hkToggle.vkCode = j["toggle"].value("vk", VK_OEM_2);
                g_hkToggle.alt = j["toggle"].value("alt", true);
                g_hkToggle.ctrl = j["toggle"].value("ctrl", false);
                g_hkToggle.shift = j["toggle"].value("shift", false);
            }
            if (j.contains("screenshot")) {
                g_hkScreenshot.vkCode = j["screenshot"].value("vk", 0);
                g_hkScreenshot.alt = j["screenshot"].value("alt", false);
                g_hkScreenshot.ctrl = j["screenshot"].value("ctrl", false);
                g_hkScreenshot.shift = j["screenshot"].value("shift", false);
            }
            if (j.contains("chatHistory") && j["chatHistory"].contains("enabled")) {
                g_chatHistoryEnabled = j["chatHistory"]["enabled"].get<bool>();
            }
            // --- TELEGRAM CONFIG ---
            if (j.contains("telegram")) {
                if (j["telegram"].contains("token")) g_telegramToken = j["telegram"]["token"].get<std::string>();
                if (j["telegram"].contains("chatId")) g_telegramChatId = j["telegram"]["chatId"].get<std::string>();
                if (j["telegram"].contains("enabled")) g_telegramEnabled = j["telegram"]["enabled"].get<bool>();
            }
        }
        catch (...) {}
    }
}

static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while (i++ < 3)
            ret += '=';
    }

    return ret;
}

std::string Base64Decode(const std::string& in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::wstring s2ws(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring r(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &r[0], len);
    return r;
}

std::string ws2s(const std::wstring& ws) {
    if (ws.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), NULL, 0, NULL, NULL);
    std::string r(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &r[0], len, NULL, NULL);
    return r;
}

static std::string ToLowerCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static std::string TrimCopy(std::string s) {
    auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && isSpace((unsigned char)s.front())) s.erase(s.begin());
    while (!s.empty() && isSpace((unsigned char)s.back())) s.pop_back();
    return s;
}

static std::string StripCodeFences(const std::string& s) {
    // Remove common ```json ... ``` wrappers
    std::string t = s;
    size_t p = t.find("```");
    if (p == std::string::npos) return t;
    // If it starts with fence, drop first line
    if (p == 0) {
        size_t firstNl = t.find('\n');
        if (firstNl != std::string::npos) t = t.substr(firstNl + 1);
    }
    size_t end = t.rfind("```");
    if (end != std::string::npos) t = t.substr(0, end);
    return t;
}

static std::string StripMarkdownCodeFenceForTyping(const std::string& in) {
    // If the text looks like a fenced code block, strip the fences.
    // Example:
    // ```cpp
    // <code>
    // ```
    std::string s = TrimCopy(in);
    if (s.rfind("```", 0) != 0) return in;
    size_t firstNl = s.find('\n');
    if (firstNl == std::string::npos) return in;
    size_t end = s.rfind("```");
    if (end == std::string::npos || end <= firstNl) return in;
    std::string body = s.substr(firstNl + 1, end - (firstNl + 1));
    // Trim one trailing newline
    if (!body.empty() && (body.back() == '\n' || body.back() == '\r')) {
        while (!body.empty() && (body.back() == '\n' || body.back() == '\r')) body.pop_back();
    }
    return body;
}

static bool LooksLikeCodeText(const std::string& s) {
    // Heuristic: return true only when the text has strong code signals.
    // DO NOT treat all multiline text as code.
    std::string l = ToLowerCopy(s);
    int score = 0;

    // Language keywords / markers
    if (l.find("#include") != std::string::npos) score += 3;
    if (l.find("using namespace") != std::string::npos) score += 3;
    if (l.find("std::") != std::string::npos) score += 2;
    if (l.find("class ") != std::string::npos) score += 2;
    if (l.find("public:") != std::string::npos) score += 2;
    if (l.find("private:") != std::string::npos) score += 2;
    if (l.find("def ") != std::string::npos) score += 2;
    if (l.find("import ") != std::string::npos) score += 2;
    if (l.find("function ") != std::string::npos) score += 2;
    if (l.find("return ") != std::string::npos) score += 1;

    // Punctuation patterns common in code
    if (s.find(";") != std::string::npos) score += 2;
    if (s.find("{") != std::string::npos) score += 2;
    if (s.find("}") != std::string::npos) score += 2;
    if (s.find("->") != std::string::npos) score += 1;
    if (s.find("==") != std::string::npos || s.find("!=") != std::string::npos) score += 1;

    // Multiline boosts only if we already have some code signal
    if (s.find('\n') != std::string::npos && score > 0) score += 1;

    return score >= 3;
}

static std::string ExtractLikelyJson(const std::string& raw) {
    std::string s = TrimCopy(StripCodeFences(raw));
    if (s.empty()) return s;
    // Fast path
    if (json::accept(s)) return s;

    auto TryExtract = [&](char openCh, char closeCh) -> std::string {
        size_t start = s.find(openCh);
        if (start == std::string::npos) return "";
        size_t end = s.rfind(closeCh);
        if (end == std::string::npos || end <= start) return "";
        std::string sub = s.substr(start, end - start + 1);
        sub = TrimCopy(sub);
        if (json::accept(sub)) return sub;
        return "";
        };

    std::string obj = TryExtract('{', '}');
    if (!obj.empty()) return obj;
    std::string arr = TryExtract('[', ']');
    if (!arr.empty()) return arr;
    return TrimCopy(s);
}

static std::wstring GetEnvVarW(const wchar_t* name) {
    DWORD needed = GetEnvironmentVariableW(name, NULL, 0);
    if (needed == 0) return L"";
    std::wstring out(needed, 0);
    GetEnvironmentVariableW(name, &out[0], needed);
    while (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

static void EnsureDirW(const std::wstring& path) {
    if (path.empty()) return;
    CreateDirectoryW(path.c_str(), NULL);
}

static void EnsureDirRecursiveW(const std::wstring& path) {
    if (path.empty()) return;
    // Prefer Shell helper that creates intermediate directories.
    // Available on Windows; safe no-op if already exists.
    std::wstring p = path;
    while (!p.empty() && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
    if (p.empty()) return;
    SHCreateDirectoryExW(NULL, p.c_str(), NULL);
}

static std::wstring JoinPathW(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L"\\" + b;
}

static std::wstring NormalizeSlashesW(std::wstring p) {
    for (size_t i = 0; i < p.size(); i++) {
        if (p[i] == L'/') p[i] = L'\\';
    }
    return p;
}

static std::string WinErrStrA(DWORD gle) {
    char* msg = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    DWORD n = FormatMessageA(flags, NULL, gle, lang, (LPSTR)&msg, 0, NULL);
    std::string s;
    if (n && msg) s.assign(msg, msg + n);
    if (msg) LocalFree(msg);
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
    if (s.empty()) s = "unknown";
    return s;
}

static bool IsProcessElevated() {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) || !token) return false;
    TOKEN_ELEVATION elev = {};
    DWORD cb = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &cb);
    CloseHandle(token);
    if (!ok) return false;
    return elev.TokenIsElevated != 0;
}

// Forward declarations for memory layer
bool TelegramSendPhotoBytes(const std::vector<uint8_t>& jpegBytes, const std::string& caption);
bool TelegramSendMessageText(const std::string& text);
extern bool g_telegramEnabled;
extern bool g_telegramPolling;
extern volatile LONG64 g_screenshotSeq;
void CaptureScreenshot();
bool GetLatestScreenshotSnapshot(std::string& outBase64Jpeg, std::string& outCtxText, std::string& outProcName, std::string& outWinTitle);
static std::wstring GetKnownFolderPathStr(REFKNOWNFOLDERID id);

// =========================================================
// LOCAL MEMORY (SQLite via winsqlite3.dll)
// - 3 tables: mem_files, mem_chunks (FTS5 virtual table), mem_images
// =========================================================

struct SQLiteApi {
    HMODULE dll = NULL;
    // minimal API
    int (*sqlite3_open_v2)(const char*, void**, int, const char*) = NULL;
    int (*sqlite3_open16)(const void*, void**) = NULL;
    int (*sqlite3_close)(void*) = NULL;
    int (*sqlite3_exec)(void*, const char*, int(*)(void*, int, char**, char**), void*, char**) = NULL;
    int (*sqlite3_prepare_v2)(void*, const char*, int, void**, const char**) = NULL;
    int (*sqlite3_step)(void*) = NULL;
    int (*sqlite3_finalize)(void*) = NULL;
    int (*sqlite3_bind_text)(void*, int, const char*, int, void(*)(void*)) = NULL;
    int (*sqlite3_bind_int64)(void*, int, long long) = NULL;
    const unsigned char* (*sqlite3_column_text)(void*, int) = NULL;
    long long (*sqlite3_column_int64)(void*, int) = NULL;
    int (*sqlite3_column_count)(void*) = NULL;
    const char* (*sqlite3_column_name)(void*, int) = NULL;
    const char* (*sqlite3_errmsg)(void*) = NULL;
};

static SQLiteApi g_sql;
static void* g_memDb = NULL;
static std::wstring g_memRoot;
static std::wstring g_memDbPath;
static std::wstring g_memAssetsImages;

static bool LoadSQLiteApi() {
    if (g_sql.dll) return true;
    g_sql.dll = LoadLibraryW(L"winsqlite3.dll");
    if (!g_sql.dll) return false;

    auto L = [&](const char* name) -> FARPROC { return GetProcAddress(g_sql.dll, name); };
    g_sql.sqlite3_open_v2 = (int(*)(const char*, void**, int, const char*))L("sqlite3_open_v2");
    g_sql.sqlite3_open16 = (int(*)(const void*, void**))L("sqlite3_open16");
    g_sql.sqlite3_close = (int(*)(void*))L("sqlite3_close");
    g_sql.sqlite3_exec = (int(*)(void*, const char*, int(*)(void*, int, char**, char**), void*, char**))L("sqlite3_exec");
    g_sql.sqlite3_prepare_v2 = (int(*)(void*, const char*, int, void**, const char**))L("sqlite3_prepare_v2");
    g_sql.sqlite3_step = (int(*)(void*))L("sqlite3_step");
    g_sql.sqlite3_finalize = (int(*)(void*))L("sqlite3_finalize");
    g_sql.sqlite3_bind_text = (int(*)(void*, int, const char*, int, void(*)(void*)))L("sqlite3_bind_text");
    g_sql.sqlite3_bind_int64 = (int(*)(void*, int, long long))L("sqlite3_bind_int64");
    g_sql.sqlite3_column_text = (const unsigned char* (*)(void*, int))L("sqlite3_column_text");
    g_sql.sqlite3_column_int64 = (long long (*)(void*, int))L("sqlite3_column_int64");
    g_sql.sqlite3_column_count = (int(*)(void*))L("sqlite3_column_count");
    g_sql.sqlite3_column_name = (const char* (*)(void*, int))L("sqlite3_column_name");
    g_sql.sqlite3_errmsg = (const char* (*)(void*))L("sqlite3_errmsg");

    return g_sql.sqlite3_close && g_sql.sqlite3_exec && g_sql.sqlite3_prepare_v2 &&
        g_sql.sqlite3_step && g_sql.sqlite3_finalize && g_sql.sqlite3_bind_text && g_sql.sqlite3_bind_int64 &&
        g_sql.sqlite3_column_text && g_sql.sqlite3_column_int64 && g_sql.sqlite3_column_count && g_sql.sqlite3_column_name && g_sql.sqlite3_errmsg;
}

static std::wstring GetMemoryRoot() {
    if (!g_memRoot.empty()) return g_memRoot;
    std::wstring appData = GetEnvVarW(L"APPDATA");
    if (appData.empty()) {
        wchar_t buf[MAX_PATH] = {};
        SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, buf);
        appData = buf;
    }
    g_memRoot = JoinPathW(JoinPathW(appData, L"OfradrAgent"), L"memory");
    g_memDbPath = JoinPathW(g_memRoot, L"memory.sqlite");
    g_memAssetsImages = JoinPathW(JoinPathW(g_memRoot, L"assets"), L"images");
    return g_memRoot;
}

static long long NowUtcEpochSec() {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli; uli.LowPart = ft.dwLowDateTime; uli.HighPart = ft.dwHighDateTime;
    // FILETIME is 100-ns intervals since 1601-01-01
    const unsigned long long EPOCH_DIFF = 11644473600ULL; // seconds between 1601 and 1970
    unsigned long long seconds = (uli.QuadPart / 10000000ULL);
    if (seconds < EPOCH_DIFF) return 0;
    return (long long)(seconds - EPOCH_DIFF);
}

static bool MemoryInit(std::string* errOut = nullptr) {
    if (g_memDb) return true;
    if (!LoadSQLiteApi()) {
        if (errOut) *errOut = "winsqlite3.dll not available";
        return false;
    }
    GetMemoryRoot();
    EnsureDirRecursiveW(g_memRoot);
    EnsureDirRecursiveW(JoinPathW(g_memRoot, L"assets"));
    EnsureDirRecursiveW(g_memAssetsImages);

    void* db = NULL;
    int rc = 1;
    if (g_sql.sqlite3_open16) {
        // Prefer UTF-16 open to avoid encoding/path issues
        rc = g_sql.sqlite3_open16(g_memDbPath.c_str(), &db);
    }
    else if (g_sql.sqlite3_open_v2) {
        std::string dbPath = ws2s(g_memDbPath);
        // SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        const int flags = 0x00000002 | 0x00000004 | 0x00010000;
        rc = g_sql.sqlite3_open_v2(dbPath.c_str(), &db, flags, NULL);
    }
    else {
        if (errOut) *errOut = "sqlite open entrypoint not found";
        return false;
    }
    if (rc != 0 || !db) {
        if (errOut) {
            std::string emsg = "";
            if (db && g_sql.sqlite3_errmsg) emsg = g_sql.sqlite3_errmsg(db);
            *errOut = "sqlite open failed (rc=" + std::to_string(rc) + ")" + (emsg.empty() ? "" : (": " + emsg));
        }
        return false;
    }
    g_memDb = db;

    auto Exec = [&](const char* sql) -> bool {
        char* err = NULL;
        int rc = g_sql.sqlite3_exec(g_memDb, sql, NULL, NULL, &err);
        if (rc != 0) {
            if (errOut) {
                *errOut = err ? std::string(err) : std::string(g_sql.sqlite3_errmsg(g_memDb));
            }
            if (err) {
                // winsqlite3 exports sqlite3_free but we didn't bind it; leak is tiny on init failure.
            }
            return false;
        }
        return true;
        };

    // WAL for concurrency
    Exec("PRAGMA journal_mode=WAL;");
    Exec("PRAGMA synchronous=NORMAL;");

    // 1) Files table
    if (!Exec(
        "CREATE TABLE IF NOT EXISTS mem_files("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "path TEXT UNIQUE,"
        "name TEXT,"
        "ext TEXT,"
        "size INTEGER,"
        "mtime_utc INTEGER,"
        "sha256 TEXT,"
        "last_indexed_utc INTEGER,"
        "meta_json TEXT"
        ");"
    )) return false;
    Exec("CREATE INDEX IF NOT EXISTS idx_mem_files_name ON mem_files(name);");
    Exec("CREATE INDEX IF NOT EXISTS idx_mem_files_ext ON mem_files(ext);");

    // 2) Chunks table (FTS5 virtual table) - stores chat/events and extracted file text
    // Keep 3-table constraint by making mem_chunks itself the FTS table.
    if (!Exec(
        "CREATE VIRTUAL TABLE IF NOT EXISTS mem_chunks USING fts5("
        "text,"
        "source_type UNINDEXED,"
        "source_id UNINDEXED,"
        "path UNINDEXED,"
        "chunk_index UNINDEXED,"
        "meta_json UNINDEXED,"
        "created_utc UNINDEXED"
        ");"
    )) {
        // Fallback: create a normal table if FTS5 isn't available
        if (!Exec(
            "CREATE TABLE IF NOT EXISTS mem_chunks("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "text TEXT,"
            "source_type TEXT,"
            "source_id TEXT,"
            "path TEXT,"
            "chunk_index INTEGER,"
            "meta_json TEXT,"
            "created_utc INTEGER"
            ");"
        )) return false;
        Exec("CREATE INDEX IF NOT EXISTS idx_mem_chunks_source ON mem_chunks(source_type);");
    }

    // 3) Images table
    if (!Exec(
        "CREATE TABLE IF NOT EXISTS mem_images("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "jpg_path TEXT,"
        "captured_utc INTEGER,"
        "window_title TEXT,"
        "process_name TEXT,"
        "ocr_text TEXT,"
        "caption TEXT,"
        "meta_json TEXT"
        ");"
    )) return false;
    Exec("CREATE INDEX IF NOT EXISTS idx_mem_images_captured ON mem_images(captured_utc);");

    return true;
}

static bool MemoryExecPrepared(void* stmt, std::string* errOut = nullptr) {
    int rc = g_sql.sqlite3_step(stmt);
    // SQLITE_DONE=101, SQLITE_ROW=100
    if (rc != 101 && rc != 100) {
        if (errOut) *errOut = g_sql.sqlite3_errmsg(g_memDb);
        return false;
    }
    return true;
}

static bool MemoryInsertChunk(const std::string& text, const std::string& sourceType, const std::string& sourceId, const std::string& path, int chunkIndex, const std::string& metaJson) {
    std::string err;
    if (!MemoryInit(&err)) return false;
    const char* sqlFts = "INSERT INTO mem_chunks(text,source_type,source_id,path,chunk_index,meta_json,created_utc) VALUES(?,?,?,?,?,?,?);";
    void* stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sqlFts, -1, &stmt, NULL) != 0 || !stmt) return false;
    g_sql.sqlite3_bind_text(stmt, 1, text.c_str(), (int)text.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_text(stmt, 2, sourceType.c_str(), (int)sourceType.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_text(stmt, 3, sourceId.c_str(), (int)sourceId.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_text(stmt, 4, path.c_str(), (int)path.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_int64(stmt, 5, (long long)chunkIndex);
    g_sql.sqlite3_bind_text(stmt, 6, metaJson.c_str(), (int)metaJson.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_int64(stmt, 7, NowUtcEpochSec());
    bool ok = MemoryExecPrepared(stmt);
    g_sql.sqlite3_finalize(stmt);
    return ok;
}

static bool MemoryUpsertFile(const std::wstring& pathW, long long size, long long mtimeUtc) {
    std::string err;
    if (!MemoryInit(&err)) return false;

    std::wstring file = pathW;
    size_t slash = file.find_last_of(L"\\/");
    std::wstring base = (slash == std::wstring::npos) ? file : file.substr(slash + 1);
    std::wstring ext;
    size_t dot = base.find_last_of(L'.');
    if (dot != std::wstring::npos && dot + 1 < base.size()) ext = base.substr(dot + 1);
    std::wstring name = base;

    std::string path = ws2s(pathW);
    std::string n = ws2s(name);
    std::string e = ws2s(ext);

    const char* sql =
        "INSERT INTO mem_files(path,name,ext,size,mtime_utc,sha256,last_indexed_utc,meta_json) "
        "VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(path) DO UPDATE SET name=excluded.name, ext=excluded.ext, size=excluded.size, mtime_utc=excluded.mtime_utc;";
    void* stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sql, -1, &stmt, NULL) != 0 || !stmt) return false;
    g_sql.sqlite3_bind_text(stmt, 1, path.c_str(), (int)path.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_text(stmt, 2, n.c_str(), (int)n.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_text(stmt, 3, e.c_str(), (int)e.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_int64(stmt, 4, size);
    g_sql.sqlite3_bind_int64(stmt, 5, mtimeUtc);
    g_sql.sqlite3_bind_text(stmt, 6, "", 0, (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_int64(stmt, 7, 0);
    g_sql.sqlite3_bind_text(stmt, 8, "{}", 2, (void(*)(void*)) - 1);
    bool ok = MemoryExecPrepared(stmt);
    g_sql.sqlite3_finalize(stmt);
    return ok;
}

static void IndexRootsDefault() {
    std::string err;
    if (!MemoryInit(&err)) return;

    std::vector<std::wstring> roots;
    roots.push_back(GetKnownFolderPathStr(FOLDERID_Desktop));
    roots.push_back(GetKnownFolderPathStr(FOLDERID_Documents));
    roots.push_back(GetKnownFolderPathStr(FOLDERID_Downloads));
    // Also index current working directory (repo) if available
    wchar_t cwd[MAX_PATH] = {};
    GetCurrentDirectoryW(MAX_PATH, cwd);
    if (cwd[0]) roots.push_back(cwd);

    int indexed = 0;
    const int kMaxFiles = 25000;
    for (const auto& root : roots) {
        if (root.empty()) continue;
        std::vector<std::wstring> files;
        // Reuse recursive enumerator: grab a few common extensions + everything by walking, but limit count.
        // We'll just index all files by enumerating directories directly.
        std::vector<std::wstring> stack;
        stack.push_back(root);
        while (!stack.empty() && indexed < kMaxFiles) {
            std::wstring dir = stack.back();
            stack.pop_back();
            WIN32_FIND_DATAW f = {};
            std::wstring pattern = dir;
            if (!pattern.empty() && pattern.back() != L'\\') pattern += L"\\";
            pattern += L"*";
            HANDLE h = FindFirstFileW(pattern.c_str(), &f);
            if (h == INVALID_HANDLE_VALUE) continue;
            do {
                if (wcscmp(f.cFileName, L".") == 0 || wcscmp(f.cFileName, L"..") == 0) continue;
                std::wstring full = dir;
                if (!full.empty() && full.back() != L'\\') full += L"\\";
                full += f.cFileName;
                if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    // Skip some noisy/system dirs
                    std::wstring n = f.cFileName;
                    std::wstring nLower = n;
                    std::transform(nLower.begin(), nLower.end(), nLower.begin(), ::towlower);
                    if (nLower == L"node_modules" || nLower == L".git" || nLower == L"appdata") continue;
                    stack.push_back(full);
                }
                else {
                    ULARGE_INTEGER sz; sz.LowPart = f.nFileSizeLow; sz.HighPart = f.nFileSizeHigh;
                    // Convert FILETIME (last write) to epoch seconds
                    ULARGE_INTEGER uli; uli.LowPart = f.ftLastWriteTime.dwLowDateTime; uli.HighPart = f.ftLastWriteTime.dwHighDateTime;
                    unsigned long long seconds = (uli.QuadPart / 10000000ULL);
                    const unsigned long long EPOCH_DIFF = 11644473600ULL;
                    long long mtime = (seconds > EPOCH_DIFF) ? (long long)(seconds - EPOCH_DIFF) : 0;
                    MemoryUpsertFile(full, (long long)sz.QuadPart, mtime);
                    indexed++;
                    if (indexed >= kMaxFiles) break;
                }
            } while (FindNextFileW(h, &f));
            FindClose(h);
        }
    }
}

static std::string MemoryFindPaths(const std::string& query) {
    std::string err;
    if (!MemoryInit(&err)) return "MEMORY: init failed: " + err;
    std::string q = query;
    if (q.empty()) q = "";
    std::string like = "%" + q + "%";

    const char* sql = "SELECT path,name,ext,size,mtime_utc FROM mem_files WHERE name LIKE ?1 OR path LIKE ?1 ORDER BY mtime_utc DESC LIMIT 50;";
    void* stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sql, -1, &stmt, NULL) != 0 || !stmt) return "MEMORY: prepare failed";
    g_sql.sqlite3_bind_text(stmt, 1, like.c_str(), (int)like.size(), (void(*)(void*)) - 1);

    std::stringstream ss;
    ss << "MEMORY PATHS (query: '" << query << "'):\n";
    int rows = 0;
    while (g_sql.sqlite3_step(stmt) == 100) {
        const unsigned char* p = g_sql.sqlite3_column_text(stmt, 0);
        const unsigned char* n = g_sql.sqlite3_column_text(stmt, 1);
        const unsigned char* e = g_sql.sqlite3_column_text(stmt, 2);
        long long sz = g_sql.sqlite3_column_int64(stmt, 3);
        long long mt = g_sql.sqlite3_column_int64(stmt, 4);
        ss << "- " << (p ? (const char*)p : "") << " (" << (n ? (const char*)n : "") << ")";
        if (e && ((const char*)e)[0]) ss << " ." << (const char*)e;
        ss << " | " << sz << " bytes | mtime " << mt << "\n";
        rows++;
    }
    g_sql.sqlite3_finalize(stmt);
    if (rows == 0) ss << "(no matches)\n";
    return ss.str();
}

static std::string MemorySearch(const std::string& query) {
    std::string err;
    if (!MemoryInit(&err)) return "MEMORY: init failed: " + err;
    if (query.empty()) return "MEMORY SEARCH: empty query";

    // Try FTS match first
    const char* sqlFts = "SELECT text, source_type, path, created_utc FROM mem_chunks WHERE mem_chunks MATCH ?1 LIMIT 8;";
    void* stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sqlFts, -1, &stmt, NULL) == 0 && stmt) {
        g_sql.sqlite3_bind_text(stmt, 1, query.c_str(), (int)query.size(), (void(*)(void*)) - 1);
        std::stringstream ss;
        ss << "MEMORY SEARCH (FTS) query: '" << query << "'\n";
        int rows = 0;
        while (g_sql.sqlite3_step(stmt) == 100) {
            const unsigned char* t = g_sql.sqlite3_column_text(stmt, 0);
            const unsigned char* st = g_sql.sqlite3_column_text(stmt, 1);
            const unsigned char* p = g_sql.sqlite3_column_text(stmt, 2);
            long long created = g_sql.sqlite3_column_int64(stmt, 3);
            ss << "- [" << (st ? (const char*)st : "") << "] " << (p ? (const char*)p : "") << " @" << created << "\n";
            std::string snippet = t ? (const char*)t : "";
            if (snippet.size() > 800) snippet.resize(800);
            ss << snippet << "\n\n";
            rows++;
        }
        g_sql.sqlite3_finalize(stmt);
        if (rows == 0) ss << "(no matches)\n";
        return ss.str();
    }
    if (stmt) g_sql.sqlite3_finalize(stmt);

    // Fallback LIKE
    std::string like = "%" + query + "%";
    const char* sql = "SELECT text, source_type, path, created_utc FROM mem_chunks WHERE text LIKE ?1 LIMIT 8;";
    stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sql, -1, &stmt, NULL) != 0 || !stmt) return "MEMORY SEARCH: prepare failed";
    g_sql.sqlite3_bind_text(stmt, 1, like.c_str(), (int)like.size(), (void(*)(void*)) - 1);
    std::stringstream ss;
    ss << "MEMORY SEARCH (LIKE) query: '" << query << "'\n";
    int rows = 0;
    while (g_sql.sqlite3_step(stmt) == 100) {
        const unsigned char* t = g_sql.sqlite3_column_text(stmt, 0);
        const unsigned char* st = g_sql.sqlite3_column_text(stmt, 1);
        const unsigned char* p = g_sql.sqlite3_column_text(stmt, 2);
        long long created = g_sql.sqlite3_column_int64(stmt, 3);
        ss << "- [" << (st ? (const char*)st : "") << "] " << (p ? (const char*)p : "") << " @" << created << "\n";
        std::string snippet = t ? (const char*)t : "";
        if (snippet.size() > 800) snippet.resize(800);
        ss << snippet << "\n\n";
        rows++;
    }
    g_sql.sqlite3_finalize(stmt);
    if (rows == 0) ss << "(no matches)\n";
    return ss.str();
}

static int ClampInt(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static std::string MemoryRecentByType(const std::string& typeFilter, int limit) {
    std::string err;
    if (!MemoryInit(&err)) return "MEMORY: init failed: " + err;
    limit = ClampInt(limit, 1, 200);

    std::stringstream ss;
    ss << "MEMORY RECENT";
    if (!typeFilter.empty()) ss << " (type=" << typeFilter << ")";
    ss << " last " << limit << ":\n";

    // Works for both FTS5 virtual table and fallback normal table.
    std::string sql = "SELECT created_utc, source_type, path, text FROM mem_chunks ";
    if (!typeFilter.empty()) sql += "WHERE source_type=?1 ";
    sql += "ORDER BY created_utc DESC LIMIT " + std::to_string(limit) + ";";

    void* stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sql.c_str(), -1, &stmt, NULL) != 0 || !stmt) return "MEMORY RECENT: prepare failed";
    if (!typeFilter.empty()) g_sql.sqlite3_bind_text(stmt, 1, typeFilter.c_str(), (int)typeFilter.size(), (void(*)(void*)) - 1);

    int rows = 0;
    while (g_sql.sqlite3_step(stmt) == 100) {
        long long created = g_sql.sqlite3_column_int64(stmt, 0);
        const unsigned char* st = g_sql.sqlite3_column_text(stmt, 1);
        const unsigned char* p = g_sql.sqlite3_column_text(stmt, 2);
        const unsigned char* t = g_sql.sqlite3_column_text(stmt, 3);
        std::string text = t ? (const char*)t : "";
        if (text.size() > 600) text.resize(600);
        ss << "- @" << created << " [" << (st ? (const char*)st : "") << "] " << (p ? (const char*)p : "") << "\n";
        ss << text << "\n\n";
        rows++;
    }
    g_sql.sqlite3_finalize(stmt);
    if (rows == 0) ss << "(no rows)\n";
    return ss.str();
}

static std::string MemoryRecentActions(int limit) {
    std::string err;
    if (!MemoryInit(&err)) return "MEMORY: init failed: " + err;
    limit = ClampInt(limit, 1, 200);

    std::stringstream ss;
    ss << "MEMORY RECENT ACTIONS last " << limit << ":\n";
    std::string sql = "SELECT created_utc, source_type, text FROM mem_chunks WHERE source_type IN ('agent_action','agent_error','agent_result') ORDER BY created_utc DESC LIMIT " + std::to_string(limit) + ";";
    void* stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sql.c_str(), -1, &stmt, NULL) != 0 || !stmt) return "MEMORY RECENT ACTIONS: prepare failed";
    int rows = 0;
    while (g_sql.sqlite3_step(stmt) == 100) {
        long long created = g_sql.sqlite3_column_int64(stmt, 0);
        const unsigned char* st = g_sql.sqlite3_column_text(stmt, 1);
        const unsigned char* t = g_sql.sqlite3_column_text(stmt, 2);
        std::string text = t ? (const char*)t : "";
        if (text.size() > 900) text.resize(900);
        ss << "- @" << created << " [" << (st ? (const char*)st : "") << "] " << text << "\n";
        rows++;
    }
    g_sql.sqlite3_finalize(stmt);
    if (rows == 0) ss << "(no rows)\n";
    return ss.str();
}

static std::string MemoryListImages(int limit) {
    std::string err;
    if (!MemoryInit(&err)) return "MEMORY: init failed: " + err;
    limit = ClampInt(limit, 1, 100);

    std::stringstream ss;
    ss << "MEMORY IMAGES last " << limit << ":\n";
    std::string sql = "SELECT id, captured_utc, caption, jpg_path FROM mem_images ORDER BY captured_utc DESC LIMIT " + std::to_string(limit) + ";";
    void* stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sql.c_str(), -1, &stmt, NULL) != 0 || !stmt) return "MEMORY IMAGES: prepare failed";
    int rows = 0;
    while (g_sql.sqlite3_step(stmt) == 100) {
        long long id = g_sql.sqlite3_column_int64(stmt, 0);
        long long ts = g_sql.sqlite3_column_int64(stmt, 1);
        const unsigned char* cap = g_sql.sqlite3_column_text(stmt, 2);
        const unsigned char* p = g_sql.sqlite3_column_text(stmt, 3);
        ss << "- id " << id << " @" << ts << " | " << (cap ? (const char*)cap : "") << "\n";
        ss << "  " << (p ? (const char*)p : "") << "\n";
        rows++;
    }
    g_sql.sqlite3_finalize(stmt);
    if (rows == 0) ss << "(no images)\n";
    return ss.str();
}

static std::string MemoryIngestFile(const std::string& path) {
    std::string err;
    if (!MemoryInit(&err)) return "MEMORY: init failed: " + err;
    if (path.empty()) return "MEMORY INGEST: empty path";

    std::wstring wPath = s2ws(path);
    HANDLE h = CreateFileW(wPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return "MEMORY INGEST: failed to open file";

    LARGE_INTEGER sz = {};
    GetFileSizeEx(h, &sz);
    if (sz.QuadPart <= 0) {
        CloseHandle(h);
        return "MEMORY INGEST: empty file";
    }
    const long long kMaxRead = 256 * 1024; // 256KB
    long long toRead = (sz.QuadPart > kMaxRead) ? kMaxRead : sz.QuadPart;
    std::string buf;
    buf.resize((size_t)toRead);
    DWORD read = 0;
    if (!ReadFile(h, &buf[0], (DWORD)toRead, &read, NULL) || read == 0) {
        CloseHandle(h);
        return "MEMORY INGEST: read failed";
    }
    buf.resize(read);
    FILETIME ft = {};
    GetFileTime(h, NULL, NULL, &ft);
    CloseHandle(h);

    ULARGE_INTEGER uli; uli.LowPart = ft.dwLowDateTime; uli.HighPart = ft.dwHighDateTime;
    unsigned long long seconds = (uli.QuadPart / 10000000ULL);
    const unsigned long long EPOCH_DIFF = 11644473600ULL;
    long long mtime = (seconds > EPOCH_DIFF) ? (long long)(seconds - EPOCH_DIFF) : 0;

    // Upsert file into mem_files
    MemoryUpsertFile(wPath, (long long)sz.QuadPart, mtime);

    // Chunk and insert into mem_chunks
    const size_t kChunk = 3000;
    size_t off = 0;
    int idx = 0;
    while (off < buf.size() && idx < 50) {
        size_t n = std::min(kChunk, buf.size() - off);
        std::string chunk = buf.substr(off, n);
        MemoryInsertChunk(chunk, "file", "", path, idx, "{}");
        off += n;
        idx++;
    }

    std::stringstream ss;
    ss << "MEMORY INGEST: OK (" << idx << " chunk(s))\n";
    if (sz.QuadPart > kMaxRead) ss << "Note: truncated to first " << kMaxRead << " bytes\n";
    return ss.str();
}

static bool MemoryInsertImageJpeg(const std::vector<uint8_t>& jpg, const std::string& windowTitle, const std::string& processName, const std::string& ocrText, std::string* outIdStr, std::wstring* outPathW) {
    std::string err;
    if (!MemoryInit(&err)) return false;
    if (jpg.empty()) return false;

    // Ensure image asset directory exists
    EnsureDirRecursiveW(g_memAssetsImages);

    long long ts = NowUtcEpochSec();
    std::wstring fileName = L"shot_" + std::to_wstring(ts) + L"_" + std::to_wstring(GetTickCount64()) + L".jpg";
    std::wstring full = JoinPathW(g_memAssetsImages, fileName);

    HANDLE h = CreateFileW(full.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        char dbg[512];
        sprintf_s(dbg, "[Memory] CreateFileW failed gle=%lu path=%s\n", (unsigned long)gle, ws2s(full).c_str());
        OutputDebugStringA(dbg);
        return false;
    }
    DWORD wrote = 0;
    BOOL ok = WriteFile(h, jpg.data(), (DWORD)jpg.size(), &wrote, NULL);
    CloseHandle(h);
    if (!ok || wrote != (DWORD)jpg.size()) return false;

    std::string jpgPath = ws2s(full);
    std::string caption = "Screenshot";
    if (!windowTitle.empty()) caption += " | " + windowTitle;

    const char* sql = "INSERT INTO mem_images(jpg_path,captured_utc,window_title,process_name,ocr_text,caption,meta_json) VALUES(?,?,?,?,?,?,?);";
    void* stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sql, -1, &stmt, NULL) != 0 || !stmt) return false;
    g_sql.sqlite3_bind_text(stmt, 1, jpgPath.c_str(), (int)jpgPath.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_int64(stmt, 2, ts);
    g_sql.sqlite3_bind_text(stmt, 3, windowTitle.c_str(), (int)windowTitle.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_text(stmt, 4, processName.c_str(), (int)processName.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_text(stmt, 5, ocrText.c_str(), (int)ocrText.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_text(stmt, 6, caption.c_str(), (int)caption.size(), (void(*)(void*)) - 1);
    g_sql.sqlite3_bind_text(stmt, 7, "{}", 2, (void(*)(void*)) - 1);
    bool stepOk = MemoryExecPrepared(stmt);
    g_sql.sqlite3_finalize(stmt);
    if (!stepOk) return false;

    // Get last row id
    void* stmt2 = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, "SELECT last_insert_rowid();", -1, &stmt2, NULL) == 0 && stmt2) {
        long long id = 0;
        if (g_sql.sqlite3_step(stmt2) == 100) id = g_sql.sqlite3_column_int64(stmt2, 0);
        g_sql.sqlite3_finalize(stmt2);
        if (outIdStr) *outIdStr = std::to_string(id);
    }
    if (outPathW) *outPathW = full;
    return true;
}

static std::string MemoryCaptureAndStoreScreenshot(bool sendToTelegram) {
    std::string err;
    if (!MemoryInit(&err)) return "MEMORY: init failed: " + err;

    LONG64 seqBefore = g_screenshotSeq;
    CaptureScreenshot();
    LONG64 seqAfter = g_screenshotSeq;
    if (seqAfter == seqBefore) return "MEMORY SCREENSHOT: not available (black/failed)";

    std::string base64;
    std::string ctx;
    std::string proc;
    std::string winTitle;
    if (!GetLatestScreenshotSnapshot(base64, ctx, proc, winTitle)) return "MEMORY SCREENSHOT: missing snapshot";
    if (base64.empty()) return "MEMORY SCREENSHOT: missing jpeg data";
    std::string raw = Base64Decode(base64);
    std::vector<uint8_t> jpg(raw.begin(), raw.end());

    std::string id;
    std::wstring pathW;
    if (!MemoryInsertImageJpeg(jpg, winTitle, proc, ctx, &id, &pathW)) return "MEMORY SCREENSHOT: failed to store";

    // Also index OCR/context so it is searchable
    if (!ctx.empty()) {
        MemoryInsertChunk(ctx, "image_ocr", id, ws2s(pathW), 0, "{}");
    }

    if (sendToTelegram && g_telegramEnabled) {
        std::string caption = "[MEMORY] Screenshot saved (id " + id + ")";
        if (!winTitle.empty()) caption += " | " + winTitle;
        bool sent = TelegramSendPhotoBytes(jpg, caption);
        if (!sent) {
            TelegramSendMessageText("[MEMORY] Screenshot captured, but Telegram upload failed.");
        }
    }

    raw.assign(raw.size(), '\0');
    raw.clear();
    return "MEMORY SCREENSHOT: saved id=" + id + " path=" + ws2s(pathW);
}

static std::string MemoryGetImageAndSendTelegram(const std::string& idStr) {
    std::string err;
    if (!MemoryInit(&err)) return "MEMORY: init failed: " + err;
    if (idStr.empty()) return "MEMORY GET IMAGE: missing id";

    // Query path
    const char* sql = "SELECT jpg_path, caption FROM mem_images WHERE id=?1 LIMIT 1;";
    void* stmt = NULL;
    if (g_sql.sqlite3_prepare_v2(g_memDb, sql, -1, &stmt, NULL) != 0 || !stmt) return "MEMORY GET IMAGE: prepare failed";
    long long id = 0;
    try { id = std::stoll(idStr); }
    catch (...) { id = 0; }
    g_sql.sqlite3_bind_int64(stmt, 1, id);
    std::string path;
    std::string caption;
    if (g_sql.sqlite3_step(stmt) == 100) {
        const unsigned char* p = g_sql.sqlite3_column_text(stmt, 0);
        const unsigned char* c = g_sql.sqlite3_column_text(stmt, 1);
        path = p ? (const char*)p : "";
        caption = c ? (const char*)c : "";
    }
    g_sql.sqlite3_finalize(stmt);
    if (path.empty()) return "MEMORY GET IMAGE: not found";

    // Read file bytes
    std::wstring wPath = s2ws(path);
    HANDLE h = CreateFileW(wPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return "MEMORY GET IMAGE: open failed";
    LARGE_INTEGER sz = {};
    GetFileSizeEx(h, &sz);
    if (sz.QuadPart <= 0 || sz.QuadPart > (50LL * 1024LL * 1024LL)) { CloseHandle(h); return "MEMORY GET IMAGE: invalid size"; }
    std::vector<uint8_t> jpg((size_t)sz.QuadPart);
    DWORD read = 0;
    BOOL ok = ReadFile(h, jpg.data(), (DWORD)jpg.size(), &read, NULL);
    CloseHandle(h);
    if (!ok || read != (DWORD)jpg.size()) return "MEMORY GET IMAGE: read failed";

    if (g_telegramEnabled && g_telegramPolling) {
        TelegramSendPhotoBytes(jpg, caption.empty() ? ("[MEMORY] Screenshot id " + idStr) : caption);
        return "MEMORY GET IMAGE: sent to Telegram (id=" + idStr + ")";
    }
    return "MEMORY GET IMAGE: Telegram not enabled";
}

static bool WaitForTelegramUserInput(int timeoutMs, std::string& outText) {
    outText.clear();
    DWORD start = GetTickCount();
    while (true) {
        {
            std::lock_guard<std::mutex> lock(g_telegramMutex);
            if (g_telegramInputReady) {
                outText = g_telegramInputBuffer;
                g_telegramInputBuffer.clear();
                g_telegramInputReady = false;
                return true;
            }
        }
        if (timeoutMs > 0 && (int)(GetTickCount() - start) > timeoutMs) return false;
        Sleep(100);
    }
}

static std::wstring GetConfigPathW() {
    std::wstring appData = GetEnvVarW(L"APPDATA");
    if (appData.empty()) {
        wchar_t buf[MAX_PATH] = {};
        SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, buf);
        appData = buf;
    }
    std::wstring dir = JoinPathW(appData, L"OfradrAgent");
    EnsureDirRecursiveW(dir);
    return JoinPathW(dir, L"config.json");
}

static json LoadLocalConfig() {
    json j = json::object();
    std::wstring pathW = GetConfigPathW();
    std::ifstream f(ws2s(pathW));
    if (!f.good()) return j;
    try { f >> j; }
    catch (...) { return json::object(); }
    if (!j.is_object()) return json::object();
    return j;
}

static bool SaveLocalConfig(const json& j) {
    std::wstring pathW = GetConfigPathW();
    std::ofstream f(ws2s(pathW), std::ios::binary | std::ios::trunc);
    if (!f.good()) return false;
    try { f << j.dump(2); }
    catch (...) { return false; }
    return true;
}

// =========================================================
// SYSTEM INVENTORY + COMMAND RUNNER (AGENT TOOLS)
// =========================================================

struct InstalledAppEntry {
    std::string name;
    std::string version;
    std::string publisher;
    std::string installLocation;
    std::string uninstallString;
    std::string keyPath;
};

static bool ReadRegStringValue(HKEY hKey, const wchar_t* valueName, std::wstring& out) {
    out.clear();
    DWORD type = 0;
    DWORD cb = 0;
    LSTATUS s = RegQueryValueExW(hKey, valueName, NULL, &type, NULL, &cb);
    if (s != ERROR_SUCCESS || cb == 0) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;

    std::wstring buf(cb / sizeof(wchar_t), 0);
    s = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)&buf[0], &cb);
    if (s != ERROR_SUCCESS) return false;
    // Trim trailing nulls
    while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
    out = buf;
    return !out.empty();
}

static void AppendUninstallEntries(std::vector<InstalledAppEntry>& out, HKEY root, const std::wstring& rootName, REGSAM viewFlag, const std::string& filterLower) {
    const wchar_t* sub = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    HKEY hBase = NULL;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ | viewFlag, &hBase) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t keyName[512];
    DWORD keyNameLen = 0;
    FILETIME ft = {};
    while (true) {
        keyNameLen = (DWORD)(sizeof(keyName) / sizeof(keyName[0]));
        LSTATUS s = RegEnumKeyExW(hBase, idx, keyName, &keyNameLen, NULL, NULL, NULL, &ft);
        if (s != ERROR_SUCCESS) break;
        idx++;

        HKEY hApp = NULL;
        if (RegOpenKeyExW(hBase, keyName, 0, KEY_READ | viewFlag, &hApp) != ERROR_SUCCESS) continue;

        std::wstring wName, wVer, wPub, wLoc, wUn;
        ReadRegStringValue(hApp, L"DisplayName", wName);
        if (wName.empty()) {
            RegCloseKey(hApp);
            continue;
        }
        ReadRegStringValue(hApp, L"DisplayVersion", wVer);
        ReadRegStringValue(hApp, L"Publisher", wPub);
        ReadRegStringValue(hApp, L"InstallLocation", wLoc);
        ReadRegStringValue(hApp, L"UninstallString", wUn);

        InstalledAppEntry e;
        e.name = ws2s(wName);
        e.version = ws2s(wVer);
        e.publisher = ws2s(wPub);
        e.installLocation = ws2s(wLoc);
        e.uninstallString = ws2s(wUn);
        e.keyPath = ws2s(rootName + L"\\" + sub + L"\\" + std::wstring(keyName));

        if (!filterLower.empty()) {
            std::string hay = ToLowerCopy(e.name + " " + e.publisher + " " + e.installLocation);
            if (hay.find(filterLower) == std::string::npos) {
                RegCloseKey(hApp);
                continue;
            }
        }

        out.push_back(e);
        RegCloseKey(hApp);
    }

    RegCloseKey(hBase);
}

static std::string ListInstalledApps(const std::string& filter) {
    std::string filterLower = ToLowerCopy(filter);
    std::vector<InstalledAppEntry> entries;
    entries.reserve(2048);

    // HKLM 64-bit + 32-bit views
    AppendUninstallEntries(entries, HKEY_LOCAL_MACHINE, L"HKLM", KEY_WOW64_64KEY, filterLower);
    AppendUninstallEntries(entries, HKEY_LOCAL_MACHINE, L"HKLM", KEY_WOW64_32KEY, filterLower);
    // HKCU 64-bit + 32-bit views
    AppendUninstallEntries(entries, HKEY_CURRENT_USER, L"HKCU", KEY_WOW64_64KEY, filterLower);
    AppendUninstallEntries(entries, HKEY_CURRENT_USER, L"HKCU", KEY_WOW64_32KEY, filterLower);

    // De-dup by (name, version, publisher)
    std::sort(entries.begin(), entries.end(), [](const InstalledAppEntry& a, const InstalledAppEntry& b) {
        if (a.name != b.name) return a.name < b.name;
        if (a.version != b.version) return a.version < b.version;
        if (a.publisher != b.publisher) return a.publisher < b.publisher;
        return a.keyPath < b.keyPath;
        });
    entries.erase(std::unique(entries.begin(), entries.end(), [](const InstalledAppEntry& a, const InstalledAppEntry& b) {
        return a.name == b.name && a.version == b.version && a.publisher == b.publisher;
        }), entries.end());

    std::stringstream ss;
    ss << "INSTALLED APPS";
    if (!filter.empty()) ss << " (filter: '" << filter << "')";
    ss << ":\n";
    ss << "Count: " << entries.size() << "\n\n";
    size_t shown = 0;
    for (const auto& e : entries) {
        if (shown >= 200) {
            ss << "... (truncated; showing first 200)\n";
            break;
        }
        ss << "- " << e.name;
        if (!e.version.empty()) ss << " | " << e.version;
        if (!e.publisher.empty()) ss << " | " << e.publisher;
        if (!e.installLocation.empty()) ss << " | " << e.installLocation;
        ss << "\n";
        shown++;
    }
    return ss.str();
}

struct LaunchableEntry {
    std::string name;
    std::string target;
    std::string args;
    std::string shortcutPath;
};

static std::wstring GetKnownFolderPathStr(REFKNOWNFOLDERID id) {
    PWSTR p = NULL;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(id, 0, NULL, &p)) && p) {
        out = p;
        CoTaskMemFree(p);
    }
    return out;
}

static void EnumerateFilesRecursive(const std::wstring& dir, const std::wstring& extLower, std::vector<std::wstring>& outFiles) {
    WIN32_FIND_DATAW f = {};
    std::wstring pattern = dir;
    if (!pattern.empty() && pattern.back() != L'\\') pattern += L"\\";
    pattern += L"*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &f);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(f.cFileName, L".") == 0 || wcscmp(f.cFileName, L"..") == 0) continue;
        std::wstring full = dir;
        if (!full.empty() && full.back() != L'\\') full += L"\\";
        full += f.cFileName;

        if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EnumerateFilesRecursive(full, extLower, outFiles);
        }
        else {
            // extension check
            std::wstring nameLower = f.cFileName;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
            if (nameLower.size() >= extLower.size() && nameLower.substr(nameLower.size() - extLower.size()) == extLower) {
                outFiles.push_back(full);
            }
        }
    } while (FindNextFileW(h, &f));
    FindClose(h);
}

static bool ResolveShortcut(const std::wstring& lnkPath, std::wstring& targetPath, std::wstring& argsOut) {
    targetPath.clear();
    argsOut.clear();

    HRESULT hrInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    bool didInit = SUCCEEDED(hrInit);

    IShellLinkW* pLink = NULL;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&pLink);
    if (FAILED(hr) || !pLink) {
        if (didInit) CoUninitialize();
        return false;
    }
    IPersistFile* pFile = NULL;
    hr = pLink->QueryInterface(IID_IPersistFile, (void**)&pFile);
    if (FAILED(hr) || !pFile) {
        pLink->Release();
        if (didInit) CoUninitialize();
        return false;
    }

    hr = pFile->Load(lnkPath.c_str(), STGM_READ);
    if (SUCCEEDED(hr)) {
        wchar_t path[MAX_PATH] = {};
        WIN32_FIND_DATAW wfd = {};
        if (SUCCEEDED(pLink->GetPath(path, MAX_PATH, &wfd, SLGP_RAWPATH)) && path[0]) {
            targetPath = path;
        }
        wchar_t args[2048] = {};
        if (SUCCEEDED(pLink->GetArguments(args, (int)(sizeof(args) / sizeof(args[0]))))) {
            argsOut = args;
        }
    }

    pFile->Release();
    pLink->Release();
    if (didInit) CoUninitialize();
    return !targetPath.empty();
}

static std::string ListLaunchableApps(const std::string& filter) {
    std::string filterLower = ToLowerCopy(filter);
    std::vector<std::wstring> lnkFiles;

    std::wstring userPrograms = GetKnownFolderPathStr(FOLDERID_Programs);
    std::wstring commonPrograms = GetKnownFolderPathStr(FOLDERID_CommonPrograms);
    if (!userPrograms.empty()) EnumerateFilesRecursive(userPrograms, L".lnk", lnkFiles);
    if (!commonPrograms.empty()) EnumerateFilesRecursive(commonPrograms, L".lnk", lnkFiles);

    std::vector<LaunchableEntry> entries;
    entries.reserve(lnkFiles.size());

    for (const auto& lnk : lnkFiles) {
        std::wstring target, args;
        if (!ResolveShortcut(lnk, target, args)) continue;

        // Name from file name
        std::wstring file = lnk;
        size_t slash = file.find_last_of(L"\\/");
        std::wstring base = (slash == std::wstring::npos) ? file : file.substr(slash + 1);
        if (base.size() > 4 && (base.substr(base.size() - 4) == L".lnk" || base.substr(base.size() - 4) == L".LNK")) {
            base = base.substr(0, base.size() - 4);
        }

        LaunchableEntry e;
        e.name = ws2s(base);
        e.target = ws2s(target);
        e.args = ws2s(args);
        e.shortcutPath = ws2s(lnk);

        if (!filterLower.empty()) {
            std::string hay = ToLowerCopy(e.name + " " + e.target + " " + e.shortcutPath);
            if (hay.find(filterLower) == std::string::npos) continue;
        }
        entries.push_back(e);
    }

    std::sort(entries.begin(), entries.end(), [](const LaunchableEntry& a, const LaunchableEntry& b) {
        if (a.name != b.name) return a.name < b.name;
        return a.target < b.target;
        });

    std::stringstream ss;
    ss << "LAUNCHABLE APPS (Start Menu shortcuts)";
    if (!filter.empty()) ss << " (filter: '" << filter << "')";
    ss << ":\n";
    ss << "Count: " << entries.size() << "\n\n";
    size_t shown = 0;
    for (const auto& e : entries) {
        if (shown >= 200) {
            ss << "... (truncated; showing first 200)\n";
            break;
        }
        ss << "- " << e.name << " -> " << e.target;
        if (!e.args.empty()) ss << " " << e.args;
        ss << "\n";
        shown++;
    }
    return ss.str();
}

static std::string NetCheck() {
    // Basic HTTPS reachability check
    std::string host = "api.telegram.org";
    std::wstring wHost = s2ws(host);
    HINTERNET hSession = WinHttpOpen(L"HopeNetCheck/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return "NET CHECK: WinHttpOpen failed";
    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "NET CHECK: WinHttpConnect failed (DNS/connection)";
    }
    HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", L"/", NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (!hReq) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "NET CHECK: WinHttpOpenRequest failed";
    }
    bool ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && WinHttpReceiveResponse(hReq, NULL);
    DWORD status = 0;
    DWORD cb = sizeof(status);
    if (ok) {
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &cb, WINHTTP_NO_HEADER_INDEX);
    }
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    if (!ok) return "NET CHECK: HTTPS request failed";
    std::stringstream ss;
    ss << "NET CHECK: OK (https://" << host << "/ status " << status << ")";
    return ss.str();
}

static std::string HttpRequestFullUrl(
    const std::string& url,
    const std::string& method,
    const std::string& body,
    const std::vector<std::wstring>& headers,
    int timeoutMs,
    int maxBytes,
    DWORD* outStatus,
    std::string* outContentType
) {
    if (outStatus) *outStatus = 0;
    if (outContentType) outContentType->clear();
    if (url.rfind("https://", 0) != 0) return "ERROR: only https:// URLs are allowed";

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;
    std::wstring wUrl = s2ws(url);
    if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp)) return "ERROR: WinHttpCrackUrl failed";

    std::wstring host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.dwExtraInfoLength > 0) {
        path.append(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }
    INTERNET_PORT port = urlComp.nPort;
    bool secure = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hS = WinHttpOpen(L"Ofradr/HttpTool", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hS) return "ERROR: WinHttpOpen failed";
    if (timeoutMs > 0) {
        WinHttpSetTimeouts(hS, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
    }
    HINTERNET hC = WinHttpConnect(hS, host.c_str(), port, 0);
    if (!hC) { WinHttpCloseHandle(hS); return "ERROR: WinHttpConnect failed"; }

    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hR = WinHttpOpenRequest(hC, s2ws(method).c_str(), path.c_str(), NULL, NULL, NULL, flags);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return "ERROR: WinHttpOpenRequest failed"; }

    for (const auto& hdr : headers) {
        WinHttpAddRequestHeaders(hR, hdr.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
    }

    const void* pBody = body.empty() ? NULL : body.data();
    DWORD cbBody = (DWORD)body.size();
    bool ok = WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)pBody, cbBody, cbBody, 0)
        && WinHttpReceiveResponse(hR, NULL);
    if (!ok) {
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return "ERROR: request failed";
    }

    // Status code
    DWORD code = 0; DWORD sz = sizeof(code);
    WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
    if (outStatus) *outStatus = code;

    // Content-Type
    wchar_t ctype[256] = {};
    sz = sizeof(ctype);
    if (WinHttpQueryHeaders(hR, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX, ctype, &sz, WINHTTP_NO_HEADER_INDEX)) {
        if (outContentType) *outContentType = ws2s(ctype);
    }

    // Body (capped)
    if (maxBytes <= 0) maxBytes = 200000;
    std::string res;
    res.reserve((size_t)std::min(maxBytes, 16384));
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
        DWORD toRead = avail;
        if ((int)res.size() + (int)toRead > maxBytes) {
            toRead = (DWORD)std::max(0, maxBytes - (int)res.size());
        }
        if (toRead == 0) break;
        std::vector<char> buf(toRead);
        DWORD rd = 0;
        if (!WinHttpReadData(hR, buf.data(), toRead, &rd) || rd == 0) break;
        res.append(buf.data(), buf.data() + rd);
        if ((int)res.size() >= maxBytes) break;
    }

    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    return res;
}

static std::string RunCommandCapture(const std::wstring& commandLine, DWORD timeoutMs, DWORD* exitCodeOut) {
    if (exitCodeOut) *exitCodeOut = 0;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = NULL;

    PROCESS_INFORMATION pi = {};
    std::wstring cmd = commandLine;
    // CreateProcess requires modifiable buffer
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);

    BOOL ok = CreateProcessW(NULL, buf.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWrite);
    if (!ok) {
        CloseHandle(hRead);
        return "";
    }

    std::string output;
    DWORD start = GetTickCount();
    while (true) {
        // Drain pipe
        DWORD avail = 0;
        if (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            std::vector<char> chunk(avail);
            DWORD read = 0;
            if (ReadFile(hRead, chunk.data(), avail, &read, NULL) && read > 0) {
                output.append(chunk.data(), chunk.data() + read);
            }
        }

        DWORD waitRes = WaitForSingleObject(pi.hProcess, 50);
        if (waitRes == WAIT_OBJECT_0) break;
        if (timeoutMs != INFINITE && (GetTickCount() - start) > timeoutMs) {
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    }

    // Drain remaining
    while (true) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) || avail == 0) break;
        std::vector<char> chunk(avail);
        DWORD read = 0;
        if (!ReadFile(hRead, chunk.data(), avail, &read, NULL) || read == 0) break;
        output.append(chunk.data(), chunk.data() + read);
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    if (exitCodeOut) *exitCodeOut = exitCode;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hRead);
    return output;
}

static std::string WingetCmd(const std::string& args, DWORD timeoutMs, DWORD* exitCodeOut) {
    std::wstring cmd = L"cmd.exe /C winget " + s2ws(args);
    std::string out = RunCommandCapture(cmd, timeoutMs, exitCodeOut);
    if (out.empty()) out = "(no output)";
    return out;
}

static std::wstring GetDesktopDirW() {
    wchar_t buf[MAX_PATH] = {};
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, buf) == S_OK) {
        return buf;
    }
    return L"";
}

// =========================================================
// WORKSPACE FILE + COMMAND TOOLS (agentic coding)
// =========================================================

static std::wstring GetCwdW() {
    wchar_t buf[MAX_PATH] = {};
    GetCurrentDirectoryW(MAX_PATH, buf);
    return buf;
}

static bool IsAbsolutePathW(const std::wstring& p) {
    if (p.size() >= 2 && ((p[1] == L':') || (p[0] == L'\\' && p[1] == L'\\'))) return true;
    return false;
}

static std::wstring ResolvePathW(const std::wstring& baseDirW, const std::wstring& pathW) {
    if (pathW.empty()) return L"";
    if (IsAbsolutePathW(pathW)) return pathW;
    std::wstring base = baseDirW.empty() ? GetCwdW() : baseDirW;
    return NormalizeSlashesW(JoinPathW(base, pathW));
}

// Forward decl (used by ResolveFsPathW)
static std::wstring GetParentDirW(const std::wstring& pathW);

static bool PathExistsW(const std::wstring& pathW) {
    DWORD a = GetFileAttributesW(pathW.c_str());
    return a != INVALID_FILE_ATTRIBUTES;
}

static bool DirExistsW(const std::wstring& pathW) {
    DWORD a = GetFileAttributesW(pathW.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return false;
    return (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static bool HasSlashW(const std::wstring& p) {
    return p.find_first_of(L"\\/") != std::wstring::npos;
}

static std::wstring ResolveCwdW(const std::wstring& cwdW) {
    if (cwdW.empty()) return L"";
    std::wstring c = NormalizeSlashesW(cwdW);
    if (IsAbsolutePathW(c)) return c;
    return NormalizeSlashesW(JoinPathW(GetCwdW(), c));
}

static std::wstring GetCodingBaseW() {
    // Default place for agent-created coding/projects so user can find it easily.
    std::wstring desktop = GetDesktopDirW();
    if (desktop.empty()) return GetCwdW();
    std::wstring base = JoinPathW(desktop, L"OfradrAgentWorkspace");
    EnsureDirRecursiveW(base);
    return base;
}

static std::wstring ResolveFsPathW(const std::wstring& baseDirW, const std::wstring& pathW) {
    // Resolution rules:
    // - absolute path: use as-is
    // - if baseDirW provided: base + path
    // - else: prefer CWD when path exists OR when writing under an existing subdir in CWD
    //         otherwise put new stuff under Desktop\OfradrAgentWorkspace
    if (pathW.empty()) return L"";
    if (IsAbsolutePathW(pathW)) return NormalizeSlashesW(pathW);
    if (!baseDirW.empty()) return NormalizeSlashesW(JoinPathW(baseDirW, pathW));

    std::wstring cwd = GetCwdW();
    std::wstring candCwd = NormalizeSlashesW(JoinPathW(cwd, pathW));
    if (PathExistsW(candCwd)) return candCwd;

    // If the relative path includes subdirs and the parent directory exists in CWD,
    // assume this is a repo edit (new file inside existing tree).
    if (HasSlashW(pathW)) {
        std::wstring parent = GetParentDirW(candCwd);
        if (!parent.empty() && DirExistsW(parent)) return candCwd;
    }

    return NormalizeSlashesW(JoinPathW(GetCodingBaseW(), pathW));
}

static bool ReadFileBytesW(const std::wstring& pathW, std::string& outBytes, std::string* errOut = nullptr, long long maxBytes = 2LL * 1024LL * 1024LL) {
    outBytes.clear();
    HANDLE h = CreateFileW(pathW.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        if (errOut) {
            DWORD gle = GetLastError();
            *errOut = "open failed gle=" + std::to_string((unsigned long)gle) + ": " + WinErrStrA(gle);
        }
        return false;
    }
    LARGE_INTEGER sz = {};
    GetFileSizeEx(h, &sz);
    if (sz.QuadPart < 0) sz.QuadPart = 0;
    long long toRead = sz.QuadPart;
    if (maxBytes > 0 && toRead > maxBytes) toRead = maxBytes;
    if (toRead == 0) {
        CloseHandle(h);
        outBytes.clear();
        return true;
    }
    outBytes.resize((size_t)toRead);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, &outBytes[0], (DWORD)toRead, &rd, NULL);
    CloseHandle(h);
    if (!ok) {
        if (errOut) {
            DWORD gle = GetLastError();
            *errOut = "read failed gle=" + std::to_string((unsigned long)gle) + ": " + WinErrStrA(gle);
        }
        outBytes.clear();
        return false;
    }
    outBytes.resize((size_t)rd);
    return true;
}

static std::string Base64DecodeLoose(const std::string& in) {
    // Accept base64 with whitespace/newlines; ignore non-base64 chars.
    std::string cleaned;
    cleaned.reserve(in.size());
    for (unsigned char c : in) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            cleaned.push_back((char)c);
        }
        else if (c == '-' || c == '_') {
            // base64url -> base64
            cleaned.push_back(c == '-' ? '+' : '/');
        }
        else {
            // skip whitespace/other
        }
    }
    return Base64Decode(cleaned);
}

static bool WriteFileBytesW(const std::wstring& pathW, const std::string& bytes, std::string* errOut = nullptr) {
    HANDLE h = CreateFileW(pathW.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        if (errOut) {
            DWORD gle = GetLastError();
            *errOut = "create failed gle=" + std::to_string((unsigned long)gle) + ": " + WinErrStrA(gle);
        }
        return false;
    }
    DWORD wrote = 0;
    BOOL ok = TRUE;
    if (!bytes.empty()) {
        ok = WriteFile(h, bytes.data(), (DWORD)bytes.size(), &wrote, NULL);
    }
    CloseHandle(h);
    if (!ok || wrote != (DWORD)bytes.size()) {
        if (errOut) {
            DWORD gle = GetLastError();
            *errOut = "write failed gle=" + std::to_string((unsigned long)gle) + ": " + WinErrStrA(gle) +
                " wrote=" + std::to_string((unsigned long)wrote) + " expected=" + std::to_string((unsigned long)bytes.size());
        }
        return false;
    }
    return true;
}

static std::wstring GetParentDirW(const std::wstring& pathW) {
    if (pathW.empty()) return L"";
    size_t slash = pathW.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L"";
    return pathW.substr(0, slash);
}

static std::string BackupFileToMemoryRoot(const std::wstring& pathW) {
    // Best-effort backup; returns backup path or empty.
    std::string err;
    GetMemoryRoot();
    std::wstring backupDir = JoinPathW(g_memRoot, L"backups");
    EnsureDirRecursiveW(backupDir);

    std::string content;
    std::string readErr;
    if (!ReadFileBytesW(pathW, content, &readErr, 2LL * 1024LL * 1024LL)) return "";

    // Skip backup for empty file
    if (content.empty()) return "";

    // Generate filename
    long long ts = NowUtcEpochSec();
    std::wstring base = pathW;
    size_t slash = base.find_last_of(L"\\/");
    if (slash != std::wstring::npos) base = base.substr(slash + 1);
    if (base.empty()) base = L"file";

    std::wstring name = L"bk_" + std::to_wstring(ts) + L"_" + std::to_wstring(GetTickCount64()) + L"_" + base;
    std::wstring outPathW = JoinPathW(backupDir, name);
    std::string writeErr;
    if (!WriteFileBytesW(outPathW, content, &writeErr)) return "";
    return ws2s(outPathW);
}

static void SplitLines(const std::string& text, std::vector<std::string>& outLines, bool& outEndsWithNewline) {
    outLines.clear();
    outEndsWithNewline = false;
    if (text.empty()) return;
    outEndsWithNewline = (!text.empty() && (text.back() == '\n'));
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        size_t end = (nl == std::string::npos) ? text.size() : nl;
        std::string line = text.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        outLines.push_back(line);
        if (nl == std::string::npos) break;
        start = nl + 1;
        if (start == text.size()) break;
    }
}

static std::string JoinLines(const std::vector<std::string>& lines, const std::string& newline, bool endWithNewline) {
    std::string out;
    for (size_t i = 0; i < lines.size(); i++) {
        out += lines[i];
        if (i + 1 < lines.size()) out += newline;
    }
    if (endWithNewline && (out.empty() || (out.size() >= 1 && out.back() != '\n'))) {
        out += newline;
    }
    return out;
}

static std::string DetectNewline(const std::string& text) {
    // Prefer CRLF if present.
    if (text.find("\r\n") != std::string::npos) return "\r\n";
    return "\n";
}

static std::string FsReadTextLines(const std::wstring& pathW, int startLine, int lineCount) {
    std::string bytes;
    std::string err;
    if (!ReadFileBytesW(pathW, bytes, &err, 4LL * 1024LL * 1024LL)) {
        return "FS_READ: failed (" + err + ")";
    }
    std::vector<std::string> lines;
    bool endsNl = false;
    SplitLines(bytes, lines, endsNl);
    int n = (int)lines.size();
    if (startLine < 1) startLine = 1;
    if (lineCount < 1) lineCount = 200;
    if (lineCount > 2000) lineCount = 2000;
    int endLine = startLine + lineCount - 1;
    if (endLine > n) endLine = n;
    if (startLine > n) {
        return "FS_READ: OK (0 lines)\n";
    }
    std::stringstream ss;
    ss << "FS_READ: " << ws2s(pathW) << "\n";
    ss << "Lines " << startLine << ".." << endLine << " of " << n << "\n";
    for (int i = startLine; i <= endLine; i++) {
        std::string l = lines[(size_t)i - 1];
        if (l.size() > 2000) l.resize(2000);
        ss << i << ": " << l << "\n";
    }
    return ss.str();
}

static std::string FsWriteFile(const std::wstring& baseDirW, const std::string& path, const std::string& content, bool createDirs, bool backup) {
    std::wstring pathW = ResolveFsPathW(baseDirW, s2ws(path));
    if (pathW.empty()) return "FS_WRITE: missing path";

    if (createDirs) {
        std::wstring parent = GetParentDirW(pathW);
        if (!parent.empty()) EnsureDirRecursiveW(parent);
    }

    std::string bk;
    DWORD attrs = GetFileAttributesW(pathW.c_str());
    if (backup && attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        bk = BackupFileToMemoryRoot(pathW);
    }

    std::string err;
    if (!WriteFileBytesW(pathW, content, &err)) {
        return "FS_WRITE: failed path=" + ws2s(pathW) + " (" + err + ")";
    }
    std::stringstream ss;
    ss << "FS_WRITE: OK " << ws2s(pathW) << " (" << content.size() << " bytes)";
    if (!bk.empty()) ss << "\nBackup: " << bk;
    return ss.str();
}

static std::string FsReplaceLines(const std::wstring& baseDirW, const std::string& path, int startLine, int endLine, const std::string& newText, bool createDirs, bool backup) {
    std::wstring pathW = ResolveFsPathW(baseDirW, s2ws(path));
    if (pathW.empty()) return "FS_REPLACE_LINES: missing path";

    if (createDirs) {
        std::wstring parent = GetParentDirW(pathW);
        if (!parent.empty()) EnsureDirRecursiveW(parent);
    }

    std::string oldBytes;
    std::string err;
    bool existed = (GetFileAttributesW(pathW.c_str()) != INVALID_FILE_ATTRIBUTES);
    if (existed) {
        if (!ReadFileBytesW(pathW, oldBytes, &err, 4LL * 1024LL * 1024LL)) {
            return "FS_REPLACE_LINES: read failed path=" + ws2s(pathW) + " (" + err + ")";
        }
    }

    std::string newline = DetectNewline(oldBytes);
    std::vector<std::string> lines;
    bool endsNl = false;
    SplitLines(oldBytes, lines, endsNl);
    int n = (int)lines.size();
    if (n == 1 && lines[0].empty() && oldBytes.empty()) n = 0;

    if (startLine < 1) startLine = 1;
    if (endLine < startLine - 1) endLine = startLine - 1;
    if (startLine > n + 1) { startLine = n + 1; endLine = n; }
    if (endLine > n) endLine = n;

    std::vector<std::string> newLines;
    bool newEnds = false;
    SplitLines(newText, newLines, newEnds);
    // If newText is empty, SplitLines returns empty; represent deletion

    std::vector<std::string> out;
    out.reserve((size_t)n + newLines.size() + 8);
    for (int i = 1; i <= startLine - 1 && i <= n; i++) out.push_back(lines[(size_t)i - 1]);
    for (size_t i = 0; i < newLines.size(); i++) out.push_back(newLines[i]);
    if (endLine >= startLine) {
        for (int i = endLine + 1; i <= n; i++) out.push_back(lines[(size_t)i - 1]);
    }
    bool outEndsNl = endsNl;
    std::string outBytes = JoinLines(out, newline, outEndsNl);

    std::string bk;
    if (backup && existed) {
        bk = BackupFileToMemoryRoot(pathW);
    }
    std::string werr;
    if (!WriteFileBytesW(pathW, outBytes, &werr)) {
        return "FS_REPLACE_LINES: write failed path=" + ws2s(pathW) + " (" + werr + ")";
    }

    std::stringstream ss;
    ss << "FS_REPLACE_LINES: OK " << ws2s(pathW) << "\n";
    ss << "Replaced lines " << startLine << ".." << endLine << " (old lines=" << n << ")";
    if (!bk.empty()) ss << "\nBackup: " << bk;
    return ss.str();
}

static std::string NormalizePathForMatch(const std::wstring& pW) {
    std::string p = ws2s(pW);
    for (size_t i = 0; i < p.size(); i++) {
        if (p[i] == '\\') p[i] = '/';
        p[i] = (char)tolower((unsigned char)p[i]);
    }
    return p;
}

static void SplitBySlash(const std::string& s, std::vector<std::string>& out) {
    out.clear();
    size_t start = 0;
    while (start <= s.size()) {
        size_t slash = s.find('/', start);
        if (slash == std::string::npos) slash = s.size();
        std::string part = s.substr(start, slash - start);
        if (!part.empty()) out.push_back(part);
        if (slash == s.size()) break;
        start = slash + 1;
    }
}

static bool GlobMatchSegment(const std::string& pat, const std::string& txt) {
    // '*' matches any run, '?' matches one char. Case-insensitive (caller lowercases).
    size_t p = 0, t = 0;
    size_t star = std::string::npos, starMatch = 0;
    while (t < txt.size()) {
        if (p < pat.size() && (pat[p] == '?' || pat[p] == txt[t])) {
            p++; t++; continue;
        }
        if (p < pat.size() && pat[p] == '*') {
            star = p++;
            starMatch = t;
            continue;
        }
        if (star != std::string::npos) {
            p = star + 1;
            t = ++starMatch;
            continue;
        }
        return false;
    }
    while (p < pat.size() && pat[p] == '*') p++;
    return p == pat.size();
}

static bool GlobMatchPathParts(const std::vector<std::string>& patParts, size_t pi, const std::vector<std::string>& pathParts, size_t si) {
    if (pi >= patParts.size()) return si >= pathParts.size();
    const std::string& pp = patParts[pi];
    if (pp == "**") {
        // Match zero or more path segments
        if (pi + 1 >= patParts.size()) return true;
        for (size_t k = si; k <= pathParts.size(); k++) {
            if (GlobMatchPathParts(patParts, pi + 1, pathParts, k)) return true;
        }
        return false;
    }
    if (si >= pathParts.size()) return false;
    if (!GlobMatchSegment(pp, pathParts[si])) return false;
    return GlobMatchPathParts(patParts, pi + 1, pathParts, si + 1);
}

static bool GlobMatchPath(const std::string& patternLower, const std::string& pathLower) {
    std::vector<std::string> patParts;
    std::vector<std::string> pathParts;
    SplitBySlash(patternLower, patParts);
    SplitBySlash(pathLower, pathParts);
    return GlobMatchPathParts(patParts, 0, pathParts, 0);
}

static bool ShouldSkipDirName(const std::wstring& nameW) {
    std::wstring n = nameW;
    std::transform(n.begin(), n.end(), n.begin(), ::towlower);
    if (n == L".git" || n == L"node_modules" || n == L".venv" || n == L"venv" || n == L"__pycache__") return true;
    if (n == L"dist" || n == L"build" || n == L"out" || n == L".idea" || n == L".vs") return true;
    return false;
}

static std::string FsListDir(const std::wstring& dirW, int limit) {
    if (limit < 1) limit = 200;
    if (limit > 2000) limit = 2000;

    DWORD a = GetFileAttributesW(dirW.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) {
        DWORD gle = GetLastError();
        return "FS_LIST_DIR: not found path=" + ws2s(dirW) + " gle=" + std::to_string((unsigned long)gle) + ": " + WinErrStrA(gle);
    }
    if ((a & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return "FS_LIST_DIR: not a directory path=" + ws2s(dirW);
    }

    std::wstring pattern = dirW;
    if (!pattern.empty() && pattern.back() != L'\\' && pattern.back() != L'/') pattern += L"\\";
    pattern += L"*";
    WIN32_FIND_DATAW f = {};
    HANDLE h = FindFirstFileW(pattern.c_str(), &f);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        return "FS_LIST_DIR: failed path=" + ws2s(dirW) + " gle=" + std::to_string((unsigned long)gle) + ": " + WinErrStrA(gle);
    }
    std::stringstream ss;
    ss << "FS_LIST_DIR: " << ws2s(dirW) << "\n";
    int count = 0;
    do {
        if (wcscmp(f.cFileName, L".") == 0 || wcscmp(f.cFileName, L"..") == 0) continue;
        std::wstring nameW = f.cFileName;
        bool isDir = (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (isDir) ss << "D "; else ss << "F ";
        ss << ws2s(nameW);
        if (!isDir) {
            ULARGE_INTEGER sz; sz.LowPart = f.nFileSizeLow; sz.HighPart = f.nFileSizeHigh;
            ss << " (" << (unsigned long long)sz.QuadPart << " bytes)";
        }
        ss << "\n";
        count++;
        if (count >= limit) break;
    } while (FindNextFileW(h, &f));
    FindClose(h);
    if (count >= limit) ss << "...(truncated)...\n";
    return ss.str();
}

static std::string FsGlob(const std::wstring& baseDirW, const std::string& patternUtf8, int maxResults) {
    if (maxResults < 1) maxResults = 200;
    if (maxResults > 5000) maxResults = 5000;
    std::wstring rootW = baseDirW.empty() ? GetCwdW() : baseDirW;
    std::string pat = patternUtf8;
    for (size_t i = 0; i < pat.size(); i++) {
        if (pat[i] == '\\') pat[i] = '/';
        pat[i] = (char)tolower((unsigned char)pat[i]);
    }

    std::vector<std::wstring> stack;
    stack.push_back(rootW);
    std::vector<std::string> matches;
    matches.reserve((size_t)std::min(maxResults, 256));

    while (!stack.empty() && (int)matches.size() < maxResults) {
        std::wstring dirW = stack.back();
        stack.pop_back();

        std::wstring search = dirW;
        if (!search.empty() && search.back() != L'\\' && search.back() != L'/') search += L"\\";
        search += L"*";

        WIN32_FIND_DATAW f = {};
        HANDLE h = FindFirstFileW(search.c_str(), &f);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (wcscmp(f.cFileName, L".") == 0 || wcscmp(f.cFileName, L"..") == 0) continue;
            std::wstring nameW = f.cFileName;
            std::wstring fullW = dirW;
            if (!fullW.empty() && fullW.back() != L'\\' && fullW.back() != L'/') fullW += L"\\";
            fullW += nameW;

            bool isDir = (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            if (isDir) {
                if (ShouldSkipDirName(nameW)) continue;
                stack.push_back(fullW);
            }

            // Compute relative path for matching
            std::wstring relW = fullW;
            if (relW.size() >= rootW.size()) {
                std::wstring r = rootW;
                if (!r.empty() && (r.back() == L'\\' || r.back() == L'/')) r.pop_back();
                if (relW.size() >= r.size() && _wcsnicmp(relW.c_str(), r.c_str(), r.size()) == 0) {
                    relW = relW.substr(r.size());
                    while (!relW.empty() && (relW[0] == L'\\' || relW[0] == L'/')) relW.erase(relW.begin());
                }
            }
            std::string relLower = NormalizePathForMatch(relW);
            if (GlobMatchPath(pat, relLower)) {
                matches.push_back(ws2s(fullW));
                if ((int)matches.size() >= maxResults) break;
            }

        } while (FindNextFileW(h, &f));
        FindClose(h);
    }

    std::stringstream ss;
    ss << "FS_GLOB: pattern='" << patternUtf8 << "' base='" << ws2s(rootW) << "'\n";
    if (matches.empty()) {
        ss << "(no matches)\n";
        return ss.str();
    }
    for (size_t i = 0; i < matches.size(); i++) {
        ss << matches[i] << "\n";
    }
    if ((int)matches.size() >= maxResults) ss << "...(truncated)...\n";
    return ss.str();
}

static std::string RunCommandCaptureEx(const std::wstring& commandLine, const std::wstring& cwdW, DWORD timeoutMs, DWORD* exitCodeOut, int maxBytes, std::string* errOut) {
    if (exitCodeOut) *exitCodeOut = 0;
    if (maxBytes <= 0) maxBytes = 200000;
    if (errOut) errOut->clear();
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        if (errOut) {
            DWORD gle = GetLastError();
            *errOut = "CreatePipe failed gle=" + std::to_string((unsigned long)gle) + ": " + WinErrStrA(gle);
        }
        return "";
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = NULL;

    PROCESS_INFORMATION pi = {};
    std::wstring cmd = commandLine;
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);

    const wchar_t* cwdPtr = (cwdW.empty() ? NULL : cwdW.c_str());

    // Use a Job object so timeouts/terminations kill the whole process tree.
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &info, sizeof(info));
    }

    DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;
    BOOL ok = CreateProcessW(NULL, buf.data(), NULL, NULL, TRUE, flags, NULL, cwdPtr, &si, &pi);
    CloseHandle(hWrite);
    if (!ok) {
        if (errOut) {
            DWORD gle = GetLastError();
            *errOut = "CreateProcessW failed gle=" + std::to_string((unsigned long)gle) + ": " + WinErrStrA(gle);
        }
        if (hJob) CloseHandle(hJob);
        CloseHandle(hRead);
        return "";
    }

    if (hJob) {
        AssignProcessToJobObject(hJob, pi.hProcess);
    }
    ResumeThread(pi.hThread);

    std::string output;
    output.reserve((size_t)std::min(maxBytes, 16384));
    bool truncated = false;
    DWORD start = GetTickCount();
    while (true) {
        DWORD avail = 0;
        if (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD chunkSize = avail;
            if (chunkSize > 32768) chunkSize = 32768;
            std::vector<char> chunk(chunkSize);
            DWORD read = 0;
            if (ReadFile(hRead, chunk.data(), chunkSize, &read, NULL) && read > 0) {
                if (!truncated) {
                    int remain = maxBytes - (int)output.size();
                    if (remain > 0) {
                        DWORD take = (DWORD)std::min<int>(remain, (int)read);
                        output.append(chunk.data(), chunk.data() + take);
                        if ((int)output.size() >= maxBytes) truncated = true;
                    }
                    else {
                        truncated = true;
                    }
                }
            }
        }

        DWORD waitRes = WaitForSingleObject(pi.hProcess, 50);
        if (waitRes == WAIT_OBJECT_0) break;
        if (timeoutMs != INFINITE && (GetTickCount() - start) > timeoutMs) {
            TerminateProcess(pi.hProcess, 1);
            if (errOut && errOut->empty()) {
                *errOut = "timeout after " + std::to_string((unsigned long)timeoutMs) + "ms";
            }
            break;
        }
    }

    // Drain remaining
    while (true) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) || avail == 0) break;
        DWORD chunkSize = avail;
        if (chunkSize > 32768) chunkSize = 32768;
        std::vector<char> chunk(chunkSize);
        DWORD read = 0;
        if (!ReadFile(hRead, chunk.data(), chunkSize, &read, NULL) || read == 0) break;
        if (!truncated) {
            int remain = maxBytes - (int)output.size();
            if (remain > 0) {
                DWORD take = (DWORD)std::min<int>(remain, (int)read);
                output.append(chunk.data(), chunk.data() + take);
                if ((int)output.size() >= maxBytes) truncated = true;
            }
            else truncated = true;
        }
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    if (exitCodeOut) *exitCodeOut = exitCode;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hRead);
    if (hJob) CloseHandle(hJob);
    if (truncated) output += "\n...(truncated)...\n";
    return output;
}

// =========================================================
// MCP (Model Context Protocol) CLIENT (NPX/stdio)
// - Spawns MCP servers via `npx -y` (stdio transport)
// - Speaks newline-delimited JSON-RPC 2.0 over stdin/stdout
// =========================================================

static std::string UrlEncodeSimple(const std::string& s) {
    // Encode only the common set we need for file:// URIs (spaces etc.).
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '/' || c == ':' || c == '~') {
            out.push_back((char)c);
        }
        else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

static std::string FileUriFromPathW(const std::wstring& pathW) {
    std::string p = ws2s(pathW);
    for (size_t i = 0; i < p.size(); i++) if (p[i] == '\\') p[i] = '/';
    // Windows absolute path like C:/...
    if (p.size() >= 2 && p[1] == ':') {
        return "file:///" + UrlEncodeSimple(p);
    }
    // UNC path //server/share
    if (p.size() >= 2 && p[0] == '/' && p[1] == '/') {
        return "file:" + UrlEncodeSimple(p);
    }
    return "file://" + UrlEncodeSimple(p);
}

struct McpConn {
    std::string id;
    std::string package;
    std::vector<std::string> args;
    std::unordered_map<std::string, std::string> env;
    std::wstring cwdW;

    PROCESS_INFORMATION pi = {};
    HANDLE hJob = NULL;
    HANDLE hStdinWrite = NULL;
    HANDLE hStdoutRead = NULL;
    HANDLE hStderrRead = NULL;

    std::atomic<bool> running{ false };
    std::thread tOut;
    std::thread tErr;

    std::mutex mu;
    std::condition_variable cv;
    int nextId = 1;
    std::unordered_map<int, json> responses; // id -> full response object
    std::vector<std::string> stderrLog;      // recent stderr lines
    json serverCaps = json::object();
    json toolCache = json();
    json resourceCache = json();
};

static std::mutex g_mcpMu;
static std::unordered_map<std::string, std::shared_ptr<McpConn>> g_mcp;

static void McpPushErr(std::shared_ptr<McpConn> c, const std::string& line) {
    std::lock_guard<std::mutex> lk(c->mu);
    c->stderrLog.push_back(line);
    if (c->stderrLog.size() > 60) c->stderrLog.erase(c->stderrLog.begin(), c->stderrLog.begin() + (c->stderrLog.size() - 60));
}

static bool McpWriteLine(std::shared_ptr<McpConn> c, const std::string& line) {
    if (!c || !c->hStdinWrite) return false;
    std::string msg = line;
    msg += "\n";
    DWORD wrote = 0;
    BOOL ok = WriteFile(c->hStdinWrite, msg.data(), (DWORD)msg.size(), &wrote, NULL);
    return ok && wrote == (DWORD)msg.size();
}

static std::string McpMakeCmdLineNPX(const std::string& package, const std::vector<std::string>& args) {
    std::stringstream ss;
    ss << "npx -y " << package;
    for (const auto& a : args) {
        ss << " " << a;
    }
    return ss.str();
}

static void BuildMergedEnvBlockW(const std::unordered_map<std::string, std::string>& overrides, std::vector<wchar_t>& outBlock) {
    outBlock.clear();
    // Load current environment
    std::unordered_map<std::wstring, std::wstring> env;
    LPWCH base = GetEnvironmentStringsW();
    if (base) {
        const wchar_t* p = base;
        while (*p) {
            std::wstring entry = p;
            size_t eq = entry.find(L'=');
            if (eq != std::wstring::npos && eq > 0) {
                env[entry.substr(0, eq)] = entry.substr(eq + 1);
            }
            p += entry.size() + 1;
        }
        FreeEnvironmentStringsW(base);
    }
    // Apply overrides
    for (const auto& kv : overrides) {
        env[s2ws(kv.first)] = s2ws(kv.second);
    }
    // Sort keys for nicer blocks
    std::vector<std::wstring> keys;
    keys.reserve(env.size());
    for (const auto& kv : env) keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end(), [](const std::wstring& a, const std::wstring& b) {
        return _wcsicmp(a.c_str(), b.c_str()) < 0;
        });

    // Build block: "k=v\0...\0\0"
    for (const auto& k : keys) {
        auto it = env.find(k);
        if (it == env.end()) continue;
        const std::wstring& v = it->second;
        outBlock.insert(outBlock.end(), k.begin(), k.end());
        outBlock.push_back(L'=');
        outBlock.insert(outBlock.end(), v.begin(), v.end());
        outBlock.push_back(0);
    }
    outBlock.push_back(0);
}

static bool McpSpawnServer(std::shared_ptr<McpConn> c, std::string* errOut) {
    if (errOut) errOut->clear();
    if (!c) { if (errOut) *errOut = "missing conn"; return false; }

    // Pipes
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE inRead = NULL, inWrite = NULL;
    HANDLE outRead = NULL, outWrite = NULL;
    HANDLE errRead = NULL, errWrite = NULL;
    if (!CreatePipe(&inRead, &inWrite, &sa, 0)) { if (errOut) *errOut = "stdin pipe failed"; return false; }
    if (!CreatePipe(&outRead, &outWrite, &sa, 0)) { CloseHandle(inRead); CloseHandle(inWrite); if (errOut) *errOut = "stdout pipe failed"; return false; }
    if (!CreatePipe(&errRead, &errWrite, &sa, 0)) { CloseHandle(inRead); CloseHandle(inWrite); CloseHandle(outRead); CloseHandle(outWrite); if (errOut) *errOut = "stderr pipe failed"; return false; }

    SetHandleInformation(inWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = inRead;
    si.hStdOutput = outWrite;
    si.hStdError = errWrite;

    // Job object to kill full tree
    c->hJob = CreateJobObjectW(NULL, NULL);
    if (c->hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(c->hJob, JobObjectExtendedLimitInformation, &info, sizeof(info));
    }

    std::string cmd = McpMakeCmdLineNPX(c->package, c->args);
    std::wstring wcmd = L"cmd.exe /Q /D /S /C " + s2ws(cmd);
    std::vector<wchar_t> buf(wcmd.begin(), wcmd.end());
    buf.push_back(0);

    // Environment block (optional overrides)
    std::vector<wchar_t> envBlock;
    LPVOID envPtr = NULL;
    if (!c->env.empty()) {
        BuildMergedEnvBlockW(c->env, envBlock);
        envPtr = envBlock.data();
    }

    DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;
    BOOL ok = CreateProcessW(NULL, buf.data(), NULL, NULL, TRUE, flags, (LPVOID)envPtr, c->cwdW.empty() ? NULL : c->cwdW.c_str(), &si, &c->pi);

    // Parent closes child ends
    CloseHandle(inRead);
    CloseHandle(outWrite);
    CloseHandle(errWrite);

    if (!ok) {
        DWORD gle = GetLastError();
        if (errOut) *errOut = "CreateProcessW failed gle=" + std::to_string((unsigned long)gle) + ": " + WinErrStrA(gle);
        if (c->hJob) { CloseHandle(c->hJob); c->hJob = NULL; }
        CloseHandle(inWrite);
        CloseHandle(outRead);
        CloseHandle(errRead);
        ZeroMemory(&c->pi, sizeof(c->pi));
        return false;
    }

    if (c->hJob) AssignProcessToJobObject(c->hJob, c->pi.hProcess);
    ResumeThread(c->pi.hThread);

    c->hStdinWrite = inWrite;
    c->hStdoutRead = outRead;
    c->hStderrRead = errRead;

    CloseHandle(c->pi.hThread); // we don't need thread handle
    c->pi.hThread = NULL;
    c->running = true;
    return true;
}

static void McpHandleServerRequest(std::shared_ptr<McpConn> c, const json& msg) {
    // Only handle roots/list for now.
    if (!msg.contains("method") || !msg["method"].is_string()) return;
    std::string method = msg["method"].get<std::string>();
    if (!msg.contains("id")) return;
    int id = 0;
    try { id = msg["id"].get<int>(); }
    catch (...) { return; }

    if (method == "roots/list") {
        json res;
        res["jsonrpc"] = "2.0";
        res["id"] = id;
        json roots = json::array();
        roots.push_back({ {"uri", FileUriFromPathW(GetCwdW())}, {"name", "WorkspaceCWD"} });
        roots.push_back({ {"uri", FileUriFromPathW(GetCodingBaseW())}, {"name", "DesktopWorkspace"} });
        res["result"] = { {"roots", roots} };
        (void)McpWriteLine(c, res.dump());
    }
    else {
        // Method not found
        json err;
        err["jsonrpc"] = "2.0";
        err["id"] = id;
        err["error"] = { {"code", -32601}, {"message", "Method not found"} };
        (void)McpWriteLine(c, err.dump());
    }
}

static void McpStdoutThread(std::shared_ptr<McpConn> c) {
    std::string buf;
    buf.reserve(8192);
    char chunk[4096];
    while (c && c->running && c->hStdoutRead) {
        DWORD rd = 0;
        BOOL ok = ReadFile(c->hStdoutRead, chunk, sizeof(chunk), &rd, NULL);
        if (!ok || rd == 0) break;
        buf.append(chunk, chunk + rd);
        for (;;) {
            size_t nl = buf.find('\n');
            if (nl == std::string::npos) break;
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            if (line.empty()) continue;

            // MCP requires stdout to be JSON-RPC; in practice some servers log to stdout. Be tolerant.
            json j;
            bool parsed = false;
            try {
                j = json::parse(line);
                parsed = true;
            }
            catch (...) {
                McpPushErr(c, std::string("[stdout-nonjson] ") + line);
            }
            if (!parsed) continue;

            // Response
            if (j.contains("id") && (j.contains("result") || j.contains("error"))) {
                int id = 0;
                try { id = j["id"].get<int>(); }
                catch (...) { continue; }
                {
                    std::lock_guard<std::mutex> lk(c->mu);
                    c->responses[id] = j;
                }
                c->cv.notify_all();
                continue;
            }

            // Server request
            if (j.contains("id") && j.contains("method") && !j.contains("result") && !j.contains("error")) {
                McpHandleServerRequest(c, j);
                continue;
            }

            // Notification: ignore
        }
    }
    if (c) c->running = false;
}

static void McpStderrThread(std::shared_ptr<McpConn> c) {
    std::string buf;
    buf.reserve(4096);
    char chunk[2048];
    while (c && c->running && c->hStderrRead) {
        DWORD rd = 0;
        BOOL ok = ReadFile(c->hStderrRead, chunk, sizeof(chunk), &rd, NULL);
        if (!ok || rd == 0) break;
        buf.append(chunk, chunk + rd);
        for (;;) {
            size_t nl = buf.find('\n');
            if (nl == std::string::npos) break;
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            if (line.empty()) continue;
            McpPushErr(c, line);
        }
    }
}

static bool McpRpc(std::shared_ptr<McpConn> c, const std::string& method, const json& params, int timeoutMs, json& outResp, std::string* errOut) {
    if (errOut) errOut->clear();
    outResp = json();
    if (!c || !c->running) { if (errOut) *errOut = "not connected"; return false; }
    int id = 0;
    {
        std::lock_guard<std::mutex> lk(c->mu);
        id = c->nextId++;
    }
    json req;
    req["jsonrpc"] = "2.0";
    req["id"] = id;
    req["method"] = method;
    if (!params.is_null()) req["params"] = params;
    if (!McpWriteLine(c, req.dump())) {
        if (errOut) *errOut = "write failed";
        return false;
    }

    std::unique_lock<std::mutex> lk(c->mu);
    auto pred = [&]() { return c->responses.find(id) != c->responses.end() || !c->running; };
    if (!c->cv.wait_for(lk, std::chrono::milliseconds(timeoutMs <= 0 ? 30000 : timeoutMs), pred)) {
        if (errOut) *errOut = "timeout";
        return false;
    }
    auto it = c->responses.find(id);
    if (it == c->responses.end()) {
        if (errOut) *errOut = "no response";
        return false;
    }
    outResp = it->second;
    c->responses.erase(it);
    return true;
}

static bool McpInitialize(std::shared_ptr<McpConn> c, int timeoutMs, std::string* errOut) {
    if (errOut) errOut->clear();
    json initParams;
    initParams["protocolVersion"] = "2024-11-05";
    initParams["capabilities"] = { {"roots", { {"listChanged", true} } } };
    initParams["clientInfo"] = { {"name", "OfradrAgent"}, {"version", "1.0"} };
    json resp;
    std::string e;
    if (!McpRpc(c, "initialize", initParams, timeoutMs <= 0 ? 30000 : timeoutMs, resp, &e)) {
        if (errOut) *errOut = "initialize failed: " + e;
        return false;
    }
    if (resp.contains("result") && resp["result"].is_object()) {
        c->serverCaps = resp["result"].value("capabilities", json::object());
    }
    json inited;
    inited["jsonrpc"] = "2.0";
    inited["method"] = "notifications/initialized";
    (void)McpWriteLine(c, inited.dump());
    return true;
}

static std::string McpServerSummary(std::shared_ptr<McpConn> c) {
    std::stringstream ss;
    ss << "MCP CONNECTED id='" << c->id << "' package='" << c->package << "'";
    if (!c->args.empty()) {
        ss << "\nArgs:";
        for (auto& a : c->args) ss << " " << a;
    }
    if (!c->serverCaps.is_null() && !c->serverCaps.empty()) {
        ss << "\nCapabilities: " << c->serverCaps.dump();
    }
    if (!c->stderrLog.empty()) {
        ss << "\nRecent stderr (last " << c->stderrLog.size() << "):\n";
        size_t start = c->stderrLog.size() > 10 ? c->stderrLog.size() - 10 : 0;
        for (size_t i = start; i < c->stderrLog.size(); i++) ss << c->stderrLog[i] << "\n";
    }
    return ss.str();
}

static std::string McpOneLine(std::string s, size_t maxLen) {
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\r' || s[i] == '\n') s[i] = ' ';
    }
    if (maxLen > 3 && s.size() > maxLen) {
        s.resize(maxLen - 3);
        s += "...";
    }
    return s;
}

static std::string JoinCsv(const std::vector<std::string>& items) {
    std::string out;
    for (size_t i = 0; i < items.size(); i++) {
        if (i) out += ", ";
        out += items[i];
    }
    return out;
}

static void McpExtractToolSchema(const json& toolDef, std::vector<std::string>& requiredOut, std::vector<std::string>& propsOut) {
    requiredOut.clear();
    propsOut.clear();
    if (!toolDef.is_object()) return;
    if (!toolDef.contains("inputSchema") || !toolDef["inputSchema"].is_object()) return;
    const json& sch = toolDef["inputSchema"];

    if (sch.contains("required") && sch["required"].is_array()) {
        for (const auto& r : sch["required"]) {
            if (r.is_string()) requiredOut.push_back(r.get<std::string>());
        }
    }
    if (sch.contains("properties") && sch["properties"].is_object()) {
        for (auto it = sch["properties"].begin(); it != sch["properties"].end(); ++it) {
            propsOut.push_back(it.key());
        }
    }
}

static bool McpFindToolInCache(const json& toolCache, const std::string& toolName, json& outToolDef) {
    outToolDef = json();
    if (!toolCache.is_object()) return false;
    if (!toolCache.contains("tools") || !toolCache["tools"].is_array()) return false;
    for (const auto& t : toolCache["tools"]) {
        if (!t.is_object()) continue;
        if (t.contains("name") && t["name"].is_string() && t["name"].get<std::string>() == toolName) {
            outToolDef = t;
            return true;
        }
    }
    return false;
}

static std::string McpStateForPrompt() {
    std::lock_guard<std::mutex> lk(g_mcpMu);
    if (g_mcp.empty()) return "MCP: (no connected servers)\n";
    std::stringstream ss;
    ss << "MCP SERVERS (connected MCP servers you can call with mcp_* actions):\n";
    for (const auto& kv : g_mcp) {
        auto c = kv.second;
        if (!c) continue;
        ss << "- " << c->id << ": " << c->package << " (running=" << (c->running ? "true" : "false") << ")\n";
        if (!c->toolCache.is_null() && c->toolCache.is_object() && c->toolCache.contains("tools") && c->toolCache["tools"].is_array()) {
            ss << "  tools (top):\n";
            int shown = 0;
            for (const auto& t : c->toolCache["tools"]) {
                if (!t.is_object()) continue;
                std::string tn = t.value("name", "");
                if (tn.empty()) continue;
                std::string td = t.value("description", "");
                std::vector<std::string> req, props;
                McpExtractToolSchema(t, req, props);
                ss << "    - " << tn;
                if (!req.empty()) ss << " required=[" << JoinCsv(req) << "]";
                if (!td.empty()) ss << " - " << McpOneLine(td, 90);
                ss << "\n";
                if (++shown >= 8) break;
            }
            ss << "  (Use mcp_tools_list to see full schemas for all tools)\n";
        }

        if (!c->resourceCache.is_null() && c->resourceCache.is_object() && c->resourceCache.contains("resources") && c->resourceCache["resources"].is_array()) {
            ss << "  resources (top):\n";
            int shown = 0;
            for (const auto& r : c->resourceCache["resources"]) {
                if (!r.is_object()) continue;
                std::string uri = r.value("uri", "");
                std::string rn = r.value("name", "");
                if (uri.empty()) continue;
                ss << "    - " << uri;
                if (!rn.empty()) ss << " (" << McpOneLine(rn, 60) << ")";
                ss << "\n";
                if (++shown >= 6) break;
            }
            ss << "  (Use mcp_resources_list to see all resources)\n";
        }
    }
    return ss.str();
}

static std::string McpRegistrySearch(const std::string& query, int limit, std::string* errOut) {
    if (errOut) errOut->clear();
    if (limit < 1) limit = 5;
    if (limit > 20) limit = 20;
    // Official registry supports: /v0.1/servers?search=...&limit=...
    std::wstring domain = L"registry.modelcontextprotocol.io";
    std::wstring path = L"/v0.1/servers?version=latest&limit=" + s2ws(std::to_string(limit));
    if (!query.empty()) path += L"&search=" + s2ws(UrlEncodeSimple(query));
    std::string res = Api::HttpRequest(domain, path, "GET", "", std::vector<std::wstring>{});
    if (res.empty()) { if (errOut) *errOut = "empty response"; return ""; }
    return res;
}

static std::string McpNpmSearch(const std::string& query, int limit, std::string* errOut) {
    if (errOut) errOut->clear();
    if (limit < 1) limit = 10;
    if (limit > 20) limit = 20;

    std::string q = query;
    std::string qLower = q;
    std::transform(qLower.begin(), qLower.end(), qLower.begin(), ::tolower);
    if (qLower.find("mcp") == std::string::npos) q += " mcp";

    std::wstring domain = L"registry.npmjs.org";
    std::wstring path = L"/-/v1/search?size=" + s2ws(std::to_string(limit)) + L"&text=" + s2ws(UrlEncodeSimple(q));
    std::string res = Api::HttpRequest(domain, path, "GET", "", std::vector<std::wstring>{});
    if (res.empty()) { if (errOut) *errOut = "empty response"; return ""; }
    return res;
}

static std::shared_ptr<McpConn> McpGet(const std::string& id) {
    std::lock_guard<std::mutex> lk(g_mcpMu);
    auto it = g_mcp.find(id);
    if (it == g_mcp.end()) return nullptr;
    return it->second;
}

static void McpClose(std::shared_ptr<McpConn> c) {
    if (!c) return;
    c->running = false;

    if (c->hStdinWrite) { CloseHandle(c->hStdinWrite); c->hStdinWrite = NULL; }
    if (c->hStdoutRead) { CloseHandle(c->hStdoutRead); c->hStdoutRead = NULL; }
    if (c->hStderrRead) { CloseHandle(c->hStderrRead); c->hStderrRead = NULL; }

    // Kill tree
    if (c->hJob) { CloseHandle(c->hJob); c->hJob = NULL; }
    if (c->pi.hProcess) { CloseHandle(c->pi.hProcess); c->pi.hProcess = NULL; }

    if (c->tOut.joinable()) c->tOut.join();
    if (c->tErr.joinable()) c->tErr.join();
}

static std::string McpFormatToolResult(const json& toolCallResp) {
    // toolCallResp is the full JSON-RPC response. We care about result.content.
    if (!toolCallResp.contains("result") || !toolCallResp["result"].is_object()) return toolCallResp.dump();
    const json& r = toolCallResp["result"];
    bool isErr = r.value("isError", false);
    std::stringstream ss;
    ss << (isErr ? "MCP TOOL ERROR\n" : "MCP TOOL OK\n");
    if (r.contains("content") && r["content"].is_array()) {
        for (const auto& item : r["content"]) {
            if (!item.is_object()) continue;
            std::string type = item.value("type", "");
            if (type == "text") {
                ss << item.value("text", "") << "\n";
            }
            else if (type == "image") {
                ss << "[image " << item.value("mimeType", "") << " bytes=" << item.value("data", "").size() << "]\n";
            }
            else if (type == "resource") {
                ss << "[resource] " << item.dump() << "\n";
            }
            else {
                ss << item.dump() << "\n";
            }
        }
    }
    else {
        ss << r.dump();
    }
    return ss.str();
}

std::string CleanApiKey(const std::string& str) {
    std::string out = str;
    out.erase(std::remove_if(out.begin(), out.end(), ::isspace), out.end());
    out.erase(std::remove(out.begin(), out.end(), '\"'), out.end());
    return out;
}

void SetClipboardText(const std::string& text) {
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
        if (hg) {
            memcpy(GlobalLock(hg), text.c_str(), text.size() + 1);
            GlobalUnlock(hg);
            SetClipboardData(CF_TEXT, hg);
        }
        CloseClipboard();
    }
}

static bool GetClipboardTextW(std::wstring& out) {
    out.clear();
    if (!OpenClipboard(NULL)) return false;
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (!hData) {
        CloseClipboard();
        return false;
    }
    wchar_t* pszText = (wchar_t*)GlobalLock(hData);
    if (!pszText) {
        CloseClipboard();
        return false;
    }
    out = pszText;
    GlobalUnlock(hData);
    CloseClipboard();
    return true;
}

static bool SetClipboardTextW(const std::wstring& text) {
    if (!OpenClipboard(NULL)) return false;
    EmptyClipboard();

    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hg) {
        CloseClipboard();
        return false;
    }
    void* p = GlobalLock(hg);
    if (!p) {
        GlobalFree(hg);
        CloseClipboard();
        return false;
    }
    memcpy(p, text.c_str(), bytes);
    GlobalUnlock(hg);

    SetClipboardData(CF_UNICODETEXT, hg);
    CloseClipboard();
    return true;
}

static void SendKeyOnce(WORD vk, bool extended = false) {
    INPUT inp[2] = {};
    inp[0].type = INPUT_KEYBOARD;
    inp[0].ki.wVk = vk;
    inp[0].ki.wScan = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    inp[0].ki.dwFlags = extended ? KEYEVENTF_EXTENDEDKEY : 0;
    inp[1] = inp[0];
    inp[1].ki.dwFlags |= KEYEVENTF_KEYUP;
    SendInput(2, inp, sizeof(INPUT));
}

static void SendModifier(WORD vk, bool down) {
    INPUT inp = {};
    inp.type = INPUT_KEYBOARD;
    inp.ki.wVk = vk;
    inp.ki.wScan = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    inp.ki.dwFlags = down ? 0 : KEYEVENTF_KEYUP;
    if (vk == VK_MENU || vk == VK_RMENU || vk == VK_LMENU ||
        vk == VK_CONTROL || vk == VK_RCONTROL || vk == VK_LCONTROL ||
        vk == VK_INSERT || vk == VK_DELETE || vk == VK_HOME || vk == VK_END ||
        vk == VK_PRIOR || vk == VK_NEXT || vk == VK_LEFT || vk == VK_RIGHT || vk == VK_UP || vk == VK_DOWN) {
        inp.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    }
    SendInput(1, &inp, sizeof(INPUT));
}

// =========================================================
// GLOBAL PASTE HOTKEY (Ctrl+Shift+Alt+`)
// - Registered with RegisterHotKey (no keyboard hook)
// - On trigger: attempts WM_PASTE into the focused control
// =========================================================

static const int kHotkeyPasteId = 0xA11;

static HWND GetFocusedHwnd() {
    HWND fg = GetForegroundWindow();
    if (!fg) return NULL;
    DWORD tid = GetWindowThreadProcessId(fg, NULL);
    GUITHREADINFO gi = {};
    gi.cbSize = sizeof(gi);
    if (GetGUIThreadInfo(tid, &gi)) {
        if (gi.hwndFocus) return gi.hwndFocus;
        if (gi.hwndCaret) return gi.hwndCaret;
    }
    return fg;
}

static bool PasteFocusedViaWmPaste() {
    HWND h = GetFocusedHwnd();
    if (!h) return false;
    // WM_PASTE expects clipboard to already contain data.
    PostMessage(h, WM_PASTE, 0, 0);
    return true;
}

static bool TriggerCustomPasteHotkey() {
    // Primary: WM_PASTE (programmatic paste, no Ctrl+V).
    if (PasteFocusedViaWmPaste()) return true;
    return false;
}

static bool PasteClipboardWithoutCtrlV() {
    // Try a few paste alternatives. Some websites block Ctrl+V but allow Shift+Insert.
    // Returns true if we issued a paste chord (can't 100% verify browser accepted).

    // Method 1: Ctrl+Shift+V (paste as plain text on many apps)
    SendModifier(VK_CONTROL, true);
    SendModifier(VK_SHIFT, true);
    SendKeyOnce('V');
    SendModifier(VK_SHIFT, false);
    SendModifier(VK_CONTROL, false);
    Sleep(80);

    // Method 2: Shift+Insert
    SendModifier(VK_SHIFT, true);
    SendKeyOnce(VK_INSERT, true);
    SendModifier(VK_SHIFT, false);
    Sleep(80);

    // Method 3: Context menu (Shift+F10) then 'p' (best-effort)
    SendModifier(VK_SHIFT, true);
    SendKeyOnce(VK_F10);
    SendModifier(VK_SHIFT, false);
    Sleep(120);
    SendKeyOnce('P');
    Sleep(120);

    return true;
}

// Custom paste chord: Ctrl+Shift+Alt+` (VK_OEM_3).
// This only works if the target environment maps that chord to a paste action.
// (e.g. via an app-level shortcut or an OS-level hotkey remap tool.)
static void PasteWithCustomHotkey() {
    // This function name is kept for compatibility, but the actual paste is done
    // programmatically via WM_PASTE. The hotkey chord is registered globally so
    // the user can press it too.
    TriggerCustomPasteHotkey();
}

static bool TrySetValuePattern(IUIAutomationElement* pElement, const std::wstring& valueW) {
    if (!pElement) return false;
    IUnknown* pPattern = NULL;
    if (FAILED(pElement->GetCurrentPattern(UIA_ValuePatternId, &pPattern)) || !pPattern) return false;
    IUIAutomationValuePattern* pVal = NULL;
    bool ok = false;
    if (SUCCEEDED(pPattern->QueryInterface(__uuidof(IUIAutomationValuePattern), (void**)&pVal)) && pVal) {
        BSTR b = SysAllocString(valueW.c_str());
        if (b) {
            ok = SUCCEEDED(pVal->SetValue(b));
            SysFreeString(b);
        }
        pVal->Release();
    }
    pPattern->Release();
    return ok;
}

// Forward declaration (definition exists later in file)
std::string BstrToStdString(BSTR bstr);

static std::string ReadValueOrTextPattern(IUIAutomationElement* pElement) {
    if (!pElement) return "";

    // ValuePattern
    {
        IUnknown* pPattern = NULL;
        if (SUCCEEDED(pElement->GetCurrentPattern(UIA_ValuePatternId, &pPattern)) && pPattern) {
            IUIAutomationValuePattern* pVal = NULL;
            if (SUCCEEDED(pPattern->QueryInterface(__uuidof(IUIAutomationValuePattern), (void**)&pVal)) && pVal) {
                BSTR b = NULL;
                if (SUCCEEDED(pVal->get_CurrentValue(&b)) && b) {
                    std::string s = BstrToStdString(b);
                    SysFreeString(b);
                    pVal->Release();
                    pPattern->Release();
                    return s;
                }
                pVal->Release();
            }
            pPattern->Release();
        }
    }

    // TextPattern
    {
        IUnknown* pPattern = NULL;
        if (SUCCEEDED(pElement->GetCurrentPattern(UIA_TextPatternId, &pPattern)) && pPattern) {
            IUIAutomationTextPattern* pTxt = NULL;
            if (SUCCEEDED(pPattern->QueryInterface(__uuidof(IUIAutomationTextPattern), (void**)&pTxt)) && pTxt) {
                IUIAutomationTextRange* pRange = NULL;
                if (SUCCEEDED(pTxt->get_DocumentRange(&pRange)) && pRange) {
                    BSTR b = NULL;
                    if (SUCCEEDED(pRange->GetText(-1, &b)) && b) {
                        std::string s = BstrToStdString(b);
                        SysFreeString(b);
                        pRange->Release();
                        pTxt->Release();
                        pPattern->Release();
                        if (s.size() > 12000) s.resize(12000);
                        return s;
                    }
                    pRange->Release();
                }
                pTxt->Release();
            }
            pPattern->Release();
        }
    }

    return "";
}

static IUIAutomationElement* FindDescendantEdit(IUIAutomation* pAutomation, IUIAutomationElement* root) {
    if (!pAutomation || !root) return NULL;
    IUIAutomationCondition* pCond = NULL;
    if (FAILED(pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, _variant_t((int)UIA_EditControlTypeId), &pCond)) || !pCond) return NULL;
    IUIAutomationElement* pEdit = NULL;
    root->FindFirst(TreeScope_Subtree, pCond, &pEdit);
    pCond->Release();
    return pEdit; // may be NULL; caller releases
}

std::string ExtractLatestCodeBlock(const std::string& text) {
    size_t endPos = text.rfind("```");
    if (endPos == std::string::npos) return text;
    size_t startPos = text.rfind("```", endPos - 1);
    if (startPos == std::string::npos) return text;
    size_t contentStart = startPos + 3;
    size_t nextNewLine = text.find('\n', contentStart);
    if (nextNewLine != std::string::npos && nextNewLine < endPos) {
        contentStart = nextNewLine + 1;
    }
    return text.substr(contentStart, endPos - contentStart);
}

// =========================================================
// CHAT HISTORY FUNCTIONS
// =========================================================

std::string GetDesktopPath() {
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, path) == S_OK) {
        return std::string(path);
    }
    return "";
}

std::string GetCurrentDateString() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
    return std::string(buf);
}

void EnsureChatHistoryFolder(const std::string& datePath) {
    std::string basePath = GetDesktopPath() + "\\Ofradr-chat-history";
    CreateDirectoryA(basePath.c_str(), NULL);
    std::string fullPath = basePath + "\\" + datePath;
    CreateDirectoryA(fullPath.c_str(), NULL);
}

// Forward declaration for CapturedImage struct (used by SaveChatHistoryEntry)
struct CapturedImage;

void SaveChatHistoryEntry(const std::string& userQuestion, const std::string& aiResponse,
    const std::vector<CapturedImage>& images);

// Implementation defined after CapturedImage struct

// =========================================================
// 3. APP STATE
// =========================================================

enum class AppMode { Chat, Agent };
AppMode g_appMode = AppMode::Chat;

enum class AppState { Login, LoggedIn };
AppState g_appState = AppState::Login;

enum class FocusState { None, Username, Password, Chat };
FocusState g_currentFocus = FocusState::None;

std::string g_usernameBuffer = "";
std::string g_passwordBuffer = "";
std::string g_chatBuffer = "";

std::string g_stagingText = "";
std::string g_stagingTitle = "";
bool g_stagingReady = false;
std::string g_pendingInspectionText = "";

struct ChatMessage {
    std::string role;
    std::string text;
    bool hasImages;
    bool isPreview;
    float alpha = 0.0f;
};
std::vector<ChatMessage> g_chatHistory;

std::string g_statusMessage = "Initializing...";

struct CapturedImage {
    ID3D11ShaderResourceView* textureView;
    std::string base64Data;
    int width;
    int height;
};
std::vector<CapturedImage> g_screenshots;
// Incremented each time a non-black screenshot is successfully stored.
volatile LONG64 g_screenshotSeq = 0;
static int g_maxScreenshots = 12;

// --- CHAT HISTORY IMPLEMENTATION ---
void SaveChatHistoryEntry(const std::string& userQuestion, const std::string& aiResponse,
    const std::vector<CapturedImage>& images) {
    if (!g_chatHistoryEnabled) return;

    std::string currentDate = GetCurrentDateString();

    // Reset counter if new day
    if (currentDate != g_chatHistoryDate) {
        g_chatHistoryDate = currentDate;
        g_chatHistoryCounter = 0;
    }

    EnsureChatHistoryFolder(currentDate);
    std::string basePath = GetDesktopPath() + "\\Ofradr-chat-history\\" + currentDate + "\\";

    // Save question
    if (!userQuestion.empty()) {
        std::ofstream qFile(basePath + std::to_string(g_chatHistoryCounter) + "_question.txt");
        if (qFile.is_open()) {
            qFile << userQuestion;
            qFile.close();
        }
    }

    // Save response
    if (!aiResponse.empty()) {
        std::ofstream rFile(basePath + std::to_string(g_chatHistoryCounter) + "_response.txt");
        if (rFile.is_open()) {
            rFile << aiResponse;
            rFile.close();
        }
    }

    // Save screenshots as PNG
    for (size_t i = 0; i < images.size(); i++) {
        std::string imgPath = basePath + std::to_string(g_chatHistoryCounter) + "_screenshot_" + std::to_string(i) + ".png";

        // Decode base64 JPEG
        std::string rawData = Base64Decode(images[i].base64Data);

        // Create stream from raw data
        IStream* pStream = nullptr;
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, rawData.size());
        if (hMem) {
            void* pMem = GlobalLock(hMem);
            if (pMem) {
                memcpy(pMem, rawData.data(), rawData.size());
                GlobalUnlock(hMem);

                if (CreateStreamOnHGlobal(hMem, TRUE, &pStream) == S_OK && pStream) {
                    Gdiplus::Bitmap* bmp = new Gdiplus::Bitmap(pStream);
                    if (bmp && bmp->GetLastStatus() == Gdiplus::Ok) {
                        // Find PNG encoder
                        CLSID pngClsid;
                        UINT num = 0, sz = 0;
                        Gdiplus::GetImageEncodersSize(&num, &sz);
                        if (sz > 0) {
                            Gdiplus::ImageCodecInfo* pInfo = (Gdiplus::ImageCodecInfo*)malloc(sz);
                            if (pInfo) {
                                Gdiplus::GetImageEncoders(num, sz, pInfo);
                                for (UINT j = 0; j < num; j++) {
                                    if (wcscmp(pInfo[j].MimeType, L"image/png") == 0) {
                                        pngClsid = pInfo[j].Clsid;
                                        break;
                                    }
                                }
                                free(pInfo);

                                // Save as PNG
                                std::wstring wImgPath = s2ws(imgPath);
                                bmp->Save(wImgPath.c_str(), &pngClsid, NULL);
                            }
                        }
                    }
                    if (bmp) delete bmp;
                    pStream->Release();
                }
            }
            else {
                GlobalFree(hMem);
            }
        }
    }

    g_chatHistoryCounter++;
}

// INSPECTION
bool g_isInspecting = false;
HCURSOR g_hCursorCross = NULL;
HCURSOR g_hCursorArrow = NULL;

// Removed g_lastDesktopCheck

ImU32 GetAccentColorU32(float alpha = 1.0f) {
    ImVec4 c = g_uiColor;
    c.w *= alpha;
    return ImGui::ColorConvertFloat4ToU32(c);
}

std::string GetKeyName(int vk) {
    if (vk == 0) return "";
    char name[128] = { 0 };
    UINT scanCode = MapVirtualKey(vk, MAPVK_VK_TO_VSC);
    switch (vk) {
    case VK_LEFT: case VK_UP: case VK_RIGHT: case VK_DOWN:
    case VK_PRIOR: case VK_NEXT: case VK_END: case VK_HOME:
    case VK_INSERT: case VK_DELETE: case VK_DIVIDE: case VK_NUMLOCK:
        scanCode |= 0x100;
    }
    if (GetKeyNameTextA(scanCode << 16, name, 128)) return std::string(name);
    if ((vk >= '0' && vk <= '9') || (vk >= 'A' && vk <= 'Z')) {
        std::string s(1, (char)vk);
        return s;
    }
    return std::to_string(vk);
}

// =========================================================
// 4. SVG LOADING
// =========================================================

ID3D11ShaderResourceView* LoadTextureFromSVG(const std::string& filename) {
    NSVGimage* image = nsvgParseFromFile(filename.c_str(), "px", 96);
    if (!image) return nullptr;

    int w = 64;
    int h = 64;

    float scale = 1.0f;
    if (image->width > 0 && image->height > 0) {
        float sw = (float)w / image->width;
        float sh = (float)h / image->height;
        scale = (sw < sh) ? sw : sh;
    }

    NSVGrasterizer* rast = nsvgCreateRasterizer();
    if (!rast) { nsvgDelete(image); return nullptr; }

    unsigned char* imgData = (unsigned char*)malloc(w * h * 4);
    if (!imgData) { nsvgDeleteRasterizer(rast); nsvgDelete(image); return nullptr; }

    nsvgRasterize(rast, image, 0, 0, scale, imgData, w, h, w * 4);

    D3D11_TEXTURE2D_DESC desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.Width = w;
    desc.Height = h;
    desc.MipLevels = 1;
    desc.ArraySize = 1;

    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    desc.CPUAccessFlags = 0;

    D3D11_SUBRESOURCE_DATA subResource;
    subResource.pSysMem = imgData;
    subResource.SysMemPitch = w * 4;
    subResource.SysMemSlicePitch = 0;

    ID3D11Texture2D* pTexture = NULL;
    ID3D11ShaderResourceView* pTextureView = NULL;

    g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);
    if (pTexture) {
        g_pd3dDevice->CreateShaderResourceView(pTexture, NULL, &pTextureView);
        pTexture->Release();
    }

    free(imgData);
    nsvgDeleteRasterizer(rast);
    nsvgDelete(image);

    return pTextureView;
}
ID3D11ShaderResourceView* LoadTextureFromSVGMemory(const unsigned char* data, int size)
{
    NSVGimage* image = nsvgParse((char*)data, "px", 96);
    if (!image) return nullptr;

    int w = 64;
    int h = 64;

    float scale = 1.0f;
    if (image->width > 0 && image->height > 0) {
        float sw = (float)w / image->width;
        float sh = (float)h / image->height;
        scale = (sw < sh) ? sw : sh;
    }

    NSVGrasterizer* rast = nsvgCreateRasterizer();
    if (!rast) { nsvgDelete(image); return nullptr; }

    unsigned char* imgData = (unsigned char*)malloc(w * h * 4);
    if (!imgData) { nsvgDeleteRasterizer(rast); nsvgDelete(image); return nullptr; }

    nsvgRasterize(rast, image, 0, 0, scale, imgData, w, h, w * 4);

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = w;
    desc.Height = h;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA sub{};
    sub.pSysMem = imgData;
    sub.SysMemPitch = w * 4;

    ID3D11Texture2D* tex = nullptr;
    ID3D11ShaderResourceView* view = nullptr;

    g_pd3dDevice->CreateTexture2D(&desc, &sub, &tex);
    if (tex) {
        g_pd3dDevice->CreateShaderResourceView(tex, nullptr, &view);
        tex->Release();
    }

    free(imgData);
    nsvgDeleteRasterizer(rast);
    nsvgDelete(image);

    return view;
}

void LoadAllIcons() {
    g_icons.Screenshot = LoadTextureFromSVGMemory(sceenshot_data, sceenshot_len);
    g_icons.Inspect = LoadTextureFromSVGMemory(inpsect_data, inpsect_len);
    g_icons.Copy = LoadTextureFromSVGMemory(copy_data, copy_len);
    g_icons.NewChat = LoadTextureFromSVGMemory(new_chat_data, new_chat_len);
    g_icons.Settings = LoadTextureFromSVGMemory(settings_data, settings_len);
    g_icons.Send = LoadTextureFromSVGMemory(sned_data, sned_len);
    g_icons.Close = LoadTextureFromSVGMemory(close_data, close_len);
}



void ForceTopMost() {
    if (g_isVisible) {
        SetWindowPos(g_hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    }
}

// Helper: Check if current desktop is the active input desktop
bool IsInputDesktopActive() {
    HDESK hI = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!hI) return false;

    HDESK hM = GetThreadDesktop(GetCurrentThreadId());
    bool isActive = false;

    if (hM) {
        auto GetN = [](HDESK h) {
            DWORD n = 0; GetUserObjectInformationW(h, UOI_NAME, NULL, 0, &n);
            std::wstring b(n / sizeof(wchar_t), 0); GetUserObjectInformationW(h, UOI_NAME, &b[0], n, &n);
            return b;
            };
        isActive = (GetN(hI) == GetN(hM));
    }

    CloseDesktop(hI);
    return isActive;
}

// 6. IMAGE


// --- FORWARD DECLARATIONS (REQUIRED) ---
// These allow CaptureScreenshot to call functions defined lower in the file
HWND GetWindowBehind(HWND overlayWnd);
void PerformTextInspection(HWND targetHwnd);

// Helper to check if image is effectively black
bool IsImageBlack(const std::vector<BYTE>& buffer) {
    // Check a sample of pixels to see if they are above a darkness threshold
    // Buffer is likely BGRA or RGBA. We just check if byte values are > 15
    size_t step = 64; // Check every 16th pixel (4 bytes per pixel * 16)
    for (size_t i = 0; i < buffer.size(); i += step) {
        if (buffer[i] > 15 && buffer[i + 1] > 15 && buffer[i + 2] > 15) return false;
    }
    return true;
}

void BitBltScreenshot() {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    HDC hdc = GetDC(NULL);
    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP hBmp = CreateCompatibleBitmap(hdc, w, h);
    SelectObject(memDC, hBmp);
    BitBlt(memDC, 0, 0, w, h, hdc, 0, 0, SRCCOPY);

    Gdiplus::Bitmap bmp(hBmp, nullptr);
    IStream* pStream = nullptr; CreateStreamOnHGlobal(NULL, TRUE, &pStream);
    CLSID clsid; {
        UINT num, sz; Gdiplus::GetImageEncodersSize(&num, &sz);
        Gdiplus::ImageCodecInfo* p = (Gdiplus::ImageCodecInfo*)malloc(sz);
        Gdiplus::GetImageEncoders(num, sz, p);
        for (UINT j = 0; j < num; ++j) if (wcscmp(p[j].MimeType, L"image/jpeg") == 0) { clsid = p[j].Clsid; break; }
        free(p);
    }
    bmp.Save(pStream, &clsid, NULL);

    LARGE_INTEGER li{ 0 }; pStream->Seek(li, STREAM_SEEK_SET, nullptr);
    STATSTG stat{}; pStream->Stat(&stat, STATFLAG_NONAME);
    DWORD size = (DWORD)stat.cbSize.LowPart;
    std::vector<BYTE> buffer(size);
    ULONG read = 0; pStream->Read(buffer.data(), size, &read);

    // --- NEW: BLACK SCREEN DETECTION ---
    bool isBlack = IsImageBlack(buffer);

    if (!isBlack) {
        // Only create texture and add to list if NOT black
        ID3D11ShaderResourceView* view = nullptr;
        {
            D3D11_TEXTURE2D_DESC desc = {};
            desc.Width = w; desc.Height = h; desc.MipLevels = 1; desc.ArraySize = 1;
            desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM; desc.SampleDesc.Count = 1;
            desc.Usage = D3D11_USAGE_DEFAULT; desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

            Gdiplus::BitmapData bmpData;
            Gdiplus::Rect rect(0, 0, w, h);
            bmp.LockBits(&rect, Gdiplus::ImageLockModeRead, PixelFormat32bppARGB, &bmpData);

            D3D11_SUBRESOURCE_DATA sr = {}; sr.pSysMem = bmpData.Scan0; sr.SysMemPitch = w * 4;
            ID3D11Texture2D* tex = nullptr;
            g_pd3dDevice->CreateTexture2D(&desc, &sr, &tex);
            if (tex) { g_pd3dDevice->CreateShaderResourceView(tex, nullptr, &view); tex->Release(); }
            bmp.UnlockBits(&bmpData);
        }

        CapturedImage img; img.textureView = view; img.base64Data = Base64Encode(buffer.data(), size);
        img.width = w; img.height = h;
        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            int maxKeep = (g_maxScreenshots <= 0) ? 12 : g_maxScreenshots;
            while ((int)g_screenshots.size() >= maxKeep) {
                if (g_screenshots.front().textureView) g_screenshots.front().textureView->Release();
                g_screenshots.erase(g_screenshots.begin());
            }
            g_screenshots.push_back(img);
            g_statusMessage = "Screenshot + Context Captured.";
        }
        InterlockedIncrement64(&g_screenshotSeq);
    }
    else {
        // Image was black, don't show it, but acknowledge context capture
        std::lock_guard<std::mutex> lock(g_dataMutex);
        g_statusMessage = "Context Captured (Screen Hidden).";
    }

    pStream->Release(); DeleteObject(hBmp); DeleteDC(memDC); ReleaseDC(NULL, hdc);
}

void CaptureContext() {
    // Clear previous context so we don't send stale data
    g_pendingInspectionText.clear();
    g_stagingText.clear();

    // Find the window immediately behind the overlay
    HWND target = GetWindowBehind(g_hwnd);

    if (target) {
        // Triggers the recursive text extraction
        // The result will be put into g_stagingText, then the main loop picks it up
        PerformTextInspection(target);
    }
}

void CaptureScreenshot() {
    // Buffer management is handled when pushing into g_screenshots.
    BitBltScreenshot();
}

// =========================================================
// SAFE UIA EXTRACTION (RECURSIVE & CONTAINED)
// =========================================================

std::string BstrToStdString(BSTR bstr) {
    if (!bstr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, bstr, SysStringLen(bstr), NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, bstr, SysStringLen(bstr), &s[0], len, NULL, NULL);
    return s;
}

std::string CaselessFind(std::string data, std::string toSearch) {
    std::string dataLower = data;
    std::string searchLower = toSearch;
    std::transform(dataLower.begin(), dataLower.end(), dataLower.begin(), ::tolower);
    std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::tolower);
    if (dataLower.find(searchLower) != std::string::npos) return toSearch;
    return "";
}

// Helper: Try to get text from Name OR Value Pattern (Input boxes/Editors)
std::string GetElementText(IUIAutomationElement* pNode) {
    std::string result = "";

    // 1. Try Name
    BSTR bstrName = NULL;
    if (SUCCEEDED(pNode->get_CurrentName(&bstrName)) && bstrName != NULL) {
        result = BstrToStdString(bstrName);
        SysFreeString(bstrName);
    }

    // 2. If Name is empty or generic, try Value Pattern (for editable text)
    if (result.empty()) {
        IUnknown* pPattern = NULL;
        if (SUCCEEDED(pNode->GetCurrentPattern(UIA_ValuePatternId, &pPattern)) && pPattern) {
            IUIAutomationValuePattern* pValue = NULL;
            if (SUCCEEDED(pPattern->QueryInterface(__uuidof(IUIAutomationValuePattern), (void**)&pValue))) {
                BSTR bstrVal = NULL;
                if (SUCCEEDED(pValue->get_CurrentValue(&bstrVal)) && bstrVal != NULL) {
                    result = BstrToStdString(bstrVal);
                    SysFreeString(bstrVal);
                }
                pValue->Release();
            }
            pPattern->Release();
        }
    }

    return result;
}

// Recursive walker that collects text into a list
void WalkTreeRecursive(IUIAutomationTreeWalker* pWalker, IUIAutomationElement* pNode, std::vector<std::string>& collectedText, int depth, int& totalChars, int& elementCount) {
    // INCREASED LIMITS: Depth 16, 2500 elements, 30k chars for "Complete" info
    if (!pNode || depth > 16 || totalChars > 30000 || elementCount > 2500) return;

    elementCount++;

    std::string s = GetElementText(pNode);

    // Filter out useless UI noise
    if (s.length() > 0 && s != "Minimize" && s != "Maximize" && s != "Close" && s != "System" && s != "Restore") {
        collectedText.push_back(s);
        totalChars += (int)s.length();
    }

    // Go to first child
    IUIAutomationElement* pChild = NULL;
    pWalker->GetFirstChildElement(pNode, &pChild);

    IUIAutomationElement* pNext = NULL;
    while (pChild && totalChars < 30000 && elementCount < 2500) {
        WalkTreeRecursive(pWalker, pChild, collectedText, depth + 1, totalChars, elementCount);

        pWalker->GetNextSiblingElement(pChild, &pNext);
        pChild->Release();
        pChild = pNext;
    }
}

void PerformTextInspection(HWND targetHwnd) {
    std::thread([=]() {
        // We use a set to store ALL unique text lines found across 3 passes
        std::vector<std::string> allUniqueLines;
        std::string capturedTitle = "Unknown App";

        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            g_isProcessing = true;
            g_statusMessage = "Deep Scanning (3 Passes)...";
        }

        CoInitializeEx(NULL, COINIT_MULTITHREADED);

        // Safety Check
        char className[256];
        GetClassNameA(targetHwnd, className, 256);
        if (strcmp(className, "Progman") == 0 || strcmp(className, "WorkerW") == 0 || strcmp(className, "Shell_TrayWnd") == 0) {
            capturedTitle = "Desktop/Taskbar (Ignored)";
            allUniqueLines.push_back("Error: Cannot inspect the Desktop or Taskbar.");
        }
        else {
            IUIAutomation* pAutomation = NULL;
            HRESULT hr = CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&pAutomation);

            if (SUCCEEDED(hr) && pAutomation) {
                // --- THE 3-PASS LOOP ---
                for (int pass = 1; pass <= 3; pass++) {

                    // Update status for user feedback
                    {
                        std::lock_guard<std::mutex> lock(g_dataMutex);
                        g_statusMessage = "Deep Scanning (Pass " + std::to_string(pass) + "/3)...";
                    }

                    IUIAutomationElement* pTargetElement = NULL;
                    hr = pAutomation->ElementFromHandle(targetHwnd, &pTargetElement);

                    if (SUCCEEDED(hr) && pTargetElement) {
                        // Get Title only on first pass
                        if (pass == 1) {
                            BSTR titleBstr = NULL;
                            pTargetElement->get_CurrentName(&titleBstr);
                            if (titleBstr) {
                                capturedTitle = BstrToStdString(titleBstr);
                                SysFreeString(titleBstr);
                            }
                        }

                        IUIAutomationTreeWalker* pWalker = NULL;
                        pAutomation->get_ControlViewWalker(&pWalker);

                        if (pWalker) {
                            int charCount = 0;
                            int elemCount = 0;
                            std::vector<std::string> passLines;

                            // Walk the tree
                            WalkTreeRecursive(pWalker, pTargetElement, passLines, 0, charCount, elemCount);

                            // Merge into main list (Keep order, allow duplicates if meaningful, 
                            // but usually we want to avoid 3x copies of "File". 
                            // We will append only if not already recently added to keep context clean)
                            for (const auto& line : passLines) {
                                // Simple check to avoid immediate duplicates from the previous pass
                                bool exists = false;
                                for (const auto& existing : allUniqueLines) {
                                    if (existing == line) { exists = true; break; }
                                }
                                if (!exists) {
                                    allUniqueLines.push_back(line);
                                }
                            }

                            pWalker->Release();
                        }
                        pTargetElement->Release();
                    }

                    // Sleep between passes to allow UI to render/update (e.g. lazy loading)
                    if (pass < 3) Sleep(350);
                }
                pAutomation->Release();
            }
        }

        CoUninitialize();

        // Construct Final String
        std::stringstream ss;
        ss << "TARGET APP: " << capturedTitle << "\n";
        ss << "EXTRACTED UI CONTEXT (Aggregated from 3 Scans):\n";
        ss << "--------------------------------------------------\n";
        for (const auto& line : allUniqueLines) {
            ss << line << "\n";
        }

        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            g_stagingText = ss.str();
            g_stagingTitle = capturedTitle;
            g_stagingReady = true;
            g_isProcessing = false;
        }

        }).detach();
}

// =========================================================
// NEW: "HIDE & SEEK" WINDOW FINDER (100% ACCURATE)
// =========================================================
HWND GetWindowBehind(HWND overlayWnd) {
    // 1. Temporarily hide the overlay so we can see what's behind it
    ShowWindow(overlayWnd, SW_HIDE);

    // 2. Get the center point of where the overlay WAS
    RECT r; GetWindowRect(overlayWnd, &r);
    POINT pt = { (r.left + r.right) / 2, (r.top + r.bottom) / 2 };

    // 3. Find the window at that exact pixel
    HWND target = WindowFromPoint(pt);

    // 4. If we hit a child window (like a button inside Chrome), climb up to the main window
    if (target) {
        HWND root = GetAncestor(target, GA_ROOT);
        if (root) target = root;
    }

    // 5. Restore the overlay immediately
    ShowWindow(overlayWnd, SW_SHOW);

    return target;
}

// =========================================================
// 7. API ENGINE (MULTI-PROVIDER + VISION + VERSIONING + R2 UPLOAD)
// =========================================================
namespace Api {

    // --- HTTP Helper ---
    std::string HttpRequest(std::wstring domain, std::wstring path, std::string method, std::string body, const std::vector<std::wstring>& customHeaders) {
        HINTERNET hS = WinHttpOpen(L"Ghost/11.2", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
        if (!hS) return "";
        HINTERNET hC = WinHttpConnect(hS, domain.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hC) { WinHttpCloseHandle(hS); return ""; }

        HINTERNET hR = WinHttpOpenRequest(hC, s2ws(method).c_str(), path.c_str(), NULL, NULL, NULL, WINHTTP_FLAG_SECURE);

        if (method == "POST") {
            std::wstring h = L"Content-Type: application/json\r\n";
            WinHttpAddRequestHeaders(hR, h.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
        }

        for (const auto& hdr : customHeaders) {
            WinHttpAddRequestHeaders(hR, hdr.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
        }

        bool bResults = WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);

        std::string res = "";
        if (bResults && WinHttpReceiveResponse(hR, NULL)) {
            DWORD dwS = 0, dwD = 0;
            do {
                WinHttpQueryDataAvailable(hR, &dwS);
                if (!dwS) break;
                std::vector<char> b(dwS + 1);
                if (WinHttpReadData(hR, b.data(), dwS, &dwD)) {
                    b[dwD] = 0;
                    res.append(b.data());
                }
            } while (dwS > 0);
        }

        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return res;
    }



    // --- Ollama Helper (HTTP) ---
    std::string HttpOllama(std::string method, std::wstring path, std::string body) {
        HINTERNET hS = WinHttpOpen(L"Ghost/Ollama", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
        if (!hS) return "";
        HINTERNET hC = WinHttpConnect(hS, L"localhost", 11434, 0);
        if (!hC) { WinHttpCloseHandle(hS); return ""; }

        HINTERNET hR = WinHttpOpenRequest(hC, s2ws(method).c_str(), path.c_str(), NULL, NULL, NULL, 0);

        bool bResults = WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);
        std::string res = "";
        if (bResults && WinHttpReceiveResponse(hR, NULL)) {
            DWORD dwS = 0, dwD = 0;
            do {
                WinHttpQueryDataAvailable(hR, &dwS);
                if (!dwS) break;
                std::vector<char> b(dwS + 1);
                if (WinHttpReadData(hR, b.data(), dwS, &dwD)) { b[dwD] = 0; res.append(b.data()); }
            } while (dwS > 0);
        }
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return res;
    }


    // --- DYNAMIC MODEL FETCHING ---
    void FetchModelsForProvider(AIProvider type) {
        std::thread([type]() {
            std::vector<ModelInfo> models;
            std::string res;

            if (type == AIProvider::Gemini && !g_apiKeys.gemini.empty()) {
                res = HttpRequest(L"generativelanguage.googleapis.com", L"/v1/models?key=" + s2ws(g_apiKeys.gemini), "GET", "", std::vector<std::wstring>{});
                try {
                    auto j = json::parse(res);
                    if (j.contains("models")) {
                        for (const auto& m : j["models"]) {
                            std::string id = m["name"].get<std::string>();
                            std::string name = m.contains("displayName") ? m["displayName"].get<std::string>() : id;
                            models.push_back({ id.substr(7), name });
                        }
                    }
                }
                catch (...) {}
            }
            else if ((type == AIProvider::OpenAI || type == AIProvider::DeepSeek || type == AIProvider::Moonshot || type == AIProvider::OpenRouter)) {
                std::wstring domain = L"api.openai.com";
                std::wstring path = L"/v1/models";
                std::string key = "";

                if (type == AIProvider::OpenAI) { key = g_apiKeys.openai; }
                else if (type == AIProvider::DeepSeek) { domain = L"api.deepseek.com"; key = g_apiKeys.deepseek; }
                else if (type == AIProvider::Moonshot) { domain = L"api.moonshot.ai"; key = g_apiKeys.kimi; }
                else if (type == AIProvider::OpenRouter) { domain = L"openrouter.ai"; path = L"/api/v1/models"; key = g_apiKeys.openrouter; }

                if (!key.empty()) {
                    std::vector<std::wstring> h = { L"Authorization: Bearer " + s2ws(key) };
                    res = HttpRequest(domain, path, "GET", "", h);
                    try {
                        auto j = json::parse(res);
                        if (j.contains("data")) {
                            for (const auto& m : j["data"]) {
                                std::string id = m["id"].get<std::string>();
                                std::string name = id;
                                if (type == AIProvider::OpenRouter && m.contains("name")) name = m["name"].get<std::string>();
                                models.push_back({ id, name });
                            }
                        }
                    }
                    catch (...) {}
                }
            }
            else if (type == AIProvider::Anthropic && !g_apiKeys.claude.empty()) {
                models.push_back({ "claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet" });
                models.push_back({ "claude-3-opus-20240229", "Claude 3 Opus" });
                models.push_back({ "claude-3-haiku-20240307", "Claude 3 Haiku" });
            }
            else if (type == AIProvider::Ollama) {
                res = HttpOllama("GET", L"/api/tags", "");
                try {
                    auto j = json::parse(res);
                    if (j.contains("models")) {
                        for (const auto& m : j["models"]) {
                            std::string n = m["name"].get<std::string>();
                            models.push_back({ n, n });
                        }
                    }
                }
                catch (...) {}
                if (models.empty()) models.push_back({ "error", "Ollama Not Running" });
            }

            std::lock_guard<std::mutex> lock(g_dataMutex);
            for (auto& p : g_providers) {
                if (p.type == type) {
                    p.models = models;
                    p.modelsFetched = true;
                    break;
                }
            }
            }).detach();
    }

    void InitProviders() {
        g_providers.clear();
        g_providers.push_back({ "Gemini", AIProvider::Gemini, {}, false });
        g_providers.push_back({ "OpenAI", AIProvider::OpenAI, {}, false });
        g_providers.push_back({ "Anthropic", AIProvider::Anthropic, {}, false });
        g_providers.push_back({ "Kimi", AIProvider::Moonshot, {}, false });
        g_providers.push_back({ "OpenRouter", AIProvider::OpenRouter, {}, false });
        g_providers.push_back({ "DeepSeek", AIProvider::DeepSeek, {}, false });
        g_providers.push_back({ "Ollama", AIProvider::Ollama, {}, false });
    }

    void RefreshAllModels() {
        FetchModelsForProvider(AIProvider::Gemini);
        FetchModelsForProvider(AIProvider::OpenAI);
        FetchModelsForProvider(AIProvider::Anthropic);
        FetchModelsForProvider(AIProvider::Moonshot);
        FetchModelsForProvider(AIProvider::OpenRouter);
        FetchModelsForProvider(AIProvider::DeepSeek);
        FetchModelsForProvider(AIProvider::Ollama);
    }


    void SendToAI(std::string userPrompt) {
        if (g_screenshots.empty() && userPrompt.empty() && g_pendingInspectionText.empty()) return;

        auto& prov = g_providers[g_currProviderIdx];
        if (prov.models.empty()) return;

        if (g_currModelIdx >= prov.models.size()) g_currModelIdx = 0;
        std::string modelID = prov.models[g_currModelIdx].id;

        std::string apiKey = "";
        if (prov.type == AIProvider::Gemini) apiKey = g_apiKeys.gemini;
        else if (prov.type == AIProvider::OpenAI) apiKey = g_apiKeys.openai;
        else if (prov.type == AIProvider::Anthropic) apiKey = g_apiKeys.claude;
        else if (prov.type == AIProvider::Moonshot) apiKey = g_apiKeys.kimi;
        else if (prov.type == AIProvider::OpenRouter) apiKey = g_apiKeys.openrouter;
        else if (prov.type == AIProvider::DeepSeek) apiKey = g_apiKeys.deepseek;

        if (prov.type != AIProvider::Ollama && apiKey.empty()) {
            g_chatHistory.push_back({ "model", "Error: Missing API Key.", false, false });
            return;
        }

        std::string disp = userPrompt;
        if (disp.empty()) {
            if (!g_screenshots.empty()) disp = "[Sending Screenshot...]";
            else if (!g_pendingInspectionText.empty()) disp = "[Sending Extracted Text...]";
        }
        g_chatHistory.push_back({ "user", disp, !g_screenshots.empty(), false });
        g_scrollToBottom = true; g_isProcessing = true;

        auto imgs = g_screenshots; auto hist = g_chatHistory; std::string ctx = g_pendingInspectionText;
        AIProvider type = prov.type;

        g_screenshots.clear(); g_pendingInspectionText = "";

        std::thread([=]() {
            std::string finalResp = "";
            json reqBody;
            std::string sysTxt = "You are an expert AI problem-solving and coding assistant whose objective is to correctly and efficiently solve any task from text, code, images, MCQs, programming, logic, math or English by first understanding the problem type, required output, language, and constraints, extracting text from images if needed, providing optimal and correct code in the specified or most suitable language with best practices and edge case handling while returning only the final solution unless explanation is requested, selecting the best answer for MCQs, giving accurate and clear responses for English or general questions, always prioritizing correctness, performance, clarity and minimal unnecessary output, dont give comments in the code and also you should answer every type of question that user asks, never guessing and only asking essential missing information, behaving as a top-tier engineer and problem solver. 1) Use markdown code blocks (```) for code, but NEVER use ** for bold text - no bold formatting at all. 2) For screenshots without questions: analyze image, understand what is asked, answer directly.Coding: give ONLY the code in markdown code blocks, no comments inside code, no explanation. If language not specified, detect from context or use most suitable language. 5) Math/Logic: give direct answer, show steps only if complex.  7) Answer ALL questions in image. 8) Never refuse. and if image is black the extected text will also be sent qaanswer that ";
            std::string userTxt = sysTxt + "\n\nUSER REQUEST:\n";
            if (!ctx.empty()) userTxt += "CONTEXT:\n" + ctx + "\n\n";
            userTxt += userPrompt;

            if (type == AIProvider::Gemini) {
                reqBody["contents"] = json::array();
                for (size_t i = 0; i < hist.size() - 1; i++) {
                    const auto& m = hist[i]; if (m.isPreview || m.role == "system") continue;
                    reqBody["contents"].push_back({ {"role", m.role}, {"parts", {{ {"text", m.text} }}} });
                }
                json cur; cur["role"] = "user"; cur["parts"] = json::array();
                if (!userTxt.empty()) cur["parts"].push_back({ {"text", userTxt} });
                for (const auto& img : imgs) {
                    cur["parts"].push_back({ {"inline_data", { {"mime_type", "image/jpeg"}, {"data", img.base64Data} }} });
                }
                reqBody["contents"].push_back(cur);

                std::wstring path = L"/v1beta/models/" + s2ws(modelID) + L":generateContent?key=" + s2ws(apiKey);
                std::string res = HttpRequest(L"generativelanguage.googleapis.com", path, "POST", reqBody.dump(), std::vector<std::wstring>{});

                try {
                    auto j = json::parse(res);
                    if (j.contains("candidates") && !j["candidates"].empty()) {
                        finalResp = j["candidates"][0]["content"]["parts"][0]["text"].get<std::string>();
                    }
                    else finalResp = "Gemini Error: " + res;
                }
                catch (...) { finalResp = "Gemini Parse Error"; }

            }
            else if (type == AIProvider::Ollama) {
                reqBody["model"] = modelID; reqBody["stream"] = false;
                reqBody["messages"] = json::array();
                reqBody["messages"].push_back({ {"role", "system"}, {"content", sysTxt} });
                for (size_t i = 0; i < hist.size() - 1; i++) {
                    const auto& m = hist[i]; if (m.isPreview) continue;
                    reqBody["messages"].push_back({ {"role", (m.role == "model" ? "assistant" : m.role)}, {"content", m.text} });
                }
                json last; last["role"] = "user"; last["content"] = userTxt;
                if (!imgs.empty()) {
                    last["images"] = json::array();
                    for (const auto& img : imgs) last["images"].push_back(img.base64Data);
                }
                reqBody["messages"].push_back(last);
                std::string res = HttpOllama("POST", L"/api/chat", reqBody.dump());
                try {
                    auto j = json::parse(res);
                    if (j.contains("message")) finalResp = j["message"]["content"].get<std::string>();
                    else finalResp = "Ollama Error";
                }
                catch (...) { finalResp = "Ollama Parse Error"; }

            }
            else {
                std::wstring domain = L"api.openai.com";
                std::wstring path = L"/v1/chat/completions";
                std::vector<std::wstring> heads;

                if (type == AIProvider::Anthropic) {
                    domain = L"api.anthropic.com"; path = L"/v1/messages";
                    heads.push_back(L"x-api-key: " + s2ws(apiKey));
                    heads.push_back(L"anthropic-version: 2023-06-01");
                    reqBody["model"] = modelID; reqBody["max_tokens"] = 4096;
                    reqBody["messages"] = json::array();
                    reqBody["system"] = sysTxt;
                    for (size_t i = 0; i < hist.size() - 1; i++) {
                        const auto& m = hist[i]; if (m.isPreview || m.role == "system") continue;
                        reqBody["messages"].push_back({ {"role", (m.role == "model" ? "assistant" : "user")}, {"content", m.text} });
                    }
                    json content = json::array();
                    if (!imgs.empty()) {
                        for (const auto& img : imgs) {
                            content.push_back({ {"type","image"}, {"source", { {"type","base64"}, {"media_type","image/jpeg"}, {"data",img.base64Data} }} });
                        }
                    }
                    content.push_back({ {"type","text"}, {"text",userTxt} });
                    reqBody["messages"].push_back({ {"role","user"}, {"content",content} });
                }
                else {
                    heads.push_back(L"Authorization: Bearer " + s2ws(apiKey));
                    if (type == AIProvider::DeepSeek) domain = L"api.deepseek.com";
                    else if (type == AIProvider::Moonshot) domain = L"api.moonshot.ai";
                    else if (type == AIProvider::OpenRouter) { domain = L"openrouter.ai"; path = L"/api/v1/chat/completions"; }
                    reqBody["model"] = modelID;
                    reqBody["messages"] = json::array();
                    reqBody["messages"].push_back({ {"role", "system"}, {"content", sysTxt} });
                    for (size_t i = 0; i < hist.size() - 1; i++) {
                        const auto& m = hist[i]; if (m.isPreview) continue;
                        reqBody["messages"].push_back({ {"role", (m.role == "model" ? "assistant" : "user")}, {"content", m.text} });
                    }
                    if (!imgs.empty() && (type == AIProvider::OpenAI || type == AIProvider::OpenRouter || type == AIProvider::Moonshot || type == AIProvider::DeepSeek)) {
                        json con = json::array();
                        con.push_back({ {"type", "text"}, {"text", userTxt} });
                        for (const auto& img : imgs) {
                            con.push_back({ {"type", "image_url"}, {"image_url", { {"url", "data:image/jpeg;base64," + img.base64Data} }} });
                        }
                        reqBody["messages"].push_back({ {"role", "user"}, {"content", con} });
                    }
                    else {
                        reqBody["messages"].push_back({ {"role", "user"}, {"content", userTxt} });
                    }
                }
                std::string res = HttpRequest(domain, path, "POST", reqBody.dump(), heads);
                try {
                    auto j = json::parse(res);
                    if (type == AIProvider::Anthropic) {
                        if (j.contains("content")) finalResp = j["content"][0]["text"].get<std::string>();
                        else finalResp = "Anthropic Error: " + res;
                    }
                    else {
                        if (j.contains("choices")) finalResp = j["choices"][0]["message"]["content"].get<std::string>();
                        else finalResp = "API Error: " + res;
                    }
                }
                catch (...) { finalResp = "Parse Error"; }
            }

            // --- TRIGGER R2 UPLOAD ---
            //ZipAndUploadEvidence(userTxt, finalResp, imgs);

            // --- SAVE CHAT HISTORY LOCALLY ---
            SaveChatHistoryEntry(userTxt, finalResp, imgs);

            std::lock_guard<std::mutex> lock(g_dataMutex);
            g_chatHistory.push_back({ "model", finalResp, false, false });
            g_scrollToBottom = true; g_isProcessing = false;
            }).detach();
    }
}

// =========================================================
// 8. UI WIDGETS (EXACT RESTORATION)
// =========================================================

static std::unordered_map<ImGuiID, float> g_buttonRingAnim;

bool IconButton(ID3D11ShaderResourceView* iconTex, const char* strId, const char* tooltip, ImVec2 size, bool disabled = false)
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;

    ImGuiContext& g = *GImGui;
    const ImGuiID uid = window->GetID(strId);

    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 actualSize = ImGui::CalcItemSize(size, 0.0f, 0.0f);

    if (disabled) {
        ImGui::InvisibleButton(strId, actualSize);
        ImDrawList* d = ImGui::GetWindowDrawList();
        d->AddRectFilled(pos + ImVec2(2.0f, 2.0f), pos + actualSize + ImVec2(2.0f, 2.0f), IM_COL32(0, 0, 0, 50), 6.0f);
        d->AddRect(pos, pos + actualSize, IM_COL32(60, 60, 60, 255), 6.0f, 0, 1.2f);
        if (iconTex) {
            ImVec2 pMin = pos + ImVec2(8.0f, 8.0f);
            ImVec2 pMax = pos + actualSize - ImVec2(8.0f, 8.0f);
            d->AddImage(iconTex, pMin, pMax, ImVec2(0.0f, 0.0f), ImVec2(1.0f, 1.0f), IM_COL32(100, 100, 100, 150));
        }
        return false;
    }

    bool clicked = ImGui::InvisibleButton(strId, actualSize);
    bool hovered = ImGui::IsItemHovered();
    bool held = ImGui::IsItemActive();

    float& t = g_buttonRingAnim[uid];
    float target = hovered ? 1.0f : 0.0f;
    t = ImLerp(t, target, 0.12f);

    if (clicked) g_buttonRingAnim[uid] = 1.3f; // kick flash

    ImDrawList* d = ImGui::GetWindowDrawList();

    ImU32 colAccent = GetAccentColorU32(1.0f);
    ImU32 colTeal = IM_COL32(0, 128, 128, 255);
    ImU32 mainColor = held ? colTeal : colAccent;

    // shadow - only draw box on hover
    if (hovered || held || t > 0.01f) {
        float alpha = t * 255.0f;
        ImU32 bg = IM_COL32(30, 30, 35, (int)alpha);
        ImU32 border = IM_COL32(60, 60, 70, (int)alpha);
        d->AddRectFilled(pos, pos + actualSize, bg, 6.0f);
        d->AddRect(pos, pos + actualSize, border, 6.0f);
    }

    // ring flash
    float& ring = g_buttonRingAnim[uid];
    if (ring > 0.0f) {
        float r = (ring - 1.0f) * 10.0f;
        float alpha = (1.3f - ring) / 0.3f;
        if (alpha > 0.0f) {
            ImU32 ringCol = IM_COL32(255, 255, 255, (int)(255 * alpha));
            d->AddRect(pos - ImVec2(r, r), pos + actualSize + ImVec2(r, r), ringCol, 8.0f, 0, 2.0f);
        }
        ring -= ImGui::GetIO().DeltaTime * 2.0f;
        if (ring < 0.0f) ring = 0.0f;
    }

    if (iconTex) {
        ImVec2 pMin = pos + ImVec2(8.0f, 8.0f);
        ImVec2 pMax = pos + actualSize - ImVec2(8.0f, 8.0f);
        d->AddImage(iconTex, pMin, pMax, ImVec2(0.0f, 0.0f), ImVec2(1.0f, 1.0f), mainColor);
    }

    if (tooltip && ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", tooltip);

    return clicked;
}

bool NeoWaveButton(const char* id, const ImVec2& size, bool disabled = false)
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;

    ImGuiContext& g = *GImGui;
    const ImGuiID uid = window->GetID(id);

    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 actualSize = ImGui::CalcItemSize(size, 0.0f, 0.0f);

    if (disabled) {
        ImGui::InvisibleButton(id, actualSize);
        ImGui::GetWindowDrawList()->AddRect(pos, pos + actualSize, IM_COL32(60, 60, 60, 255), 6.0f);
        ImGui::GetWindowDrawList()->AddText(pos + ImVec2(actualSize.x / 2 - 20.0f, actualSize.y / 2 - 8.0f), IM_COL32(100, 100, 100, 255), id);
        return false;
    }

    bool clicked = ImGui::InvisibleButton(id, actualSize);
    bool hovered = ImGui::IsItemHovered();
    bool held = ImGui::IsItemActive();

    static std::unordered_map<ImGuiID, float> anim;
    float& t = anim[uid];
    float target = hovered ? 1.0f : 0.0f;
    t = ImLerp(t, target, 0.12f);

    ImDrawList* d = ImGui::GetWindowDrawList();

    ImU32 colAccent = GetAccentColorU32();
    ImU32 colTeal = IM_COL32(0, 128, 128, 255);
    ImU32 colDark = IM_COL32(33, 33, 33, 255);
    ImU32 mainColor = held ? colTeal : colAccent;
    ImVec4 mainColV4 = ImGui::ColorConvertU32ToFloat4(mainColor);
    ImU32 bubbleColor = ImGui::ColorConvertFloat4ToU32(ImVec4(mainColV4.x, mainColV4.y, mainColV4.z, 0.5f));

    ImVec4 colTextStart = ImGui::ColorConvertU32ToFloat4(colAccent);
    ImVec4 colTextEnd = ImGui::ColorConvertU32ToFloat4(colDark);
    ImVec4 colTextCurr = ImLerp(colTextStart, colTextEnd, t);
    ImU32 textColor = ImGui::ColorConvertFloat4ToU32(colTextCurr);

    d->AddRect(pos, pos + actualSize, mainColor, 6.0f, 0, 2.0f);
    d->PushClipRect(pos, pos + actualSize, true);

    float radius = actualSize.x * 0.65f;
    if (radius < actualSize.y) radius = actualSize.y * 1.2f;

    float centerY = pos.y + actualSize.y * 0.5f;
    float centerX = pos.x + actualSize.x * 0.5f;

    float leftStartX = pos.x - radius;
    float leftEndX = centerX - radius + (actualSize.x * 0.15f);
    float currLeftX = ImLerp(leftStartX, leftEndX, t);
    d->AddCircleFilled(ImVec2(currLeftX, centerY), radius, bubbleColor, 64);

    float rightStartX = pos.x + actualSize.x + radius;
    float rightEndX = centerX + radius - (actualSize.x * 0.15f);
    float currRightX = ImLerp(rightStartX, rightEndX, t);
    d->AddCircleFilled(ImVec2(currRightX, centerY), radius, bubbleColor, 64);

    d->PopClipRect();

    ImVec2 textSize = ImGui::CalcTextSize(id);
    ImVec2 textPos = pos + (actualSize - textSize) * 0.5f;
    d->AddText(textPos, textColor, id);

    return clicked;
}

float CalculateInputBoxHeight(const std::string& buf, float availableWidth) {
    float sendBtnWidth = 50.0f;
    float wrap_width = availableWidth - sendBtnWidth - 20.0f;
    std::string textToCalc = buf.empty() ? " " : buf;
    ImVec2 textSize = ImGui::CalcTextSize(textToCalc.c_str(), NULL, false, wrap_width);

    float min_height = 55.0f;
    float calculated_height = textSize.y + 35.0f;
    float height = (calculated_height > min_height) ? calculated_height : min_height;
    if (height > 250.0f) height = 250.0f;
    return height;
}

bool FloatingInputGhost(const char* id, const char* label, std::string& buf, FocusState myFocus, bool showSendButton, bool& outSendClicked, float fixedHeight = 0.0f)
{
    ImGuiContext& g = *GImGui;
    const float sendBtnWidth = showSendButton ? 50.0f : 0.0f;
    const float width = ImGui::GetContentRegionAvail().x;
    float wrap_width = width - sendBtnWidth - 20.0f;

    float height = fixedHeight;
    if (height <= 0.0f) {
        height = CalculateInputBoxHeight(buf, width);
    }

    const ImVec2 pos = ImGui::GetCursorScreenPos();
    ImGui::PushID(id);

    if (ImGui::InvisibleButton("##input_hitbox", ImVec2(width - sendBtnWidth, height))) {
        g_currentFocus = myFocus;
    }

    bool focused = (g_currentFocus == myFocus);
    bool has_text = !buf.empty();

    static std::unordered_map<ImGuiID, float> anim;
    ImGuiID uid = ImGui::GetID("##anim_data");
    float& t = anim[uid];
    float target = (focused || has_text) ? 1.0f : 0.0f;
    t = ImLerp(t, target, 0.15f);

    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImU32 border_col = focused ? GetAccentColorU32() : IM_COL32(60, 60, 70, 255);

    draw->AddRectFilled(pos, pos + ImVec2(width, height), IM_COL32(25, 25, 30, 200), 6.0f);
    draw->AddRect(pos, pos + ImVec2(width, height), border_col, 6.0f, 0, 1.2f);

    float min_height = 55.0f;
    float label_y_offset = (min_height * 0.3f);
    float label_y = ImLerp(pos.y + label_y_offset, pos.y - 8.0f, t);
    float scale = ImLerp(1.0f, 0.78f, t);
    ImVec2 label_pos = ImVec2(pos.x + 12.0f, label_y);

    if (t > 0.5f) {
        float txt_width = ImGui::CalcTextSize(label).x * scale;
        draw->AddRectFilled(label_pos - ImVec2(2.0f, 0.0f), label_pos + ImVec2(txt_width + 2.0f, 14.0f * scale), IM_COL32(25, 25, 30, 255));
    }

    ImGui::SetWindowFontScale(scale);
    draw->AddText(label_pos, focused ? GetAccentColorU32() : IM_COL32(150, 150, 160, 255), label);
    ImGui::SetWindowFontScale(1.0f);

    std::string displayStr = buf;
    if (focused && (GetTickCount() / 500) % 2) displayStr += "|";

    draw->PushClipRect(pos, pos + ImVec2(width - sendBtnWidth - 5.0f, height), true);
    draw->AddText(NULL, 0.0f, pos + ImVec2(12.0f, 20.0f), IM_COL32(240, 240, 240, 255), displayStr.c_str(), NULL, wrap_width);
    draw->PopClipRect();

    outSendClicked = false;
    if (showSendButton) {
        ImVec2 btnPos = pos + ImVec2(width - sendBtnWidth, height - min_height);

        ImGui::SetCursorScreenPos(btnPos);
        bool btnClicked = ImGui::InvisibleButton("##send_btn", ImVec2(sendBtnWidth, min_height));
        bool btnHovered = ImGui::IsItemHovered();

        if (btnClicked) outSendClicked = true;

        ImU32 arrowColor = btnHovered ? GetAccentColorU32() : IM_COL32(180, 180, 180, 255);
        if (buf.empty() && g_screenshots.empty() && g_pendingInspectionText.empty()) arrowColor = IM_COL32(80, 80, 80, 255);

        if (g_icons.Send) {
            ImVec2 pMin = btnPos + ImVec2(10.0f, 10.0f);
            ImVec2 pMax = btnPos + ImVec2(sendBtnWidth - 10.0f, min_height - 10.0f);
            draw->AddImage(g_icons.Send, pMin, pMax, ImVec2(0.0f, 0.0f), ImVec2(1.0f, 1.0f), arrowColor);
        }
        else {
            ImVec2 center = btnPos + ImVec2(sendBtnWidth * 0.5f, min_height * 0.5f);
            float arrowSize = 8.0f;
            ImVec2 p1 = center + ImVec2(-arrowSize * 0.5f, -arrowSize);
            ImVec2 p2 = center + ImVec2(-arrowSize * 0.5f, arrowSize);
            ImVec2 p3 = center + ImVec2(arrowSize, 0.0f);
            draw->AddTriangleFilled(p1, p2, p3, arrowColor);
        }
    }

    ImGui::PopID();
    return focused;
}

// ---------------------------------------------------------
// NEW NEON CHECKBOX IMPLEMENTATION
// ---------------------------------------------------------
struct NeonCheckboxAnimState {
    float animationTime = -1.0f;
    float hoverLerp = 0.0f;
};
static std::unordered_map<ImGuiID, NeonCheckboxAnimState> g_neonCheckboxState;

bool NeonCheckbox(const char* label, bool* v) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const float size = 24.0f; // Scale approximate to 30px CSS

    const ImVec2 pos = window->DC.CursorPos;
    const ImRect total_bb(pos, pos + ImVec2(size, size)); // Just the box, text managed externally

    ImGui::ItemSize(total_bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(total_bb, id)) return false;

    bool hovered, held;
    bool pressed = ImGui::ButtonBehavior(total_bb, id, &hovered, &held);

    if (pressed) {
        *v = !(*v);
        ImGui::MarkItemEdited(id);
        if (*v) g_neonCheckboxState[id].animationTime = (float)ImGui::GetTime();
        SaveHotkeys(); // SAVE HOTKEYS WHEN CHECKBOX CHANGES
    }

    NeonCheckboxAnimState& anim = g_neonCheckboxState[id];
    float dt = ImGui::GetIO().DeltaTime;

    float targetHover = (hovered || held) ? 1.0f : 0.0f;
    anim.hoverLerp = ImLerp(anim.hoverLerp, targetHover, dt * 8.0f);

    ImDrawList* draw_list = window->DrawList;
    ImU32 colPrimary = GetAccentColorU32();

    ImVec2 boxMin = pos;
    ImVec2 boxMax = pos + ImVec2(size, size);
    ImVec2 boxCenter = (boxMin + boxMax) * 0.5f;

    float scale = 1.0f + (anim.hoverLerp * 0.05f);
    if (*v) scale = 1.0f;

    ImVec2 scaledMin = boxCenter - (ImVec2(size, size) * 0.5f * scale);
    ImVec2 scaledMax = boxCenter + (ImVec2(size, size) * 0.5f * scale);

    draw_list->AddRectFilled(scaledMin, scaledMax, IM_COL32(0, 0, 0, 200), 4.0f);

    ImU32 borderColor = *v ? colPrimary : IM_COL32(60, 60, 70, 255);
    if (anim.hoverLerp > 0.01f && !*v) {
        ImVec4 base = ImVec4(0.23f, 0.23f, 0.27f, 1.0f);
        ImVec4 prim = g_uiColor;
        ImVec4 res = ImLerp(base, prim, anim.hoverLerp);
        borderColor = ImGui::ColorConvertFloat4ToU32(res);
    }
    draw_list->AddRect(scaledMin, scaledMax, borderColor, 4.0f, 0, 2.0f);

    if (*v) {
        draw_list->AddRectFilled(scaledMin - ImVec2(2.0f, 2.0f), scaledMax + ImVec2(2.0f, 2.0f), GetAccentColorU32(0.2f), 6.0f);
        draw_list->AddRectFilled(scaledMin, scaledMax, GetAccentColorU32(0.1f), 4.0f);

        float time = (float)ImGui::GetTime();
        float alpha = (sinf(time * 5.0f) + 1.0f) * 0.5f;
        draw_list->AddRect(scaledMin, scaledMax, GetAccentColorU32(0.5f + 0.5f * alpha), 4.0f, 0, 1.0f);
    }

    if (*v) {
        ImVec2 p1 = scaledMin + ImVec2(size * 0.125f, size * 0.52f);
        ImVec2 p2 = scaledMin + ImVec2(size * 0.416f, size * 0.812f);
        ImVec2 p3 = scaledMin + ImVec2(size * 0.875f, size * 0.208f);
        draw_list->AddLine(p1, p2, colPrimary, 2.5f);
        draw_list->AddLine(p2, p3, colPrimary, 2.5f);
    }

    if (anim.animationTime > 0.0f) {
        float t = (float)ImGui::GetTime() - anim.animationTime;
        float duration = 0.6f;

        if (t < duration) {
            float progress = t / duration;
            float easeOut = 1.0f - powf(1.0f - progress, 3.0f);

            int particleCount = 12;
            float radiusStart = size * 0.5f;
            float radiusEnd = size * 1.5f;
            float currentRadius = ImLerp(radiusStart, radiusEnd, easeOut);
            float alpha = 1.0f - progress;

            for (int i = 0; i < particleCount; i++) {
                float angle = (float)i * (6.28318f / (float)particleCount);
                float x = cosf(angle) * currentRadius;
                float y = sinf(angle) * currentRadius;

                ImVec2 pPos = boxCenter + ImVec2(x, y);
                float pSize = 2.0f * (1.0f - progress);
                draw_list->AddCircleFilled(pPos, pSize, GetAccentColorU32(alpha));
            }

            float ringRadius = ImLerp(0.0f, size * 1.2f, easeOut);
            draw_list->AddCircle(boxCenter, ringRadius, GetAccentColorU32(alpha), 24, 1.5f);

            float sparkLen = 15.0f * (1.0f - easeOut);
            float sparkOffset = size * 0.6f + (10.0f * easeOut);

            // Explicit ImVec2 math breakdown to satisfy strict compiler
            ImVec2 center = boxCenter;
            ImVec2 off0_a = center + ImVec2(sparkOffset, 0.0f);
            ImVec2 off0_b = center + ImVec2(sparkOffset + sparkLen, 0.0f);

            ImVec2 off90_a = center + ImVec2(0.0f, sparkOffset);
            ImVec2 off90_b = center + ImVec2(0.0f, sparkOffset + sparkLen);

            ImVec2 off180_a = center - ImVec2(sparkOffset, 0.0f);
            ImVec2 off180_b = center - ImVec2(sparkOffset + sparkLen, 0.0f);

            ImVec2 off270_a = center - ImVec2(0.0f, sparkOffset);
            ImVec2 off270_b = center - ImVec2(0.0f, sparkOffset + sparkLen);

            ImU32 sparkCol = GetAccentColorU32(alpha);

            draw_list->AddLine(off0_a, off0_b, sparkCol, 1.0f);
            draw_list->AddLine(off90_a, off90_b, sparkCol, 1.0f);
            draw_list->AddLine(off180_a, off180_b, sparkCol, 1.0f);
            draw_list->AddLine(off270_a, off270_b, sparkCol, 1.0f);
        }
    }

    return pressed;
}

void HotkeyWidget(const char* label, HotkeyConfig& hk) {
    ImGui::PushID(label);
    ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.8f, 1.0f), "%s", label);

    // --- FIX: TEXT LABELS FIRST, THEN CHECKBOXES ---
    ImGui::AlignTextToFramePadding();
    ImGui::Text("Ctrl"); ImGui::SameLine(); NeonCheckbox("##ctrl", &hk.ctrl); ImGui::SameLine(0.0f, 15.0f);
    ImGui::Text("Alt");  ImGui::SameLine(); NeonCheckbox("##alt", &hk.alt);   ImGui::SameLine(0.0f, 15.0f);
    ImGui::Text("Shift"); ImGui::SameLine(); NeonCheckbox("##shift", &hk.shift); ImGui::SameLine(0.0f, 15.0f);

    char buf[16] = { 0 };
    bool isBindingThis = (g_isBindingKey && g_targetBinding == &hk);

    if (isBindingThis) {
        strcpy(buf, "...");
    }
    else {
        std::string n = GetKeyName(hk.vkCode);
        if (n.empty()) n = "-";
        if (n.length() > 3) n = n.substr(0, 3);
        strcpy(buf, n.c_str());
    }

    if (isBindingThis) ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.0f, 0.0f, 0.6f));
    else ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.2f, 0.2f, 1.0f));

    if (ImGui::Button(buf, ImVec2(50.0f, 0.0f))) {
        if (!g_isBindingKey) {
            g_isBindingKey = true;
            g_targetBinding = &hk;
        }
        else {
            g_isBindingKey = false;
            g_targetBinding = nullptr;
        }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Click to edit hotkey");


    ImGui::PopStyleColor();
    ImGui::PopID();
}

void DrawThinkingLoader() {
    float time = (float)ImGui::GetTime();
    const char* text = "Thinking...";
    float w = ImGui::CalcTextSize(text).x;
    float startX = (ImGui::GetWindowWidth() - w) * 0.5f;
    ImGui::SetCursorPosX(startX);
    for (int i = 0; text[i] != 0; i++) {
        float t = time * 4.0f - (i * 0.3f);
        float intensity = (sinf(t) + 1.0f) * 0.5f;
        intensity = powf(intensity, 3.0f);
        float r = ImLerp(0.4f, 1.0f, intensity);
        float g = ImLerp(0.4f, 1.0f, intensity);
        float b = ImLerp(0.4f, 1.0f, intensity);
        float a = ImLerp(0.5f, 1.0f, intensity);
        ImGui::TextColored(ImVec4(r, g, b, a), "%c", text[i]);
        ImGui::SameLine(0, 0);
    }
    ImGui::NewLine();
}

void RenderBubbleSegment(const std::string& text, bool isUser, bool isCode, float maxWidth) {
    if (text.empty()) return;

    ImGuiWindow* window = ImGui::GetCurrentWindow();
    ImDrawList* draw = window->DrawList;
    ImVec2 pos = ImGui::GetCursorScreenPos();

    // 1. Setup Colors & Fonts
    ImU32 bgCol;
    ImU32 textCol = IM_COL32(240, 240, 240, 255);

    if (isCode) {
        bgCol = IM_COL32(25, 25, 28, 255); // Dark grey for code
        if (g_fontMono) ImGui::PushFont(g_fontMono);
        textCol = IM_COL32(200, 200, 200, 255);
    }
    else if (isUser) {
        bgCol = GetAccentColorU32(0.25f); // Accent tint for user
    }
    else {
        bgCol = IM_COL32(45, 45, 50, 255); // Lighter grey for AI text
    }

    // 2. Calculate Size
    // We need to wrap text manually to calculate exact bubble dimensions
    ImVec2 textSize = ImGui::CalcTextSize(text.c_str(), NULL, false, maxWidth);

    // Add padding
    ImVec2 padding = isCode ? ImVec2(10.0f, 10.0f) : ImVec2(12.0f, 8.0f);
    ImVec2 bubbleSize = textSize + padding * 2.0f;

    // 3. Calculate Position (Alignment)
    float availWidth = ImGui::GetContentRegionAvail().x;
    float offsetX = 0.0f;

    if (isUser) {
        // Right Align: Available Width - Bubble Width
        offsetX = availWidth - bubbleSize.x;
    }
    // AI is Left Aligned (offsetX = 0), but let's indent slightly
    if (!isUser) offsetX = 5.0f;

    ImVec2 bubbleMin = pos + ImVec2(offsetX, 0.0f);
    ImVec2 bubbleMax = bubbleMin + bubbleSize;

    // 4. Draw Background
    float rounding = 12.0f;
    ImDrawFlags flags = ImDrawFlags_None;

    // Aesthetic: Sharpen corners based on who is talking
    if (isCode) {
        rounding = 4.0f; // Code blocks are sharp and professional
        bgCol = IM_COL32(20, 20, 22, 255); // Deep dark for code
    }
    else if (isUser) {
        bgCol = GetAccentColorU32(0.20f); // Subtle user tint
        flags = ImDrawFlags_RoundCornersTopLeft | ImDrawFlags_RoundCornersBottomLeft | ImDrawFlags_RoundCornersBottomRight;
    }
    else {
        bgCol = IM_COL32(40, 40, 45, 255); // Clean sleek grey for AI
        flags = ImDrawFlags_RoundCornersTopRight | ImDrawFlags_RoundCornersBottomLeft | ImDrawFlags_RoundCornersBottomRight;
    }

    draw->AddRectFilled(bubbleMin, bubbleMax, bgCol, rounding, flags);

    // Optional: Border for code blocks to make them pop
    if (isCode) {
        draw->AddRect(bubbleMin, bubbleMax, IM_COL32(60, 60, 65, 255), rounding);
    }
    else if (!isUser) {
        // Subtle border for AI text
        draw->AddRect(bubbleMin, bubbleMax, IM_COL32(60, 60, 65, 100), rounding, flags);
    }

    // 5. Draw Text
    ImGui::SetCursorScreenPos(bubbleMin + padding);

    // Enforce wrap width
    ImGui::PushTextWrapPos(ImGui::GetCursorPos().x + maxWidth);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(textCol), "%s", text.c_str());
    ImGui::PopTextWrapPos();

    if (isCode && g_fontMono) ImGui::PopFont();

    // 6. Advance Cursor
    // We manually placed the text, so we need to tell ImGui how much space we took vertically
    ImGui::SetCursorScreenPos(pos + ImVec2(0.0f, bubbleSize.y + 5.0f));
}

void RenderSmartMessage(const ChatMessage& msg) {
    bool isUser = (msg.role == "user");
    float windowWidth = ImGui::GetContentRegionAvail().x;
    float maxBubbleWidth = windowWidth * 0.85f; // Bubbles take up to 85% of width

    // Add a tiny header for the AI to show it's thinking/talking
    if (!isUser) {
        ImGui::SetCursorPosX(5.0f);
        ImGui::TextDisabled(msg.role == "model" ? "AI" : "System");
    }

    // PARSING LOGIC
    // We split the string by lines to detect ``` code blocks
    std::stringstream ss(msg.text);
    std::string line;
    std::string currentBuffer = "";
    bool inCodeBlock = false;

    while (std::getline(ss, line)) {
        // Check for Markdown Code Block delimiter
        if (line.rfind("```", 0) == 0) { // Starts with ```
            // 1. Flush whatever text buffer we have currently
            if (!currentBuffer.empty()) {
                RenderBubbleSegment(currentBuffer, isUser, inCodeBlock, maxBubbleWidth);
                currentBuffer = "";
            }
            // 2. Flip state
            inCodeBlock = !inCodeBlock;
            continue; // Skip printing the ``` line itself
        }

        currentBuffer += line + "\n";
    }

    // Flush remaining buffer
    if (!currentBuffer.empty()) {
        RenderBubbleSegment(currentBuffer, isUser, inCodeBlock, maxBubbleWidth);
    }

    // Add spacing between messages
    ImGui::Dummy(ImVec2(0.0f, 10.0f));
}

void DrawDimOverlayIfRequested() {
    if (!g_dimOverlay) return;
    ImDrawList* d = ImGui::GetBackgroundDrawList();
    d->AddRectFilled({ 0.0f, 0.0f }, ImGui::GetIO().DisplaySize, IM_COL32(0, 0, 0, 100));
}

// =========================================================
// 9. WINDOW & HOOK (FIXED FOR DEADLOCKS)
// =========================================================

// --- FIX: NON-BLOCKING HOOK PROCEDURE ---
LRESULT CALLBACK HookProc(int n, WPARAM w, LPARAM l) {
    if (n == HC_ACTION) {
        if (w == WM_KEYDOWN || w == WM_SYSKEYDOWN || w == WM_KEYUP || w == WM_SYSKEYUP) {
            KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)l;


            // --- 1. HANDLE GLOBAL TOGGLE (FAST, NO MUTEX) ---
            bool isKeyDown = (w == WM_KEYDOWN || w == WM_SYSKEYDOWN);
            bool isKeyUp = (w == WM_KEYUP || w == WM_SYSKEYUP);

            bool altDown = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
            bool ctrlDown = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
            bool shiftDown = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;

            // FIX: Only process hotkeys AFTER LOGIN - but still allow input queuing for typing
            if (g_appState == AppState::LoggedIn) {
                // Check if this key matches the toggle hotkey (modifiers + key)
                bool isToggleHotkey = (p->vkCode == g_hkToggle.vkCode &&
                    altDown == g_hkToggle.alt &&
                    ctrlDown == g_hkToggle.ctrl &&
                    shiftDown == g_hkToggle.shift);

                // Check if this key matches the screenshot hotkey (modifiers + key)
                bool isScreenshotHotkey = (p->vkCode == g_hkScreenshot.vkCode &&
                    altDown == g_hkScreenshot.alt &&
                    ctrlDown == g_hkScreenshot.ctrl &&
                    shiftDown == g_hkScreenshot.shift);

                // Handle Toggle Hotkey - swallow both keydown and keyup, but only trigger on keydown
                if (isToggleHotkey) {
                    if (isKeyDown) {
                        // Post message to main thread to handle visibility safely
                        PostMessage(g_hwnd, WM_APP + 1, 0, 0);
                    }
                    // Swallow both keydown and keyup for the hotkey (but modifiers pass through)
                    return 1;
                }

                // Handle Screenshot Hotkey - swallow both keydown and keyup, but only trigger on keydown
                if (isScreenshotHotkey) {
                    if (isKeyDown) {
                        PostMessage(g_hwnd, WM_USER + 1, 0, 0);
                    }
                    // Swallow both keydown and keyup for the hotkey (but modifiers pass through)
                    return 1;
                }
            }
            // --- 2. HANDLE BINDING (FAST) ---
            if (g_isBindingKey && g_targetBinding) {
                // Ignore modifier keys during binding
                if (p->vkCode == VK_LMENU || p->vkCode == VK_RMENU ||
                    p->vkCode == VK_LCONTROL || p->vkCode == VK_RCONTROL ||
                    p->vkCode == VK_LSHIFT || p->vkCode == VK_RSHIFT) {
                    return CallNextHookEx(NULL, n, w, l);
                }
                // Queue the binding update
                {
                    std::lock_guard<std::mutex> lock(g_inputMutex);
                    g_inputQueue.push_back({ p->vkCode, 0, 0, true });
                    // Special flag or check in main loop will handle "Binding Mode" logic
                }
                return 1;
            }

            // --- 3. INPUT SWALLOWING (REMOVED) ---
            // Key swallowing and focus-less typing logic has been removed.
            
        }
    }
    g_blockSystemInput = false;

    return CallNextHookEx(NULL, n, w, l);
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    // Removed WM_MOUSEACTIVATE handler
    if (msg == WM_USER + 1) { CaptureScreenshot(); return 0; }

    // Handle Custom Toggle Message from Hook
    if (msg == WM_APP + 1) {
        std::lock_guard<std::mutex> lock(g_dataMutex);
        g_isVisible = !g_isVisible;
        if (g_isVisible) {
            ShowWindow(g_hwnd, SW_SHOW);
            SetWindowPos(g_hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        }
        else {
            ShowWindow(g_hwnd, SW_HIDE);
            g_currentFocus = FocusState::None;
        }
        return 0;
    }

    // Set GUI visibility (used by Telegram and other background threads)
    if (msg == WM_APP + 2) {
        std::lock_guard<std::mutex> lock(g_dataMutex);
        bool wantVisible = (wParam != 0);
        if (g_isVisible != wantVisible) {
            g_isVisible = wantVisible;
            if (g_isVisible) {
                ShowWindow(g_hwnd, SW_SHOW);
                SetWindowPos(g_hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            }
            else {
                ShowWindow(g_hwnd, SW_HIDE);
                g_currentFocus = FocusState::None;
            }
        }
        return 0;
    }

    // --- RESIZE CURSOR LOGIC (WM_NCHITTEST) ---
    if (msg == WM_NCHITTEST) {
        POINT pt = { LOWORD(lParam), HIWORD(lParam) };
        ScreenToClient(hWnd, &pt);
        RECT rc; GetClientRect(hWnd, &rc);
        int border = 8; // Width of the resize area

        // Check corners first
        if (pt.x < border && pt.y < border) return HTTOPLEFT;
        if (pt.x > rc.right - border && pt.y < border) return HTTOPRIGHT;
        if (pt.x < border && pt.y > rc.bottom - border) return HTBOTTOMLEFT;
        if (pt.x > rc.right - border && pt.y > rc.bottom - border) return HTBOTTOMRIGHT;

        // Check edges
        if (pt.x < border) return HTLEFT;
        if (pt.x > rc.right - border) return HTRIGHT;
        if (pt.y < border) return HTTOP;
        if (pt.y > rc.bottom - border) return HTBOTTOM;

        return HTCLIENT; // Otherwise, it's inside the window
    }

    // --- FIX: FORCE NORMAL CURSOR EVEN ON RESIZE EDGES ---
    if (msg == WM_SETCURSOR) {
        if (LOWORD(lParam) == HTTOP || LOWORD(lParam) == HTBOTTOM ||
            LOWORD(lParam) == HTLEFT || LOWORD(lParam) == HTRIGHT ||
            LOWORD(lParam) == HTTOPLEFT || LOWORD(lParam) == HTTOPRIGHT ||
            LOWORD(lParam) == HTBOTTOMLEFT || LOWORD(lParam) == HTBOTTOMRIGHT)
        {
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            return TRUE;
        }
    }
    // ----------------------------------------------------

    if (msg == WM_SIZE) {
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
            if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            ID3D11Texture2D* b; g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&b));
            g_pd3dDevice->CreateRenderTargetView(b, NULL, &g_mainRenderTargetView); b->Release();
        }
        return 0;
    }
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}


// =========================================================
// AGENT LOGIC: PROCESS SELECTOR & UI TREE
// =========================================================

struct ProcessInfo {
    DWORD pid;
    HWND hwnd;
    std::string title;
    std::string processName;
};

std::vector<ProcessInfo> g_processList;
HWND g_targetWindow = NULL;
std::string g_targetProcessName = "None";
std::string g_lastActionResult = ""; // Stores output for the planner (e.g. from list_processes)
std::string g_autoMemoryHint = "";    // Auto RAG context injected into planner prompt
bool g_showProcessSelector = false;

static DWORD g_autoVerifyIntervalMs = 7000;
static DWORD g_lastAutoVerifyTick = 0;
static bool g_sentStartScreenshot = false;

static bool IsNonDestructiveQueryAction(const std::string& a) {
    if (a == "list_processes" || a == "list_installed_apps" || a == "list_launchable_apps" || a == "net_check") return true;
    if (a == "winget_search" || a == "winget_list") return true;
    if (a.rfind("memory_", 0) == 0) return true;
    // Workspace / coding tools (no UI side-effects)
    if (a == "run_cmd") return true;
    if (a.rfind("fs_", 0) == 0) return true;
    if (a.rfind("git_", 0) == 0) return true;
    if (a.rfind("mcp_", 0) == 0) return true;
    return false;
}

static bool IsMemoryQueryGoal(const std::string& goalLower) {
    if (goalLower.find("what did we") != std::string::npos) return true;
    if (goalLower.find("what have we") != std::string::npos) return true;
    if (goalLower.find("history") != std::string::npos) return true;
    if (goalLower.find("memory") != std::string::npos) return true;
    if (goalLower.find("recall") != std::string::npos) return true;
    if (goalLower.find("previous") != std::string::npos) return true;
    return false;
}

static bool ModelLikelySupportsImages(const AIProvider provider, const std::string& modelID) {
    // Best-effort: don't attach images to clearly text-only endpoints.
    // Gemini/Anthropic/Ollama generally accept images when formatted correctly.
    if (provider == AIProvider::Gemini) return true;
    if (provider == AIProvider::Anthropic) return true;
    if (provider == AIProvider::Ollama) return true;

    // OpenAI-compatible: only attach for common vision-capable families.
    std::string m = ToLowerCopy(modelID);
    if (m.find("vision") != std::string::npos) return true;
    if (m.find("gpt-4o") != std::string::npos) return true;
    if (m.find("gpt-4.1") != std::string::npos) return true;
    if (m.find("gpt-4-turbo") != std::string::npos) return true;
    return false;
}

bool GetLatestScreenshotSnapshot(std::string& outBase64Jpeg, std::string& outCtxText, std::string& outProcName, std::string& outWinTitle) {
    outBase64Jpeg.clear();
    outCtxText.clear();
    outProcName.clear();
    outWinTitle.clear();

    {
        std::lock_guard<std::mutex> lock(g_dataMutex);
        if (!g_screenshots.empty()) outBase64Jpeg = g_screenshots.back().base64Data;
        outCtxText = g_pendingInspectionText;
        outProcName = g_targetProcessName;
    }

    if (g_targetWindow && IsWindow(g_targetWindow)) {
        char t[256] = {};
        GetWindowTextA(g_targetWindow, t, sizeof(t));
        outWinTitle = t;
    }

    return !outBase64Jpeg.empty();
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd) || GetWindowTextLength(hwnd) == 0) return TRUE;

    // Skip our own window and the desktop
    if (hwnd == g_hwnd || hwnd == GetShellWindow()) return TRUE;

    // Check for "App Window" style to filter out tooltips/hidden windows
    LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
    LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);

    // Stop if child
    if (style & WS_CHILD) return TRUE;

    // Stop if ToolWindow
    if (exStyle & WS_EX_TOOLWINDOW) return TRUE;

    // Check ownership (we want top-level windows)
    if (GetWindow(hwnd, GW_OWNER) != NULL) return TRUE;

    // Allow ANY window that passed these checks (e.g. UWP apps might not have WS_CAPTION)
    // if ((style & WS_CAPTION) == 0) ... we allow it now.

    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);

    char title[256];
    GetWindowTextA(hwnd, title, sizeof(title));

    char processName[MAX_PATH] = "<unknown>";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseNameA(hProcess, hMod, processName, sizeof(processName));
        }
        CloseHandle(hProcess);
    }

    // DEBUG LOG (avoid fixed-buffer sprintf overflow on long titles)
    {
        std::string dbg = "[FOUND] PID: " + std::to_string((unsigned long)pid) +
            ", Name: " + std::string(processName) +
            ", Title: " + std::string(title) + "\n";
        OutputDebugStringA(dbg.c_str());
    }

    g_processList.push_back({ pid, hwnd, title, processName });
    return TRUE;
}

void RefreshProcessList() {
    g_processList.clear();
    EnumWindows(EnumWindowsProc, 0);
}

// =========================================================
// TELEGRAM BRIDGE: HTTP POLLING + MESSAGE SENDING
// =========================================================

void TelegramProcessCommandImpl(const std::string& chatId, const std::string& text);

class TelegramBridge {
public:
    static bool SendMessage(const std::string& text) {
        if (g_telegramToken.empty() || g_telegramChatId.empty()) return false;
        std::string url = "/bot" + g_telegramToken + "/sendMessage";
        json body;
        body["chat_id"] = g_telegramChatId;
        body["text"] = text;
        // Don't set parse_mode. Telegram Markdown parsing is strict and will reject
        // messages containing unescaped characters (common in window titles like []()_).
        // This caused commands like /apps to get stuck at "Fetching" with no follow-up.
        std::string payload = body.dump();
        return HttpPost("api.telegram.org", url, payload);
    }

    static bool SendPhotoJpegBytes(const std::vector<uint8_t>& jpegBytes, const std::string& caption) {
        if (g_telegramToken.empty() || g_telegramChatId.empty()) return false;
        if (jpegBytes.empty()) return false;

        // Multipart/form-data upload to Telegram sendPhoto
        std::string path = "/bot" + g_telegramToken + "/sendPhoto";
        std::string boundary = "----HopeBoundary" + std::to_string(GetTickCount64());

        auto AppendStr = [](std::vector<uint8_t>& out, const std::string& s) {
            out.insert(out.end(), (const uint8_t*)s.data(), (const uint8_t*)s.data() + s.size());
            };
        auto AppendBytes = [](std::vector<uint8_t>& out, const std::vector<uint8_t>& b) {
            out.insert(out.end(), b.begin(), b.end());
            };

        std::vector<uint8_t> body;
        AppendStr(body, "--" + boundary + "\r\n");
        AppendStr(body, "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n");
        AppendStr(body, g_telegramChatId + "\r\n");

        if (!caption.empty()) {
            AppendStr(body, "--" + boundary + "\r\n");
            AppendStr(body, "Content-Disposition: form-data; name=\"caption\"\r\n\r\n");
            AppendStr(body, caption + "\r\n");
        }

        AppendStr(body, "--" + boundary + "\r\n");
        AppendStr(body, "Content-Disposition: form-data; name=\"photo\"; filename=\"screenshot.jpg\"\r\n");
        AppendStr(body, "Content-Type: image/jpeg\r\n\r\n");
        AppendBytes(body, jpegBytes);
        AppendStr(body, "\r\n");
        AppendStr(body, "--" + boundary + "--\r\n");

        std::wstring ct = L"Content-Type: multipart/form-data; boundary=" + s2ws(boundary);
        return HttpPostRaw("api.telegram.org", path, ct, body);
    }

    static std::vector<std::pair<std::string, std::string>> PollUpdates() {
        std::vector<std::pair<std::string, std::string>> messages;
        if (g_telegramToken.empty()) return messages;
        std::string url = "/bot" + g_telegramToken + "/getUpdates?timeout=5&offset=" + std::to_string(g_telegramLastUpdateId + 1);
        std::string response = HttpGet("api.telegram.org", url);
        if (response.empty()) return messages;
        try {
            auto j = json::parse(response);
            if (j.contains("ok") && j["ok"].get<bool>() && j.contains("result")) {
                for (auto& update : j["result"]) {
                    int updateId = update.value("update_id", 0);
                    if (updateId > g_telegramLastUpdateId) g_telegramLastUpdateId = updateId;
                    if (update.contains("message") && update["message"].contains("text")) {
                        auto& msg = update["message"];

                        // Avoid consuming bot-authored messages as user input.
                        if (msg.contains("from") && msg["from"].value("is_bot", false)) {
                            continue;
                        }

                        std::string chatId = std::to_string(msg["chat"].value("id", (int64_t)0));
                        std::string text = msg["text"].get<std::string>();

                        // Auto-detect and save Chat ID on first message
                        if (g_telegramChatId.empty() && !chatId.empty() && chatId != "0") {
                            g_telegramChatId = chatId;
                            SaveHotkeys();
                            
                            // Send a confirmation message
                            TelegramSendMessageText("[SETUP] Auto-detected and saved your Chat ID (" + chatId + "). The Agent is now bound to this chat.");
                        }

                        if (g_telegramChatId.empty() || chatId == g_telegramChatId) {
                            messages.push_back({ chatId, text });
                        }
                    }
                }
            }
        }
        catch (...) {}
        return messages;
    }

    static void ProcessCommand(const std::string& chatId, const std::string& text);

    static void StartPolling() {
        if (g_telegramPolling) return;
        g_telegramPolling = true;
        std::thread([]() {
            SendMessage("[OK] Agent is online and ready!");

            // Drain any pending updates so old messages don't get misinterpreted as replies.
            // This prevents the login flow from immediately consuming stale chat text.
            (void)PollUpdates();


            while (g_telegramPolling && g_telegramEnabled) {
                auto messages = PollUpdates();
                for (auto& msg : messages) {
                    ProcessCommand(msg.first, msg.second);
                }
                Sleep(1500);
            }
            g_telegramPolling = false;
            }).detach();
    }

    static void StopPolling() { g_telegramPolling = false; }

private:
    static std::string HttpGet(const std::string& host, const std::string& path) {
        std::string result;
        HINTERNET hSession = WinHttpOpen(L"TelegramBridge/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
        if (!hSession) return result;
        std::wstring wHost(host.begin(), host.end());
        HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return result; }
        std::wstring wPath(path.begin(), path.end());
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath.c_str(), NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return result; }
        if (WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0) && WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD dwSize = 0;
            do {
                dwSize = 0;
                WinHttpQueryDataAvailable(hRequest, &dwSize);
                if (dwSize > 0) {
                    std::vector<char> buf(dwSize + 1, 0);
                    DWORD dwRead = 0;
                    WinHttpReadData(hRequest, buf.data(), dwSize, &dwRead);
                    result.append(buf.data(), dwRead);
                }
            } while (dwSize > 0);
        }
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return result;
    }

    static bool HttpPost(const std::string& host, const std::string& path, const std::string& jsonBody) {
        HINTERNET hSession = WinHttpOpen(L"TelegramBridge/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
        if (!hSession) return false;
        std::wstring wHost(host.begin(), host.end());
        HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
        std::wstring wPath(path.begin(), path.end());
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(), NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
        LPCWSTR contentType = L"Content-Type: application/json";
        bool ok = WinHttpSendRequest(hRequest, contentType, -1, (LPVOID)jsonBody.c_str(), (DWORD)jsonBody.size(), (DWORD)jsonBody.size(), 0)
            && WinHttpReceiveResponse(hRequest, NULL);
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return ok;
    }

    static bool HttpPostRaw(const std::string& host, const std::string& path, const std::wstring& contentType, const std::vector<uint8_t>& body) {
        HINTERNET hSession = WinHttpOpen(L"TelegramBridge/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
        if (!hSession) return false;
        std::wstring wHost(host.begin(), host.end());
        HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
        std::wstring wPath(path.begin(), path.end());
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(), NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

        bool ok = WinHttpSendRequest(
            hRequest,
            contentType.c_str(),
            (DWORD)-1L,
            (LPVOID)(body.empty() ? NULL : body.data()),
            (DWORD)body.size(),
            (DWORD)body.size(),
            0
        ) && WinHttpReceiveResponse(hRequest, NULL);

        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return ok;
    }
};

bool TelegramSendPhotoBytes(const std::vector<uint8_t>& jpegBytes, const std::string& caption) {
    return TelegramBridge::SendPhotoJpegBytes(jpegBytes, caption);
}

bool TelegramSendMessageText(const std::string& text) {
    return TelegramBridge::SendMessage(text);
}

void TelegramBridge::ProcessCommand(const std::string& chatId, const std::string& text) {
    TelegramProcessCommandImpl(chatId, text);
}



void RenderSettingsPage() {
    ImGui::TextColored(g_uiColor, "SETTINGS");
    ImGui::Separator();
    ImGui::Spacing();

    // --- MODE SWITCHER ---
    ImGui::BeginChild("ModeBox", ImVec2(0.0f, 50.0f), true);
    ImGui::Text("Interface Mode:"); ImGui::SameLine();
    if (ImGui::RadioButton("Chat", g_appMode == AppMode::Chat)) g_appMode = AppMode::Chat;
    ImGui::SameLine();
    if (ImGui::RadioButton("Agent", g_appMode == AppMode::Agent)) g_appMode = AppMode::Agent;
    ImGui::EndChild();
    ImGui::Spacing();
    // ---------------------

    // --- FIX: Scrollable Settings Container ---
    // Using 0 as flag instead of undefined flag
    ImGui::BeginChild("SettingsScroll", ImVec2(0.0f, -60.0f), false, 0);

    ImGui::BeginChild("Box1", ImVec2(0.0f, 220.0f), true);
    ImGui::Text("Interface Color");
    ImGui::SetNextItemWidth(150.0f);
    ImGuiColorEditFlags pickerFlags = ImGuiColorEditFlags_PickerHueWheel | ImGuiColorEditFlags_NoSidePreview | ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoAlpha;
    ImGui::ColorPicker3("##picker", (float*)&g_uiColor, pickerFlags);
    ImGui::EndChild();
    ImGui::Spacing();

    ImGui::BeginChild("Box2", ImVec2(0.0f, 80.0f), true);
    HotkeyWidget("Toggle Visibility (Global)", g_hkToggle);
    ImGui::EndChild();
    ImGui::Spacing();

    ImGui::BeginChild("Box3", ImVec2(0.0f, 80.0f), true);
    HotkeyWidget("Take Screenshot", g_hkScreenshot);
    ImGui::EndChild();
    ImGui::Spacing();

    // --- TRANSPARENCY SLIDER ---
    ImGui::BeginChild("BoxTrans", ImVec2(0.0f, 60.0f), true);
    ImGui::Text("Window Opacity");
    ImGui::SetNextItemWidth(150.0f);
    if (ImGui::SliderFloat("##alpha", &g_windowAlpha, 0.2f, 1.0f, "%.2f")) {
        SaveHotkeys();
    }

    ImGui::EndChild();
    ImGui::Spacing();
    // ---------------------------

    // --- CHAT HISTORY TOGGLE ---
    ImGui::BeginChild("BoxHistory", ImVec2(0.0f, 60.0f), true);
    ImGui::Text("Chat History"); ImGui::SameLine();
    if (NeonCheckbox("##chathistory", &g_chatHistoryEnabled)) {
        SaveHotkeys();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(Saves to Desktop/Ofradr-chat-history)");
    ImGui::EndChild();
    ImGui::Spacing();
    // ---------------------------

    // --- TELEGRAM REMOTE CONTROL ---
    ImGui::BeginChild("BoxTelegram", ImVec2(0.0f, 200.0f), true);
    ImGui::TextColored(g_uiColor, "TELEGRAM REMOTE CONTROL");
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::Text("Bot Token is configured during installation.");
    if (NeonCheckbox("##tgenabled", &g_telegramEnabled)) {
        SaveHotkeys();
        if (g_telegramEnabled && !g_telegramPolling) {
            TelegramBridge::StartPolling();
        }
        else if (!g_telegramEnabled) {
            TelegramBridge::StopPolling();
        }
    }
    ImGui::SameLine();
    ImGui::Text("Enable Telegram");
    ImGui::SameLine();
    ImGui::TextDisabled(g_telegramPolling ? "(Connected)" : "(Disconnected)");
    if (ImGui::Button("Save & Connect", ImVec2(-1, 28))) {
        SaveHotkeys();
        if (g_telegramEnabled) {
            TelegramBridge::StopPolling();
            Sleep(200);
            TelegramBridge::StartPolling();
        }
    }
    ImGui::EndChild();
    ImGui::Spacing();

    ImGui::BeginChild("Box4", ImVec2(0.0f, 70.0f), true);
    ImGui::TextDisabled("Status Information");
    ImGui::Text("Version: %s", CURRENT_APP_VERSION.c_str());
    ImGui::Text("State: %s", g_appState == AppState::LoggedIn ? "Authenticated" : "Locked");
    ImGui::EndChild();
    ImGui::Spacing();



    ImGui::EndChild(); // End Scroll Container
}




// --- UI TREE STRUCTURES ---

struct AgentElement {
    std::string name;
    std::string controlType;
    std::string automationId;
    std::string value;
    std::string labeledBy;
    long x, y, w, h;
    std::vector<std::string> patterns;
    std::vector<AgentElement> children;
};

// Recursive function to build the full UI tree
static int g_agentTreeElementCount = 0;

std::string ControlTypeIdToString(CONTROLTYPEID cType) {
    switch (cType) {
    case UIA_ButtonControlTypeId: return "Button";
    case UIA_EditControlTypeId: return "Edit";
    case UIA_WindowControlTypeId: return "Window";
    case UIA_ListControlTypeId: return "List";
    case UIA_ListItemControlTypeId: return "ListItem";
    case UIA_CheckBoxControlTypeId: return "CheckBox";
    case UIA_ComboBoxControlTypeId: return "ComboBox";
    case UIA_DocumentControlTypeId: return "Document";
    case UIA_TextControlTypeId: return "Text";
    case UIA_HyperlinkControlTypeId: return "Hyperlink";
    case UIA_MenuItemControlTypeId: return "MenuItem";
    case UIA_MenuControlTypeId: return "Menu";
    case UIA_MenuBarControlTypeId: return "MenuBar";
    case UIA_TabControlTypeId: return "Tab";
    case UIA_TabItemControlTypeId: return "TabItem";
    case UIA_TreeControlTypeId: return "Tree";
    case UIA_TreeItemControlTypeId: return "TreeItem";
    case UIA_ToolBarControlTypeId: return "ToolBar";
    case UIA_RadioButtonControlTypeId: return "RadioButton";
    case UIA_ScrollBarControlTypeId: return "ScrollBar";
    case UIA_SliderControlTypeId: return "Slider";
    case UIA_ProgressBarControlTypeId: return "ProgressBar";
    case UIA_GroupControlTypeId: return "Group";
    case UIA_PaneControlTypeId: return "Pane";
    case UIA_DataGridControlTypeId: return "DataGrid";
    case UIA_DataItemControlTypeId: return "DataItem";
    case UIA_StatusBarControlTypeId: return "StatusBar";
    case UIA_HeaderControlTypeId: return "Header";
    case UIA_SplitButtonControlTypeId: return "SplitButton";
    case UIA_SpinnerControlTypeId: return "Spinner";
    case UIA_ImageControlTypeId: return "Image";
    case UIA_TitleBarControlTypeId: return "TitleBar";
    default: return "Other";
    }
}

void BuildAgentTree(IUIAutomation* pAutomation, IUIAutomationElement* pElement, AgentElement& node, int depth = 0) {
    if (!pElement) return;
    g_agentTreeElementCount++;

    BSTR bName = NULL, bId = NULL, bValue = NULL;
    CONTROLTYPEID cType = 0;
    pElement->get_CurrentName(&bName);
    pElement->get_CurrentControlType(&cType);
    pElement->get_CurrentAutomationId(&bId);

    node.name = BstrToStdString(bName);
    node.automationId = BstrToStdString(bId);
    node.controlType = ControlTypeIdToString(cType);

    RECT r;
    pElement->get_CurrentBoundingRectangle(&r);
    node.x = r.left; node.y = r.top; node.w = r.right - r.left; node.h = r.bottom - r.top;

    // Check Patterns (expanded set)
    IUnknown* pPattern = NULL;
    if (SUCCEEDED(pElement->GetCurrentPattern(UIA_InvokePatternId, &pPattern)) && pPattern) {
        node.patterns.push_back("Invoke"); pPattern->Release();
    }
    if (SUCCEEDED(pElement->GetCurrentPattern(UIA_ValuePatternId, &pPattern)) && pPattern) {
        node.patterns.push_back("Value");
        IUIAutomationValuePattern* pVal = NULL;
        pElement->QueryInterface(__uuidof(IUIAutomationValuePattern), (void**)&pVal);
        if (pVal) {
            pVal->get_CurrentValue(&bValue);
            node.value = BstrToStdString(bValue);
            pVal->Release();
            SysFreeString(bValue);
        }
        pPattern->Release();
    }
    if (SUCCEEDED(pElement->GetCurrentPattern(UIA_TogglePatternId, &pPattern)) && pPattern) {
        node.patterns.push_back("Toggle"); pPattern->Release();
    }
    if (SUCCEEDED(pElement->GetCurrentPattern(UIA_SelectionItemPatternId, &pPattern)) && pPattern) {
        node.patterns.push_back("SelectionItem"); pPattern->Release();
    }
    if (SUCCEEDED(pElement->GetCurrentPattern(UIA_ExpandCollapsePatternId, &pPattern)) && pPattern) {
        node.patterns.push_back("ExpandCollapse"); pPattern->Release();
    }
    if (SUCCEEDED(pElement->GetCurrentPattern(UIA_ScrollPatternId, &pPattern)) && pPattern) {
        node.patterns.push_back("Scroll"); pPattern->Release();
    }

    // LabeledBy
    IUIAutomationElement* pLabel = NULL;
    if (SUCCEEDED(pElement->get_CurrentLabeledBy(&pLabel)) && pLabel) {
        BSTR bLabelName;
        if (SUCCEEDED(pLabel->get_CurrentName(&bLabelName))) {
            node.labeledBy = BstrToStdString(bLabelName);
            SysFreeString(bLabelName);
        }
        pLabel->Release();
    }

    SysFreeString(bName);
    SysFreeString(bId);

    // Recurse children
    {
        IUIAutomationTreeWalker* pWalker = NULL;
        pAutomation->get_ControlViewWalker(&pWalker);
        if (pWalker) {
            IUIAutomationElement* pChild = NULL;
            pWalker->GetFirstChildElement(pElement, &pChild);
            while (pChild) {
                AgentElement childNode;
                BuildAgentTree(pAutomation, pChild, childNode, depth + 1);
                node.children.push_back(childNode);

                IUIAutomationElement* pNext = NULL;
                pWalker->GetNextSiblingElement(pChild, &pNext);
                pChild->Release();
                pChild = pNext;
            }
            pWalker->Release();
        }
    }
}

// Convert Tree to JSON (Manual string building to avoid heavy dependencies if possible, but we have json lib)
void SerializeAgentTree(const AgentElement& node, json& j) {
    j["name"] = node.name;
    j["controlType"] = node.controlType;
    if (!node.automationId.empty()) j["automationId"] = node.automationId;
    if (!node.value.empty()) j["value"] = node.value;
    if (!node.labeledBy.empty()) j["labeledBy"] = node.labeledBy;
    j["bounds"] = { {"x", node.x}, {"y", node.y}, {"w", node.w}, {"h", node.h} };
    if (!node.patterns.empty()) j["patterns"] = node.patterns;

    if (!node.children.empty()) {
        j["children"] = json::array();
        for (const auto& child : node.children) {
            json c;
            SerializeAgentTree(child, c);
            j["children"].push_back(c);
        }
    }
}

// Compact JSON for Planner (Only Actionable)
void SerializeCompactTree(const AgentElement& node, json& j, bool& isActionable) {
    bool hasActionableChild = false;
    json children = json::array();

    for (const auto& child : node.children) {
        json c;
        bool childActionable = false;
        SerializeCompactTree(child, c, childActionable);
        if (childActionable) {
            children.push_back(c);
            hasActionableChild = true;
        }
    }

    bool localActionable = !node.patterns.empty() || node.controlType == "Edit" || node.controlType == "Document";

    isActionable = localActionable || hasActionableChild;

    if (isActionable) {
        j["name"] = node.name;
        j["controlType"] = node.controlType;
        if (!node.automationId.empty()) j["automationId"] = node.automationId;
        if (!node.labeledBy.empty()) j["labeledBy"] = node.labeledBy;
        j["bounds"] = { {"x", node.x}, {"y", node.y}, {"w", node.w}, {"h", node.h} };
        if (!node.patterns.empty()) j["patterns"] = node.patterns;
        if (!children.empty()) j["children"] = children;
    }
}

// Helper struct for enumerating all windows of a process
struct PidWindowEnum {
    DWORD pid;
    std::vector<HWND> windows;
};

BOOL CALLBACK EnumWindowsForPidProc(HWND hwnd, LPARAM lParam) {
    PidWindowEnum* data = (PidWindowEnum*)lParam;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == data->pid && IsWindowVisible(hwnd) && GetWindowTextLength(hwnd) > 0) {
        data->windows.push_back(hwnd);
    }
    return TRUE;
}

std::string GetUiTreeSnapshot(HWND hwnd) {
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    IUIAutomation* pAutomation = NULL;
    CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&pAutomation);

    if (!pAutomation) return "{}";

    // Get PID from the target window and find ALL windows for this process
    DWORD targetPid = 0;
    GetWindowThreadProcessId(hwnd, &targetPid);

    PidWindowEnum enumData;
    enumData.pid = targetPid;
    EnumWindows(EnumWindowsForPidProc, (LPARAM)&enumData);

    // If no windows found, fall back to just the provided hwnd
    if (enumData.windows.empty()) {
        enumData.windows.push_back(hwnd);
    }

    // Build combined tree from ALL process windows (root of exe)
    AgentElement processRoot;
    processRoot.name = "ProcessRoot";
    processRoot.controlType = "Process";
    g_agentTreeElementCount = 0;

    for (HWND wnd : enumData.windows) {
        IUIAutomationElement* pTarget = NULL;
        pAutomation->ElementFromHandle(wnd, &pTarget);
        if (pTarget) {
            AgentElement windowNode;
            BuildAgentTree(pAutomation, pTarget, windowNode);
            processRoot.children.push_back(windowNode);
            pTarget->Release();
        }
    }

    json j;
    // If only one window, serialize it directly (cleaner output)
    if (processRoot.children.size() == 1) {
        SerializeAgentTree(processRoot.children[0], j);
    }
    else {
        SerializeAgentTree(processRoot, j);
    }

    pAutomation->Release();
    CoUninitialize();

    return j.dump(2);
}

// =========================================================
// UI DIFF: Compare two UI snapshots and produce readable diff
// =========================================================

void CollectElementNames(const json& tree, std::vector<std::string>& names, const std::string& prefix = "") {
    if (!tree.is_object()) return;
    std::string name = tree.value("name", "");
    std::string type = tree.value("controlType", "");
    std::string val = tree.value("value", "");
    std::string entry = type + ":" + name;
    if (!val.empty()) entry += "=" + val;
    if (!name.empty() || !val.empty()) names.push_back(entry);
    if (tree.contains("children") && tree["children"].is_array()) {
        for (const auto& child : tree["children"]) {
            CollectElementNames(child, names, prefix + "  ");
        }
    }
}

std::string ComputeUiDiff(const std::string& oldJson, const std::string& newJson) {
    if (oldJson.empty() || oldJson == "{}") return "(first snapshot, no diff)";

    try {
        auto oldTree = json::parse(oldJson);
        auto newTree = json::parse(newJson);

        std::vector<std::string> oldNames, newNames;
        CollectElementNames(oldTree, oldNames);
        CollectElementNames(newTree, newNames);

        // Find added and removed
        std::set<std::string> oldSet(oldNames.begin(), oldNames.end());
        std::set<std::string> newSet(newNames.begin(), newNames.end());

        std::stringstream ss;
        bool hasDiff = false;

        // Added elements
        for (const auto& n : newSet) {
            if (oldSet.find(n) == oldSet.end()) {
                ss << "ADDED: " << n << "\n";
                hasDiff = true;
            }
        }
        // Removed elements
        for (const auto& n : oldSet) {
            if (newSet.find(n) == newSet.end()) {
                ss << "REMOVED: " << n << "\n";
                hasDiff = true;
            }
        }

        if (!hasDiff) return "(no changes detected)";
        return ss.str();
    }
    catch (...) {
        return "(diff failed)";
    }
}



// =========================================================
// AGENT CORE: PLANNER & EXECUTOR
// =========================================================

struct AgentAction {
    std::string action; // "click", "type", "press_key"
    std::string value;
    json locator;
};

struct AgentStepLog {
    int step;
    std::string goal;
    std::string reasoning;  // Planner's explanation
    std::string error;
    json plan;
    std::string rawPlannerResponse; // Raw text from model (truncated)
    bool success;
    float confidence = 1.0f;
};

class AgentCore {
public:
    bool isRunning = false;
    bool isPaused = false;
    std::string currentGoal;
    std::string currentSubGoal;   // Refined goal from planner (what's left to do)
    std::vector<AgentStepLog> executionLog;
    std::string statusMessage = "Idle";
    int maxSteps = 1500;

    void Start(const std::string& goal) {
        if (isRunning) return;
        currentGoal = goal;
        currentSubGoal = "";
        isRunning = true;
        g_agentExecuting = true;
        isPaused = false;
        executionLog.clear();

        std::thread([this]() {
            RunLoop();
            }).detach();
    }

    void Stop() {
        isRunning = false;
        g_agentExecuting = false;
        statusMessage = "Stopped by user.";
    }

    void Pause() { isPaused = true; statusMessage = "Paused by user."; }
    void Resume() { isPaused = false; statusMessage = "Resumed."; }

private:
    void RunLoop() {
        // UI Settle Wait
        Sleep(1000);

        std::vector<json> actionHistory;
        std::string executionError = "";


        DWORD lastDesktopInactiveNotify = 0;

        for (int step = 1; step <= maxSteps && isRunning; step++) {
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                statusMessage = "Step " + std::to_string(step) + ": Analysing...";
            }

            // SAFETY: Check if we are on the active desktop. If not, pause agent to prevent UIA hangs/deadlocks.
            if (!IsInputDesktopActive()) {
                {
                    std::lock_guard<std::mutex> lock(g_dataMutex);
                    statusMessage = "Desktop Inactive (Paused)...";
                }
                // This commonly happens when a UAC consent prompt is on the secure desktop.
                // Avoid spamming the chat / burning steps while the user needs to approve it.
                if (g_telegramEnabled && g_telegramPolling) {
                    DWORD now = GetTickCount();
                    if (lastDesktopInactiveNotify == 0 || (now - lastDesktopInactiveNotify) > 8000) {
                        lastDesktopInactiveNotify = now;
                        TelegramBridge::SendMessage("[PAUSED] Desktop switched (often UAC prompt). Approve/close the prompt, then I'll resume automatically.");
                    }
                }
                Sleep(500);
                continue;
            }

            // --- TELEGRAM: Report step progress (only when desktop is active) ---
            if (g_telegramEnabled && g_telegramPolling) {
                TelegramBridge::SendMessage("[Step " + std::to_string(step) + "] Analysing UI...");
            }

            // 1. Snapshot - with browser window recovery
            if (g_targetWindow && !IsWindow(g_targetWindow)) {
                // Try to re-find a window from the same process (browsers recreate HWNDs)
                DWORD savedPid = 0;
                GetWindowThreadProcessId(g_targetWindow, &savedPid);
                HWND recovered = NULL;
                if (savedPid != 0) {
                    PidWindowEnum recovery;
                    recovery.pid = savedPid;
                    EnumWindows(EnumWindowsForPidProc, (LPARAM)&recovery);
                    if (!recovery.windows.empty()) {
                        recovered = recovery.windows[0];
                    }
                }
                if (recovered) {
                    g_targetWindow = recovered;
                    std::lock_guard<std::mutex> lock(g_dataMutex);
                    statusMessage = "Window recovered. Continuing...";
                }
                else {
                    g_targetWindow = NULL;

                    // AUTO-ATTACH ATTEMPT (Cold Start Fix)
                    HWND hFg = GetForegroundWindow();
                    if (hFg && hFg != g_hwnd && hFg != GetShellWindow()) {
                        DWORD pid = 0; GetWindowThreadProcessId(hFg, &pid);
                        DWORD myPid = GetCurrentProcessId();
                        if (pid != myPid) {
                            g_targetWindow = hFg;
                            std::lock_guard<std::mutex> lock(g_dataMutex);
                            statusMessage = "Auto-Attached to active window.";
                            // Optional: Get name for logging
                            char pname[MAX_PATH] = "<unknown>";
                            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                            if (hProc) {
                                HMODULE hMod; DWORD cbNeeded;
                                if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded))
                                    GetModuleBaseNameA(hProc, hMod, pname, sizeof(pname));
                                CloseHandle(hProc);
                            }
                            g_targetProcessName = pname;
                        }
                    }

                    if (!g_targetWindow) {
                        std::lock_guard<std::mutex> lock(g_dataMutex);
                        statusMessage = "No target window. Waiting for Planner command...";
                    }
                }
            }

            // Bring to front (Only if we have a window)
            if (g_targetWindow && IsWindow(g_targetWindow)) {
                if (IsIconic(g_targetWindow)) ShowWindow(g_targetWindow, SW_RESTORE);
                SetForegroundWindow(g_targetWindow);
                Sleep(500); // Wait for focus
            }

            // Scan UI 3 times (Only if we have a window)
            std::string uiJson = "{}";
            if (g_targetWindow && IsWindow(g_targetWindow)) {
                for (int scanPass = 0; scanPass < 3; scanPass++) {
                    {
                        std::lock_guard<std::mutex> lock(g_dataMutex);
                        statusMessage = "Step " + std::to_string(step) + ": Analysing (" + std::to_string(scanPass + 1) + "/3)...";
                    }
                    Sleep(1000); // Wait 1s between scans for UI to settle
                    uiJson = GetUiTreeSnapshot(g_targetWindow); // Full tree
                }
            }
            else {
                // Cold start / No window
                uiJson = "{\"root\": {\"name\": \"No Process Attached\", \"controlType\": \"Pane\", \"children\": []}}";
            }

            // Send one "start" screenshot to Telegram at the beginning of a run.
            // The agent may still capture additional screenshots for its own context.
            if (step == 1 && !g_sentStartScreenshot) {
                g_sentStartScreenshot = true;
                std::string shotRes = MemoryCaptureAndStoreScreenshot(true);
                MemoryInsertChunk(shotRes, "agent_result", std::to_string(step), "", 0, "{}");
            }

            // Automatic memory retrieval (RAG hint) for the current goal
            // This makes the agent "free" to use memory without needing an explicit user instruction.
            {
                std::string q = currentSubGoal.empty() ? currentGoal : currentSubGoal;
                std::string qLower = ToLowerCopy(q);
                std::string hint;
                if (IsMemoryQueryGoal(qLower)) hint = MemoryRecentActions(60);
                else hint = MemorySearch(q);
                if (hint.size() > 3500) hint.resize(3500);
                {
                    std::lock_guard<std::mutex> lock(g_dataMutex);
                    g_autoMemoryHint = hint;
                }
            }

            // Check for pause
            while (isPaused && isRunning) {
                Sleep(100);
            }
            if (!isRunning) break;

            // 2. Plan
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                statusMessage = "Step " + std::to_string(step) + ": Planning...";
            }
            std::string prompt = BuildPrompt(uiJson, actionHistory, executionError);

            // Call Planner API
            bool includePlannerImages = !executionError.empty();
            std::string planJsonStrRaw = CallPlannerApi(prompt, includePlannerImages);
            std::string planJsonStr = ExtractLikelyJson(planJsonStrRaw);
            if (planJsonStr != planJsonStrRaw) {
                // Keep raw response for debugging in memory
                MemoryInsertChunk(planJsonStrRaw, "planner_raw", std::to_string(step), "", 0, "{}");
            }

            AgentStepLog logEntry;
            logEntry.step = step;
            logEntry.goal = currentSubGoal.empty() ? currentGoal : currentSubGoal;

            // Store raw response for UI/debug (truncate to avoid huge memory)
            logEntry.rawPlannerResponse = planJsonStrRaw;
            if (logEntry.rawPlannerResponse.size() > 12000) logEntry.rawPlannerResponse.resize(12000);

            // Try parse plan for logging
            try {
                logEntry.plan = json::parse(planJsonStr);
            }
            catch (...) {
                logEntry.plan = planJsonStr; // Store raw string if parse fails
            }

            // 3. Parse structured response
            // New format: {"reasoning":"...", "next_goal":"...", "is_done":bool, "actions":[...]}
            // Also supports old format: [{"action":"...", ...}]
            bool goalDone = false;
            std::string plannerReasoning = "";
            float plannerConfidence = 1.0f;
            std::vector<AgentAction> actions;

            try {
                auto parsed = json::parse(planJsonStr);

                if (parsed.is_object()) {
                    // New structured format
                    if (parsed.contains("is_done") && parsed["is_done"].is_boolean() && parsed["is_done"].get<bool>()) {
                        goalDone = true;
                    }
                    if (parsed.contains("next_goal") && parsed["next_goal"].is_string()) {
                        currentSubGoal = parsed["next_goal"].get<std::string>();
                    }
                    if (parsed.contains("reasoning") && parsed["reasoning"].is_string()) {
                        plannerReasoning = parsed["reasoning"].get<std::string>();
                    }
                    if (parsed.contains("confidence") && parsed["confidence"].is_number()) {
                        plannerConfidence = parsed["confidence"].get<float>();
                    }
                    // Extract actions from the "actions" field
                    if (parsed.contains("actions") && parsed["actions"].is_array()) {
                        actions = ParsePlan(parsed["actions"].dump());
                    }
                }
                else if (parsed.is_array()) {
                    // Old format: raw action array
                    actions = ParsePlan(planJsonStr);
                }
            }
            catch (...) {
                // Try as raw action array as last resort
                actions = ParsePlan(planJsonStr);
            }

            // Apply parsed values to log entry
            logEntry.reasoning = plannerReasoning;
            logEntry.confidence = plannerConfidence;

            // --- TELEGRAM: Report planner reasoning ---
            if (g_telegramEnabled && g_telegramPolling && !plannerReasoning.empty()) {
                TelegramBridge::SendMessage("[PLANNER] " + plannerReasoning);
            }

            // Check if planner says we're done
            if (goalDone) {
                // Send one final screenshot to Telegram at completion.
                {
                    std::string shotRes = MemoryCaptureAndStoreScreenshot(true);
                    MemoryInsertChunk(shotRes, "agent_result", std::to_string(step), "", 0, "{}");
                }
                std::lock_guard<std::mutex> lock(g_dataMutex);
                statusMessage = "Goal Achieved!";
                logEntry.success = true;
                logEntry.error = "Goal completed. Reasoning: " + plannerReasoning;
                executionLog.push_back(logEntry);
                isRunning = false;
                // --- TELEGRAM: Report completion ---
                if (g_telegramEnabled && g_telegramPolling) {
                    TelegramBridge::SendMessage("[DONE] Goal Achieved! " + plannerReasoning);
                }
                break;
            }

            static int s_noActionStreak = 0;
            if (actions.empty() && !goalDone) {
                s_noActionStreak++;

                // Capture a screenshot for diagnosis (only once per streak to avoid hangs/spam)
                std::string shotRes = "";
                if (s_noActionStreak == 1) {
                    shotRes = MemoryCaptureAndStoreScreenshot(true);
                    MemoryInsertChunk(shotRes, "agent_result", std::to_string(step), "", 0, "{}");
                }

                executionError = "Planner returned no actions (streak=" + std::to_string(s_noActionStreak) + "). "
                    "Reasoning: " + plannerReasoning + (shotRes.empty() ? "" : (" | " + shotRes));

                // Log this as a visible step entry so the GUI shows the error immediately.
                logEntry.success = false;
                logEntry.error = executionError;
                {
                    std::lock_guard<std::mutex> lock(g_dataMutex);
                    executionLog.push_back(logEntry);
                }

                // Persist raw planner response to memory for debugging
                MemoryInsertChunk(planJsonStrRaw, "planner_no_actions_raw", std::to_string(step), "", 0, "{}");

                // Ask the planner again instead of stopping, but don't loop forever
                if (s_noActionStreak >= 3) {
                    std::lock_guard<std::mutex> lock(g_dataMutex);
                    statusMessage = "Planner returned no actions repeatedly. Showing last error above.";
                    logEntry.success = false;
                    logEntry.error = executionError;
                    executionLog.push_back(logEntry);
                    isRunning = false;
                    if (g_telegramEnabled && g_telegramPolling) {
                        TelegramBridge::SendMessage("[FAILED] Planner returned no actions repeatedly. Check model/prompt.");
                    }
                    break;
                }

                continue;
            }
            if (!actions.empty()) s_noActionStreak = 0;

            // 4. Execute
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                statusMessage = "Step " + std::to_string(step) + ": Executing " + actions[0].action + "...";
            }
            bool success = true;
            for (const auto& action : actions) {
                // --- TELEGRAM: Report each action ---
                if (g_telegramEnabled && g_telegramPolling) {
                    std::string actionMsg = "[EXEC] " + action.action;
                    if (!action.value.empty()) actionMsg += " '" + action.value + "'";
                    TelegramBridge::SendMessage(actionMsg);
                }
                if (!ExecuteAction(action)) {
                    success = false;
                    executionError = "Action failed: " + action.action + (action.locator.is_object() && !action.locator.empty() ? " on " + action.locator.dump() : "");
                    // --- TELEGRAM: Report failure ---
                    if (g_telegramEnabled && g_telegramPolling) {
                        TelegramBridge::SendMessage("[FAILED] " + action.action);
                    }

                    // Capture screenshot on failure for UI actions only.
                    // For coding/system tools (run_cmd/fs_*/memory_*), a screenshot is usually noise.
                    if (!IsNonDestructiveQueryAction(action.action)) {
                        std::string shotRes = MemoryCaptureAndStoreScreenshot(true);
                        {
                            std::lock_guard<std::mutex> lock(g_dataMutex);
                            if (!g_lastActionResult.empty()) g_lastActionResult += "\n";
                            g_lastActionResult += "AUTO VERIFY (failure): " + shotRes;
                        }
                        MemoryInsertChunk(shotRes, "agent_result", std::to_string(step), "", 0, "{}");
                    }
                    break;
                }

                // Automatic self-verification screenshot for UI-changing actions.
                // Avoid requiring the user to explicitly request it.
                {
                    DWORD now = GetTickCount();
                    if (!IsNonDestructiveQueryAction(action.action) && action.action != "capture_screenshot") {
                        if (g_lastAutoVerifyTick == 0 || (now - g_lastAutoVerifyTick) > g_autoVerifyIntervalMs) {
                            g_lastAutoVerifyTick = now;
                            // Capture for LLM context, but do not spam Telegram.
                            MemoryCaptureAndStoreScreenshot(false);
                        }
                    }
                }

                // Persist latest tool/action result to memory (so recall works across chats)
                {
                    std::string res;
                    {
                        std::lock_guard<std::mutex> lock(g_dataMutex);
                        res = g_lastActionResult;
                    }
                    if (!res.empty()) {
                        if (res.size() > 6000) res.resize(6000);
                        MemoryInsertChunk(res, "agent_result", std::to_string(step), "", 0, "{}");
                    }
                }
                Sleep(1500); // 1.5s delay between every action (click, type, key)
            }

            logEntry.success = success;
            if (success) {
                executionError = "";
                // Log ALL executed actions, not just the first one
                for (const auto& action : actions) {
                    json acc;
                    acc["action"] = action.action;
                    acc["locator"] = action.locator;
                    acc["value"] = action.value;
                    if (!plannerReasoning.empty()) acc["reasoning"] = plannerReasoning;
                    actionHistory.push_back(acc);

                    // Persist to local memory for later retrieval
                    {
                        std::stringstream ss;
                        ss << "STEP " << step << " | " << action.action;
                        if (!action.value.empty()) ss << " value='" << action.value << "'";
                        if (action.locator.is_object() && !action.locator.empty()) ss << " locator=" << action.locator.dump();
                        if (!plannerReasoning.empty()) ss << " | reasoning: " << plannerReasoning;
                        MemoryInsertChunk(ss.str(), "agent_action", std::to_string(step), "", 0, "{}");
                    }
                }
            }
            else {
                logEntry.error = executionError;
                // Persist error to memory
                if (!executionError.empty()) {
                    MemoryInsertChunk(executionError, "agent_error", std::to_string(step), "", 0, "{}");
                }
            }

            // Log to UI safely
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                executionLog.push_back(logEntry);
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            if (isRunning) statusMessage = "Finished.";
            isRunning = false;
            g_agentExecuting = false;
        }
    }

    std::string BuildPrompt(const std::string& uiJson, const std::vector<json>& history, const std::string& error) {
        std::stringstream ss;
        ss << "ORIGINAL USER GOAL: " << currentGoal << "\n\n";

        // Workspace hint (for coding/build tasks)
        ss << "WORKSPACE CWD: " << ws2s(GetCwdW()) << "\n\n";
        ss << "DESKTOP DIR: " << ws2s(GetDesktopDirW()) << "\n\n";
        ss << "CODING DEFAULT BASE: " << ws2s(GetCodingBaseW()) << "\n\n";
        ss << "ELEVATED: " << (IsProcessElevated() ? "true" : "false") << "\n\n";

        // MCP context (connected servers + cached tools)
        ss << McpStateForPrompt() << "\n";

        // Auto RAG / memory hint
        if (!g_autoMemoryHint.empty()) {
            ss << "MEMORY (auto-retrieved, may be relevant):\n" << g_autoMemoryHint << "\n\n";
        }

        // If the planner gave us a refined sub-goal, use it
        if (!currentSubGoal.empty() && currentSubGoal != currentGoal) {
            ss << "REMAINING GOAL (focus on this, the above steps are done): " << currentSubGoal << "\n\n";
        }

        // --- PROCESS AWARENESS: Show available processes ---

        {
            RefreshProcessList();
            ss << "AVAILABLE PROCESSES (open windows on this machine):\n";
            for (size_t i = 0; i < g_processList.size(); i++) {
                ss << "  " << (i + 1) << ". " << g_processList[i].processName << " - \"" << g_processList[i].title << "\"";
                if (g_processList[i].hwnd == g_targetWindow) ss << " [ATTACHED ✓]";
                ss << "\n";
            }
            if (g_targetWindow && IsWindow(g_targetWindow)) {
                char tBuf[256] = {};
                GetWindowTextA(g_targetWindow, tBuf, sizeof(tBuf));
                ss << "\nCURRENTLY ATTACHED TO: \"" << tBuf << "\"\n\n";
            }
            else {
                ss << "\nNO PROCESS ATTACHED. For UI tasks use open_app/attach_process; for coding/build/lint/test tasks you may use fs_* and run_cmd without attaching.\n\n";
            }
        }


        // Inject result from tools (like list_processes)
        if (!g_lastActionResult.empty()) {
            ss << "LAST ACTION RESULT:\n" << g_lastActionResult << "\n\n";
            g_lastActionResult = ""; // Clear after consuming
        }

        if (g_targetWindow && IsWindow(g_targetWindow)) {
            char tBuf[256] = {};
            GetWindowTextA(g_targetWindow, tBuf, sizeof(tBuf));
            ss << "CURRENTLY ATTACHED TO: \"" << tBuf << "\"\n\n";
        }
        else {
            ss << "NO PROCESS ATTACHED. (UI tasks: open_app/attach_process. Coding tasks: fs_* + run_cmd are allowed.)\n\n";

            // Smart Context: Inject process list to help agent decide
            RefreshProcessList();
            ss << "AVAILABLE WINDOWS (Use 'attach_process' to select one):\n";
            for (size_t i = 0; i < g_processList.size(); i++) {
                ss << "  " << (i + 1) << ". " << g_processList[i].processName << " - \"" << g_processList[i].title << "\"\n";
            }
            if (g_processList.empty()) ss << "  (No visible windows found)\n";
            ss << "\n";
        }

        // Show completed actions clearly
        if (!history.empty()) {
            ss << "COMPLETED ACTIONS (these are ALREADY DONE - DO NOT repeat them):\n";
            for (size_t i = 0; i < history.size(); i++) {
                ss << "  Step " << (i + 1) << ": ";
                std::string act = history[i].value("action", "?");
                std::string val = history[i].value("value", "");
                std::string reasoning = history[i].value("reasoning", "");
                ss << act;
                if (!val.empty()) ss << " \"" << val << "\"";
                if (history[i].contains("locator")) ss << " on " << history[i]["locator"].dump();
                if (!reasoning.empty()) ss << " (" << reasoning << ")";
                ss << " [DONE]\n";
            }
            ss << "\n";
        }

        // Show errors from last attempt
        if (!error.empty()) {
            ss << "LAST ERROR (you must work around this): " << error << "\n\n";
        }

        ss << "CURRENT UI STATE (live snapshot of the application right now):\n" << uiJson << "\n\n";

        ss << "Respond with a JSON object: {\"reasoning\": \"why you chose this action\", \"confidence\": 0.9, \"next_goal\": \"what remains to be done after this step\", \"is_done\": false, \"actions\": [{\"action\":\"click\",\"locator\":{\"name\":\"...\"}}, ...]}\n";
        ss << "If the goal is fully completed based on the current UI, respond: {\"reasoning\": \"...\", \"confidence\": 1.0, \"next_goal\": \"\", \"is_done\": true, \"actions\": []}";
        return ss.str();
    }

    std::string CallPlannerApi(const std::string& prompt, bool includeImages) {
        // Reuse Api::HttpRequest logic but stripped down for custom prompt

        if (g_providers.empty() || g_currProviderIdx >= g_providers.size()) return "[]";
        auto& prov = g_providers[g_currProviderIdx];

        std::string apiKey = "";
        std::string modelID = "gemini-2.0-flash-exp"; // Default fallback

        if (!prov.models.empty()) {
            if (g_currModelIdx >= prov.models.size()) g_currModelIdx = 0;
            modelID = prov.models[g_currModelIdx].id;
        }

        if (prov.type == AIProvider::Gemini) apiKey = g_apiKeys.gemini;
        else if (prov.type == AIProvider::OpenAI) apiKey = g_apiKeys.openai;
        else if (prov.type == AIProvider::Anthropic) apiKey = g_apiKeys.claude;
        else if (prov.type == AIProvider::Moonshot) apiKey = g_apiKeys.kimi;
        else if (prov.type == AIProvider::OpenRouter) apiKey = g_apiKeys.openrouter;
        else if (prov.type == AIProvider::DeepSeek) apiKey = g_apiKeys.deepseek;

        if (prov.type != AIProvider::Ollama && apiKey.empty()) return "[]";

        // Screenshots can be sent to the planner for diagnosis, but this increases request size.
        // We only include them when needed (e.g. after failures) and we only send the latest one.
        std::string plannerImageB64;
        if (includeImages) {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            for (auto it = g_screenshots.rbegin(); it != g_screenshots.rend(); ++it) {
                if (!it->base64Data.empty()) { plannerImageB64 = it->base64Data; break; }
            }
            // Avoid huge payloads; ~1.6MB base64 ~= ~1.2MB jpeg
            const size_t kMaxB64 = 1600000;
            if (plannerImageB64.size() > kMaxB64) plannerImageB64.clear();
        }

        std::string finalResp = "[]";
        std::string rawResOrError = ""; // Store for debugging

        // System Prompt for Agent
        std::string sysTxt =
            "You are an AI Agent controlling a Windows desktop application via UI Automation. "
            "You receive the current UI element tree (JSON), UI diff, and a user goal with action history.\n\n"
            "CRITICAL RULES:\n"
            "1. Do NOT repeat actions marked as [DONE] unless they are safe query/verification actions (list_processes, list_installed_apps, list_launchable_apps, net_check, winget_search, winget_list, memory_*, capture_screenshot, run_cmd, fs_*, git_*, mcp_*).\n"
            "2. Only return the NEXT action(s) needed to make progress toward the goal.\n"
            "3. If the goal is already achieved (based on the current UI state), set is_done to true.\n"
            "4. Look at the CURRENT UI STATE to determine what has already happened.\n"
            "5. Check the UI CHANGES section to understand what your last action caused.\n"
            "6. Include a 'confidence' score from 0.0 to 1.0 indicating how sure you are.\n\n"
            "7. If is_done is false, you MUST return at least one action. Never return an empty actions array unless is_done=true.\n\n"

            "CODE ENTRY (IMPORTANT):\n"
            "- Use 'type' for everything. If the value looks like code or is large, the runtime may paste using clipboard + Ctrl+V.\n\n"

            "TOOL USE (IMPORTANT):\n"
            "- If the goal asks for memory / history / recall, DO NOT answer in reasoning. Call memory_recent_actions or memory_search as an action.\n"
            "- After any UI-changing action (click/type/press_key/open_app/attach_process), you SHOULD verify the result. You may call capture_screenshot, and the runtime may also auto-capture.\n\n"
            "- You may call system/memory tools at ANY time if they help you (memory_*, list_*, winget_*, net_check, run_cmd, fs_*, mcp_*). Prefer tools over guessing.\n"
            "- For coding/build/lint/test tasks, prefer workspace tools (fs_* + run_cmd) over UI typing whenever possible.\n\n"

            "MULTI-LANGUAGE CODING (IMPORTANT):\n"
            "- You can create/edit files and run builds/tests for ANY language/toolchain (Node, Python, Go, Rust, Java, .NET, C/C++, etc.).\n"
            "- Use fs_glob/fs_list_dir to detect the project type (e.g. package.json, pyproject.toml, go.mod, Cargo.toml, pom.xml, *.sln, CMakeLists.txt).\n"
            "- Use run_cmd to reproduce failures (build/lint/test), then use fs_read + fs_replace_lines/fs_write to fix, then run_cmd again until clean.\n\n"
            "QUERY GOALS (HOW TO ANSWER):\n"
            "- Step 1: call a tool action to fetch data (e.g. memory_recent_actions).\n"
            "- Step 2: on the next turn, use LAST ACTION RESULT to answer in reasoning and set is_done=true with actions=[].\n\n"
            "SUPPORTED ACTIONS:\n"
            "- click: Click on a UI element. Locator: {\"name\": \"Button Text\", \"controlType\": \"Button\"}\n"
            "- right_click: Right-click to open context menu. Same locator format as click.\n"
            "- double_click: Double-click (e.g. open file, select word). Same locator format.\n"
            "- type: Type text into a field. Needs \"value\". For code/large multi-line text, runtime may paste using clipboard + Ctrl+V. Locator: {\"name\": \"Field\", \"controlType\": \"Edit\"}\n"
            "- press_key: Press keyboard key. \"value\": \"enter\"/\"tab\"/\"escape\"/\"backspace\"/\"ctrl+a\" etc.\n"
            "- scroll: Scroll up or down. \"value\": \"down\" or \"up\". Optionally provide a locator.\n"
            "- hover: Hover over element to reveal tooltip/dropdown. Provide locator.\n"
            "- wait_for: Wait for an element to appear. Provide locator of expected element.\n"
            "- switch_window: Switch target to another window. \"value\": partial window title.\n"
            "- clipboard: Clipboard ops. \"value\": \"copy\"/\"paste\"/\"cut\"/\"select_all\".\n"
            "- open_app: Open an application. \"value\": executable name (e.g. \"chrome.exe\", \"notepad.exe\", \"calc.exe\"). Will auto-attach to the new window.\n"
            "- attach_process: Attach to an already-open window. \"value\": partial window title from the process list.\n"
            "- list_processes: Get a list of all open application windows and their titles. Use this before attaching.\n\n"

            "SYSTEM / INVENTORY ACTIONS:\n"
            "- list_installed_apps: List installed applications (registry). Optional \"value\": filter substring.\n"
            "- list_launchable_apps: List launchable apps from Start Menu shortcuts. Optional \"value\": filter substring.\n"
            "- net_check: Check basic HTTPS connectivity.\n"
            "- http_request: Make a generic HTTPS API call. \"value\" is JSON: {method,url,headers,body,timeout_ms,max_bytes,content_type}. Returns status + body.\n"
            "- config_get: Read a saved API key. \"value\": key name.\n"
            "- config_set: Save an API key. \"value\" is JSON: {key,value}.\n"

            "WORKSPACE / CODING ACTIONS (NO UI REQUIRED):\n"
            "- run_cmd: Run a local command and capture output. \"value\" is JSON: {cmd,cwd,timeout_ms,max_bytes,shell,allow_nonzero}. Default shell=true runs via a fresh cmd.exe (/Q /D /S /C) each call; shell=false runs the executable directly.\n"
            "  Note: Some tools use non-zero exit codes for 'no matches' (e.g. ripgrep). Use allow_nonzero=true for those queries.\n"
            "- fs_mkdirs: Create directories recursively. \"value\" is JSON: {path,base}.\n"
            "- fs_list_dir: List a directory. \"value\" is JSON: {path,base,limit}.\n"
            "- fs_glob: Find files by glob pattern (supports **,*,?). \"value\" is JSON: {pattern,base,max_results}.\n"
            "- fs_read: Read a text file with line numbers. \"value\" is JSON: {path,base,start_line,line_count}.\n"
            "- fs_write: Create/overwrite a file. \"value\" is JSON: {path,base,content|content_b64,create_dirs,backup}. Prefer content_b64 for large/multi-line code.\n"
            "- fs_replace_lines: Replace a line range in a file (AI-IDE style). \"value\" is JSON: {path,base,start_line,end_line,new_text|new_text_b64,create_dirs,backup}.\n\n"

            "MCP (MODEL CONTEXT PROTOCOL) ACTIONS (NPX ONLY, NO UI REQUIRED):\n"
            "- google to find MCP serversfirst know how to install them and install them \n"
            "- mcp_npm_search:  search on the NPM registry. \"value\" is JSON: {query,limit}.\n"
            "- mcp_connect: Start an MCP server via npx -y and connect via stdio. \"value\" is JSON: {id,package,args,cwd,env,init_timeout_ms}. If connect fails, retry with args=[\"--stdio\"].\n"
            "- mcp_disconnect: Disconnect/kill an MCP server. \"value\": id or JSON {id}.\n"
            "- mcp_list_servers: List connected MCP servers.\n"
            "- mcp_tools_list: List tools from a server. \"value\" is JSON: {id}.\n"
            "- mcp_tool_call: Call a tool. \"value\" is JSON: {id,name,arguments,timeout_ms}.\n"
            "- mcp_resources_list: List resources. \"value\" is JSON: {id}.\n"
            "- mcp_resource_read: Read a resource URI. \"value\" is JSON: {id,uri,timeout_ms}.\n\n"

            "MCP WORKFLOW RULES (CRITICAL):\n"
            "- If mcp_registry_search returns no matches or fails, you MUST try mcp_npm_search.\n"
            "- If both searches fail, fall back to opening a browser and searching (Google/Bing) for an NPX MCP server package name, then connect with mcp_connect.\n"
            "- Before calling mcp_tool_call, you SHOULD call mcp_tools_list and follow the tool inputSchema required fields (do not guess arguments).\n\n"

            "PATH DEFAULTS (IMPORTANT):\n"
            "- For fs_* actions, if 'base' is omitted, the runtime resolves relative paths to the current WORKSPACE CWD when the file exists or when the parent directory exists.\n"
            "- Otherwise, new coding/projects are created under the Desktop folder 'OfradrAgentWorkspace'.\n\n"

            "JSON PATHS (IMPORTANT):\n"
            "- When providing paths in JSON, prefer relative paths or use forward slashes (/) to avoid backslash escaping issues.\n\n"
            "API KEY USAGE:\n"
            "- Before calling a API that requires a key, ALWAYS call config_get first.\n"
            "- If the key is missing but the user provided it in the goal text, call config_set then proceed.\n"
            "- If the key is missing and not provided, you MUST go find the api key from any browser you need to know where to go login andd billing do everything and find it after save it using config_set\n\n"
            "-  If the key is available use the http_reuqest with correct authorization and headers if necessary call it get the output and display to user\n"
            "- winget_search: Search packages using winget. \"value\": query.\n"
            "- winget_list: List installed winget packages. Optional \"value\": filter.\n"
            "- winget_install: Install a package via winget. \"value\": package id/name.\n"
            "- winget_upgrade: Upgrade a package via winget. Optional \"value\": package id/name (empty = all).\n\n"

            "LOCAL MEMORY / RAG ACTIONS:\n"
            "- memory_index_roots: Index common folders (Desktop/Documents/Downloads + repo) so you can find files without Explorer.\n"
            "- memory_find_paths: Search indexed file paths by name/path. Optional \"value\": query.\n"
            "- memory_ingest_file: Read a file and store its text into memory for later retrieval. \"value\": full path.\n"
            "- memory_search: Search memory (past actions/chat/file text/OCR). \"value\": query.\n"
            "- memory_recent_actions: Show recent actions/errors/results from memory. Optional \"value\": count (default 30).\n"
            "- memory_list_images: List recent stored screenshots with ids. Optional \"value\": count (default 20).\n"
            "- capture_screenshot: Capture a screenshot for self-verification, store it to memory, and (if Telegram is enabled) send it to the user.\n"
            "- memory_get_image: Re-send a stored screenshot by id to the user (Telegram). \"value\": image id.\n\n"
            "APP USAGE RULES (CRITICAL):\n"
            "1. IF NO PROCESS IS ATTACHED (see 'NO PROCESS ATTACHED' in prompt):\n"
            "   - If the goal requires UI interaction, call 'list_processes' first to see what is running.\n"
            "   - If the goal is coding/build/lint/test (workspace task), you may start with fs_* and/or run_cmd without attaching any window.\n"
            "   - DO NOT EXECUTE 'open_app' BLINDLY unless you have already checked the list.\n"
            "2. IF YOU WANT TO SWITCH APPS:\n"
            "   - FIRST call 'list_processes'.\n"
            "   - IF the app is found, use 'attach_process'.\n"
            "   - IF NOT found, ONLY THEN use 'open_app'.\n"
            "3. 'open_app' is expensive and slow. Always prefer 'attach_process' if possible.\n\n"

            "DEPENDENCY RULES (SYSTEM TOOLS):\n"
            "- If you need a tool/app and you're not sure it's installed: use 'list_installed_apps' or 'winget_list' first.\n"
            "- To find an installable package: use 'winget_search'.\n"
            "- To install/upgrade: use 'winget_install' / 'winget_upgrade', then re-check with 'winget_list'.\n\n"
            "CRITICAL SEQUENCE RULES:\n"
            "For UI text editing/replacement tasks, DO NOT output a chain of actions. DO ONE STEP AT A TIME.\n"
            "Example: If you need to replace text, do NOT send [Ctrl+A, Backspace, Type] in one response.\n"
            "INSTEAD:\n"
            "1. Send ONLY [Ctrl+A]. Wait for the next turn.\n"
            "2. In the next turn, send ONLY [Backspace].\n"
            "3. In the next turn, send ONLY [Type].\n"
            "This ensures stability. NEVER chain complex hotkeys.\n\n"
            "FOR CODING TASKS:\n"
            "Prefer workspace edits (fs_read/fs_replace_lines/fs_write) + run_cmd over UI typing for code changes.\n"
            "If you must edit inside a UI editor, then clear existing code first (Ctrl+A, Backspace, then type/paste).\n"
            "DO NOT APPEND TO EXISTING CODE unless explicitly asked.\n\n"
            "LOCATOR FORMAT: {\"name\": \"...\", \"controlType\": \"...\", \"automationId\": \"...\"}\n"
            "Use the most specific locator possible. Prefer automationId when available.\n"
            "Use controlType to disambiguate (Button, Edit, Document, ListItem, Hyperlink, etc).\n\n"
            "RESPONSE FORMAT (STRICT JSON, no markdown):\n"
            "{\n"
            "  \"reasoning\": \"Brief explanation of why this action is needed\",\n"
            "  \"confidence\": 0.9,\n"
            "  \"next_goal\": \"What remains to be done after this action\",\n"
            "  \"is_done\": false,\n"
            "  \"actions\": [{\"action\": \"click\", \"locator\": {\"name\": \"Search\"}}]\n"
            "}\n\n"
            "EXAMPLE - Multi-step task 'Open YouTube and search for cats':\n"
            "Step 1 (address bar visible): {\"reasoning\": \"Need to navigate to YouTube first\", \"confidence\": 0.95, \"next_goal\": \"Search for cats on YouTube\", \"is_done\": false, \"actions\": [{\"action\": \"click\", \"locator\": {\"name\": \"Address and search bar\", \"controlType\": \"Edit\"}}, {\"action\": \"type\", \"locator\": {\"name\": \"Address and search bar\"}, \"value\": \"youtube.com\"}, {\"action\": \"press_key\", \"value\": \"enter\"}]}\n"
            "Step 2 (YouTube loaded): {\"reasoning\": \"YouTube is open, now search\", \"confidence\": 0.9, \"next_goal\": \"Click on search results\", \"is_done\": false, \"actions\": [{\"action\": \"click\", \"locator\": {\"name\": \"Search\", \"controlType\": \"Edit\"}}, {\"action\": \"type\", \"locator\": {\"name\": \"Search\"}, \"value\": \"cats\"}, {\"action\": \"press_key\", \"value\": \"enter\"}]}\n"
            "Step 3 (goal done): {\"reasoning\": \"Search results are showing for cats\", \"confidence\": 1.0, \"next_goal\": \"\", \"is_done\": true, \"actions\": []}\n\n"
            "ERROR RECOVERY & SELF-CORRECTION:\n"
            "If a previous action failed or the UI shows an error (e.g. compilation error, build failure, syntax error):\n"
            "1. READ the error message carefully from the UI tree.\n"
            "2. To FIX or REPLACE code: first click the editor, then press_key 'ctrl+a' to Select All, then press_key 'backspace' to DELETE the old content, THEN use 'type' to enter the corrected code.\n"
            "   Example: [{\"action\": \"click\", \"locator\": {\"name\": \"Editor\", \"controlType\": \"Edit\"}}, "
            "{\"action\": \"press_key\", \"value\": \"ctrl+a\"}, "
            "{\"action\": \"press_key\", \"value\": \"backspace\"}, "
            "{\"action\": \"type\", \"locator\": {\"name\": \"Editor\"}, \"value\": \"corrected code here...\"}]\n"
            "3. If a click failed because the element wasn't found, try a different locator (name, automationId, or controlType).\n"
            "4. If typing didn't work, try clicking the field first, then ctrl+a, then backspace to clear, then type new text.\n"
            "5. Always check the LAST ERROR in the prompt - it tells you what went wrong. Adapt your approach.\n"
            "6. If the user asked you to complete/fix code and there's a build error visible, you MUST fix it before marking done.\n"
            "7. Don't give up after one failure - try alternative approaches (different element, different action sequence).\n\n"
            "RETURN ONLY RAW JSON. NO MARKDOWN. NO COMMENTS. NO EXTRA TEXT.";

        if (prov.type == AIProvider::Gemini) {
            json reqBody;
            reqBody["system_instruction"] = { {"parts", { {{"text", sysTxt}} }} };
            json cur;
            cur["role"] = "user";
            cur["parts"] = json::array();
            cur["parts"].push_back({ {"text", prompt} });
            if (!plannerImageB64.empty()) {
                cur["parts"].push_back({ {"inline_data", { {"mime_type", "image/jpeg"}, {"data", plannerImageB64} } } });
            }
            reqBody["contents"] = json::array();
            reqBody["contents"].push_back(cur);

            std::wstring path = L"/v1beta/models/" + s2ws(modelID) + L":generateContent?key=" + s2ws(apiKey);
            std::string res = Api::HttpRequest(L"generativelanguage.googleapis.com", path, "POST", reqBody.dump(), std::vector<std::wstring>{});
            rawResOrError = res;

            try {
                auto j = json::parse(res);
                if (j.contains("candidates") && j["candidates"].is_array() && !j["candidates"].empty()) {
                    auto& cand = j["candidates"][0];
                    if (cand.contains("content") && cand["content"].contains("parts")
                        && cand["content"]["parts"].is_array() && !cand["content"]["parts"].empty()
                        && cand["content"]["parts"][0].contains("text")) {
                        finalResp = cand["content"]["parts"][0]["text"].get<std::string>();
                    }
                }
            }
            catch (...) {}
        }
        else if (prov.type == AIProvider::Ollama) {
            // ... Ollama implementation ...
            json reqBody;
            reqBody["model"] = modelID;
            reqBody["stream"] = false;
            reqBody["messages"] = json::array();
            reqBody["messages"].push_back({ {"role", "system"}, {"content", sysTxt} });
            {
                json last;
                last["role"] = "user";
                last["content"] = prompt;
                if (!plannerImageB64.empty()) {
                    last["images"] = json::array();
                    last["images"].push_back(plannerImageB64);
                }
                reqBody["messages"].push_back(last);
            }

            std::string res = Api::HttpOllama("POST", L"/api/chat", reqBody.dump());
            rawResOrError = res;
            try {
                auto j = json::parse(res);
                if (j.contains("message") && j["message"].contains("content")) {
                    finalResp = j["message"]["content"].get<std::string>();
                }
            }
            catch (...) {}
        }
        else {
            // OpenAI Compatible (DeepSeek, OpenRouter, Moonshot, etc.)
            std::wstring domain = L"api.openai.com";
            std::wstring path = L"/v1/chat/completions";
            std::vector<std::wstring> heads;

            if (prov.type == AIProvider::Anthropic) {
                domain = L"api.anthropic.com"; path = L"/v1/messages";
                heads.push_back(L"x-api-key: " + s2ws(apiKey));
                heads.push_back(L"anthropic-version: 2023-06-01");

                json reqBody;
                reqBody["model"] = modelID;
                reqBody["max_tokens"] = 1024;
                reqBody["system"] = sysTxt;
                reqBody["messages"] = json::array();
                if (!plannerImageB64.empty()) {
                    json content = json::array();
                    content.push_back({ {"type","image"}, {"source", { {"type","base64"}, {"media_type","image/jpeg"}, {"data", plannerImageB64} } } });
                    content.push_back({ {"type","text"}, {"text", prompt} });
                    reqBody["messages"].push_back({ {"role","user"}, {"content", content} });
                }
                else {
                    reqBody["messages"].push_back({ {"role", "user"}, {"content", prompt} });
                }

                std::string res = Api::HttpRequest(domain, path, "POST", reqBody.dump(), heads);
                rawResOrError = res;
                try {
                    auto j = json::parse(res);
                    if (j.contains("content") && !j["content"].empty()) {
                        finalResp = j["content"][0]["text"].get<std::string>();
                    }
                }
                catch (...) {}
            }
            else {
                // Std OpenAI
                if (prov.type == AIProvider::DeepSeek) domain = L"api.deepseek.com";
                else if (prov.type == AIProvider::Moonshot) domain = L"api.moonshot.ai";
                else if (prov.type == AIProvider::OpenRouter) { domain = L"openrouter.ai"; path = L"/api/v1/chat/completions"; }

                heads.push_back(L"Authorization: Bearer " + s2ws(apiKey));

                json reqBody;
                reqBody["model"] = modelID;
                reqBody["messages"] = json::array();
                reqBody["messages"].push_back({ {"role", "system"}, {"content", sysTxt} });
                if (!plannerImageB64.empty() && ModelLikelySupportsImages(prov.type, modelID)) {
                    json con = json::array();
                    con.push_back({ {"type", "text"}, {"text", prompt} });
                    con.push_back({ {"type", "image_url"}, {"image_url", { {"url", "data:image/jpeg;base64," + plannerImageB64} } } });
                    reqBody["messages"].push_back({ {"role", "user"}, {"content", con} });
                }
                else {
                    reqBody["messages"].push_back({ {"role", "user"}, {"content", prompt} });
                }

                std::string res = Api::HttpRequest(domain, path, "POST", reqBody.dump(), heads);
                rawResOrError = res;
                try {
                    auto j = json::parse(res);
                    if (j.contains("choices") && !j["choices"].empty()) {
                        finalResp = j["choices"][0]["message"]["content"].get<std::string>();
                    }
                }
                catch (...) {}
            }
        }

        if (finalResp == "[]" || finalResp.empty()) {
            // If we failed to extract a response, verify if it was truly empty or an error
            // If rawResOrError looks like a JSON error, return it
            if (rawResOrError.find("\"error\"") != std::string::npos) return rawResOrError;
            if (finalResp.empty()) return rawResOrError;
        }

        // Clean up markdown
        size_t start = finalResp.find("```json");
        if (start != std::string::npos) {
            size_t end = finalResp.find("```", start + 7);
            if (end != std::string::npos) {
                return finalResp.substr(start + 7, end - (start + 7));
            }
        }
        size_t start2 = finalResp.find("```");
        if (start2 != std::string::npos) {
            size_t end2 = finalResp.find("```", start2 + 3);
            if (end2 != std::string::npos) {
                return finalResp.substr(start2 + 3, end2 - (start2 + 3));
            }
        }

        return finalResp;
    }

    std::vector<AgentAction> ParsePlan(const std::string& jsonStr) {
        std::vector<AgentAction> res;
        try {
            auto j = json::parse(jsonStr);
            if (j.is_array()) {
                for (const auto& item : j) {
                    AgentAction a;
                    a.action = item.value("action", "");
                    // LLMs may emit non-string JSON values (objects/arrays/numbers) for `value`.
                    // Store them as a JSON string so downstream handlers that call json::parse(action.value)
                    // (e.g. http_request/config_set/wait_user) keep working.
                    if (item.contains("value")) {
                        const auto& v = item["value"];
                        if (v.is_string()) a.value = v.get<std::string>();
                        else a.value = v.dump();
                    }
                    else {
                        a.value.clear();
                    }
                    // Safely handle locator — press_key/scroll may not have one
                    if (item.contains("locator") && item["locator"].is_object()) {
                        a.locator = item["locator"];
                    }
                    else {
                        a.locator = json::object(); // Empty object
                    }
                    res.push_back(a);
                }
            }
        }
        catch (...) {}
        return res;
    }

    // Helper to parse key names to VK codes
    WORD ParseKeyName(const std::string& keyName) {
        if (keyName == "enter" || keyName == "return") return VK_RETURN;
        if (keyName == "tab") return VK_TAB;
        if (keyName == "escape" || keyName == "esc") return VK_ESCAPE;
        if (keyName == "backspace") return VK_BACK;
        if (keyName == "delete" || keyName == "del") return VK_DELETE;
        if (keyName == "space") return VK_SPACE;
        if (keyName == "up") return VK_UP;
        if (keyName == "down") return VK_DOWN;
        if (keyName == "left") return VK_LEFT;
        if (keyName == "right") return VK_RIGHT;
        if (keyName == "home") return VK_HOME;
        if (keyName == "end") return VK_END;
        if (keyName == "pageup") return VK_PRIOR;
        if (keyName == "pagedown") return VK_NEXT;
        if (keyName == "f1") return VK_F1;
        if (keyName == "f2") return VK_F2;
        if (keyName == "f3") return VK_F3;
        if (keyName == "f4") return VK_F4;
        if (keyName == "f5") return VK_F5;
        if (keyName == "f11") return VK_F11;
        if (keyName == "f12") return VK_F12;
        // Single character
        if (keyName.length() == 1) {
            return (WORD)VkKeyScanA(keyName[0]);
        }
        return 0;
    }

    // =========================================================
    // HUMAN-LIKE TYPING FUNCTION
    // Types text character-by-character with realistic timing.
    // Handles: \n (Enter), \t (spaces to next tab stop), \r (skip),
    // and unicode.
    // Monaco/LeetCode auto-inserts closing brackets; when enabled, we skip
    // intended closing brackets by moving the caret (RightArrow) instead of typing.
    // =========================================================
    void HumanType(const std::string& text, bool assumeAutoPairEditor, int tabAsSpaces) {
        if (text.empty()) return;

        // --- Helper lambdas (same as ExecuteAction) ---
        auto ForceFG = [](HWND hwnd) {
            if (!hwnd || !IsWindow(hwnd)) return;
            DWORD targetTid = GetWindowThreadProcessId(hwnd, NULL);
            DWORD curTid = GetCurrentThreadId();
            if (targetTid != curTid) AttachThreadInput(curTid, targetTid, TRUE);
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
            SetFocus(hwnd);
            if (targetTid != curTid) AttachThreadInput(curTid, targetTid, FALSE);
            Sleep(60);
            };

        auto TypeSendKey = [](WORD vk, bool keyUp) {
            INPUT inp = {};
            inp.type = INPUT_KEYBOARD;
            inp.ki.wVk = vk;
            inp.ki.wScan = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
            inp.ki.dwFlags = (keyUp ? KEYEVENTF_KEYUP : 0);
            if (vk == VK_UP || vk == VK_DOWN || vk == VK_LEFT || vk == VK_RIGHT ||
                vk == VK_HOME || vk == VK_END || vk == VK_PRIOR || vk == VK_NEXT ||
                vk == VK_INSERT || vk == VK_DELETE || vk == VK_NUMLOCK) {
                inp.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
            }
            SendInput(1, &inp, sizeof(INPUT));
            };

        auto SendUnicode = [](wchar_t wc) {
            INPUT inp[2] = {};
            inp[0].type = INPUT_KEYBOARD;
            inp[0].ki.wScan = wc;
            inp[0].ki.dwFlags = KEYEVENTF_UNICODE;
            inp[1].type = INPUT_KEYBOARD;
            inp[1].ki.wScan = wc;
            inp[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            SendInput(2, inp, sizeof(INPUT));
            };

        // Random delay generator for human-like timing
        std::mt19937 rng((unsigned)GetTickCount64());
        std::uniform_int_distribution<int> charDelay(25, 45);   // ms between chars
        std::uniform_int_distribution<int> lineDelay(80, 150);  // ms after newline

        // Ensure target window is focused
        ForceFG(g_targetWindow);
        Sleep(100);

        OutputDebugStringA("[Agent] HumanType: START typing\n");

        auto IsOpener = [](char c) { return c == '(' || c == '{' || c == '['; };
        auto IsCloser = [](char c) { return c == ')' || c == '}' || c == ']'; };
        auto MatchingCloser = [](char c) -> char {
            if (c == '(') return ')';
            if (c == '{') return '}';
            if (c == '[') return ']';
            return 0;
            };

        size_t i = 0;
        size_t len = text.size();
        int col = 0;
        bool atLineStart = true;
        std::vector<char> closerStack;
        while (i < len && isRunning) {
            char c = text[i];

            // Monaco/LeetCode auto-indents on Enter. If we also type leading whitespace,
            // indentation can double/triple. So when auto-pair/editor mode is enabled,
            // skip leading spaces/tabs at the start of each line.
            if (assumeAutoPairEditor && atLineStart) {
                while (i < len && (text[i] == ' ' || text[i] == '\t')) {
                    i++;
                }
                if (i >= len) break;
                c = text[i];
            }

            // Skip intended closers in auto-pair editors by moving caret over the already-inserted closer.
            if (assumeAutoPairEditor && IsCloser(c) && !closerStack.empty() && c == closerStack.back()) {
                TypeSendKey(VK_RIGHT, false);
                Sleep(10);
                TypeSendKey(VK_RIGHT, true);
                closerStack.pop_back();
                col++;
                Sleep(charDelay(rng));
                i++;
                continue;
            }

            if (c == '\r') {
                // Skip carriage return (will be handled with \n)
                i++;
                continue;
            }

            if (c == '\n') {
                // Newline → press Enter
                TypeSendKey(VK_RETURN, false);
                Sleep(15);
                TypeSendKey(VK_RETURN, true);
                Sleep(lineDelay(rng));
                col = 0;
                atLineStart = true;
                i++;
                continue;
            }

            if (c == '\t') {
                // Convert tab to spaces for reliable indentation in Monaco/LeetCode.
                int tabW = tabAsSpaces <= 0 ? 4 : tabAsSpaces;
                int spaces = tabW - (col % tabW);
                for (int s = 0; s < spaces; s++) {
                    SendUnicode(L' ');
                    Sleep(5);
                }
                col += spaces;
                Sleep(charDelay(rng));
                atLineStart = false;
                i++;
                continue;
            }

            // Try standard VkKeyScan mapping
            SHORT vkResult = VkKeyScanA(c);
            if (vkResult != -1) {
                BYTE vk = LOBYTE(vkResult);
                BYTE mods = HIBYTE(vkResult);
                bool needShift = (mods & 1) != 0;
                bool needCtrl = (mods & 2) != 0;
                bool needAlt = (mods & 4) != 0;

                if (needCtrl)  TypeSendKey(VK_CONTROL, false);
                if (needAlt)   TypeSendKey(VK_MENU, false);
                if (needShift) TypeSendKey(VK_SHIFT, false);

                TypeSendKey(vk, false);
                Sleep(10);
                TypeSendKey(vk, true);

                if (needShift) TypeSendKey(VK_SHIFT, true);
                if (needAlt)   TypeSendKey(VK_MENU, true);
                if (needCtrl)  TypeSendKey(VK_CONTROL, true);
            }
            else {
                // Fallback: Unicode input for chars VkKeyScan can't map
                wchar_t wc = 0;
                int converted = MultiByteToWideChar(CP_UTF8, 0, &text[i], 1, &wc, 1);
                if (converted > 0) {
                    SendUnicode(wc);
                }
            }

            // After typing an opener, assume the editor inserted its closer.
            if (assumeAutoPairEditor && IsOpener(c)) {
                char cl = MatchingCloser(c);
                if (cl != 0) closerStack.push_back(cl);
            }

            if (c == ' ') col++;
            else if (c >= 32) col++;
            if (c != '\r' && c != '\n') atLineStart = false;

            Sleep(charDelay(rng));
            i++;
        }

        OutputDebugStringA("[Agent] HumanType: DONE typing\n");
    }

    bool ExecuteAction(const AgentAction& action) {
        // --- Helper: Force target window to foreground from background thread ---
        auto ForceForeground = [](HWND hwnd) {
            if (!hwnd || !IsWindow(hwnd)) return;
            DWORD targetTid = GetWindowThreadProcessId(hwnd, NULL);
            DWORD curTid = GetCurrentThreadId();
            if (targetTid != curTid) AttachThreadInput(curTid, targetTid, TRUE);
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
            SetFocus(hwnd);
            if (targetTid != curTid) AttachThreadInput(curTid, targetTid, FALSE);
            Sleep(60);
            };

        // ------------------------------------------------------------
        // System / inventory actions (do not require attached window)
        // ------------------------------------------------------------
        if (action.action == "list_installed_apps") {
            g_lastActionResult = ListInstalledApps(action.value);
            return true;
        }
        if (action.action == "list_launchable_apps") {
            g_lastActionResult = ListLaunchableApps(action.value);
            return true;
        }
        if (action.action == "net_check") {
            g_lastActionResult = NetCheck();
            return true;
        }
        if (action.action == "winget_search") {
            DWORD code = 0;
            std::string out = WingetCmd("search " + (action.value.empty() ? std::string(" ") : "\"" + action.value + "\""), 60000, &code);
            g_lastActionResult = "WINGET SEARCH (exit " + std::to_string(code) + "):\n" + out;
            return true;
        }
        if (action.action == "winget_list") {
            DWORD code = 0;
            std::string args = "list";
            if (!action.value.empty()) args += " \"" + action.value + "\"";
            std::string out = WingetCmd(args, 60000, &code);
            g_lastActionResult = "WINGET LIST (exit " + std::to_string(code) + "):\n" + out;
            return true;
        }
        if (action.action == "winget_install") {
            DWORD code = 0;
            std::string args = "install --disable-interactivity --accept-package-agreements --accept-source-agreements ";
            if (!action.value.empty()) args += "\"" + action.value + "\"";
            std::string out = WingetCmd(args, 300000, &code);
            g_lastActionResult = "WINGET INSTALL (exit " + std::to_string(code) + "):\n" + out;
            return true;
        }
        if (action.action == "winget_upgrade") {
            DWORD code = 0;
            std::string args = "upgrade --disable-interactivity --accept-package-agreements --accept-source-agreements ";
            if (action.value.empty()) args += "--all";
            else args += "\"" + action.value + "\"";
            std::string out = WingetCmd(args, 300000, &code);
            g_lastActionResult = "WINGET UPGRADE (exit " + std::to_string(code) + "):\n" + out;
            return true;
        }

        // ------------------------------------------------------------
        // Workspace / coding tools (no UI required)
        // ------------------------------------------------------------
        if (action.action == "run_cmd") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string cmd = req.value("cmd", "");
                std::string cwd = req.value("cwd", "");
                int timeoutMs = req.value("timeout_ms", 120000);
                int maxBytes = req.value("max_bytes", 200000);
                // shell=true runs via cmd.exe (fresh shell each call). Use shell=false to run an executable directly.
                bool shell = req.value("shell", true);
                bool allowNonZero = req.value("allow_nonzero", false);
                if (cmd.empty()) { g_lastActionResult = "RUN_CMD: missing cmd"; return false; }

                std::wstring wcmd;
                if (shell) wcmd = L"cmd.exe /Q /D /S /C " + s2ws(cmd);
                else wcmd = s2ws(cmd);

                DWORD exitCode = 0;
                std::wstring wcwd = ResolveCwdW(cwd.empty() ? L"" : s2ws(cwd));
                if (!wcwd.empty() && !DirExistsW(wcwd)) {
                    g_lastActionResult = "RUN_CMD: invalid cwd=" + ws2s(wcwd);
                    return false;
                }

                std::string runErr;
                std::string out = RunCommandCaptureEx(wcmd, wcwd, (DWORD)timeoutMs, &exitCode, maxBytes, &runErr);
                if (out.empty() && !runErr.empty()) out = "(no output)\nERROR: " + runErr + "\n";
                if (out.empty()) out = "(no output)";

                std::stringstream ss;
                ss << "RUN_CMD (exit " << exitCode << ")\n";
                ss << "CWD: " << (wcwd.empty() ? ws2s(GetCwdW()) : ws2s(wcwd)) << "\n";
                ss << "CMD: " << cmd << "\n";
                ss << "SHELL: " << (shell ? "true" : "false") << "\n";
                ss << "OUTPUT (truncated to " << maxBytes << " bytes):\n";
                ss << out;
                g_lastActionResult = ss.str();
                if (allowNonZero) return true;
                return exitCode == 0;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("RUN_CMD: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "fs_mkdirs") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string path = req.value("path", "");
                std::string base = req.value("base", "");
                if (path.empty()) { g_lastActionResult = "FS_MKDIRS: missing path"; return false; }
                std::wstring dirW = ResolveFsPathW(base.empty() ? L"" : s2ws(base), s2ws(path));
                EnsureDirRecursiveW(dirW);
                g_lastActionResult = "FS_MKDIRS: OK " + ws2s(dirW);
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("FS_MKDIRS: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "fs_read") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string path = req.value("path", "");
                std::string base = req.value("base", "");
                int startLine = req.value("start_line", 1);
                int lineCount = req.value("line_count", 200);
                if (path.empty()) { g_lastActionResult = "FS_READ: missing path"; return false; }
                std::wstring pathW = ResolveFsPathW(base.empty() ? L"" : s2ws(base), s2ws(path));
                g_lastActionResult = FsReadTextLines(pathW, startLine, lineCount);
                // Consider missing file a failure to trigger recovery.
                if (g_lastActionResult.rfind("FS_READ: failed", 0) == 0) return false;
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("FS_READ: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "fs_list_dir") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string path = req.value("path", "");
                std::string base = req.value("base", "");
                int limit = req.value("limit", 200);
                if (path.empty()) path = ".";
                std::wstring dirW = ResolveFsPathW(base.empty() ? L"" : s2ws(base), s2ws(path));
                g_lastActionResult = FsListDir(dirW, limit);
                if (g_lastActionResult.rfind("FS_LIST_DIR: failed", 0) == 0) return false;
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("FS_LIST_DIR: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "fs_glob") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string pattern = req.value("pattern", "");
                std::string base = req.value("base", "");
                int maxResults = req.value("max_results", 200);
                if (pattern.empty()) { g_lastActionResult = "FS_GLOB: missing pattern"; return false; }
                g_lastActionResult = FsGlob(base.empty() ? L"" : s2ws(base), pattern, maxResults);
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("FS_GLOB: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "fs_write") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string path = req.value("path", "");
                std::string base = req.value("base", "");
                bool createDirs = req.value("create_dirs", true);
                bool backup = req.value("backup", true);

                std::string content = "";
                if (req.contains("content_b64") && req["content_b64"].is_string()) {
                    content = Base64DecodeLoose(req["content_b64"].get<std::string>());
                }
                else {
                    content = req.value("content", "");
                }

                g_lastActionResult = FsWriteFile(base.empty() ? L"" : s2ws(base), path, content, createDirs, backup);
                if (g_lastActionResult.rfind("FS_WRITE: failed", 0) == 0 || g_lastActionResult.rfind("FS_WRITE: missing", 0) == 0) return false;
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("FS_WRITE: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "fs_replace_lines") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string path = req.value("path", "");
                std::string base = req.value("base", "");
                int startLine = req.value("start_line", 1);
                int endLine = req.value("end_line", startLine);
                bool createDirs = req.value("create_dirs", true);
                bool backup = req.value("backup", true);

                std::string newText = "";
                if (req.contains("new_text_b64") && req["new_text_b64"].is_string()) {
                    newText = Base64DecodeLoose(req["new_text_b64"].get<std::string>());
                }
                else {
                    newText = req.value("new_text", "");
                }

                g_lastActionResult = FsReplaceLines(base.empty() ? L"" : s2ws(base), path, startLine, endLine, newText, createDirs, backup);
                if (g_lastActionResult.rfind("FS_REPLACE_LINES:", 0) == 0 && g_lastActionResult.find("write failed") != std::string::npos) return false;
                if (g_lastActionResult.rfind("FS_REPLACE_LINES:", 0) == 0 && g_lastActionResult.find("read failed") != std::string::npos) return false;
                if (g_lastActionResult.rfind("FS_REPLACE_LINES: missing", 0) == 0) return false;
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("FS_REPLACE_LINES: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "http_request") {
            // action.value is a JSON string: {method,url,headers,body,timeout_ms,max_bytes}
            try {
                json j = json::parse(action.value.empty() ? "{}" : action.value);
                std::string method = j.value("method", "GET");
                std::string url = j.value("url", "");
                std::string body = j.value("body", "");
                int timeoutMs = j.value("timeout_ms", 20000);
                int maxBytes = j.value("max_bytes", 200000);

                std::vector<std::wstring> headers;
                if (j.contains("headers") && j["headers"].is_object()) {
                    for (auto it = j["headers"].begin(); it != j["headers"].end(); ++it) {
                        if (!it.value().is_string()) continue;
                        std::string h = it.key() + ": " + it.value().get<std::string>();
                        headers.push_back(s2ws(h + "\r\n"));
                    }
                }

                // Default content type for JSON body
                if (!body.empty() && (method == "POST" || method == "PUT" || method == "PATCH") && j.value("content_type", "").empty()) {
                    headers.push_back(L"Content-Type: application/json\r\n");
                }
                if (j.contains("content_type") && j["content_type"].is_string()) {
                    std::string ct = j["content_type"].get<std::string>();
                    if (!ct.empty()) headers.push_back(s2ws("Content-Type: " + ct + "\r\n"));
                }

                DWORD status = 0;
                std::string ct;
                std::string resp = HttpRequestFullUrl(url, method, body, headers, timeoutMs, maxBytes, &status, &ct);
                std::stringstream ss;
                ss << "HTTP REQUEST\n";
                ss << method << " " << url << "\n";
                ss << "Status: " << status << "\n";
                if (!ct.empty()) ss << "Content-Type: " << ct << "\n";
                ss << "Body (truncated to " << maxBytes << " bytes):\n";
                ss << resp;
                g_lastActionResult = ss.str();
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("http_request parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "config_get") {
            try {
                json j = LoadLocalConfig();
                std::string key = action.value;
                // Allow planners to send {"key":"..."} as value.
                if (!key.empty() && (key[0] == '{' || key[0] == '[')) {
                    try {
                        json req = json::parse(key);
                        if (req.is_object()) {
                            key = req.value("key", key);
                        }
                    }
                    catch (...) {}
                }
                if (key.empty()) { g_lastActionResult = "CONFIG GET: missing key"; return false; }
                if (j.contains("api_keys") && j["api_keys"].is_object() && j["api_keys"].contains(key)) {
                    g_lastActionResult = "CONFIG GET " + key + ": " + j["api_keys"][key].get<std::string>();
                    return true;
                }
                g_lastActionResult = "CONFIG GET " + key + ": (not set)";
                return true;
            }
            catch (...) {
                g_lastActionResult = "CONFIG GET: error";
                return false;
            }
        }

        if (action.action == "config_set") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string key = req.value("key", "");
                std::string val = req.value("value", "");
                if (key.empty()) { g_lastActionResult = "CONFIG SET: missing key"; return false; }
                json j = LoadLocalConfig();
                if (!j.is_object()) j = json::object();
                if (!j.contains("api_keys") || !j["api_keys"].is_object()) j["api_keys"] = json::object();
                j["api_keys"][key] = val;
                if (!SaveLocalConfig(j)) { g_lastActionResult = "CONFIG SET: save failed"; return false; }
                g_lastActionResult = "CONFIG SET " + key + ": OK";
                return true;
            }
            catch (...) {
                g_lastActionResult = "CONFIG SET: parse error";
                return false;
            }
        }

        // ------------------------------------------------------------
        // MCP (Model Context Protocol) client actions (NPX/stdio)
        // ------------------------------------------------------------
        if (action.action == "mcp_registry_search") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string query = req.value("query", "");
                int limit = req.value("limit", 5);
                std::string err;
                std::string raw = McpRegistrySearch(query, limit, &err);
                if (raw.empty()) {
                    g_lastActionResult = "MCP_REGISTRY_SEARCH: failed (" + err + ")";
                    return false;
                }
                json j = json::parse(raw);
                std::stringstream ss;
                ss << "MCP_REGISTRY_SEARCH: query='" << query << "'\n";
                int found = 0;
                if (j.contains("servers") && j["servers"].is_array()) {
                    for (const auto& item : j["servers"]) {
                        if (!item.contains("server") || !item["server"].is_object()) continue;
                        const auto& s = item["server"];
                        std::string name = s.value("name", "");
                        std::string desc = s.value("description", "");
                        if (name.empty()) continue;
                        found++;
                        ss << "- " << name;
                        if (!desc.empty()) ss << ": " << McpOneLine(desc, 140);
                        ss << "\n";
                        if (s.contains("packages") && s["packages"].is_array()) {
                            for (const auto& p : s["packages"]) {
                                if (!p.is_object()) continue;
                                std::string reg = p.value("registryType", "");
                                if (reg != "npm") continue;

                                std::string ident = p.value("identifier", "");
                                std::string ver = p.value("version", "");
                                std::string transport = "";
                                if (p.contains("transport") && p["transport"].is_object()) transport = p["transport"].value("type", "");

                                std::vector<std::string> reqEnv;
                                if (p.contains("environmentVariables") && p["environmentVariables"].is_array()) {
                                    for (const auto& ev : p["environmentVariables"]) {
                                        if (!ev.is_object()) continue;
                                        bool isReq = ev.value("isRequired", false);
                                        std::string evName = ev.value("name", "");
                                        if (isReq && !evName.empty()) reqEnv.push_back(evName);
                                    }
                                }

                                std::vector<std::string> reqArgs;
                                if (p.contains("packageArguments") && p["packageArguments"].is_array()) {
                                    for (const auto& a : p["packageArguments"]) {
                                        if (!a.is_object()) continue;
                                        bool isReq = a.value("isRequired", false);
                                        if (!isReq) continue;
                                        std::string type = a.value("type", "");
                                        if (type == "named") {
                                            std::string an = a.value("name", "");
                                            if (!an.empty()) reqArgs.push_back(an);
                                        }
                                        else if (type == "positional") {
                                            std::string vh = a.value("valueHint", "positional");
                                            reqArgs.push_back("<" + vh + ">");
                                        }
                                    }
                                }

                                ss << "  npm: " << ident;
                                if (!ver.empty()) ss << "@" << ver;
                                if (!transport.empty()) ss << " (transport=" << transport << ")";
                                ss << "\n";
                                if (!reqArgs.empty()) ss << "    required_args: " << JoinCsv(reqArgs) << "\n";
                                if (!reqEnv.empty()) ss << "    required_env: " << JoinCsv(reqEnv) << "\n";
                            }
                        }
                    }
                }
                if (j.contains("metadata")) ss << "metadata: " << j["metadata"].dump() << "\n";
                g_lastActionResult = ss.str();
                if (found == 0) return false;
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("MCP_REGISTRY_SEARCH: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "mcp_npm_search") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string query = req.value("query", "");
                int limit = req.value("limit", 10);
                std::string err;
                std::string raw = McpNpmSearch(query, limit, &err);
                if (raw.empty()) {
                    g_lastActionResult = "MCP_NPM_SEARCH: failed (" + err + ")";
                    return false;
                }
                json j = json::parse(raw);
                std::stringstream ss;
                ss << "MCP_NPM_SEARCH: query='" << query << "'\n";

                int found = 0;
                if (j.contains("objects") && j["objects"].is_array()) {
                    for (const auto& obj : j["objects"]) {
                        if (!obj.is_object() || !obj.contains("package") || !obj["package"].is_object()) continue;
                        const auto& p = obj["package"];
                        std::string name = p.value("name", "");
                        std::string ver = p.value("version", "");
                        std::string desc = p.value("description", "");
                        if (name.empty()) continue;
                        found++;
                        ss << "- " << name;
                        if (!ver.empty()) ss << "@" << ver;
                        if (!desc.empty()) ss << ": " << McpOneLine(desc, 160);
                        ss << "\n";
                        if (found >= limit) break;
                    }
                }
                if (j.contains("total")) ss << "total: " << j["total"].dump() << "\n";
                g_lastActionResult = ss.str();
                if (found == 0) return false;
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("MCP_NPM_SEARCH: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "mcp_list_servers") {
            std::lock_guard<std::mutex> lk(g_mcpMu);
            std::stringstream ss;
            ss << "MCP_SERVERS: " << g_mcp.size() << "\n";
            for (const auto& kv : g_mcp) {
                auto c = kv.second;
                if (!c) continue;
                ss << "- " << c->id << ": " << c->package << " running=" << (c->running ? "true" : "false") << "\n";
            }
            g_lastActionResult = ss.str();
            return true;
        }

        if (action.action == "mcp_disconnect") {
            std::string id = action.value;
            try {
                if (!id.empty() && (id[0] == '{' || id[0] == '[')) {
                    json req = json::parse(id);
                    if (req.is_object()) id = req.value("id", id);
                }
            }
            catch (...) {}
            if (id.empty()) { g_lastActionResult = "MCP_DISCONNECT: missing id"; return false; }

            std::shared_ptr<McpConn> c;
            {
                std::lock_guard<std::mutex> lk(g_mcpMu);
                auto it = g_mcp.find(id);
                if (it != g_mcp.end()) {
                    c = it->second;
                    g_mcp.erase(it);
                }
            }
            if (!c) { g_lastActionResult = "MCP_DISCONNECT: not found id=" + id; return false; }
            McpClose(c);
            g_lastActionResult = "MCP_DISCONNECT: OK id=" + id;
            return true;
        }

        if (action.action == "mcp_connect") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string id = req.value("id", "default");
                std::string package = req.value("package", "");
                std::string cwd = req.value("cwd", "");
                int initTimeoutMs = req.value("init_timeout_ms", 30000);
                if (package.empty()) { g_lastActionResult = "MCP_CONNECT: missing package"; return false; }

                std::vector<std::string> args;
                if (req.contains("args") && req["args"].is_array()) {
                    for (const auto& a : req["args"]) if (a.is_string()) args.push_back(a.get<std::string>());
                }
                // Many MCP servers auto-default to stdio; some require explicit flags like --stdio.
                // If connect fails and args was empty, we auto-retry once with args=["--stdio"].

                std::unordered_map<std::string, std::string> env;
                if (req.contains("env") && req["env"].is_object()) {
                    for (auto it = req["env"].begin(); it != req["env"].end(); ++it) {
                        if (it.value().is_string()) env[it.key()] = it.value().get<std::string>();
                    }
                }

                // If already connected, disconnect first.
                {
                    std::lock_guard<std::mutex> lk(g_mcpMu);
                    auto it = g_mcp.find(id);
                    if (it != g_mcp.end()) {
                        auto old = it->second;
                        g_mcp.erase(it);
                        McpClose(old);
                    }
                }

                auto TryConnect = [&](const std::vector<std::string>& attemptArgs, std::string& outErr) -> bool {
                    outErr.clear();
                    auto c = std::make_shared<McpConn>();
                    c->id = id;
                    c->package = package;
                    c->args = attemptArgs;
                    c->env = env;
                    c->cwdW = ResolveCwdW(cwd.empty() ? L"" : s2ws(cwd));

                    std::string spawnErr;
                    if (!McpSpawnServer(c, &spawnErr)) {
                        outErr = "spawn failed: " + spawnErr;
                        return false;
                    }

                    c->tOut = std::thread(McpStdoutThread, c);
                    c->tErr = std::thread(McpStderrThread, c);

                    std::string initErr;
                    if (!McpInitialize(c, initTimeoutMs, &initErr)) {
                        McpClose(c);
                        outErr = "init failed: " + initErr;
                        return false;
                    }

                    // Cache tools/resources lists (best-effort)
                    {
                        json resp;
                        std::string e;
                        if (McpRpc(c, "tools/list", json::object(), 15000, resp, &e) && resp.contains("result")) c->toolCache = resp["result"];
                        if (McpRpc(c, "resources/list", json::object(), 15000, resp, &e) && resp.contains("result")) c->resourceCache = resp["result"];
                    }

                    {
                        std::lock_guard<std::mutex> lk(g_mcpMu);
                        g_mcp[id] = c;
                    }
                    g_lastActionResult = McpServerSummary(c);
                    return true;
                    };

                std::string err1;
                if (TryConnect(args, err1)) return true;

                if (args.empty()) {
                    std::string err2;
                    if (TryConnect(std::vector<std::string>{"--stdio"}, err2)) return true;
                    g_lastActionResult = "MCP_CONNECT: failed\n- attempt1: " + err1 + "\n- attempt2 (--stdio): " + err2;
                    return false;
                }

                g_lastActionResult = "MCP_CONNECT: failed (" + err1 + ")";
                return false;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("MCP_CONNECT: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "mcp_tools_list") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string id = req.value("id", "default");
                auto c = McpGet(id);
                if (!c) { g_lastActionResult = "MCP_TOOLS_LIST: not connected id=" + id; return false; }
                json resp;
                std::string e;
                if (!McpRpc(c, "tools/list", json::object(), 20000, resp, &e)) {
                    g_lastActionResult = "MCP_TOOLS_LIST: failed: " + e;
                    return false;
                }
                if (resp.contains("error")) {
                    g_lastActionResult = "MCP_TOOLS_LIST: error: " + resp["error"].dump();
                    return false;
                }
                if (resp.contains("result")) c->toolCache = resp["result"];
                g_lastActionResult = "MCP_TOOLS_LIST:\n" + (resp.contains("result") ? resp["result"].dump() : resp.dump());
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("MCP_TOOLS_LIST: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "mcp_resources_list") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string id = req.value("id", "default");
                auto c = McpGet(id);
                if (!c) { g_lastActionResult = "MCP_RESOURCES_LIST: not connected id=" + id; return false; }
                json resp;
                std::string e;
                if (!McpRpc(c, "resources/list", json::object(), 20000, resp, &e)) {
                    g_lastActionResult = "MCP_RESOURCES_LIST: failed: " + e;
                    return false;
                }
                if (resp.contains("error")) {
                    g_lastActionResult = "MCP_RESOURCES_LIST: error: " + resp["error"].dump();
                    return false;
                }
                if (resp.contains("result")) c->resourceCache = resp["result"];
                g_lastActionResult = "MCP_RESOURCES_LIST:\n" + (resp.contains("result") ? resp["result"].dump() : resp.dump());
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("MCP_RESOURCES_LIST: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "mcp_resource_read") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string id = req.value("id", "default");
                std::string uri = req.value("uri", "");
                int timeoutMs = req.value("timeout_ms", 30000);
                if (uri.empty()) { g_lastActionResult = "MCP_RESOURCE_READ: missing uri"; return false; }
                auto c = McpGet(id);
                if (!c) { g_lastActionResult = "MCP_RESOURCE_READ: not connected id=" + id; return false; }
                json resp;
                std::string e;
                if (!McpRpc(c, "resources/read", { {"uri", uri} }, timeoutMs, resp, &e)) {
                    g_lastActionResult = "MCP_RESOURCE_READ: failed: " + e;
                    return false;
                }
                if (resp.contains("error")) {
                    g_lastActionResult = "MCP_RESOURCE_READ: error: " + resp["error"].dump();
                    return false;
                }
                g_lastActionResult = "MCP_RESOURCE_READ: uri=" + uri + "\n" + (resp.contains("result") ? resp["result"].dump() : resp.dump());
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("MCP_RESOURCE_READ: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "mcp_tool_call") {
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                std::string id = req.value("id", "default");
                std::string name = req.value("name", "");
                int timeoutMs = req.value("timeout_ms", 60000);
                json args = json::object();
                if (req.contains("arguments")) args = req["arguments"];
                if (name.empty()) { g_lastActionResult = "MCP_TOOL_CALL: missing name"; return false; }
                auto c = McpGet(id);
                if (!c) { g_lastActionResult = "MCP_TOOL_CALL: not connected id=" + id; return false; }

                // Validate required arguments against cached tool schema (if available) to avoid guessy calls.
                json toolDef;
                bool haveTool = McpFindToolInCache(c->toolCache, name, toolDef);
                if (!haveTool) {
                    // Refresh tool cache once.
                    json listResp;
                    std::string le;
                    if (McpRpc(c, "tools/list", json::object(), 20000, listResp, &le) && listResp.contains("result")) {
                        c->toolCache = listResp["result"];
                        haveTool = McpFindToolInCache(c->toolCache, name, toolDef);
                    }
                }
                if (haveTool && args.is_object()) {
                    std::vector<std::string> required, props;
                    McpExtractToolSchema(toolDef, required, props);
                    std::vector<std::string> missing;
                    for (const auto& r : required) {
                        if (!args.contains(r)) missing.push_back(r);
                    }
                    if (!missing.empty()) {
                        std::stringstream ss;
                        ss << "MCP_TOOL_CALL: missing required arguments for tool '" << name << "': " << JoinCsv(missing) << "\n";
                        if (!props.empty()) ss << "Known properties: " << JoinCsv(props) << "\n";
                        if (toolDef.contains("description") && toolDef["description"].is_string()) ss << "Tool description: " << McpOneLine(toolDef["description"].get<std::string>(), 180) << "\n";
                        ss << "Tip: call mcp_tools_list to inspect the full inputSchema.\n";
                        g_lastActionResult = ss.str();
                        return false;
                    }
                }

                json resp;
                std::string e;
                if (!McpRpc(c, "tools/call", { {"name", name}, {"arguments", args} }, timeoutMs, resp, &e)) {
                    g_lastActionResult = "MCP_TOOL_CALL: failed: " + e;
                    return false;
                }
                if (resp.contains("error")) {
                    g_lastActionResult = "MCP_TOOL_CALL: error: " + resp["error"].dump();
                    return false;
                }
                std::string formatted = McpFormatToolResult(resp);
                if (formatted.size() > 60000) formatted.resize(60000);
                g_lastActionResult = "MCP_TOOL_CALL: " + name + "\n" + formatted;
                // If tool execution error, fail the action so planner reacts.
                if (resp.contains("result") && resp["result"].is_object() && resp["result"].value("isError", false)) return false;
                return true;
            }
            catch (const std::exception& e) {
                g_lastActionResult = std::string("MCP_TOOL_CALL: parse error: ") + e.what();
                return false;
            }
        }

        if (action.action == "wait_user") {
            // value JSON: {prompt, timeout_ms}
            int timeoutMs = 600000;
            std::string prompt = "Reply with the requested value.";
            try {
                json req = json::parse(action.value.empty() ? "{}" : action.value);
                prompt = req.value("prompt", prompt);
                timeoutMs = req.value("timeout_ms", timeoutMs);
            }
            catch (...) {}

            if (g_telegramEnabled && g_telegramPolling) {
                TelegramBridge::SendMessage("[INPUT NEEDED] " + prompt + "\n(Reply in chat; use /cancel to cancel)");
            }

            {
                std::lock_guard<std::mutex> lock(g_telegramMutex);
                g_telegramInputBuffer.clear();
                g_telegramInputReady = false;
            }
            g_waitingForUserInput = true;
            std::string reply;
            bool ok = WaitForTelegramUserInput(timeoutMs, reply);
            g_waitingForUserInput = false;
            if (!ok) {
                g_lastActionResult = "WAIT_USER: timeout";
                return false;
            }
            g_lastActionResult = "USER_INPUT: " + reply;
            return true;
        }

        // ------------------------------------------------------------
        // Local memory / RAG actions
        // ------------------------------------------------------------
        if (action.action == "memory_index_roots") {
            IndexRootsDefault();
            g_lastActionResult = "MEMORY: indexed default roots";
            return true;
        }
        if (action.action == "memory_find_paths") {
            g_lastActionResult = MemoryFindPaths(action.value);
            return true;
        }
        if (action.action == "memory_ingest_file") {
            g_lastActionResult = MemoryIngestFile(action.value);
            return true;
        }
        if (action.action == "memory_search") {
            g_lastActionResult = MemorySearch(action.value);
            return true;
        }
        if (action.action == "memory_recent_actions") {
            int n = 30;
            if (!action.value.empty()) {
                try { n = std::stoi(action.value); }
                catch (...) { n = 30; }
            }
            g_lastActionResult = MemoryRecentActions(n);
            return true;
        }
        if (action.action == "memory_list_images") {
            int n = 20;
            if (!action.value.empty()) {
                try { n = std::stoi(action.value); }
                catch (...) { n = 20; }
            }
            g_lastActionResult = MemoryListImages(n);
            return true;
        }
        if (action.action == "capture_screenshot") {
            g_lastActionResult = MemoryCaptureAndStoreScreenshot(true);
            return true;
        }
        if (action.action == "memory_get_image") {
            g_lastActionResult = MemoryGetImageAndSendTelegram(action.value);
            return true;
        }

        // Actions that must work even when no process is attached.
        // Previously, these actions were unreachable because we tried to build a UIA root
        // from g_targetWindow first, and returned false when it was NULL.
        if (action.action == "list_processes") {
            RefreshProcessList();
            std::string output = "AVAILABLE PROCESSES:\n";
            for (size_t i = 0; i < g_processList.size(); i++) {
                output += std::to_string(i + 1) + ". " + g_processList[i].processName + " - \"" + g_processList[i].title + "\"";
                if (g_processList[i].hwnd == g_targetWindow) output += " [ATTACHED]";
                output += "\n";
            }
            if (g_processList.empty()) output += "(No visible windows found)\n";
            g_lastActionResult = output;
            return true;
        }

        if (action.action == "switch_window" || action.action == "attach_process") {
            // Find window by substring match against window title OR process name.
            // Also allow numeric selection ("1", "2", ...) corresponding to the
            // current process list ordering.
            std::string targetTitle = action.value;

            // Numeric selection support
            {
                std::string trimmed = targetTitle;
                trimmed.erase(0, trimmed.find_first_not_of(" \t\n\r"));
                trimmed.erase(trimmed.find_last_not_of(" \t\n\r") + 1);
                bool allDigits = !trimmed.empty() && std::all_of(trimmed.begin(), trimmed.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
                if (allDigits) {
                    int idx = 0;
                    try { idx = std::stoi(trimmed); }
                    catch (...) { idx = 0; }
                    if (idx > 0) {
                        RefreshProcessList();
                        if (idx <= (int)g_processList.size()) {
                            HWND hw = g_processList[(size_t)idx - 1].hwnd;
                            if (hw && IsWindow(hw)) {
                                g_targetWindow = hw;
                                g_targetProcessName = g_processList[(size_t)idx - 1].processName;
                                if (IsIconic(g_targetWindow)) ShowWindow(g_targetWindow, SW_RESTORE);
                                ForceForeground(g_targetWindow);
                                Sleep(200);
                                return true;
                            }
                        }
                    }
                }
            }

            struct FindData { std::string title; HWND result; };
            FindData fd = { targetTitle, NULL };

            EnumWindows([](HWND hw, LPARAM lp) -> BOOL {
                auto* data = (FindData*)lp;
                if (!IsWindowVisible(hw)) return TRUE;
                if (hw == g_hwnd || hw == GetShellWindow()) return TRUE;

                // Filter out child/tool/owned windows (match RefreshProcessList logic)
                LONG_PTR style = GetWindowLongPtr(hw, GWL_STYLE);
                LONG_PTR exStyle = GetWindowLongPtr(hw, GWL_EXSTYLE);
                if (style & WS_CHILD) return TRUE;
                if (exStyle & WS_EX_TOOLWINDOW) return TRUE;
                if (GetWindow(hw, GW_OWNER) != NULL) return TRUE;

                char title[256] = {};
                GetWindowTextA(hw, title, sizeof(title));
                std::string t(title);

                // Get process name for matching
                std::string proc = "";
                DWORD pid = 0;
                GetWindowThreadProcessId(hw, &pid);
                if (pid) {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                    if (hProc) {
                        char pname[MAX_PATH] = {};
                        HMODULE hMod; DWORD cbNeeded;
                        if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded))
                            GetModuleBaseNameA(hProc, hMod, pname, sizeof(pname));
                        CloseHandle(hProc);
                        proc = pname;
                    }
                }

                // Case-insensitive substring search
                std::string tLower = t, searchLower = data->title;
                std::transform(tLower.begin(), tLower.end(), tLower.begin(), ::tolower);
                std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::tolower);
                std::string pLower = proc;
                std::transform(pLower.begin(), pLower.end(), pLower.begin(), ::tolower);

                if (!searchLower.empty() && (tLower.find(searchLower) != std::string::npos || pLower.find(searchLower) != std::string::npos)) {
                    data->result = hw;
                    return FALSE; // Stop enumeration
                }
                return TRUE;
                }, (LPARAM)&fd);

            if (fd.result) {
                g_targetWindow = fd.result;
                char pname[MAX_PATH] = {};
                DWORD pid = 0;
                GetWindowThreadProcessId(fd.result, &pid);
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProc) {
                    HMODULE hMod; DWORD cbNeeded;
                    if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded))
                        GetModuleBaseNameA(hProc, hMod, pname, sizeof(pname));
                    CloseHandle(hProc);
                }
                g_targetProcessName = pname;
                if (IsIconic(g_targetWindow)) ShowWindow(g_targetWindow, SW_RESTORE);
                ForceForeground(g_targetWindow);
                Sleep(200);
                return true;
            }
            return false;
        }

        if (action.action == "open_app") {
            std::string appName = action.value;
            std::string appLower = appName;
            std::transform(appLower.begin(), appLower.end(), appLower.begin(), ::tolower);

            if (appLower.find(".exe") == std::string::npos && appLower.find(".lnk") == std::string::npos) {
                appName += ".exe";
            }

            HINSTANCE result = ShellExecuteA(NULL, "open", appName.c_str(), NULL, NULL, SW_SHOW);
            if ((INT_PTR)result <= 32) {
                std::string paths[] = {
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
                    "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
                    "C:\\Program Files\\Microsoft VS Code\\Code.exe",
                };
                bool found = false;
                for (const auto& path : paths) {
                    std::string pathLower = path;
                    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);
                    if (pathLower.find(appLower) != std::string::npos) {
                        ShellExecuteA(NULL, "open", path.c_str(), NULL, NULL, SW_SHOW);
                        found = true;
                        break;
                    }
                }
                if (!found) return false;
            }

            // Try to auto-attach to the first suitable foreground window.
            for (int i = 0; i < 12; i++) {
                Sleep(500);
                HWND hFg = GetForegroundWindow();
                if (hFg && hFg != g_hwnd && hFg != GetShellWindow()) {
                    DWORD pid; GetWindowThreadProcessId(hFg, &pid);
                    DWORD myPid = GetCurrentProcessId();
                    if (pid == myPid) continue;

                    // Skip invisible/owned/tool/child windows
                    if (!IsWindowVisible(hFg)) continue;
                    LONG_PTR style = GetWindowLongPtr(hFg, GWL_STYLE);
                    LONG_PTR exStyle = GetWindowLongPtr(hFg, GWL_EXSTYLE);
                    if (style & WS_CHILD) continue;
                    if (exStyle & WS_EX_TOOLWINDOW) continue;
                    if (GetWindow(hFg, GW_OWNER) != NULL) continue;

                    char pname[MAX_PATH] = "<unknown>";
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                    if (hProc) {
                        HMODULE hMod; DWORD cbNeeded;
                        if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded))
                            GetModuleBaseNameA(hProc, hMod, pname, sizeof(pname));
                        CloseHandle(hProc);
                    }

                    if (strlen(pname) > 0 && strcmp(pname, "<unknown>") != 0) {
                        g_targetWindow = hFg;
                        g_targetProcessName = pname;
                        g_lastActionResult = "Successfully opened and attached to " + std::string(pname);
                        return true;
                    }
                }
            }

            g_lastActionResult = "Action 'open_app' executed, but could not detect new window. Process may be running in background.";
            return true;
        }

        // --- Helper: SendInput-based key press/release with logging ---
        auto SendKey = [](WORD vk, bool keyUp) {
            INPUT inp = {};
            inp.type = INPUT_KEYBOARD;
            inp.ki.wVk = vk;
            inp.ki.wScan = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
            inp.ki.dwFlags = (keyUp ? KEYEVENTF_KEYUP : 0);
            if (vk == VK_UP || vk == VK_DOWN || vk == VK_LEFT || vk == VK_RIGHT ||
                vk == VK_HOME || vk == VK_END || vk == VK_PRIOR || vk == VK_NEXT ||
                vk == VK_INSERT || vk == VK_DELETE || vk == VK_NUMLOCK) {
                inp.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
            }
            UINT sent = SendInput(1, &inp, sizeof(INPUT));
            char dbg[128];
            sprintf_s(dbg, "[Agent] SendKey vk=0x%02X scan=0x%02X %s sent=%u fg=0x%p\n",
                vk, inp.ki.wScan, keyUp ? "UP" : "DOWN", sent, GetForegroundWindow());
            OutputDebugStringA(dbg);
            };

        // press_key doesn't need a UI element target
        if (action.action == "press_key") {
            std::string keyStr = action.value;
            // Convert to lowercase for matching
            std::transform(keyStr.begin(), keyStr.end(), keyStr.begin(), ::tolower);

            // Parse modifier+key combos like "ctrl+a", "ctrl+shift+s"
            bool ctrl = false, shift = false, alt = false;
            std::string mainKey = keyStr;

            while (true) {
                if (mainKey.substr(0, 5) == "ctrl+") { ctrl = true; mainKey = mainKey.substr(5); }
                else if (mainKey.substr(0, 6) == "shift+") { shift = true; mainKey = mainKey.substr(6); }
                else if (mainKey.substr(0, 4) == "alt+") { alt = true; mainKey = mainKey.substr(4); }
                else break;
            }

            WORD vk = ParseKeyName(mainKey);
            if (vk == 0) {
                char dbg[128];
                sprintf_s(dbg, "[Agent] press_key FAILED: unknown key '%s'\n", mainKey.c_str());
                OutputDebugStringA(dbg);
                return false;
            }

            // Force target window to foreground
            ForceForeground(g_targetWindow);

            char dbg[256];
            sprintf_s(dbg, "[Agent] press_key: '%s' vk=0x%02X ctrl=%d shift=%d alt=%d target=0x%p fg=0x%p\n",
                action.value.c_str(), vk, ctrl, shift, alt, g_targetWindow, GetForegroundWindow());
            OutputDebugStringA(dbg);

            // Press modifiers
            if (ctrl) SendKey(VK_CONTROL, false);
            if (shift) SendKey(VK_SHIFT, false);
            if (alt) SendKey(VK_MENU, false);
            Sleep(30);

            // Press and release the main key
            SendKey(vk, false);
            Sleep(30);
            SendKey(vk, true);
            Sleep(30);

            // Release modifiers (reverse order)
            if (alt) SendKey(VK_MENU, true);
            if (shift) SendKey(VK_SHIFT, true);
            if (ctrl) SendKey(VK_CONTROL, true);

            return true;
        }

        // scroll doesn't necessarily need a specific target
        if (action.action == "scroll") {
            std::string dir = action.value;
            std::transform(dir.begin(), dir.end(), dir.begin(), ::tolower);
            int scrollAmount = (dir == "up") ? 120 * 3 : -120 * 3;  // 3 notches

            // If locator provided, scroll over that element; otherwise scroll at center of window
            RECT targetRect;
            if (!action.locator.empty() && action.locator.is_object()) {
                CoInitializeEx(NULL, COINIT_MULTITHREADED);
                IUIAutomation* pAuto = NULL;
                CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&pAuto);
                IUIAutomationElement* pRoot = NULL;
                if (pAuto) pAuto->ElementFromHandle(g_targetWindow, &pRoot);
                if (pRoot) {
                    IUIAutomationElement* el = FindElement(pAuto, pRoot, action.locator);
                    if (el) {
                        el->get_CurrentBoundingRectangle(&targetRect);
                        SetCursorPos((targetRect.left + targetRect.right) / 2, (targetRect.top + targetRect.bottom) / 2);
                        el->Release();
                    }
                    pRoot->Release();
                }
                if (pAuto) pAuto->Release();
                CoUninitialize();
            }
            else {
                // Scroll at center of target window
                GetWindowRect(g_targetWindow, &targetRect);
                SetCursorPos((targetRect.left + targetRect.right) / 2, (targetRect.top + targetRect.bottom) / 2);
            }

            mouse_event(MOUSEEVENTF_WHEEL, 0, 0, (DWORD)scrollAmount, 0);
            return true;
        }

        // click and type need a target element
        CoInitializeEx(NULL, COINIT_MULTITHREADED);
        IUIAutomation* pAutomation = NULL;
        CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&pAutomation);
        IUIAutomationElement* pRoot = NULL;
        pAutomation->ElementFromHandle(g_targetWindow, &pRoot);

        if (!pRoot) { pAutomation->Release(); CoUninitialize(); return false; }

        IUIAutomationElement* target = FindElement(pAutomation, pRoot, action.locator);
        bool result = false;

        if (target) {
            if (action.action == "click" || action.action == "right_click" || action.action == "double_click") {
                // Fallback chain: Invoke → SelectionItem → ExpandCollapse → Toggle → Mouse
                IUnknown* pat = NULL;
                bool usedPattern = false;

                if (action.action == "click") {
                    // 1. Try Invoke
                    if (SUCCEEDED(target->GetCurrentPattern(UIA_InvokePatternId, &pat)) && pat) {
                        ((IUIAutomationInvokePattern*)pat)->Invoke();
                        pat->Release();
                        usedPattern = true; result = true;
                    }
                    // 2. Try SelectionItem
                    if (!usedPattern && SUCCEEDED(target->GetCurrentPattern(UIA_SelectionItemPatternId, &pat)) && pat) {
                        ((IUIAutomationSelectionItemPattern*)pat)->Select();
                        pat->Release();
                        usedPattern = true; result = true;
                    }
                    // 3. Try ExpandCollapse  
                    if (!usedPattern && SUCCEEDED(target->GetCurrentPattern(UIA_ExpandCollapsePatternId, &pat)) && pat) {
                        ExpandCollapseState state;
                        ((IUIAutomationExpandCollapsePattern*)pat)->get_CurrentExpandCollapseState(&state);
                        if (state == ExpandCollapseState_Collapsed)
                            ((IUIAutomationExpandCollapsePattern*)pat)->Expand();
                        else
                            ((IUIAutomationExpandCollapsePattern*)pat)->Collapse();
                        pat->Release();
                        usedPattern = true; result = true;
                    }
                    // 4. Try Toggle
                    if (!usedPattern && SUCCEEDED(target->GetCurrentPattern(UIA_TogglePatternId, &pat)) && pat) {
                        ((IUIAutomationTogglePattern*)pat)->Toggle();
                        pat->Release();
                        usedPattern = true; result = true;
                    }
                }

                // 5. Fallback: Focus + mouse simulation
                if (!usedPattern) {
                    ForceForeground(g_targetWindow);
                    target->SetFocus();
                    RECT r; target->get_CurrentBoundingRectangle(&r);
                    int cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
                    SetCursorPos(cx, cy);
                    Sleep(50);

                    if (action.action == "right_click") {
                        mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
                        mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
                    }
                    else if (action.action == "double_click") {
                        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
                        Sleep(50);
                        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
                    }
                    else {
                        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
                    }
                    result = true;
                }
            }
            else if (action.action == "type") {
                // Focus the target element first, then use HumanType
                ForceForeground(g_targetWindow);
                target->SetFocus();
                Sleep(100);
                std::string toType = StripMarkdownCodeFenceForTyping(action.value);

                if (LooksLikeCodeText(toType) || toType.size() > 250) {
                    // Paste (clipboard + Ctrl+V)
                    std::wstring w = s2ws(toType);
                    std::wstring prevClip;
                    bool hasPrev = GetClipboardTextW(prevClip);
                    SetClipboardTextW(w);
                    Sleep(60);
                    SendModifier(VK_CONTROL, true);
                    SendKeyOnce('V');
                    SendModifier(VK_CONTROL, false);
                    Sleep(180);
                    if (hasPrev) SetClipboardTextW(prevClip);
                    g_lastActionResult = "[TYPE] Pasted via Ctrl+V.";
                    result = true;
                }
                else {
                    HumanType(toType, false, 4);
                    result = true;
                }
            }
            else if (action.action == "hover") {
                target->SetFocus();
                RECT r; target->get_CurrentBoundingRectangle(&r);
                SetCursorPos((r.left + r.right) / 2, (r.top + r.bottom) / 2);
                Sleep(500); // Wait for tooltip/dropdown to appear
                result = true;
            }
            target->Release();
        }

        pRoot->Release();
        pAutomation->Release();
        CoUninitialize();

        // Handle actions that don't need a specific element target
        if (action.action == "wait_for") {
            // Wait for an element to appear in the UI (polling)
            bool elementFound = false;
            for (int attempt = 0; attempt < 20 && !elementFound && isRunning; attempt++) {
                Sleep(500);
                CoInitializeEx(NULL, COINIT_MULTITHREADED);
                IUIAutomation* pA2 = NULL;
                CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&pA2);
                if (pA2) {
                    IUIAutomationElement* pR2 = NULL;
                    pA2->ElementFromHandle(g_targetWindow, &pR2);
                    if (pR2) {
                        IUIAutomationElement* el = FindElement(pA2, pR2, action.locator);
                        if (el) { elementFound = true; el->Release(); }
                        pR2->Release();
                    }
                    pA2->Release();
                }
                CoUninitialize();
            }
            return elementFound;
        }


        if (action.action == "clipboard") {
            std::string op = action.value;
            std::transform(op.begin(), op.end(), op.begin(), ::tolower);
            ForceForeground(g_targetWindow);
            if (op == "copy") {
                SendKey(VK_CONTROL, false); Sleep(30);
                SendKey('C', false); Sleep(20); SendKey('C', true); Sleep(30);
                SendKey(VK_CONTROL, true);
                return true;
            }
            else if (op == "paste") {
                SendKey(VK_CONTROL, false); Sleep(30);
                SendKey('V', false); Sleep(20); SendKey('V', true); Sleep(30);
                SendKey(VK_CONTROL, true);
                return true;
            }
            else if (op == "cut") {
                SendKey(VK_CONTROL, false); Sleep(30);
                SendKey('X', false); Sleep(20); SendKey('X', true); Sleep(30);
                SendKey(VK_CONTROL, true);
                return true;
            }
            else if (op == "select_all") {
                SendKey(VK_CONTROL, false); Sleep(30);
                SendKey('A', false); Sleep(20); SendKey('A', true); Sleep(30);
                SendKey(VK_CONTROL, true);
                return true;
            }
            // "set" operation: set clipboard text
            SetClipboardText(action.value);
            return true;
        }

        return result;
    }

    // Helper: Convert BSTR to std::string
    static std::string BstrToStdString(BSTR bstr) {
        if (!bstr) return "";
        int len = WideCharToMultiByte(CP_UTF8, 0, bstr, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return "";
        std::string result(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, bstr, -1, &result[0], len, NULL, NULL);
        return result;
    }

    // Scored element matching: returns best match above threshold
    IUIAutomationElement* FindElement(IUIAutomation* pAuto, IUIAutomationElement* root, json locator) {
        IUIAutomationTreeWalker* pWalker = NULL;
        pAuto->get_ControlViewWalker(&pWalker);
        if (!pWalker) return NULL;

        std::vector<IUIAutomationElement*> q;
        root->AddRef();
        q.push_back(root);

        std::string locName = locator.value("name", "");
        std::string locType = locator.value("controlType", "");
        std::string locId = locator.value("automationId", "");

        IUIAutomationElement* bestMatch = NULL;
        int bestScore = 0;
        const int MIN_SCORE = 15;  // Minimum threshold to accept a match

        int checked = 0;
        int head = 0;

        while (head < (int)q.size() && checked < 800) {
            IUIAutomationElement* curr = q[head++];
            checked++;

            // Skip root element itself
            if (checked > 1) {
                int score = 0;

                // AutomationId check (strongest signal)
                if (!locId.empty()) {
                    BSTR bId = NULL; curr->get_CurrentAutomationId(&bId);
                    std::string elemId = BstrToStdString(bId);
                    SysFreeString(bId);
                    if (!elemId.empty()) {
                        if (elemId == locId) score += 50;  // Exact ID match
                    }
                }

                // Name check
                if (!locName.empty()) {
                    BSTR bName = NULL; curr->get_CurrentName(&bName);
                    std::string elemName = BstrToStdString(bName);
                    SysFreeString(bName);
                    if (!elemName.empty()) {
                        if (elemName == locName) score += 30;  // Exact name
                        else if (!CaselessFind(elemName, locName).empty()) score += 15;  // Substring
                    }
                }

                // ControlType check
                if (!locType.empty()) {
                    CONTROLTYPEID ct = 0; curr->get_CurrentControlType(&ct);
                    std::string ctStr = ControlTypeIdToString(ct);
                    if (ctStr == locType) score += 20;
                }

                // Update best match
                if (score > bestScore && score >= MIN_SCORE) {
                    if (bestMatch) bestMatch->Release();
                    bestMatch = curr;
                    bestMatch->AddRef();
                    bestScore = score;

                    // Perfect match (all specified fields matched) — stop early
                    int maxPossible = 0;
                    if (!locId.empty()) maxPossible += 50;
                    if (!locName.empty()) maxPossible += 30;
                    if (!locType.empty()) maxPossible += 20;
                    if (score >= maxPossible) {
                        // Release remaining queue and return immediately
                        curr->Release();
                        for (size_t i = head; i < q.size(); i++) q[i]->Release();
                        pWalker->Release();
                        return bestMatch;
                    }
                }
            }

            // Enqueue children
            IUIAutomationElement* child = NULL;
            pWalker->GetFirstChildElement(curr, &child);
            while (child) {
                q.push_back(child);
                IUIAutomationElement* next = NULL;
                pWalker->GetNextSiblingElement(child, &next);
                child = next;
            }

            if (curr != bestMatch) curr->Release();
        }

        pWalker->Release();
        // Cleanup remaining queue
        for (size_t i = head; i < q.size(); i++) {
            if (q[i] != bestMatch) q[i]->Release();
        }

        return bestMatch; // Caller releases
    }

    BSTR s2bstr(const std::string& s) {
        int len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), s.length(), 0, 0);
        BSTR bstr = SysAllocStringLen(0, len);
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), s.length(), bstr, len);
        return bstr;
    }
};

AgentCore g_agent;

// =========================================================
// TELEGRAM COMMAND DISPATCHER
// =========================================================
// =========================================================
void TelegramProcessCommandImpl(const std::string& chatId, const std::string& rawText) {
    // 1. TRIM WHITESPACE
    std::string text = rawText;
    text.erase(0, text.find_first_not_of(" \t\n\r"));
    text.erase(text.find_last_not_of(" \t\n\r") + 1);

    {
        std::string dbg = "[Telegram] Command: '" + text + "' (Len: " + std::to_string((int)text.length()) + ")\n";
        OutputDebugStringA(dbg.c_str());
    }

    // If the agent is waiting for user input, accept any non-command text as a reply.
    if (g_waitingForUserInput) {
        if (!text.empty() && text[0] != '/') {
            {
                std::lock_guard<std::mutex> lock(g_telegramMutex);
                g_telegramInputBuffer = text;
                g_telegramInputReady = true;
            }
            TelegramBridge::SendMessage("[OK] Received.");
            return;
        }
    }

    // Handle /start command
    if (text == "/start") {
        g_telegramState = TelegramState::Idle;
        g_telegramAiProviderIdx = -1;
        TelegramBridge::SendMessage("Welcome! OfradrAgent is ready. Send a command like /run <prompt> to get started, or /help to see all commands.");
        return;
    }

    // /cancel - cancel any multi-step flow
    if (text == "/cancel") {
        g_telegramState = TelegramState::Idle;
        //g_telegramLoginUsername.clear();
        g_telegramAiProviderIdx = -1;
        TelegramBridge::SendMessage("[OK] Cancelled.");
        return;
    }


    // Handle AI provider/model selection flow
    if (g_telegramState == TelegramState::WaitingForAiProvider) {
        if (!text.empty() && text[0] == '/') {
            TelegramBridge::SendMessage("[AI] Reply with a provider number/name, or /cancel.");
            return;
        }

        auto SendModelsListForProvider = [](int providerIdx) {
            AIProvider pType;
            bool fetched = false;
            std::string provName;
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                if (providerIdx < 0 || providerIdx >= (int)g_providers.size()) {
                    TelegramBridge::SendMessage("[AI] Invalid provider index.");
                    return;
                }
                pType = g_providers[providerIdx].type;
                fetched = g_providers[providerIdx].modelsFetched;
                provName = g_providers[providerIdx].name;
            }

            if (!fetched) {
                Api::FetchModelsForProvider(pType);
                TelegramBridge::SendMessage("[AI] Fetching models for " + provName + "...");
                std::thread([providerIdx, provName]() {
                    for (int i = 0; i < 30; i++) {
                        Sleep(500);
                        bool ready = false;
                        {
                            std::lock_guard<std::mutex> lock(g_dataMutex);
                            if (providerIdx >= 0 && providerIdx < (int)g_providers.size()) {
                                ready = g_providers[providerIdx].modelsFetched && !g_providers[providerIdx].models.empty();
                            }
                        }
                        if (ready) break;
                    }

                    std::string msg = "[AI] Models for " + provName + ":\n";
                    {
                        std::lock_guard<std::mutex> lock(g_dataMutex);
                        if (providerIdx < 0 || providerIdx >= (int)g_providers.size()) {
                            TelegramBridge::SendMessage("[AI] Provider changed. Send /ai models again.");
                            return;
                        }
                        auto& prov = g_providers[providerIdx];
                        if (!prov.modelsFetched || prov.models.empty()) {
                            TelegramBridge::SendMessage("[AI] No models available (missing key/provider offline?).");
                            return;
                        }
                        int shown = 0;
                        for (int j = 0; j < (int)prov.models.size() && shown < 25; j++, shown++) {
                            msg += std::to_string(j + 1) + ". " + prov.models[j].displayName;
                            if (providerIdx == g_currProviderIdx && j == g_currModelIdx) msg += " [CURRENT]";
                            msg += "\n";
                        }
                        if ((int)prov.models.size() > 25) msg += "... (showing first 25)\n";
                    }
                    msg += "\nReply with a model number (or type part of the model id/name).";
                    g_telegramState = TelegramState::WaitingForAiModel;
                    TelegramBridge::SendMessage(msg);
                    }).detach();
                return;
            }

            std::string msg = "[AI] Models for " + provName + ":\n";
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                auto& prov = g_providers[providerIdx];
                if (prov.models.empty()) {
                    TelegramBridge::SendMessage("[AI] No models available (missing key/provider offline?).");
                    return;
                }
                int shown = 0;
                for (int j = 0; j < (int)prov.models.size() && shown < 25; j++, shown++) {
                    msg += std::to_string(j + 1) + ". " + prov.models[j].displayName;
                    if (providerIdx == g_currProviderIdx && j == g_currModelIdx) msg += " [CURRENT]";
                    msg += "\n";
                }
                if ((int)prov.models.size() > 25) msg += "... (showing first 25)\n";
            }
            msg += "\nReply with a model number (or type part of the model id/name).";
            g_telegramState = TelegramState::WaitingForAiModel;
            TelegramBridge::SendMessage(msg);
            };

        int selected = -1;
        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            // numeric
            bool allDigits = !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
            if (allDigits) {
                try { selected = std::stoi(text) - 1; }
                catch (...) { selected = -1; }
            }
            if (selected < 0) {
                // name match
                std::string q = text;
                std::transform(q.begin(), q.end(), q.begin(), ::tolower);
                for (int i = 0; i < (int)g_providers.size(); i++) {
                    std::string n = g_providers[i].name;
                    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
                    if (n.find(q) != std::string::npos) { selected = i; break; }
                }
            }
            if (selected >= 0 && selected < (int)g_providers.size()) {
                g_currProviderIdx = selected;
                g_currModelIdx = 0;
                g_telegramAiProviderIdx = selected;
            }
            else {
                selected = -1;
            }
        }

        if (selected < 0) {
            TelegramBridge::SendMessage("[AI] Provider not found. Reply with the number from /ai, or /cancel.");
            return;
        }

        // Immediately show models after provider selection
        TelegramBridge::SendMessage("[AI] Provider set. Listing models...");
        SendModelsListForProvider(selected);
        return;
    }

    if (g_telegramState == TelegramState::WaitingForAiModel) {
        if (!text.empty() && text[0] == '/') {
            TelegramBridge::SendMessage("[AI] Reply with a model number/id, or /cancel.");
            return;
        }

        bool ok = false;
        std::string chosen;
        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            if (!g_providers.empty() && g_currProviderIdx >= 0 && g_currProviderIdx < (int)g_providers.size()) {
                auto& prov = g_providers[g_currProviderIdx];
                if (prov.models.empty()) {
                    ok = false;
                }
                else {
                    // numeric index
                    bool allDigits = !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
                    int idx = -1;
                    if (allDigits) {
                        try { idx = std::stoi(text) - 1; }
                        catch (...) { idx = -1; }
                        if (idx >= 0 && idx < (int)prov.models.size()) {
                            g_currModelIdx = idx;
                            chosen = prov.models[g_currModelIdx].displayName;
                            ok = true;
                        }
                    }
                    if (!ok) {
                        // id/display substring match
                        std::string q = text;
                        std::transform(q.begin(), q.end(), q.begin(), ::tolower);
                        for (int i = 0; i < (int)prov.models.size(); i++) {
                            std::string id = prov.models[i].id;
                            std::string dn = prov.models[i].displayName;
                            std::transform(id.begin(), id.end(), id.begin(), ::tolower);
                            std::transform(dn.begin(), dn.end(), dn.begin(), ::tolower);
                            if (id.find(q) != std::string::npos || dn.find(q) != std::string::npos) {
                                g_currModelIdx = i;
                                chosen = prov.models[g_currModelIdx].displayName;
                                ok = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (!ok) {
            TelegramBridge::SendMessage("[AI] Model not found. Send /ai models to list models, or /cancel.");
            return;
        }

        g_telegramState = TelegramState::Idle;
        g_telegramAiProviderIdx = -1;
        TelegramBridge::SendMessage("[AI] Model set: " + chosen);
        return;
    }

    // /help - show commands
    if (text == "/help" || text == "/start") {
        bool sent = TelegramBridge::SendMessage(
            "[COMMANDS]\n"
            "/run <goal> - Run the agent with a goal\n"
            "/apps - List running applications\n"
            "/gui [on|off|toggle|<cmd>] - Show/hide GUI (or run a command with GUI briefly shown)\n"
            "/login - Login via Telegram (multi-step)\n"
            "/ai - Select AI provider/model\n"
            "/cancel - Cancel current flow\n"
            "/screenshot - Take a screenshot\n"
            "/status - Show agent status\n"
            "/stop - Stop the agent\n"
            "/help - Show this message"
        );
        if (!sent) OutputDebugStringA("[Telegram] ERROR: Failed to send /help response\n");
        return;
    }

    // /ai - provider/model selection
    if (text.rfind("/ai", 0) == 0) {

        std::string arg = (text.size() > 3) ? text.substr(3) : "";
        arg.erase(0, arg.find_first_not_of(" \t\n\r"));
        arg.erase(arg.find_last_not_of(" \t\n\r") + 1);
        std::string argLower = arg;
        std::transform(argLower.begin(), argLower.end(), argLower.begin(), ::tolower);

        auto SendProviders = []() {
            std::string msg = "[AI] Providers:\n";
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                for (int i = 0; i < (int)g_providers.size(); i++) {
                    msg += std::to_string(i + 1) + ". " + g_providers[i].name;
                    if (i == g_currProviderIdx) msg += " [CURRENT]";
                    msg += "\n";
                }
            }
            msg += "\nReply with a provider number/name, or send /ai models to list models for the current provider.";
            g_telegramState = TelegramState::WaitingForAiProvider;
            TelegramBridge::SendMessage(msg);
            };

        auto SendModels = []() {
            std::string msg;
            AIProvider pType;
            bool fetched = false;
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                if (g_providers.empty()) { TelegramBridge::SendMessage("[AI] No providers."); return; }
                if (g_currProviderIdx < 0 || g_currProviderIdx >= (int)g_providers.size()) { g_currProviderIdx = 0; }
                pType = g_providers[g_currProviderIdx].type;
                fetched = g_providers[g_currProviderIdx].modelsFetched;
                msg = "[AI] Models for " + g_providers[g_currProviderIdx].name + ":\n";
            }
            if (!fetched) {
                Api::FetchModelsForProvider(pType);
                TelegramBridge::SendMessage("[AI] Fetching models... send /ai models again in a few seconds.");
                return;
            }

            int count = 0;
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                auto& prov = g_providers[g_currProviderIdx];
                if (prov.models.empty()) {
                    TelegramBridge::SendMessage("[AI] No models available (missing key/provider offline?).");
                    return;
                }
                for (int i = 0; i < (int)prov.models.size() && count < 25; i++, count++) {
                    msg += std::to_string(i + 1) + ". " + prov.models[i].displayName;
                    if (i == g_currModelIdx) msg += " [CURRENT]";
                    msg += "\n";
                }
                if ((int)prov.models.size() > 25) msg += "... (showing first 25)\n";
            }
            msg += "\nReply with a model number (or type part of the model id/name).";
            g_telegramState = TelegramState::WaitingForAiModel;
            TelegramBridge::SendMessage(msg);
            };

        if (argLower.empty()) {
            // Status + providers
            std::string st;
            {
                std::lock_guard<std::mutex> lock(g_dataMutex);
                st = "[AI] Current: " + (g_providers.empty() ? std::string("<none>") : g_providers[g_currProviderIdx].name);
                if (!g_providers.empty() && !g_providers[g_currProviderIdx].models.empty()) {
                    if (g_currModelIdx >= (int)g_providers[g_currProviderIdx].models.size()) g_currModelIdx = 0;
                    st += " / " + g_providers[g_currProviderIdx].models[g_currModelIdx].displayName;
                }
                st += "\n\n";
            }
            TelegramBridge::SendMessage(st);
            SendProviders();
            return;
        }
        if (argLower == "providers") { SendProviders(); return; }
        if (argLower == "models") { SendModels(); return; }
        if (argLower.rfind("provider", 0) == 0) {
            std::string q = arg.substr(std::string("provider").size());
            q.erase(0, q.find_first_not_of(" \t\n\r"));
            if (q.empty()) { SendProviders(); return; }
            g_telegramState = TelegramState::WaitingForAiProvider;
            TelegramProcessCommandImpl(chatId, q);
            return;
        }
        if (argLower.rfind("model", 0) == 0) {
            std::string q = arg.substr(std::string("model").size());
            q.erase(0, q.find_first_not_of(" \t\n\r"));
            if (q.empty()) { SendModels(); return; }
            g_telegramState = TelegramState::WaitingForAiModel;
            TelegramProcessCommandImpl(chatId, q);
            return;
        }

        // Unknown subcommand -> show help
        TelegramBridge::SendMessage("[AI] Usage: /ai, /ai providers, /ai models, /ai provider <name|num>, /ai model <name|num>");
        return;
    }

    // /gui - show/hide the overlay window
    if (text.rfind("/gui", 0) == 0) {
        std::string arg = (text.size() > 4) ? text.substr(4) : "";
        arg.erase(0, arg.find_first_not_of(" \t\n\r"));
        arg.erase(arg.find_last_not_of(" \t\n\r") + 1);

        std::string argLower = arg;
        std::transform(argLower.begin(), argLower.end(), argLower.begin(), ::tolower);

        bool curVisible = false;
        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            curVisible = g_isVisible;
        }

        if (argLower.empty() || argLower == "toggle") {
            bool wantVisible = !curVisible;
            RequestGuiVisible(wantVisible);
            TelegramBridge::SendMessage(std::string("[GUI] ") + (wantVisible ? "Showing" : "Hiding"));
            return;
        }
        if (argLower == "on" || argLower == "show") {
            RequestGuiVisible(true);
            TelegramBridge::SendMessage("[GUI] Showing.");
            return;
        }
        if (argLower == "off" || argLower == "hide") {
            RequestGuiVisible(false);
            TelegramBridge::SendMessage("[GUI] Hidden.");
            return;
        }

        // /gui <command...> : briefly show GUI while processing the command
        bool restoreVisible = curVisible;
        RequestGuiVisible(true);
        TelegramBridge::SendMessage("[GUI] Showing for this command...");
        TelegramProcessCommandImpl(chatId, arg);
        RequestGuiVisible(restoreVisible);
        return;
    }



    // /status - show current status
    if (text == "/status") {
        std::string status = "[STATUS]\n";
        status += "Running: " + std::string(g_agent.isRunning ? "Yes" : "No") + "\n";
        status += "Paused: " + std::string(g_agent.isPaused ? "Yes" : "No") + "\n";
        if (!g_agent.currentGoal.empty()) status += "Goal: " + g_agent.currentGoal + "\n";
        status += "Status: " + g_agent.statusMessage + "\n";
        if (g_targetWindow && IsWindow(g_targetWindow)) {
            char title[256] = {};
            GetWindowTextA(g_targetWindow, title, sizeof(title));
            status += "Attached: " + std::string(title) + "\n";
        }
        else {
            status += "Attached: None\n";
        }
        TelegramBridge::SendMessage(status);
        return;
    }

    // /stop - stop the agent
    if (text == "/stop") {
        if (g_agent.isRunning) {
            g_agent.Stop();
            TelegramBridge::SendMessage("[STOPPED] Agent stopped.");
        }
        else {
            TelegramBridge::SendMessage("Agent is not running.");
        }
        return;
    }

    // /apps - list running processes
    if (text == "/apps") {
        TelegramBridge::SendMessage("[APPS] Fetching process list...");

        RefreshProcessList();

        char dbg2[512];
        snprintf(dbg2, sizeof(dbg2), "[Telegram] Process List Size: %d\n", (int)g_processList.size());
        OutputDebugStringA(dbg2);

        if (g_processList.empty()) {
            OutputDebugStringA("[Telegram] Sending empty list warning...\n");
            TelegramBridge::SendMessage("[APPS] No running applications found (or all filtered out).");
            return;
        }

        std::string msg = "[APPS] Running Applications:\n";
        for (size_t i = 0; i < g_processList.size(); i++) {
            std::string line = std::to_string(i + 1) + ". " + g_processList[i].processName + " - " + g_processList[i].title;
            if (g_processList[i].hwnd == g_targetWindow) line += " [ATTACHED]";
            line += "\n";

            // Split if too long (Telegram limit ~4096)
            if (msg.length() + line.length() > 4000) {
                TelegramBridge::SendMessage(msg);
                msg = "[APPS] (Cont...)\n";
            }
            msg += line;
        }
        msg += "\nReply with a number to attach to that app.";
        g_telegramState = TelegramState::WaitingForAppSelection;
        TelegramBridge::SendMessage(msg);
        return;
    }

    // /screenshot - take screenshot
    if (text == "/screenshot") {
        LONG64 seqBefore = g_screenshotSeq;

        CaptureScreenshot();

        LONG64 seqAfter = g_screenshotSeq;

        CapturedImage last;
        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            if (!g_screenshots.empty()) last = g_screenshots.back();
        }

        // g_screenshots is capped at 3 entries, so size-based checks break after the third.
        // Use a capture sequence counter to confirm a fresh screenshot was stored.
        if (seqAfter == seqBefore || last.base64Data.empty()) {
            TelegramBridge::SendMessage("[SCREENSHOT] Not available (screen hidden/black or capture failed).");
            return;
        }

        std::string raw = Base64Decode(last.base64Data);
        std::vector<uint8_t> jpg(raw.begin(), raw.end());

        std::string caption = "Screenshot";
        if (g_targetWindow && IsWindow(g_targetWindow)) {
            char title[256] = {};
            GetWindowTextA(g_targetWindow, title, sizeof(title));
            if (title[0]) caption += std::string(" (attached: ") + title + ")";
        }

        if (!TelegramBridge::SendPhotoJpegBytes(jpg, caption)) {
            TelegramBridge::SendMessage("[SCREENSHOT] Capture OK, but failed to upload to Telegram.");
        }

        // best-effort clear
        raw.assign(raw.size(), '\0');
        raw.clear();
        return;
    }

    // /run <goal> - run the agent
    if (text.substr(0, 4) == "/run" && text.size() > 5) {
        std::string goal = text.substr(5);
        if (g_agent.isRunning) {
            TelegramBridge::SendMessage("Agent is already running! Use /stop first.");
            return;
        }
        g_agent.Start(goal);
        TelegramBridge::SendMessage("[STARTED] Goal: " + goal);
        return;
    }

    // Handle app selection (number reply after /apps)
    if (g_telegramState == TelegramState::WaitingForAppSelection) {
        if (!text.empty() && text[0] == '/') {
            // User typed a command instead of a selection; exit selection mode.
            g_telegramState = TelegramState::Idle;
        }
        try {
            int idx = std::stoi(text);
            if (idx >= 1 && idx <= (int)g_processList.size()) {
                auto& proc = g_processList[idx - 1];
                g_targetWindow = proc.hwnd;
                g_targetProcessName = proc.processName;
                if (IsIconic(g_targetWindow)) ShowWindow(g_targetWindow, SW_RESTORE);
                SetForegroundWindow(g_targetWindow);
                TelegramBridge::SendMessage("[ATTACHED] " + proc.processName + " - " + proc.title);
                g_telegramState = TelegramState::Idle;
                return;
            }
        }
        catch (...) {}
        g_telegramState = TelegramState::Idle;
    }

    // Default: treat as a goal if text is reasonable
    if (!text.empty() && text[0] != '/') {
        if (g_agent.isRunning) {
            TelegramBridge::SendMessage("Agent is busy. Use /stop first.");
        }
        else {
            g_agent.Start(text);
            TelegramBridge::SendMessage("[STARTED] Goal: " + text);
        }
        return;
    }

    TelegramBridge::SendMessage("Unknown command. Use /help for available commands.");
}

void RenderProcessSelector() {
    if (!g_showProcessSelector) return;

    ImGui::OpenPopup("Select Process");
    ImGui::SetNextWindowSize(ImVec2(450, 450), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("Select Process", &g_showProcessSelector)) {
        ImGui::TextColored(g_uiColor, "SELECT TARGET PROCESS");
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::BeginChild("ProcList", ImVec2(0, -40), true)) {
            for (const auto& proc : g_processList) {
                char label[768];
                snprintf(label, sizeof(label), "[%05lu] %s - %s##%p",
                    (unsigned long)proc.pid, proc.processName.c_str(), proc.title.c_str(), (void*)proc.hwnd);
                if (ImGui::Selectable(label, g_targetWindow == proc.hwnd)) {
                    g_targetWindow = proc.hwnd;
                    g_targetProcessName = proc.processName;
                    g_showProcessSelector = false;
                }
            }
            ImGui::EndChild();
        }

        if (ImGui::Button("REFRESH", ImVec2(100, 30))) {
            RefreshProcessList();
        }
        ImGui::SameLine();
        if (ImGui::Button("CLOSE", ImVec2(100, 30))) {
            g_showProcessSelector = false;
        }

        ImGui::EndPopup();
    }
}

// AGENT PAGE (DUPLICATE OF CHAT UI FOR NOW)
// =========================================================
void RenderAgentPage() {
    RenderProcessSelector();

    if (g_showSettings) {
        RenderSettingsPage();
        ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 60.0f);
        if (NeoWaveButton("BACK TO AGENT", { ImGui::GetContentRegionAvail().x, 40.0f })) {
            g_showSettings = false;
        }
    }
    else {
        try {
            // AGENT HEADER
            ImGui::TextColored(g_uiColor, "AUTONOMOUS AGENT");
            ImGui::SameLine();
            ImGui::TextDisabled("(Beta)");

            ImGui::SameLine(ImGui::GetContentRegionAvail().x - 120);
            if (ImGui::Button(g_targetWindow ? "Change App" : "Attach App")) {
                RefreshProcessList();
                g_showProcessSelector = true;
            }

            if (g_targetWindow) {
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Target: %s", g_targetProcessName.c_str());
            }
            else {
                ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Target: None");
            }

            // --- PROVIDER SELECTOR ---
            ImGui::Spacing();
            if (g_providers.empty()) {
                ImGui::TextDisabled("No providers configured.");
            }
            else {
                if (g_currProviderIdx >= (int)g_providers.size()) g_currProviderIdx = 0;

                ImGui::PushItemWidth(130.0f);
                const char* currentProvName = g_providers[g_currProviderIdx].name.c_str();
                if (ImGui::BeginCombo("##prov_sel_ag", currentProvName)) {
                    for (int n = 0; n < (int)g_providers.size(); n++) {
                        bool isSelected = (g_currProviderIdx == n);
                        if (ImGui::Selectable(g_providers[n].name.c_str(), isSelected)) {
                            g_currProviderIdx = n;
                            g_currModelIdx = 0;
                            if (g_providers[n].type == AIProvider::Ollama && !g_providers[n].modelsFetched) Api::FetchModelsForProvider(AIProvider::Ollama);
                        }
                        if (isSelected) ImGui::SetItemDefaultFocus();
                    }
                    ImGui::EndCombo();
                }
                ImGui::SameLine();

                auto& currentProv = g_providers[g_currProviderIdx];
                std::string currentModelName = "Loading...";
                if (!currentProv.models.empty()) {
                    if (g_currModelIdx >= currentProv.models.size()) g_currModelIdx = 0;
                    currentModelName = currentProv.models[g_currModelIdx].displayName;
                }
                else {
                    currentModelName = currentProv.modelsFetched ? "No Models" : "Fetching...";
                }

                ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x);
                if (ImGui::BeginCombo("##mod_sel_ag", currentModelName.c_str())) {
                    for (int n = 0; n < (int)currentProv.models.size(); n++) {
                        bool isSelected = (g_currModelIdx == n);
                        if (ImGui::Selectable(currentProv.models[n].displayName.c_str(), isSelected)) {
                            g_currModelIdx = n;
                        }
                        if (isSelected) ImGui::SetItemDefaultFocus();
                    }
                    ImGui::EndCombo();
                }
                ImGui::PopItemWidth();
                ImGui::PopItemWidth();
            }
            // -----------------------------------------------

            ImGui::PushStyleColor(ImGuiCol_Separator, g_uiColor);
            ImGui::Separator();
            ImGui::PopStyleColor();
            ImGui::Spacing();

            // DYNAMIC FOOTER HEIGHT CALCULATION
            float inputAreaHeight = CalculateInputBoxHeight(g_chatBuffer, ImGui::GetContentRegionAvail().x);
            float toolbarHeight = 50.0f;
            float previewHeight = (!g_screenshots.empty()) ? 60.0f : 0.0f;
            float totalFooterHeight = inputAreaHeight + toolbarHeight + previewHeight + 20.0f;

            // ====== VISUAL STEP TIMELINE ======
            ImGui::BeginChild("AgentLog", ImVec2(0.0f, ImGui::GetContentRegionAvail().y - totalFooterHeight), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);

            // Copy log for rendering.
            // NOTE: RenderAgentPage() is called while g_dataMutex is already held
            // by the main UI render loop. Do NOT lock it again here.
            std::vector<AgentStepLog> logSnapshot = g_agent.executionLog;
            std::string statusSnapshot = g_agent.statusMessage;
            bool runningSnapshot = g_agent.isRunning;
            bool pausedSnapshot = g_agent.isPaused;

            // Always show the latest error prominently (no more "See Log")
            {
                int lastErrIdx = -1;
                for (int i = (int)logSnapshot.size() - 1; i >= 0; i--) {
                    if (!logSnapshot[i].success && !logSnapshot[i].error.empty() && logSnapshot[i].error.find("Goal completed") == std::string::npos) {
                        lastErrIdx = i;
                        break;
                    }
                }
                if (lastErrIdx >= 0) {
                    const auto& e = logSnapshot[lastErrIdx];
                    ImGui::Spacing();
                    ImGui::TextColored(ImVec4(1.0f, 0.25f, 0.25f, 1.0f), "Last Error (Step %d)", e.step);
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Copy##last_err")) {
                        SetClipboardText(e.error);
                    }
                    ImGui::TextWrapped("%s", e.error.c_str());
                    if (!e.rawPlannerResponse.empty()) {
                        if (ImGui::CollapsingHeader("Raw Planner Response##last_err_raw")) {
                            ImGui::BeginChild("raw_last_err", ImVec2(0.0f, 140.0f), true);
                            ImGui::TextUnformatted(e.rawPlannerResponse.c_str());
                            ImGui::EndChild();
                        }
                    }
                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();
                }
            }

            if (logSnapshot.empty() && !runningSnapshot) {
                ImGui::Spacing(); ImGui::Spacing();
                ImGui::TextDisabled("No agent activity yet.");
                ImGui::TextDisabled("Attach a target app, type a goal, and hit Enter.");
                if (!statusSnapshot.empty() && statusSnapshot != "Idle") {
                    ImGui::Spacing();
                    ImGui::TextColored(ImVec4(1, 1, 0, 1), "Status: %s", statusSnapshot.c_str());
                }
            }
            else {
                // ----- HORIZONTAL STEP INDICATOR -----
                if (!logSnapshot.empty()) {
                    ImGui::Spacing();
                    float stepBtnSize = 28.0f;
                    static int selectedStep = -1;

                    for (size_t i = 0; i < logSnapshot.size(); i++) {
                        const auto& step = logSnapshot[i];

                        // Confidence color
                        ImVec4 dotColor;
                        if (step.confidence >= 0.8f) dotColor = ImVec4(0.2f, 1.0f, 0.2f, 1.0f); // Green
                        else if (step.confidence >= 0.5f) dotColor = ImVec4(1.0f, 1.0f, 0.2f, 1.0f); // Yellow
                        else dotColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f); // Red

                        if (!step.success && !step.error.empty() && step.error.find("Goal completed") == std::string::npos) {
                            dotColor = ImVec4(1.0f, 0.2f, 0.2f, 1.0f); // Red for errors
                        }

                        ImGui::PushStyleColor(ImGuiCol_Button, dotColor);
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(dotColor.x * 0.8f, dotColor.y * 0.8f, dotColor.z * 0.8f, 1.0f));

                        char stepLabel[32];
                        snprintf(stepLabel, sizeof(stepLabel), "%d##step_%d", step.step, (int)i);
                        if (ImGui::Button(stepLabel, ImVec2(stepBtnSize, stepBtnSize))) {
                            selectedStep = (int)i;
                        }
                        if (ImGui::IsItemHovered()) {
                            std::string tipText;
                            if (step.reasoning.empty()) tipText = step.goal;
                            else {
                                tipText = step.reasoning;
                                if (tipText.size() > 60) tipText.resize(60);
                            }
                            ImGui::SetTooltip("Step %d: %s (%.0f%% confidence)", step.step, tipText.c_str(), step.confidence * 100.0f);
                        }

                        ImGui::PopStyleColor(2);

                        // Arrow between steps
                        if (i < logSnapshot.size() - 1) {
                            ImGui::SameLine();
                            ImGui::TextDisabled("->");
                            ImGui::SameLine();
                        }
                    }

                    // "Working" indicator
                    if (runningSnapshot) {
                        ImGui::SameLine();
                        ImGui::TextDisabled("->");
                        ImGui::SameLine();
                        float t = (float)ImGui::GetTime();
                        float pulse = 0.5f + 0.5f * sinf(t * 4.0f);
                        ImGui::TextColored(ImVec4(0.0f, pulse, 1.0f, 1.0f), "[...]");
                    }

                    ImGui::Spacing();
                    ImGui::PushStyleColor(ImGuiCol_Separator, g_uiColor);
                    ImGui::Separator();
                    ImGui::PopStyleColor();
                    ImGui::Spacing();

                    // ----- DETAILED STEP CARDS -----
                    int viewIdx = (selectedStep >= 0 && selectedStep < (int)logSnapshot.size())
                        ? selectedStep : (int)logSnapshot.size() - 1;

                    for (int i = (selectedStep >= 0 ? viewIdx : 0); i <= viewIdx; i++) {
                        const auto& step = logSnapshot[i];

                        // Step header with confidence dot
                        ImVec4 confColor;
                        if (step.confidence >= 0.8f) confColor = ImVec4(0.2f, 1.0f, 0.2f, 1.0f);
                        else if (step.confidence >= 0.5f) confColor = ImVec4(1.0f, 1.0f, 0.2f, 1.0f);
                        else confColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);

                        ImGui::TextColored(confColor, "[%.0f%%]", step.confidence * 100.0f);
                        ImGui::SameLine();
                        ImGui::TextColored(ImVec4(0.0f, 1.0f, 1.0f, 1.0f), "STEP %d", step.step);
                        ImGui::SameLine();
                        ImGui::TextDisabled("| %s", step.goal.c_str());

                        // Reasoning card
                        if (!step.reasoning.empty()) {
                            ImGui::Indent(16.0f);
                            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.85f, 1.0f, 1.0f));
                            ImGui::TextWrapped("Thinking: \"%s\"", step.reasoning.c_str());
                            ImGui::PopStyleColor();
                            ImGui::Unindent(16.0f);
                        }

                        // Action summary (if plan contains actions array)
                        if (step.plan.is_object() && step.plan.contains("actions") && step.plan["actions"].is_array()) {
                            ImGui::Indent(16.0f);
                            try {
                                for (const auto& act : step.plan["actions"]) {
                                    std::string actType = act.value("action", "?");
                                    std::string actVal = act.value("value", "");

                                    // Action icon
                                    const char* icon = ">";
                                    if (actType == "click" || actType == "right_click" || actType == "double_click") icon = "[click]";
                                    else if (actType == "type") icon = "[type]";
                                    else if (actType == "press_key") icon = "[key]";
                                    else if (actType == "scroll") icon = "[scroll]";
                                    else if (actType == "hover") icon = "[hover]";
                                    else if (actType == "wait_for") icon = "[wait]";
                                    else if (actType == "switch_window") icon = "[switch]";
                                    else if (actType == "clipboard") icon = "[clip]";

                                    ImGui::TextColored(g_uiColor, "%s", icon);
                                    ImGui::SameLine();

                                    std::string desc = actType;
                                    if (!actVal.empty()) desc += " \"" + actVal + "\"";
                                    if (act.contains("locator") && act["locator"].is_object()) {
                                        std::string locName = act["locator"].value("name", "");
                                        if (!locName.empty()) desc += " on '" + locName + "'";
                                    }
                                    ImGui::TextWrapped("%s", desc.c_str());
                                }
                            }
                            catch (...) { /* json error */ }
                            ImGui::Unindent(16.0f);
                        }

                        // Error display
                        if (!step.success && !step.error.empty() && step.error.find("Goal completed") == std::string::npos) {
                            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "  Error:");
                            ImGui::SameLine();
                            if (ImGui::SmallButton("Copy##step_err")) SetClipboardText(step.error);
                            ImGui::TextWrapped("%s", step.error.c_str());
                        }

                        // Raw planner response (useful for diagnosing 'no actions' / API errors)
                        if (!step.rawPlannerResponse.empty()) {
                            if (ImGui::CollapsingHeader("Raw Planner Response##step_raw")) {
                                ImGui::BeginChild("raw_step", ImVec2(0.0f, 140.0f), true);
                                ImGui::TextUnformatted(step.rawPlannerResponse.c_str());
                                ImGui::EndChild();
                            }
                        }

                        ImGui::Spacing();
                        ImGui::Separator();
                        ImGui::Spacing();
                    }
                }

                // Live status when running
                if (runningSnapshot) {
                    float t2 = (float)ImGui::GetTime();
                    float pulse2 = 0.5f + 0.5f * sinf(t2 * 3.0f);
                    ImGui::TextColored(ImVec4(0.0f, pulse2, 0.5f + pulse2 * 0.5f, 1.0f),
                        "  %s", statusSnapshot.c_str());
                }
                else if (!statusSnapshot.empty() && statusSnapshot != "Idle") {
                    ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "  %s", statusSnapshot.c_str());
                }
            }

            if (g_scrollToBottom) { ImGui::SetScrollHereY(1.0f); g_scrollToBottom = false; }
            ImGui::EndChild();
            ImGui::Separator();

            // PREVIEW AREA
            if (!g_screenshots.empty()) {
                ImGui::Dummy(ImVec2(0.0f, 5.0f));
                ImGui::TextDisabled("Attachments:");
                ImGui::SameLine();
                int itemToDelete = -1;
                for (int i = 0; i < (int)g_screenshots.size(); i++) {
                    ImGui::PushID(i);
                    ImGui::BeginGroup();
                    ImGui::Image((void*)g_screenshots[i].textureView, ImVec2(80.0f, 45.0f), ImVec2(0.0f, 0.0f), ImVec2(1.0f, 1.0f), ImVec4(1.0f, 1.0f, 1.0f, 1.0f), g_uiColor);
                    ImVec2 rectMin = ImGui::GetItemRectMin(); ImVec2 rectMax = ImGui::GetItemRectMax();
                    ImVec2 btnPos = ImVec2(rectMax.x - 16.0f, rectMin.y);
                    ImGui::SetCursorScreenPos(btnPos);
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 0.8f));
                    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
                    if (ImGui::Button("x", ImVec2(16.0f, 16.0f))) itemToDelete = i;
                    ImGui::PopStyleVar(); ImGui::PopStyleColor();
                    ImGui::EndGroup();
                    ImGui::PopID();
                    ImGui::SameLine();
                }
                if (itemToDelete != -1) {
                    if (g_screenshots[itemToDelete].textureView) g_screenshots[itemToDelete].textureView->Release();
                    g_screenshots.erase(g_screenshots.begin() + itemToDelete);
                }
                ImGui::NewLine();
                ImGui::Separator();
            }

            // ====== TOOLBAR ======
            ImGui::Spacing();
            float avail = ImGui::GetContentRegionAvail().x;
            float btnSz = 44.0f;
            float pad = (avail - 4.0f * btnSz) / 5.0f; // 4 buttons

            bool isRunning = g_agent.isRunning;

            ImGui::SetCursorPosX(pad);

            // BUTTON 1: Screenshot (idle) / Pause-Resume (running)
            if (isRunning) {
                if (g_agent.isPaused) {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.7f, 0.2f, 1.0f));
                    if (IconButton(g_icons.Screenshot, "##resume_ag", "RESUME AGENT", { btnSz, btnSz })) {
                        g_agent.Resume();
                    }
                    ImGui::PopStyleColor();
                }
                else {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.7f, 0.1f, 1.0f));
                    if (IconButton(g_icons.Screenshot, "##pause_ag", "PAUSE AGENT", { btnSz, btnSz })) {
                        g_agent.Pause();
                    }
                    ImGui::PopStyleColor();
                }
            }
            else {
                if (IconButton(g_icons.Screenshot, "##cap_ag", "Take Screenshot", { btnSz, btnSz }, false)) CaptureScreenshot();
            }
            ImGui::SameLine(0.0f, pad);

            // BUTTON 2: Inspect (idle) / Stop (running)
            if (isRunning) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
                if (IconButton(g_icons.Inspect, "##stop_ag", "STOP AGENT", { btnSz, btnSz })) {
                    g_agent.Stop();
                }
                ImGui::PopStyleColor();
            }
            else {
                if (IconButton(g_icons.Inspect, "##inspect_ag", "Inspect", { btnSz, btnSz })) {
                    // Normal inspect behavior when idle
                }
            }
            ImGui::SameLine(0.0f, pad);

            // BUTTON 3: Settings (always)
            if (IconButton(g_icons.Settings, "##set_ag", "Settings", { btnSz, btnSz })) g_showSettings = !g_showSettings;
            ImGui::SameLine(0.0f, pad);

            // BUTTON 4: Clear Log (always)
            if (IconButton(g_icons.NewChat, "##clr_ag", "Clear Agent Log", { btnSz, btnSz }, isRunning)) {
                g_agent.executionLog.clear();
                g_agent.statusMessage = "Idle";
            }

            ImGui::Spacing();

            // STATUS BAR (use snapshots, no mutex needed here)
            {
                if (runningSnapshot) {
                    if (pausedSnapshot) {
                        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), "PAUSED | %s", statusSnapshot.c_str());
                    }
                    else {
                        float t = (float)ImGui::GetTime();
                        const char* spinner[] = { "|", "/", "-", "\\" };
                        int spinIdx = (int)(t * 4.0f) % 4;
                        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.5f, 1.0f), "[%s] %s", spinner[spinIdx], statusSnapshot.c_str());
                    }
                }
                else {
                    ImGui::TextWrapped("Status: %s", statusSnapshot.c_str());
                }
            }
            ImGui::Spacing();

            // INPUT (disabled while agent is running)
            bool sendClicked = false;
            if (g_agent.isRunning) {
                // Disabled input while agent works
                ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.4f);
                std::string disabledBuf = "Agent is working...";
                bool dummySend = false;
                FloatingInputGhost("agent_input", "Agent Working...", disabledBuf, FocusState::None, false, dummySend, 0.0f);
                ImGui::PopStyleVar();
            }
            else {
                FloatingInputGhost("agent_input", "Agent Goal...", g_chatBuffer, FocusState::Chat, true, sendClicked, 0.0f);
                if (sendClicked && !g_chatBuffer.empty()) {
                    g_agent.Start(g_chatBuffer);
                    g_chatBuffer.clear();
                }
            }
        }
        catch (const std::exception& ex) {
            MessageBoxA(NULL, ex.what(), "Agent Page Crash", MB_OK | MB_ICONERROR);
        }
        catch (...) {
            MessageBoxA(NULL, "Unknown crash in RenderAgentPage", "Agent Page Crash", MB_OK | MB_ICONERROR);
        }
    }
}



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    SetProcessDPIAware();



    Gdiplus::GdiplusStartupInput gdiplusStartupInput;

    Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);

    // --- LOAD SAVED HOTKEYS ON STARTUP ---
    LoadHotkeys();
    // -------------------------------------

    // --- TELEGRAM: Auto-start if enabled ---
    if (g_telegramEnabled && !g_telegramToken.empty()) {
        TelegramBridge::StartPolling();
    }

    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, HookProc, GetModuleHandle(NULL), 0);
    static ULONGLONG lastHookCheck = GetTickCount64();
   

    // ============================================
    // STEALTH CHANGE: Randomize Class, Empty Name
    // ============================================
    g_randomClassName = GenerateRandomString(12); // Generate "Xk9vL2mP..."

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0, 0, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, g_randomClassName.c_str(), NULL };
    RegisterClassExW(&wc);

    // --- FIX: DYNAMIC HEIGHT BASED ON SCREEN RESOLUTION ---
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int winW = 600;
    int winH = (int)(screenH * 0.75f);
    int posX = (screenW - winW) / 2;
    int posY = (screenH - winH) / 2;

    // Use random string for Class Name, but EMPTY STRING for Window Title
    // This makes it invisible to simple enumeration by Installers.
    g_hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
        g_randomClassName.c_str(), L"", WS_POPUP | WS_THICKFRAME,
        posX, posY, winW, winH, NULL, NULL, wc.hInstance, NULL);



    SetLayeredWindowAttributes(g_hwnd, 0, 255, LWA_ALPHA);
    SetWindowDisplayAffinity(g_hwnd, 0x00000011);

    DXGI_SWAP_CHAIN_DESC sd = { 0 }; sd.BufferCount = 2; sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM; sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT; sd.OutputWindow = g_hwnd; sd.SampleDesc.Count = 1; sd.Windowed = TRUE; sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL fl = D3D_FEATURE_LEVEL_11_0;
    D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, &fl, 1, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, NULL, &g_pd3dDeviceContext);
    ID3D11Texture2D* b; g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&b)); g_pd3dDevice->CreateRenderTargetView(b, NULL, &g_mainRenderTargetView); b->Release();
    // Start hidden by default (controlled via Telegram /gui or hotkey).
    ShowWindow(g_hwnd, g_isVisible ? SW_SHOW : SW_HIDE);

    IMGUI_CHECKVERSION(); ImGui::CreateContext(); ImGui::GetIO().IniFilename = NULL;
    ImGui_ImplWin32_Init(g_hwnd); ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // --- FONT LOADING ---
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->AddFontFromMemoryTTF(custom_data, custom_len, 20.0f);


    // Load Monospace Font for Code Blocks
    ImFontConfig config;
    config.MergeMode = false;
    g_fontMono = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf", 16.0f, &config);
    if (!g_fontMono) g_fontMono = io.Fonts->AddFontDefault(); // Fallback if Consolas is missing
    // --------------------

    // --- PREMIUM UI STYLING ---
    ImGuiStyle& style = ImGui::GetStyle();

    // Smooth rounded corners
    style.WindowRounding = 12.0f;
    style.FrameRounding = 8.0f;
    style.ScrollbarRounding = 8.0f;
    style.GrabRounding = 8.0f;
    style.TabRounding = 6.0f;
    style.ChildRounding = 8.0f;
    style.PopupRounding = 8.0f;

    // Premium spacing
    style.WindowPadding = ImVec2(16.0f, 16.0f);
    style.FramePadding = ImVec2(12.0f, 8.0f);
    style.ItemSpacing = ImVec2(10.0f, 10.0f);
    style.ItemInnerSpacing = ImVec2(8.0f, 6.0f);
    style.ScrollbarSize = 12.0f;
    style.GrabMinSize = 12.0f;

    // Premium borders
    style.WindowBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;
    style.PopupBorderSize = 1.0f;
    style.ChildBorderSize = 1.0f;

    // Dark premium color palette
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.08f, 0.09f, 0.98f);
    style.Colors[ImGuiCol_ChildBg] = ImVec4(0.10f, 0.10f, 0.11f, 0.95f);
    style.Colors[ImGuiCol_PopupBg] = ImVec4(0.10f, 0.10f, 0.12f, 0.98f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.20f, 0.20f, 0.22f, 0.5f);
    style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);

    // Frame colors
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.12f, 0.12f, 0.14f, 1.0f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.16f, 0.16f, 0.18f, 1.0f);
    style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.20f, 0.20f, 0.22f, 1.0f);

    // Title bar (matches window bg for clean look)
    style.Colors[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.08f, 0.09f, 1.0f);
    style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.08f, 0.08f, 0.09f, 1.0f);
    style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.08f, 0.08f, 0.09f, 1.0f);

    // Scrollbar
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.08f, 0.08f, 0.09f, 0.5f);
    style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.25f, 0.25f, 0.28f, 0.8f);
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.35f, 0.35f, 0.38f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.45f, 0.45f, 0.48f, 1.0f);

    // Button colors (accent based)
    style.Colors[ImGuiCol_Button] = ImVec4(0.15f, 0.15f, 0.17f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(g_uiColor.x * 0.3f, g_uiColor.y * 0.3f, g_uiColor.z * 0.3f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(g_uiColor.x * 0.5f, g_uiColor.y * 0.5f, g_uiColor.z * 0.5f, 1.0f);

    // Header colors
    style.Colors[ImGuiCol_Header] = ImVec4(0.15f, 0.15f, 0.17f, 1.0f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(g_uiColor.x * 0.25f, g_uiColor.y * 0.25f, g_uiColor.z * 0.25f, 1.0f);
    style.Colors[ImGuiCol_HeaderActive] = ImVec4(g_uiColor.x * 0.4f, g_uiColor.y * 0.4f, g_uiColor.z * 0.4f, 1.0f);

    // Separator
    style.Colors[ImGuiCol_Separator] = ImVec4(0.20f, 0.20f, 0.22f, 0.5f);
    style.Colors[ImGuiCol_SeparatorHovered] = ImVec4(g_uiColor.x, g_uiColor.y, g_uiColor.z, 0.6f);
    style.Colors[ImGuiCol_SeparatorActive] = ImVec4(g_uiColor.x, g_uiColor.y, g_uiColor.z, 1.0f);

    // Slider/Grab
    style.Colors[ImGuiCol_SliderGrab] = ImVec4(g_uiColor.x * 0.7f, g_uiColor.y * 0.7f, g_uiColor.z * 0.7f, 1.0f);
    style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(g_uiColor.x, g_uiColor.y, g_uiColor.z, 1.0f);

    // Text colors
    style.Colors[ImGuiCol_Text] = ImVec4(0.92f, 0.92f, 0.94f, 1.0f);
    style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.55f, 1.0f);

    // LOAD SVG ICONS
    LoadAllIcons();
    Api::InitProviders();
    Api::RefreshAllModels(); // FETCH MODELS WITH HARDCODED KEYS
   // Api::PerformVersionCheck(); // CHECK FOR UPDATES ON STARTUP

    g_hCursorCross = LoadCursor(NULL, IDC_CROSS);
    g_hCursorArrow = LoadCursor(NULL, IDC_ARROW);

    bool dragging = false; POINT offset = { 0,0 }; bool done = false;
    while (!done) {
        MSG m; while (PeekMessage(&m, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessage(&m); if (m.message == WM_QUIT) done = true; }

        // --- HOOK WATCHDOG ---
        // If system load drops the hook, we re-inject it every 2 seconds
        if (GetTickCount64() - lastHookCheck > 2000) {
            lastHookCheck = GetTickCount64();
            if (g_hKeyboardHook) UnhookWindowsHookEx(g_hKeyboardHook);
            g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, HookProc, GetModuleHandle(NULL), 0);
        }

        // This avoids locking the mutex inside the hook callback
        {
            std::lock_guard<std::mutex> lock(g_inputMutex);
            if (!g_inputQueue.empty()) {
                std::lock_guard<std::mutex> dataLock(g_dataMutex); // Safe to lock here

                for (const auto& q : g_inputQueue) {
                    if (g_isBindingKey && g_targetBinding) {
                        g_targetBinding->vkCode = q.vkCode;
                        g_isBindingKey = false;
                        g_targetBinding = nullptr;
                        SaveHotkeys();
                        continue;
                    }
                }
                g_inputQueue.clear();
            }
        }


        if (!g_isVisible) { Sleep(50); continue; }
        ForceTopMost();

        // --- APPLY TRANSPARENCY ---
        SetLayeredWindowAttributes(g_hwnd, 0, (BYTE)(g_windowAlpha * 255), LWA_ALPHA);
        // --------------------------

        if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) {
            POINT p; GetCursorPos(&p); RECT r; GetWindowRect(g_hwnd, &r);
            if (!PtInRect(&r, p) && !g_isInspecting && !g_isBindingKey && !g_dimOverlay) g_currentFocus = FocusState::None;
            else if (ImGui::IsMouseDown(0) && !ImGui::IsAnyItemHovered() && !g_isInspecting && !g_isBindingKey) {
                if (!dragging) {
                    if ((p.y - r.top) < 50) { // Fix: Allow drag ONLY via the top 50px header
                        dragging = true; offset = { p.x - r.left, p.y - r.top }; g_currentFocus = FocusState::None;
                    }
                }
                if (dragging) { // Ensure check
                    SetWindowPos(g_hwnd, NULL, p.x - offset.x, p.y - offset.y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
                }
            }
        }
        else dragging = false;


        ImGui_ImplDX11_NewFrame(); ImGui_ImplWin32_NewFrame(); ImGui::NewFrame();


        ImVec2 displaySize = ImGui::GetIO().DisplaySize;
        if (displaySize.x <= 0.0f || displaySize.y <= 0.0f || IsIconic(g_hwnd)) {
            ImGui::EndFrame();
            Sleep(50);
            continue;
        }

        DrawDimOverlayIfRequested();

        // --- PREMIUM WINDOW EFFECTS ---
        ImDrawList* d = ImGui::GetBackgroundDrawList();
        RECT actualRect;
        GetWindowRect(g_hwnd, &actualRect);
        ImVec2 wPos = { float(actualRect.left), float(actualRect.top) };
        ImVec2 wSize = { float(actualRect.right - actualRect.left), float(actualRect.bottom - actualRect.top) };

        // Animated glow intensity
        float time = (float)GetTickCount64() / 1000.0f;
        float glowPulse = (sinf(time * 1.5f) + 1.0f) * 0.5f; // 0.0 to 1.0
        float glowAlpha = 0.3f + (glowPulse * 0.3f); // 0.3 to 0.6

        // Outer glow shadow (gives depth)
        for (int i = 3; i >= 1; i--) {
            float expand = (float)i * 2.0f;
            float alpha = 0.08f * (4 - i);
            ImVec2 glowMin = ImVec2(0, 0) - ImVec2(expand, expand);
            ImVec2 glowMax = ImGui::GetIO().DisplaySize + ImVec2(expand, expand);
            d->AddRect(glowMin, glowMax, GetAccentColorU32(alpha), 12.0f, 0, 2.0f);
        }

        // Main accent border with glow
        d->AddRect(ImVec2(0, 0), ImGui::GetIO().DisplaySize, GetAccentColorU32(glowAlpha + 0.3f), 12.0f, 0, 2.0f);

        // Inner subtle border
        d->AddRect(ImVec2(1, 1), ImGui::GetIO().DisplaySize - ImVec2(1, 1), IM_COL32(255, 255, 255, 10), 11.0f, 0, 1.0f);

        // Premium gradient header (top 50px)
        ImVec2 headerMax = ImVec2(ImGui::GetIO().DisplaySize.x, 50.0f);
        ImU32 headerTop = IM_COL32(25, 25, 28, 255);
        ImU32 headerBot = IM_COL32(20, 20, 23, 255);
        d->AddRectFilledMultiColor(ImVec2(0, 0), headerMax, headerTop, headerTop, headerBot, headerBot);

        // Subtle accent line under header
        d->AddLine(ImVec2(16, 49), ImVec2(ImGui::GetIO().DisplaySize.x - 16, 49), GetAccentColorU32(0.3f), 1.0f);

        ImGui::SetNextWindowPos({ 0.0f, 0.0f }); ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGui::Begin("Ghost", NULL, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoResize);

        std::lock_guard<std::mutex> lock(g_dataMutex);

        if (g_stagingReady) {
            if (!g_chatHistory.empty() && g_chatHistory.back().isPreview) {
                g_chatHistory.pop_back();
            }
            if (g_stagingText.empty()) {
                g_statusMessage = "No text found.";
            }
            else {
                g_pendingInspectionText = g_stagingText;
                ChatMessage previewMsg;
                previewMsg.role = "system";
                previewMsg.text = "[Question captured from: " + g_stagingTitle + "]";
                previewMsg.hasImages = false;
                previewMsg.isPreview = true;
                g_chatHistory.push_back(previewMsg);
                g_scrollToBottom = true;
                g_statusMessage = "Text Ready (Pending Send).";
            }
            g_stagingReady = false;
        }

        std::string titleVer = "Hope (Agent Version)";
        ImGui::TextDisabled(titleVer.c_str());

        ImGui::SameLine(ImGui::GetWindowWidth() - 32.0f);
        if (g_icons.Close) {
            ImVec2 btnSize = { 20.0f, 20.0f };
            ImVec2 p = ImGui::GetCursorScreenPos();
            if (ImGui::InvisibleButton("##close_app", btnSize)) done = true;
            bool hovered = ImGui::IsItemHovered();
            bool active = ImGui::IsItemActive();
            ImU32 tint = hovered ? IM_COL32(255, 50, 50, 255) : IM_COL32(150, 150, 150, 255);
            if (active) tint = IM_COL32(200, 0, 0, 255);
            ImGui::GetWindowDrawList()->AddImage(g_icons.Close, p, p + btnSize, ImVec2(0.0f, 0.0f), ImVec2(1.0f, 1.0f), tint);
        }
        else {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
            if (ImGui::Button("X", { 25.0f, 22.0f })) done = true;
            ImGui::PopStyleColor();
        }

        // --- FIX: USE UI COLOR FOR SEPARATOR TO AVOID WHITE ---
        ImGui::PushStyleColor(ImGuiCol_Separator, g_uiColor);
        ImGui::Separator();
        ImGui::PopStyleColor();
        ImGui::Spacing();

        if (g_appMode == AppMode::Agent) {
            RenderAgentPage();
        }
        else {
                if (g_showSettings) {
                    RenderSettingsPage();
                    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 60.0f);
                    if (NeoWaveButton("BACK TO CHAT", { ImGui::GetContentRegionAvail().x, 40.0f })) {
                        g_showSettings = false;
                    }
                }
                else {
                    // ==========================================
                    // UI: PROVIDER / MODEL SELECTOR
                    // ==========================================
                    ImGui::PushItemWidth(130.0f);

                    // Provider Selection
                    const char* currentProvName = g_providers[g_currProviderIdx].name.c_str();
                    if (ImGui::BeginCombo("##prov_sel", currentProvName)) {
                        for (int n = 0; n < g_providers.size(); n++) {
                            bool isSelected = (g_currProviderIdx == n);
                            if (ImGui::Selectable(g_providers[n].name.c_str(), isSelected)) {
                                g_currProviderIdx = n;
                                g_currModelIdx = 0; // Reset model choice on provider switch
                                if (g_providers[n].type == AIProvider::Ollama && !g_providers[n].modelsFetched) Api::FetchModelsForProvider(AIProvider::Ollama);
                            }
                            if (isSelected) ImGui::SetItemDefaultFocus();
                        }
                        ImGui::EndCombo();
                    }

                    ImGui::SameLine();

                    // Model Selection
                    auto& currentProv = g_providers[g_currProviderIdx];
                    std::string currentModelName = "Loading...";
                    if (!currentProv.models.empty()) {
                        if (g_currModelIdx >= currentProv.models.size()) g_currModelIdx = 0;
                        currentModelName = currentProv.models[g_currModelIdx].displayName;
                    }
                    else {
                        currentModelName = currentProv.modelsFetched ? "Add API key in the website to access models" : "Fetching...";
                    }

                    ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x);
                    if (ImGui::BeginCombo("##mod_sel", currentModelName.c_str())) {
                        for (int n = 0; n < currentProv.models.size(); n++) {
                            bool isSelected = (g_currModelIdx == n);
                            if (ImGui::Selectable(currentProv.models[n].displayName.c_str(), isSelected)) {
                                g_currModelIdx = n;
                            }
                            if (isSelected) ImGui::SetItemDefaultFocus();
                        }
                        ImGui::EndCombo();
                    }
                    ImGui::PopItemWidth();
                    ImGui::PopItemWidth();

                    ImGui::PushStyleColor(ImGuiCol_Separator, g_uiColor);
                    ImGui::Separator();
                    ImGui::PopStyleColor();
                    ImGui::Spacing();

                    // DYNAMIC FOOTER HEIGHT CALCULATION
                    // Basic Footer: Input (60) + Toolbar (50) + Padding (20) = 130
                    // Extra Preview: 60px
                    float inputAreaHeight = CalculateInputBoxHeight(g_chatBuffer, ImGui::GetContentRegionAvail().x);
                    float toolbarHeight = 50.0f;
                    float previewHeight = (!g_screenshots.empty()) ? 60.0f : 0.0f;
                    float totalFooterHeight = inputAreaHeight + toolbarHeight + previewHeight + 20.0f;

                    // --- NEW CHAT HISTORY RENDERING ---
                    // FIX: Always show vertical scrollbar to prevent content jumping when it appears/disappears
                    ImGui::BeginChild("ChatHistory", ImVec2(0.0f, ImGui::GetContentRegionAvail().y - totalFooterHeight), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);

                    if (ImGui::IsWindowHovered() && ImGui::IsMouseClicked(1)) g_dimOverlay = !g_dimOverlay;

                    // Padding at top
                    ImGui::Dummy(ImVec2(0.0f, 10.0f));

                    for (size_t i = 0; i < g_chatHistory.size(); i++) {
                        auto& msg = g_chatHistory[i];

                        // Animation Logic
                        if (msg.alpha < 1.0f) {
                            msg.alpha += ImGui::GetIO().DeltaTime * 4.0f;
                            if (msg.alpha > 1.0f) msg.alpha = 1.0f;
                        }

                        if (msg.isPreview) {
                            // Keep previews simple (centered, grey)
                            float avail = ImGui::GetContentRegionAvail().x;
                            ImGui::SetCursorPosX(avail * 0.1f);
                            ImGui::PushTextWrapPos(avail * 0.9f);
                            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, msg.alpha), "%s", msg.text.c_str());
                            ImGui::PopTextWrapPos();
                            ImGui::Dummy(ImVec2(0.0f, 10.0f));
                        }
                        else {
                            // Use the new Smart Bubble Renderer
                            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, msg.alpha); // Fade in the whole bubble
                            RenderSmartMessage(msg);
                            ImGui::PopStyleVar();
                        }
                    }

                    if (g_isProcessing) DrawThinkingLoader();

                    // Auto-scroll logic
                    if (g_scrollToBottom) {
                        ImGui::SetScrollHereY(1.0f);
                        g_scrollToBottom = false;
                    }

                    ImGui::EndChild();
                    ImGui::Separator();

                    // ==========================================
                    // PREVIEW AREA (RENDERED ABOVE ICONS)
                    // ==========================================
                    if (!g_screenshots.empty()) {
                        ImGui::Dummy(ImVec2(0.0f, 5.0f));
                        ImGui::TextDisabled("Attachments:");
                        ImGui::SameLine();

                        int itemToDelete = -1;
                        for (int i = 0; i < g_screenshots.size(); i++) {
                            ImGui::PushID(i);
                            ImGui::BeginGroup();

                            // Render Thumbnail
                            ImGui::Image((void*)g_screenshots[i].textureView, ImVec2(80.0f, 45.0f), ImVec2(0.0f, 0.0f), ImVec2(1.0f, 1.0f), ImVec4(1.0f, 1.0f, 1.0f, 1.0f), g_uiColor);

                            // Calculate position for the X button (Top-Right of image)
                            ImVec2 rectMin = ImGui::GetItemRectMin();
                            ImVec2 rectMax = ImGui::GetItemRectMax();
                            ImVec2 btnPos = ImVec2(rectMax.x - 16.0f, rectMin.y);

                            ImGui::SetCursorScreenPos(btnPos);

                            // Red "X" Button
                            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 0.8f));
                            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
                            if (ImGui::Button("x", ImVec2(16.0f, 16.0f))) {
                                itemToDelete = i;
                            }
                            ImGui::PopStyleVar();
                            ImGui::PopStyleColor();

                            ImGui::EndGroup();
                            ImGui::PopID();
                            ImGui::SameLine();
                        }

                        if (itemToDelete != -1) {
                            if (g_screenshots[itemToDelete].textureView) g_screenshots[itemToDelete].textureView->Release();
                            g_screenshots.erase(g_screenshots.begin() + itemToDelete);
                        }
                        ImGui::NewLine();
                        ImGui::Separator();
                    } // <--- Added closing brace for g_screenshots check

                    ImGui::Spacing();
                    float avail = ImGui::GetContentRegionAvail().x;
                    float btnSz = 44.0f;
                    // Fix: 5 buttons now (Screenshot, TextCapture, Copy, Settings, Clear)
                    // We want equal padding on edges + between buttons = 6 padding slots
                    float pad = (avail - 5.0f * btnSz) / 6.0f;

                    ImGui::SetCursorPosX(pad);
                    if (IconButton(g_icons.Screenshot, "##cap", "Take Screenshot", { btnSz, btnSz }, false)) CaptureScreenshot();
                    ImGui::SameLine(0.0f, pad);

                    if (IconButton(g_icons.Inspect, "##ins", "Text Capture", { btnSz, btnSz })) CaptureContext();

                    ImGui::SameLine(0.0f, pad);

                    static float copyFlash = 0.0f;
                    if (IconButton(g_icons.Copy, "##copy", "Copy Last Response", { btnSz, btnSz })) {
                        if (!g_chatHistory.empty()) {
                            std::string textToCopy = g_chatHistory.back().text;
                            if (!g_chatHistory.back().hasImages && g_chatHistory.back().role != "system") {
                                std::string code = ExtractLatestCodeBlock(textToCopy);
                                SetClipboardText(code.empty() ? textToCopy : code);
                                copyFlash = 1.0f;
                            }
                        }
                    }
                    ImGui::SameLine(0.0f, pad);

                    if (IconButton(g_icons.Settings, "##set", "Settings", { btnSz, btnSz })) g_showSettings = !g_showSettings;
                    ImGui::SameLine(0.0f, pad);

                    if (IconButton(g_icons.NewChat, "##clr", "Clear Chat", { btnSz, btnSz })) {
                        g_chatHistory.clear();
                        g_chatHistory.push_back({ "model", "Chat cleared.", false, false });
                    }

                    ImGui::Spacing();

                    // INPUT
                    bool sendClicked = false;
                    FloatingInputGhost("c_box", "Ask AI...", g_chatBuffer, FocusState::Chat, true, sendClicked, 0.0f);
                    if (sendClicked) {
                        Api::SendToAI(g_chatBuffer);
                        g_chatBuffer.clear();
                    }
                }
        }
        ImGui::End();

        ImGui::Render();
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }
    Gdiplus::GdiplusShutdown(g_gdiplusToken);
    return 0;
}
