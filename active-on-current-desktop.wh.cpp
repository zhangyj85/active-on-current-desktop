// ==WindhawkMod==
// @id active-on-current-desktop
// @name active-on-current-desktop
// @description Activate application windows on the current virtual desktop.
// @version 1.1.1
// @author DeskPilot contributors; meteoni (activation layer)
// @include explorer.exe
// @include SearchHost.exe
// @include StartMenuExperienceHost.exe
// @architecture x86-64
// @compilerOptions -lole32 -lshell32 -luuid -ldwmapi -ladvapi32
// @license MIT
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
Installation / 安装：
1. Install Windhawk on Windows 11 x64.
2. Create a local mod, replace the template with this entire file, then compile.
3. Add third-party launcher EXE names/paths to Advanced custom process inclusion.
   Default Windows shell/search processes are already included.
4. Disable other mods that change the same desktop activation behavior.

安装 Windhawk 后创建本地 mod，粘贴本文件全部内容并保存编译即可。
第三方启动器请在高级设置的自定义包含进程中添加，无需修改代码。
首次缺少符号时，Windhawk 可能需要下载微软符号文件。
其他 Windows 版本仍取决于私有接口和符号兼容性。

在 mod 的“设置”中添加目标应用的 EXE 名称或完整路径，再选择打开方式：
- 保留所在桌面并跳转：优先激活已有窗口，允许跳转到其所在桌面，不搬移窗口。
- 不接管，使用原始启动行为：保留应用的多实例、参数和窗口激活行为。
未配置的应用继续搬到当前桌面；重复匹配时“不接管”优先。
留空的应用项会忽略；保存设置后由 Windhawk 重新加载，不增加后台轮询。
“保留所在桌面”不绑定桌面编号；没有已有窗口时继续原始启动流程。
同一 EXE 多窗口时仍使用统一窗口选择规则，不识别账号或文档语义。
目标应用规则与高级设置中的“启动器注入进程”是两种不同配置。
本源码不需要配套 DLL、额外常驻程序、账号或联网学习服务。

普通无参数 EXE/快捷方式打开可复用已有主窗口；带参数、特殊动词或特殊快捷方式
仍执行原始启动。依赖对应版本的私有 Shell 接口和符号，未提供跨版本保证。
没有日志、测试入口、行为学习、额外常驻程序或后台定时扫描。

Activation logic adapted from Don't Pull Me to Another Desktop 0.4.1 by meteoni:
https://github.com/ramensoftware/windhawk-mods/blob/main/mods/prevent-virtual-desktop-stealing.wh.cpp
MIT license; the complete copyright and license notice are included below.
*/
// ==/WindhawkModReadme==

/*
MIT License

Copyright (c) meteoni (original activation layer)
Copyright (c) DeskPilot contributors (local additions)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// ==WindhawkModSettings==
/*
- applications:
  - - executable: ""
      $name: 应用程序 EXE 名称或完整路径
      $description: 输入进程名（包含 .exe）或完整路径；不区分大小写，留空则忽略。
    - behavior: keepDesktop
      $name: 打开方式
      $options:
      - keepDesktop: 保留所在桌面并跳转
      - original: 不接管，使用原始启动行为
  $name: 应用程序规则
  $description: >-
    点击添加按钮配置应用；未列出的应用继续在当前桌面激活。
    保留所在桌面会复用已有窗口，不绑定桌面编号；不接管适合保留多实例行为。
    同一应用重复匹配时“不接管”优先。
*/
// ==/WindhawkModSettings==

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <dwmapi.h>
#include <initializer_list>
#include <inspectable.h>
#include <objbase.h>
#include <securityappcontainer.h>
#include <servprov.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <windhawk_api.h>
#include <windhawk_utils.h>
#include <windows.h>

using SymbolHook = WindhawkUtils::SYMBOL_HOOK;
using WindhawkUtils::HookSymbols;

template <class T> struct ComPtr {
  T *p = nullptr;
  ComPtr() = default;
  ComPtr(const ComPtr &) = delete;
  ComPtr &operator=(const ComPtr &) = delete;
  ~ComPtr() {
    if (p)
      p->Release();
  }
  T *operator->() const { return p; }
};

struct ComApartment {
  HRESULT result;
  explicit ComApartment(DWORD model = COINIT_APARTMENTTHREADED)
      : result(CoInitializeEx(nullptr, model)) {}
  ComApartment(const ComApartment &) = delete;
  ComApartment &operator=(const ComApartment &) = delete;
  ~ComApartment() {
    if (SUCCEEDED(result))
      CoUninitialize();
  }
  explicit operator bool() const {
    return SUCCEEDED(result) || result == RPC_E_CHANGED_MODE;
  }
};

class Handle {
  HANDLE value = nullptr;

public:
  explicit Handle(HANDLE handle = nullptr) : value(handle) {}
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  ~Handle() {
    if (value)
      CloseHandle(value);
  }
  HANDLE get() const { return value; }
  explicit operator bool() const { return value != nullptr; }
};
namespace Process {
struct ProcessIdentity {
  std::wstring path;
  ULONGLONG created = 0;
};
static ProcessIdentity ReadProcess(DWORD pid,
                                   const std::wstring *requiredPath = nullptr) {
  Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
  if (!process)
    return {};
  wchar_t small[MAX_PATH];
  DWORD length = ARRAYSIZE(small);
  std::wstring extended;
  const wchar_t *path = small;
  if (!QueryFullProcessImageNameW(process.get(), 0, small, &length)) {
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
      return {};
    extended.resize(32768);
    length = (DWORD)extended.size();
    if (!QueryFullProcessImageNameW(process.get(), 0, extended.data(), &length))
      return {};
    path = extended.data();
  }
  if (requiredPath && (requiredPath->size() != length ||
                       _wcsnicmp(path, requiredPath->c_str(), length)))
    return {};
  // Trust checks only need a path. Creation time identifies window candidates.
  if (!requiredPath)
    return {std::wstring(path, length), 0};
  FILETIME created, exit, kernel, user;
  if (!GetProcessTimes(process.get(), &created, &exit, &kernel, &user))
    return {};
  return {{}, (ULONGLONG(created.dwHighDateTime) << 32) | created.dwLowDateTime};
}
} // namespace Process

namespace Policy {
enum class Mode { Summon, KeepDesktop, Original };
static std::vector<std::wstring> keepDesktop, original;

static std::wstring Normalize(std::wstring_view value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring_view::npos)
    return {};
  value = value.substr(first, value.find_last_not_of(L" \t\r\n") - first + 1);
  if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
    value = value.substr(1, value.size() - 2);
  std::wstring result(value);
  std::replace(result.begin(), result.end(), L'/', L'\\');
  return result;
}

static void Load() {
  // Settings are immutable while hooks run. Windhawk reloads the mod on edits.
  keepDesktop.clear();
  original.clear();
  for (int i = 0;; ++i) {
    auto mode = WindhawkUtils::StringSetting::make(L"applications[%d].behavior", i);
    if (!*mode.get())
      break;
    auto executable = WindhawkUtils::StringSetting::make(L"applications[%d].executable", i);
    auto entry = Normalize(executable.get());
    if (entry.empty())
      continue;
    if (!wcscmp(mode.get(), L"original"))
      original.push_back(std::move(entry));
    else if (!wcscmp(mode.get(), L"keepDesktop"))
      keepDesktop.push_back(std::move(entry));
  }
}

static bool Matches(const std::vector<std::wstring> &rules,
                    std::wstring_view path, std::wstring_view name) {
  for (const auto &rule : rules) {
    const auto target = rule.find_first_of(L"\\:") == std::wstring::npos ? name : path;
    if (rule.size() == target.size() &&
        CompareStringOrdinal(rule.data(), static_cast<int>(rule.size()),
                             target.data(), static_cast<int>(target.size()), TRUE) == CSTR_EQUAL)
      return true;
  }
  return false;
}

static Mode ForPath(std::wstring_view path) {
  if (keepDesktop.empty() && original.empty())
    return Mode::Summon;
  const auto slash = path.find_last_of(L"\\/");
  const auto name = path.substr(slash == std::wstring_view::npos ? 0 : slash + 1);
  if (Matches(original, path, name))
    return Mode::Original;
  return Matches(keepDesktop, path, name) ? Mode::KeepDesktop : Mode::Summon;
}

static Mode ForWindow(HWND window) noexcept {
  if (keepDesktop.empty() && original.empty())
    return Mode::Summon;
  try {
    DWORD pid = 0;
    if (!GetWindowThreadProcessId(window, &pid))
      return Mode::Original;
    const auto image = Process::ReadProcess(pid);
    return image.path.empty() ? Mode::Original : ForPath(image.path);
  } catch (...) {
    return Mode::Original;
  }
}
} // namespace Policy

namespace Activation {
// Track activation-caused switches separately from deliberate desktop
// navigation.
static const CLSID kClsidImmersiveShell = {
    0xC2F03A33,
    0x21F5,
    0x47FA,
    {0xB4, 0xBB, 0x15, 0x63, 0x62, 0xA2, 0xF2, 0x39}};

static const CLSID kClsidVirtualDesktopManagerInternal = {
    0xC5E0CDCA,
    0x7B6E,
    0x41B2,
    {0x9F, 0xC4, 0xD9, 0x39, 0x75, 0xCC, 0x46, 0x7B}};

static const GUID kServiceVirtualDesktopNotification = {
    0xA501FDEC,
    0x4A09,
    0x464C,
    {0xAE, 0x4E, 0x1B, 0x9C, 0x21, 0xB8, 0x49, 0x18}};

static const IID kIidVirtualDesktopNotification = {
    0xB9E5E94D,
    0x233E,
    0x49AB,
    {0xAF, 0x5C, 0x2B, 0x45, 0x41, 0xC3, 0xAA, 0xDE}};

static const IID kIidVirtualDesktopNotificationService = {
    0x0CD45E71,
    0xD927,
    0x4F15,
    {0x8B, 0x0A, 0x8F, 0xEF, 0x52, 0x53, 0x37, 0xBF}};

static const IID kIidVirtualDesktopManagerInternal24H2 = {
    0x53F5CA0B,
    0x158F,
    0x4124,
    {0x90, 0x0C, 0x05, 0x71, 0x58, 0x06, 0x0B, 0x27}};

static const IID kIidApplicationViewCollection = {
    0x1841C6D7,
    0x4F9D,
    0x42C0,
    {0xAF, 0x41, 0x87, 0x47, 0x53, 0x8F, 0x10, 0xE5}};

struct IVirtualDesktop : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE IsViewVisible(IUnknown *view,
                                                  BOOL *visible) = 0;

  virtual HRESULT STDMETHODCALLTYPE GetId(GUID *desktopId) = 0;
};

struct IApplicationView : IInspectable {
  virtual HRESULT STDMETHODCALLTYPE SetFocus() = 0;
};

struct IVirtualDesktopManagerPrivate;
struct IVirtualDesktopSwitchAnimator;

struct IApplicationViewCollection : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE GetViews(IUnknown **objectArray) = 0;

  virtual HRESULT STDMETHODCALLTYPE
  GetViewsByZOrder(IUnknown **objectArray) = 0;

  virtual HRESULT STDMETHODCALLTYPE
  GetViewsByAppUserModelId(LPCWSTR appUserModelId, IUnknown **objectArray) = 0;

  virtual HRESULT STDMETHODCALLTYPE GetViewForHwnd(HWND hwnd,
                                                   IApplicationView **view) = 0;
};

struct IVirtualDesktopManagerInternal : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE GetCount(UINT *) = 0;
  virtual HRESULT STDMETHODCALLTYPE MoveViewToDesktop(IApplicationView *, IVirtualDesktop *) = 0;
  virtual HRESULT STDMETHODCALLTYPE CanViewMoveDesktops(IApplicationView *, BOOL *) = 0;
  virtual HRESULT STDMETHODCALLTYPE GetCurrentDesktop(IVirtualDesktop **) = 0;
};

struct IVirtualDesktopNotification : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE
  VirtualDesktopCreated(IVirtualDesktop *desktop) = 0;

  virtual HRESULT STDMETHODCALLTYPE VirtualDesktopDestroyBegin(
      IVirtualDesktop *desktopDestroyed, IVirtualDesktop *desktopFallback) = 0;

  virtual HRESULT STDMETHODCALLTYPE VirtualDesktopDestroyFailed(
      IVirtualDesktop *desktopDestroyed, IVirtualDesktop *desktopFallback) = 0;

  virtual HRESULT STDMETHODCALLTYPE VirtualDesktopDestroyed(
      IVirtualDesktop *desktopDestroyed, IVirtualDesktop *desktopFallback) = 0;

  virtual HRESULT STDMETHODCALLTYPE VirtualDesktopMoved(
      IVirtualDesktop *desktop, INT64 oldIndex, INT64 newIndex) = 0;

  virtual HRESULT STDMETHODCALLTYPE
  VirtualDesktopNameChanged(IVirtualDesktop *desktop, void *name) = 0;

  virtual HRESULT STDMETHODCALLTYPE
  ViewVirtualDesktopChanged(IUnknown *view) = 0;

  virtual HRESULT STDMETHODCALLTYPE CurrentVirtualDesktopChanged(
      IVirtualDesktop *desktopOld, IVirtualDesktop *desktopNew) = 0;

  virtual HRESULT STDMETHODCALLTYPE
  VirtualDesktopWallpaperChanged(IVirtualDesktop *desktop, void *wallpaper) = 0;

  virtual HRESULT STDMETHODCALLTYPE
  VirtualDesktopSwitched(IVirtualDesktop *desktop) = 0;

  virtual HRESULT STDMETHODCALLTYPE
  RemoteVirtualDesktopConnected(IVirtualDesktop *desktop) = 0;
};

struct IVirtualDesktopNotificationService : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE
  Register(IVirtualDesktopNotification *notification, DWORD *cookie) = 0;

  virtual HRESULT STDMETHODCALLTYPE Unregister(DWORD cookie) = 0;
};

static HANDLE g_runtimeCancelEvent = nullptr; // manual-reset
static std::atomic<bool> g_unloading{false};
static std::atomic<bool> g_startUnsupported{false};

static void PublishStartup(bool unsupported, HANDLE readyEvent) {
  g_startUnsupported.store(unsupported, std::memory_order_release);
  SetEvent(readyEvent);
}

static bool RuntimeCancellationRequested() {
  return g_unloading.load(std::memory_order_acquire);
}

static bool GuidEqual(const GUID &a, const GUID &b) {
  return IsEqualGUID(a, b) != FALSE;
}

static SRWLOCK g_currentDesktopLock = SRWLOCK_INIT;
static GUID g_currentDesktopId = {};
static bool g_currentDesktopValid = false;

static void StoreCurrentDesktopId(const GUID &id) {
  AcquireSRWLockExclusive(&g_currentDesktopLock);
  g_currentDesktopId = id;
  g_currentDesktopValid = true;
  ReleaseSRWLockExclusive(&g_currentDesktopLock);
}

static void ClearCurrentDesktopId() {
  AcquireSRWLockExclusive(&g_currentDesktopLock);
  g_currentDesktopId = {};
  g_currentDesktopValid = false;
  ReleaseSRWLockExclusive(&g_currentDesktopLock);
}

static bool LoadCurrentDesktopId(GUID *id) {
  AcquireSRWLockShared(&g_currentDesktopLock);
  bool valid = g_currentDesktopValid;
  if (valid) {
    *id = g_currentDesktopId;
  }
  ReleaseSRWLockShared(&g_currentDesktopLock);

  return valid;
}

static bool IsRescueCandidate(HWND hwnd) {
  if (!hwnd) {
    return false;
  }

  LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
  LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);

  if (!(style & WS_VISIBLE) || (style & WS_CHILD)) {
    return false;
  }

  if (exStyle & WS_EX_TOOLWINDOW) {
    return false;
  }

  if (GetAncestor(hwnd, GA_ROOTOWNER) != hwnd) {
    return false;
  }

  return true;
}

static thread_local int g_foregroundPolicyDepth = 0;

static thread_local HWND g_foregroundPolicyHwnd = nullptr;

static std::atomic<uint64_t> g_navigationGeneration{1};

static thread_local int g_desktopChangedDepth = 0;
static thread_local uint64_t g_activeNavigationGeneration = 0;

struct NavigationFocusRecord {
  bool valid = false;
  uint64_t sequence = 0;
  uint64_t generation = 0;
  ULONGLONG recordedAt = 0;
  GUID desktopId = {};
  IApplicationView *viewIdentity = nullptr;
  HWND hwnd = nullptr;
  DWORD pid = 0;
  DWORD tid = 0;
};

static constexpr size_t kNavigationFocusHistoryCapacity = 32;

static constexpr ULONGLONG kNavigationFocusRecordMaxAgeMs = 2000;
static SRWLOCK g_navigationFocusLock = SRWLOCK_INIT;
static NavigationFocusRecord
    g_navigationFocusHistory[kNavigationFocusHistoryCapacity] = {};
static size_t g_navigationFocusWriteIndex = 0;
static std::atomic<uint64_t> g_nextNavigationFocusSequence{1};

static thread_local uint64_t g_foregroundPolicyNavigationGeneration = 0;
static thread_local NavigationFocusRecord g_foregroundPolicyNavigationFocus =
    {};

static thread_local uint64_t g_foregroundPolicyRescueSequence = 0;

static void DiscardNavigationFocusGeneration(uint64_t generation) {
  if (!generation) {
    return;
  }

  AcquireSRWLockExclusive(&g_navigationFocusLock);

  for (auto &record : g_navigationFocusHistory) {
    if (record.valid && record.generation == generation) {
      record = {};
    }
  }

  ReleaseSRWLockExclusive(&g_navigationFocusLock);
}

static void RecordNavigationSelectedFocus(uint64_t generation,
                                          const GUID &desktopId,
                                          IApplicationView *view, HWND hwnd) {
  if (!generation || !view || !hwnd) {
    return;
  }

  DWORD pid = 0;
  DWORD tid = GetWindowThreadProcessId(hwnd, &pid);

  if (!pid || !tid) {
    return;
  }

  NavigationFocusRecord record;
  record.valid = true;
  record.sequence =
      g_nextNavigationFocusSequence.fetch_add(1, std::memory_order_relaxed);
  record.generation = generation;
  record.recordedAt = GetTickCount64();
  record.desktopId = desktopId;
  record.viewIdentity = view;
  record.hwnd = hwnd;
  record.pid = pid;
  record.tid = tid;

  AcquireSRWLockExclusive(&g_navigationFocusLock);

  g_navigationFocusHistory[g_navigationFocusWriteIndex] = record;

  g_navigationFocusWriteIndex =
      (g_navigationFocusWriteIndex + 1) % kNavigationFocusHistoryCapacity;

  ReleaseSRWLockExclusive(&g_navigationFocusLock);
}

static NavigationFocusRecord
ConsumeNavigationSelectedFocus(IApplicationView *view, HWND hwnd) {
  if (!view || !hwnd) {
    return {};
  }

  DWORD pid = 0;
  DWORD tid = GetWindowThreadProcessId(hwnd, &pid);

  if (!pid || !tid) {
    return {};
  }

  size_t matchedIndex = kNavigationFocusHistoryCapacity;
  NavigationFocusRecord matched = {};

  const ULONGLONG now = GetTickCount64();

  AcquireSRWLockExclusive(&g_navigationFocusLock);

  for (size_t i = 0; i < kNavigationFocusHistoryCapacity; ++i) {
    NavigationFocusRecord &record = g_navigationFocusHistory[i];

    if (!record.valid) {
      continue;
    }

    if (!record.recordedAt ||
        now - record.recordedAt > kNavigationFocusRecordMaxAgeMs) {
      record = {};
      continue;
    }

    if (record.viewIdentity != view) {
      continue;
    }

    if (record.hwnd != hwnd || record.pid != pid || record.tid != tid) {
      record = {};
      continue;
    }

    const uint64_t currentGeneration =
        g_navigationGeneration.load(std::memory_order_acquire);

    if (record.generation > currentGeneration) {
      record = {};
      continue;
    }

    if (record.generation < currentGeneration) {
      const bool delayedFromImmediatelyPreviousNavigation =
          g_activeNavigationGeneration == currentGeneration &&
          record.generation + 1 == currentGeneration;

      if (!delayedFromImmediatelyPreviousNavigation) {
        record = {};
        continue;
      }
    }

    if (!matched.valid || record.generation < matched.generation ||
        (record.generation == matched.generation &&
         record.sequence < matched.sequence)) {
      matched = record;
      matchedIndex = i;
    }
  }

  if (matchedIndex < kNavigationFocusHistoryCapacity) {
    g_navigationFocusHistory[matchedIndex] = {};
  }

  ReleaseSRWLockExclusive(&g_navigationFocusLock);

  return matched;
}

static void InvalidateNavigationState() {
  g_navigationGeneration.fetch_add(1, std::memory_order_acq_rel);

  AcquireSRWLockExclusive(&g_navigationFocusLock);

  for (auto &record : g_navigationFocusHistory) {
    record = {};
  }

  g_navigationFocusWriteIndex = 0;

  ReleaseSRWLockExclusive(&g_navigationFocusLock);
}

using SwitchDesktopInternal_t = HRESULT (*)(void *pThis,
                                            IVirtualDesktop *desktop);

static SwitchDesktopInternal_t g_switchDesktopInternalOriginal = nullptr;

using ForegroundViewChanged_t = HRESULT (*)(
    void *pThis, IVirtualDesktopManagerPrivate *manager,
    IVirtualDesktopSwitchAnimator *animator, IApplicationView *view);

static ForegroundViewChanged_t g_foregroundViewChangedOriginal = nullptr;

static void *g_win32ApplicationViewVtable = nullptr;
static void *g_winRtApplicationViewVtable = nullptr;

using ApplicationViewGetNativeWindow_t = HRESULT(WINAPI *)(void *pThis,
                                                           HWND *windowHandle);

static ApplicationViewGetNativeWindow_t g_win32ApplicationViewGetNativeWindow =
    nullptr;
static ApplicationViewGetNativeWindow_t g_winRtApplicationViewGetNativeWindow =
    nullptr;

using DesktopChanged_t = HRESULT (*)(void *pThis, IVirtualDesktop *desktop);

static DesktopChanged_t g_desktopChangedOriginal = nullptr;

using GetNewForegroundViewForDesktopSwitch_t =
    HRESULT (*)(void *pThis, IVirtualDesktop *desktop, IApplicationView **view,
                bool *shouldFocus);

static GetNewForegroundViewForDesktopSwitch_t
    g_getNewForegroundViewForDesktopSwitchOriginal = nullptr;

static void PublishForegroundPolicyRescueCompletion(uint64_t sequence);

static HWND GetForegroundPolicyViewHwnd(IApplicationView *view) {
  if (!view) {
    return nullptr;
  }

  void *vtable = *reinterpret_cast<void **>(view);

  ApplicationViewGetNativeWindow_t getNativeWindow = nullptr;

  if (vtable == g_win32ApplicationViewVtable &&
      g_win32ApplicationViewGetNativeWindow) {
    getNativeWindow = g_win32ApplicationViewGetNativeWindow;
  } else if (vtable == g_winRtApplicationViewVtable &&
             g_winRtApplicationViewGetNativeWindow) {
    getNativeWindow = g_winRtApplicationViewGetNativeWindow;
  } else {
    return nullptr;
  }

  HWND hwnd = nullptr;
  HRESULT hr = getNativeWindow(view, &hwnd);

  if (FAILED(hr)) {
    return nullptr;
  }

  return hwnd;
}

static HRESULT DesktopChanged_Hook(void *pThis, IVirtualDesktop *desktop) {
  const bool outermost = g_desktopChangedDepth == 0;

  const uint64_t previousGeneration = g_activeNavigationGeneration;

  uint64_t generation = previousGeneration;

  if (outermost) {
    generation =
        g_navigationGeneration.fetch_add(1, std::memory_order_acq_rel) + 1;

    g_activeNavigationGeneration = generation;
  }

  ++g_desktopChangedDepth;

  HRESULT hr = g_desktopChangedOriginal(pThis, desktop);

  --g_desktopChangedDepth;

  if (outermost) {
    if (FAILED(hr)) {
      DiscardNavigationFocusGeneration(generation);
    }

    g_activeNavigationGeneration = previousGeneration;
  }

  return hr;
}

static HRESULT
GetNewForegroundViewForDesktopSwitch_Hook(void *pThis, IVirtualDesktop *desktop,
                                          IApplicationView **view,
                                          bool *shouldFocus) {
  HRESULT hr = g_getNewForegroundViewForDesktopSwitchOriginal(
      pThis, desktop, view, shouldFocus);

  const uint64_t generation = g_activeNavigationGeneration;

  if (!generation || FAILED(hr) || !desktop || !view || !*view ||
      !shouldFocus || !*shouldFocus) {
    return hr;
  }

  GUID desktopId = {};
  if (FAILED(desktop->GetId(&desktopId))) {
    return hr;
  }

  HWND hwnd = GetForegroundPolicyViewHwnd(*view);

  RecordNavigationSelectedFocus(generation, desktopId, *view, hwnd);

  return hr;
}

static HRESULT
ForegroundViewChanged_Hook(void *pThis, IVirtualDesktopManagerPrivate *manager,
                           IVirtualDesktopSwitchAnimator *animator,
                           IApplicationView *view) {
  HWND previousHwnd = g_foregroundPolicyHwnd;

  uint64_t previousNavigationGeneration =
      g_foregroundPolicyNavigationGeneration;
  NavigationFocusRecord previousNavigationFocus =
      g_foregroundPolicyNavigationFocus;
  uint64_t previousRescueSequence = g_foregroundPolicyRescueSequence;

  ++g_foregroundPolicyDepth;
  g_foregroundPolicyRescueSequence = 0;

  g_foregroundPolicyNavigationGeneration =
      g_navigationGeneration.load(std::memory_order_acquire);

  g_foregroundPolicyHwnd = GetForegroundPolicyViewHwnd(view);

  g_foregroundPolicyNavigationFocus =
      ConsumeNavigationSelectedFocus(view, g_foregroundPolicyHwnd);

  HRESULT hr = g_foregroundViewChangedOriginal(pThis, manager, animator, view);

  // Shell must finish its original foreground policy before the worker
  // moves the view; publishing earlier races the Shell's own activation.
  const uint64_t completedRescueSequence = g_foregroundPolicyRescueSequence;
  if (completedRescueSequence) {
    PublishForegroundPolicyRescueCompletion(completedRescueSequence);
  }

  g_foregroundPolicyHwnd = previousHwnd;

  g_foregroundPolicyNavigationGeneration = previousNavigationGeneration;
  g_foregroundPolicyNavigationFocus = previousNavigationFocus;
  g_foregroundPolicyRescueSequence = previousRescueSequence;

  --g_foregroundPolicyDepth;
  return hr;
}

static HANDLE g_notificationThread = nullptr;
static DWORD g_notificationThreadId = 0;
static HANDLE g_notificationReadyEvent = nullptr;
static HANDLE g_notificationStopEvent = nullptr;
static std::atomic<bool> g_notificationReady = false;

static bool NotificationStopRequested() {
  return RuntimeCancellationRequested() ||
         (g_notificationStopEvent &&
          WaitForSingleObject(g_notificationStopEvent, 0) == WAIT_OBJECT_0);
}

class VirtualDesktopNotificationListener final
    : public IVirtualDesktopNotification {
public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid,
                                           void **object) override {
    if (!object) {
      return E_POINTER;
    }

    *object = nullptr;

    if (IsEqualIID(riid, __uuidof(IUnknown)) ||
        IsEqualIID(riid, kIidVirtualDesktopNotification)) {
      *object = static_cast<IVirtualDesktopNotification *>(this);
      AddRef();
      return S_OK;
    }

    return E_NOINTERFACE;
  }

  ULONG STDMETHODCALLTYPE AddRef() override { return ++m_refCount; }

  ULONG STDMETHODCALLTYPE Release() override {
    ULONG value = --m_refCount;
    if (!value) {
      delete this;
    }
    return value;
  }

  HRESULT STDMETHODCALLTYPE VirtualDesktopCreated(IVirtualDesktop *) override {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE
  VirtualDesktopDestroyBegin(IVirtualDesktop *, IVirtualDesktop *) override {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE
  VirtualDesktopDestroyFailed(IVirtualDesktop *, IVirtualDesktop *) override {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE
  VirtualDesktopDestroyed(IVirtualDesktop *, IVirtualDesktop *) override {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE VirtualDesktopMoved(IVirtualDesktop *, INT64,
                                                INT64) override {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE VirtualDesktopNameChanged(IVirtualDesktop *,
                                                      void *) override {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE ViewVirtualDesktopChanged(IUnknown *) override {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE CurrentVirtualDesktopChanged(
      IVirtualDesktop *desktopOld, IVirtualDesktop *desktopNew) override {
    GUID newId = {};

    HRESULT newHr = desktopNew ? desktopNew->GetId(&newId) : E_POINTER;

    if (SUCCEEDED(newHr)) {
      StoreCurrentDesktopId(newId);
    } else {
      ClearCurrentDesktopId();
    }

    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE VirtualDesktopWallpaperChanged(IVirtualDesktop *,
                                                           void *) override {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE VirtualDesktopSwitched(IVirtualDesktop *) override {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE
  RemoteVirtualDesktopConnected(IVirtualDesktop *) override {
    return S_OK;
  }

private:
  std::atomic<ULONG> m_refCount{1};
};

static DWORD WINAPI NotificationThreadProc(void *) {
  MSG msg = {};
  PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);

  if (NotificationStopRequested()) {
    PublishStartup(false, g_notificationReadyEvent);
    return 0;
  }

  ComApartment apartment;
  if (!apartment) {
    PublishStartup(false, g_notificationReadyEvent);
    return 0;
  }

  if (NotificationStopRequested()) {
    PublishStartup(false, g_notificationReadyEvent);

    return 0;
  }

  ComPtr<IServiceProvider> serviceProvider;
  ComPtr<IVirtualDesktopManagerInternal> managerInternal;
  ComPtr<IVirtualDesktopNotificationService> notificationService;
  ComPtr<VirtualDesktopNotificationListener> listener;
  DWORD cookie = 0;
  bool unsupported = false;

  HRESULT hr = CoCreateInstance(kClsidImmersiveShell, nullptr,
                                CLSCTX_LOCAL_SERVER, __uuidof(IServiceProvider),
                                reinterpret_cast<void **>(&serviceProvider.p));

  if (SUCCEEDED(hr) && serviceProvider.p) {
    hr = serviceProvider->QueryService(
        kClsidVirtualDesktopManagerInternal,
        kIidVirtualDesktopManagerInternal24H2,
        reinterpret_cast<void **>(&managerInternal.p));

    if (SUCCEEDED(hr) && !managerInternal.p) {
      hr = E_NOINTERFACE;
    }

    unsupported = hr == E_NOINTERFACE;
  }

  if (SUCCEEDED(hr) && serviceProvider.p) {
    hr = serviceProvider->QueryService(
        kServiceVirtualDesktopNotification,
        kIidVirtualDesktopNotificationService,
        reinterpret_cast<void **>(&notificationService.p));

    if (SUCCEEDED(hr) && !notificationService.p) {
      hr = E_NOINTERFACE;
    }

    unsupported = unsupported || hr == E_NOINTERFACE;
  }

  if (SUCCEEDED(hr) && notificationService.p) {
    listener.p = new VirtualDesktopNotificationListener();

    hr = notificationService->Register(listener.p, &cookie);
  }

  if (SUCCEEDED(hr) && managerInternal.p) {
    ComPtr<IVirtualDesktop> currentDesktop;

    HRESULT currentHr = managerInternal->GetCurrentDesktop(&currentDesktop.p);

    if (SUCCEEDED(currentHr) && currentDesktop.p) {
      GUID id = {};
      if (SUCCEEDED(currentDesktop->GetId(&id))) {
        StoreCurrentDesktopId(id);
      }
    }
  }

  if (SUCCEEDED(hr) && cookie) {
    GUID currentId = {};
    if (LoadCurrentDesktopId(&currentId)) {
      g_notificationReady.store(true, std::memory_order_release);
    }
  }

  if (NotificationStopRequested()) {
    g_notificationReady.store(false, std::memory_order_release);
  }

  PublishStartup(unsupported, g_notificationReadyEvent);

  if (g_notificationReady.load(std::memory_order_acquire) &&
      !NotificationStopRequested()) {
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }

  g_notificationReady.store(false, std::memory_order_release);
  ClearCurrentDesktopId();

  if (notificationService.p && cookie) {
    notificationService->Unregister(cookie);
  }

  return 0;
}

static bool StartNotificationCache() {
  g_notificationReady.store(false, std::memory_order_release);
  g_startUnsupported.store(false, std::memory_order_release);

  if (RuntimeCancellationRequested()) {
    return false;
  }

  g_notificationReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

  g_notificationStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

  if (!g_notificationReadyEvent || !g_notificationStopEvent) {
    return false;
  }

  g_notificationThread = CreateThread(nullptr, 0, NotificationThreadProc,
                                      nullptr, 0, &g_notificationThreadId);

  if (!g_notificationThread) {
    return false;
  }

  HANDLE waits[] = {
      g_runtimeCancelEvent,
      g_notificationReadyEvent,
  };

  DWORD waitResult =
      WaitForMultipleObjects(ARRAYSIZE(waits), waits, FALSE, 5000);

  return waitResult == WAIT_OBJECT_0 + 1 &&
         g_notificationReady.load(std::memory_order_acquire);
}

static void StopNotificationCache() {
  g_notificationReady.store(false, std::memory_order_release);

  if (g_notificationStopEvent) {
    SetEvent(g_notificationStopEvent);
  }

  if (g_notificationThread) {
    if (g_notificationThreadId) {
      PostThreadMessageW(g_notificationThreadId, WM_QUIT, 0, 0);
    }

    WaitForSingleObject(g_notificationThread, INFINITE);

    CloseHandle(g_notificationThread);
    g_notificationThread = nullptr;
    g_notificationThreadId = 0;
  }

  if (g_notificationReadyEvent) {
    CloseHandle(g_notificationReadyEvent);
    g_notificationReadyEvent = nullptr;
  }

  if (g_notificationStopEvent) {
    CloseHandle(g_notificationStopEvent);
    g_notificationStopEvent = nullptr;
  }

  ClearCurrentDesktopId();
}

struct RescueRequest {
  uint64_t sequence = 0;
  uint64_t navigationGeneration = 0;
  bool foregroundPolicyReturned = false;
  HWND hwnd = nullptr;
  DWORD pid = 0;
  DWORD tid = 0;
  GUID sourceDesktopId = {};
  GUID requestedDesktopId = {};
};

static constexpr size_t kRescueQueueCapacity = 16;
static SRWLOCK g_requestLock = SRWLOCK_INIT;
static RescueRequest g_rescueQueue[kRescueQueueCapacity] = {};
static size_t g_rescueQueueHead = 0;
static size_t g_rescueQueueCount = 0;

static std::atomic<uint64_t> g_nextSequence = 1;

static HANDLE g_requestEvent = nullptr; // auto-reset

static HANDLE g_stopEvent = nullptr; // manual-reset
static HANDLE g_workerThread = nullptr;
static HANDLE g_workerReadyEvent = nullptr;
static std::atomic<bool> g_workerReady = false;

static bool WorkerStopRequested() {
  return RuntimeCancellationRequested() ||
         (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0);
}

struct WorkerComState {
  ComPtr<IServiceProvider> serviceProvider;
  ComPtr<IVirtualDesktopManagerInternal> managerInternal;
  ComPtr<IApplicationViewCollection> viewCollection;
  ComPtr<IVirtualDesktopManager> publicManager;
};

static bool InitializeWorkerComState(WorkerComState *state) {
  HRESULT hr =
      CoCreateInstance(kClsidImmersiveShell, nullptr, CLSCTX_LOCAL_SERVER,
                       __uuidof(IServiceProvider),
                       reinterpret_cast<void **>(&state->serviceProvider.p));

  if (FAILED(hr) || !state->serviceProvider.p) {
    return false;
  }

  hr = state->serviceProvider.p->QueryService(
      kClsidVirtualDesktopManagerInternal,
      kIidVirtualDesktopManagerInternal24H2,
      reinterpret_cast<void **>(&state->managerInternal.p));

  if (FAILED(hr) || !state->managerInternal.p) {
    if (SUCCEEDED(hr)) {
      hr = E_NOINTERFACE;
    }
    g_startUnsupported.store(hr == E_NOINTERFACE, std::memory_order_release);
    return false;
  }

  hr = state->serviceProvider.p->QueryService(
      kIidApplicationViewCollection, kIidApplicationViewCollection,
      reinterpret_cast<void **>(&state->viewCollection.p));

  if (FAILED(hr) || !state->viewCollection.p) {
    if (SUCCEEDED(hr)) {
      hr = E_NOINTERFACE;
    }
    g_startUnsupported.store(hr == E_NOINTERFACE, std::memory_order_release);
    return false;
  }

  hr = CoCreateInstance(__uuidof(VirtualDesktopManager), nullptr,
                        CLSCTX_INPROC_SERVER,
                        IID_PPV_ARGS(&state->publicManager.p));

  if (FAILED(hr) || !state->publicManager.p) {
    return false;
  }

  return true;
}

static bool IsRescueGenerationCurrent(const RescueRequest &request) {
  return request.navigationGeneration ==
         g_navigationGeneration.load(std::memory_order_acquire);
}

static bool TakePendingRequest(RescueRequest *request) {
  AcquireSRWLockExclusive(&g_requestLock);
  if (!g_rescueQueueCount ||
      !g_rescueQueue[g_rescueQueueHead].foregroundPolicyReturned) {
    ReleaseSRWLockExclusive(&g_requestLock);
    return false;
  }
  *request = g_rescueQueue[g_rescueQueueHead];
  g_rescueQueue[g_rescueQueueHead] = {};
  g_rescueQueueHead = (g_rescueQueueHead + 1) % kRescueQueueCapacity;
  --g_rescueQueueCount;
  ReleaseSRWLockExclusive(&g_requestLock);
  return true;
}

static void PublishForegroundPolicyRescueCompletion(uint64_t sequence) {
  if (!sequence)
    return;
  AcquireSRWLockExclusive(&g_requestLock);
  for (size_t i = 0; i < g_rescueQueueCount; ++i) {
    auto &request =
        g_rescueQueue[(g_rescueQueueHead + i) % kRescueQueueCapacity];
    if (request.sequence == sequence) {
      request.foregroundPolicyReturned = true;
      SetEvent(g_requestEvent);
      break;
    }
  }
  ReleaseSRWLockExclusive(&g_requestLock);
}

static void ProcessRescueRequest(WorkerComState *state,
                                 const RescueRequest &request) {
  if (WorkerStopRequested() || !IsRescueGenerationCurrent(request) ||
      !IsRescueCandidate(request.hwnd))
    return;
  const auto identityMatches = [&] {
    DWORD pid = 0;
    const DWORD tid = GetWindowThreadProcessId(request.hwnd, &pid);
    return pid == request.pid && tid == request.tid;
  };
  if (!identityMatches())
    return;

  ComPtr<IVirtualDesktop> currentDesktop;
  GUID currentId = {};
  if (FAILED(state->managerInternal->GetCurrentDesktop(&currentDesktop.p)) ||
      !currentDesktop.p || FAILED(currentDesktop->GetId(&currentId)) ||
      !GuidEqual(currentId, request.sourceDesktopId))
    return;

  BOOL onCurrent = FALSE;
  if (SUCCEEDED(state->publicManager.p->IsWindowOnCurrentVirtualDesktop(
          request.hwnd, &onCurrent)) &&
      onCurrent)
    return;
  GUID windowDesktopId = {};
  if (FAILED(state->publicManager.p->GetWindowDesktopId(request.hwnd,
                                                        &windowDesktopId)) ||
      GuidEqual(windowDesktopId, currentId) ||
      !GuidEqual(windowDesktopId, request.requestedDesktopId))
    return;

  ComPtr<IApplicationView> view;
  if (FAILED(state->viewCollection.p->GetViewForHwnd(request.hwnd, &view.p)) ||
      !view.p)
    return;
  ComPtr<IVirtualDesktop> commitDesktop;
  GUID commitId = {};
  if (WorkerStopRequested() || !IsRescueGenerationCurrent(request) ||
      FAILED(state->managerInternal->GetCurrentDesktop(&commitDesktop.p)) ||
      !commitDesktop.p || FAILED(commitDesktop->GetId(&commitId)) ||
      !GuidEqual(commitId, request.sourceDesktopId) || !identityMatches())
    return;

  if (FAILED(state->managerInternal->MoveViewToDesktop(view.p, commitDesktop.p)))
    return;
  // A desktop change while the COM call was in flight cancels focus stealing.
  if (WorkerStopRequested() || !IsRescueGenerationCurrent(request))
    return;
  if (IsIconic(request.hwnd))
    ShowWindowAsync(request.hwnd, SW_RESTORE);
  SetForegroundWindow(request.hwnd);
}

static DWORD WINAPI WorkerThreadProc(void *) {
  g_workerReady.store(false, std::memory_order_release);
  ComApartment apartment(COINIT_MULTITHREADED);
  if (FAILED(apartment.result)) {
    SetEvent(g_workerReadyEvent);
    return 0;
  }
  WorkerComState state;
  if (WorkerStopRequested() || !InitializeWorkerComState(&state)) {
    SetEvent(g_workerReadyEvent);
    return 0;
  }
  g_workerReady.store(true, std::memory_order_release);
  SetEvent(g_workerReadyEvent);
  HANDLE waits[] = {g_runtimeCancelEvent, g_stopEvent, g_requestEvent};
  while (WaitForMultipleObjects(ARRAYSIZE(waits), waits, FALSE, INFINITE) ==
         WAIT_OBJECT_0 + 2) {
    RescueRequest request;
    while (!WorkerStopRequested() && TakePendingRequest(&request)) {
      ProcessRescueRequest(&state, request);
    }
  }
  g_workerReady.store(false, std::memory_order_release);
  return 0;
}

static bool QueueRescue(HWND hwnd, DWORD pid, DWORD tid,
                        const GUID &sourceDesktopId,
                        const GUID &requestedDesktopId,
                        uint64_t navigationGeneration) {
  if (g_unloading.load(std::memory_order_acquire) ||
      g_foregroundPolicyRescueSequence)
    return false;
  RescueRequest request;
  request.sequence = g_nextSequence.fetch_add(1);
  request.navigationGeneration = navigationGeneration;
  request.hwnd = hwnd;
  request.pid = pid;
  request.tid = tid;
  request.sourceDesktopId = sourceDesktopId;
  request.requestedDesktopId = requestedDesktopId;
  bool queued = false;
  AcquireSRWLockExclusive(&g_requestLock);
  if (!g_unloading.load(std::memory_order_acquire) &&
      g_workerReady.load(std::memory_order_acquire) && g_requestEvent &&
      g_rescueQueueCount < kRescueQueueCapacity) {
    g_rescueQueue[(g_rescueQueueHead + g_rescueQueueCount) %
                  kRescueQueueCapacity] = request;
    ++g_rescueQueueCount;
    queued = true;
  }
  ReleaseSRWLockExclusive(&g_requestLock);
  if (queued)
    g_foregroundPolicyRescueSequence = request.sequence;
  return queued;
}

static HRESULT SwitchDesktopInternal_Hook(void *pThis,
                                          IVirtualDesktop *requestedDesktop) {
  if (!pThis || !requestedDesktop ||
      g_unloading.load(std::memory_order_acquire)) {
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  // Only switches nested in foreground activation are eligible. Explicit
  // Task View / desktop-shortcut navigation goes through unchanged.
  if (g_foregroundPolicyDepth <= 0) {
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  // Both opt-out modes must bypass Explorer's activation-rescue layer too.
  if (Policy::ForWindow(g_foregroundPolicyHwnd) != Policy::Mode::Summon)
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);

  GUID requestedId = {};
  HRESULT requestedIdHr = requestedDesktop->GetId(&requestedId);

  if (FAILED(requestedIdHr)) {
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  const uint64_t currentNavigationGeneration =
      g_navigationGeneration.load(std::memory_order_acquire);

  const NavigationFocusRecord navigationFocus =
      g_foregroundPolicyNavigationFocus;

  if (navigationFocus.valid) {
    if (GuidEqual(requestedId, navigationFocus.desktopId) &&
        navigationFocus.generation < currentNavigationGeneration)
      return S_OK;
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  if (currentNavigationGeneration != g_foregroundPolicyNavigationGeneration) {
    return S_OK;
  }

  if (!g_workerReady.load(std::memory_order_acquire)) {
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  GUID sourceDesktopId = {};
  if (!g_notificationReady.load(std::memory_order_acquire) ||
      !LoadCurrentDesktopId(&sourceDesktopId)) {
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  HWND candidate = g_foregroundPolicyHwnd;

  if (!IsRescueCandidate(candidate)) {
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  if (GuidEqual(sourceDesktopId, requestedId)) {
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  DWORD candidatePid = 0;
  DWORD candidateTid = GetWindowThreadProcessId(candidate, &candidatePid);

  if (!candidatePid || !candidateTid) {
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  const uint64_t navigationGeneration = g_foregroundPolicyNavigationGeneration;

  if (g_navigationGeneration.load(std::memory_order_acquire) !=
      navigationGeneration) {
    return S_OK;
  }

  if (!QueueRescue(candidate, candidatePid, candidateTid, sourceDesktopId,
                   requestedId, navigationGeneration)) {
    return g_switchDesktopInternalOriginal(pThis, requestedDesktop);
  }

  return S_OK;
}

static bool StartWorker() {
  g_workerReady.store(false, std::memory_order_release);
  g_startUnsupported.store(false, std::memory_order_release);
  if (RuntimeCancellationRequested())
    return false;
  g_requestEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  g_workerReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_requestEvent || !g_stopEvent || !g_workerReadyEvent)
    return false;
  g_workerThread =
      CreateThread(nullptr, 0, WorkerThreadProc, nullptr, 0, nullptr);
  if (!g_workerThread)
    return false;
  HANDLE waits[] = {g_runtimeCancelEvent, g_workerReadyEvent};
  DWORD result = WaitForMultipleObjects(ARRAYSIZE(waits), waits, FALSE, 5000);
  if (result == WAIT_OBJECT_0 + 1)
    return g_workerReady.load(std::memory_order_acquire);
  return false;
}

static void StopWorker() {
  InvalidateNavigationState();
  AcquireSRWLockExclusive(&g_requestLock);
  g_workerReady.store(false, std::memory_order_release);
  g_rescueQueueHead = g_rescueQueueCount = 0;
  ReleaseSRWLockExclusive(&g_requestLock);
  if (g_stopEvent)
    SetEvent(g_stopEvent);
  if (g_workerThread)
    WaitForSingleObject(g_workerThread, INFINITE);
  for (HANDLE *handle :
       {&g_workerThread, &g_workerReadyEvent, &g_stopEvent, &g_requestEvent}) {
    if (*handle) {
      CloseHandle(*handle);
      *handle = nullptr;
    }
  }
}

enum class RuntimeState {
  Stopped,
  Initializing,
  Ready,
  Unsupported,
};

static std::atomic<RuntimeState> g_runtimeState{RuntimeState::Stopped};

static SRWLOCK g_runtimeInitLock = SRWLOCK_INIT;

static HANDLE g_runtimeInitThread = nullptr;

static bool IsCurrentProcessWindow(HWND window) {
  if (!window)
    return false;
  DWORD pid = 0;
  return GetWindowThreadProcessId(window, &pid) && pid == GetCurrentProcessId();
}

static bool InstallVirtualDesktopHooks() {
  if (RuntimeCancellationRequested()) {
    return false;
  }

  HMODULE twinui = GetModuleHandleW(L"twinui.pcshell.dll");

  if (!twinui) {
    twinui = LoadLibraryExW(L"twinui.pcshell.dll", nullptr,
                            LOAD_LIBRARY_SEARCH_SYSTEM32);
  }

  if (!twinui) {
    return false;
  }

  if (RuntimeCancellationRequested()) {
    return false;
  }

  SymbolHook twinuiPcshellHooks[] = {
      {{LR"(const CWin32ApplicationView::`vftable'{for `IApplicationView'})"},
       reinterpret_cast<void **>(&g_win32ApplicationViewVtable)},
      {{LR"(private: virtual long __cdecl CWin32ApplicationView::v_GetNativeWindow(struct HWND__ * *))"},
       reinterpret_cast<void **>(&g_win32ApplicationViewGetNativeWindow)},
      {{LR"(const CWinRTApplicationView::`vftable'{for `IApplicationView'})"},
       reinterpret_cast<void **>(&g_winRtApplicationViewVtable)},
      {{LR"(private: virtual long __cdecl CWinRTApplicationView::v_GetNativeWindow(struct HWND__ * *))"},
       reinterpret_cast<void **>(&g_winRtApplicationViewGetNativeWindow)},
      {{L"public: virtual long __cdecl "
        L"CVirtualDesktopManager::"
        L"SwitchDesktopInternal("
        L"struct IVirtualDesktop *)"},
       reinterpret_cast<void **>(&g_switchDesktopInternalOriginal),
       reinterpret_cast<void *>(SwitchDesktopInternal_Hook)},
      {{L"public: virtual long __cdecl "
        L"CVirtualDesktopForegroundPolicy::"
        L"DesktopChanged("
        L"struct IVirtualDesktop *)"},
       reinterpret_cast<void **>(&g_desktopChangedOriginal),
       reinterpret_cast<void *>(DesktopChanged_Hook)},
      {{L"public: virtual long __cdecl "
        L"CVirtualDesktopForegroundPolicy::"
        L"ForegroundViewChanged("
        L"struct IVirtualDesktopManagerPrivate *,"
        L"struct IVirtualDesktopSwitchAnimator *,"
        L"struct IApplicationView *)"},
       reinterpret_cast<void **>(&g_foregroundViewChangedOriginal),
       reinterpret_cast<void *>(ForegroundViewChanged_Hook)},
      {{L"public: virtual long __cdecl "
        L"CVirtualDesktopForegroundPolicy::"
        L"GetNewForegroundViewForDesktopSwitch("
        L"struct IVirtualDesktop *,"
        L"struct IApplicationView * *,"
        L"bool *)"},
       reinterpret_cast<void **>(
           &g_getNewForegroundViewForDesktopSwitchOriginal),
       reinterpret_cast<void *>(GetNewForegroundViewForDesktopSwitch_Hook)},
  };

  if (!HookSymbols(twinui, twinuiPcshellHooks, ARRAYSIZE(twinuiPcshellHooks))) {
    return false;
  }

  if (RuntimeCancellationRequested()) {
    return false;
  }

  if (!Wh_ApplyHookOperations()) {
    return false;
  }

  return !RuntimeCancellationRequested();
}

static DWORD WINAPI ShellHostInitThreadProc(void *) {
  constexpr int kMaxRuntimeStartAttempts = 30;
  for (int attempt = 1;
       attempt <= kMaxRuntimeStartAttempts && !RuntimeCancellationRequested();
       ++attempt) {
    bool started = StartWorker();
    if (started && !RuntimeCancellationRequested())
      started = StartNotificationCache();
    bool hookInstallFailed = false;
    if (started && !RuntimeCancellationRequested()) {
      if (InstallVirtualDesktopHooks() && !RuntimeCancellationRequested()) {
        g_runtimeState.store(RuntimeState::Ready, std::memory_order_release);
        return 0;
      }
      hookInstallFailed = !RuntimeCancellationRequested();
    }
    StopNotificationCache();
    StopWorker();
    if (hookInstallFailed || RuntimeCancellationRequested())
      break;
    if (g_startUnsupported.load(std::memory_order_acquire)) {
      g_runtimeState.store(RuntimeState::Unsupported, std::memory_order_release);
      return 0;
    }
    if (attempt < kMaxRuntimeStartAttempts &&
        WaitForSingleObject(g_runtimeCancelEvent, 500) != WAIT_TIMEOUT)
      break;
  }
  g_runtimeState.store(RuntimeState::Stopped, std::memory_order_release);
  return 0;
}

static void PromoteCurrentProcessToShellHost() {
  if (g_unloading.load(std::memory_order_acquire)) {
    return;
  }

  RuntimeState state = g_runtimeState.load(std::memory_order_acquire);

  if (state == RuntimeState::Ready || state == RuntimeState::Unsupported) {
    return;
  }

  AcquireSRWLockExclusive(&g_runtimeInitLock);

  if (g_unloading.load(std::memory_order_relaxed) ||
      g_runtimeState.load(std::memory_order_relaxed) != RuntimeState::Stopped) {
    ReleaseSRWLockExclusive(&g_runtimeInitLock);
    return;
  }

  if (g_runtimeInitThread) {
    if (WaitForSingleObject(g_runtimeInitThread, 0) == WAIT_OBJECT_0) {
      CloseHandle(g_runtimeInitThread);
      g_runtimeInitThread = nullptr;
    } else {
      ReleaseSRWLockExclusive(&g_runtimeInitLock);
      return;
    }
  }

  g_runtimeState.store(RuntimeState::Initializing, std::memory_order_release);

  g_runtimeInitThread =
      CreateThread(nullptr, 0, ShellHostInitThreadProc, nullptr, 0, nullptr);

  if (!g_runtimeInitThread) {
    g_runtimeState.store(RuntimeState::Stopped, std::memory_order_release);
  }

  ReleaseSRWLockExclusive(&g_runtimeInitLock);
}

using CreateWindowExW_t = decltype(&CreateWindowExW);

static CreateWindowExW_t g_createWindowExWOriginal = nullptr;

static HWND WINAPI CreateWindowExW_Hook(DWORD dwExStyle, LPCWSTR lpClassName,
                                        LPCWSTR lpWindowName, DWORD dwStyle,
                                        int X, int Y, int nWidth, int nHeight,
                                        HWND hWndParent, HMENU hMenu,
                                        HINSTANCE hInstance, LPVOID lpParam) {
  HWND hwnd = g_createWindowExWOriginal(dwExStyle, lpClassName, lpWindowName,
                                        dwStyle, X, Y, nWidth, nHeight,
                                        hWndParent, hMenu, hInstance, lpParam);

  if (!hwnd || g_unloading.load(std::memory_order_acquire)) {
    return hwnd;
  }

  RuntimeState state = g_runtimeState.load(std::memory_order_acquire);

  if (state == RuntimeState::Ready || state == RuntimeState::Unsupported) {
    return hwnd;
  }

  bool isPrimaryTaskbar = false;

  if (lpClassName && !IS_INTRESOURCE(lpClassName)) {
    isPrimaryTaskbar = _wcsicmp(lpClassName, L"Shell_TrayWnd") == 0;
  } else {
    wchar_t className[32] = {};

    if (GetClassNameW(hwnd, className, ARRAYSIZE(className))) {
      isPrimaryTaskbar = _wcsicmp(className, L"Shell_TrayWnd") == 0;
    }
  }

  if (!isPrimaryTaskbar) {
    return hwnd;
  }

  PromoteCurrentProcessToShellHost();

  return hwnd;
}

static void StopRuntimeBeforeUninit() {
  g_unloading.store(true, std::memory_order_release);

  if (g_runtimeCancelEvent) {
    SetEvent(g_runtimeCancelEvent);
  }

  HANDLE initThread = nullptr;

  AcquireSRWLockExclusive(&g_runtimeInitLock);

  initThread = g_runtimeInitThread;
  g_runtimeInitThread = nullptr;

  ReleaseSRWLockExclusive(&g_runtimeInitLock);

  if (initThread) {
    WaitForSingleObject(initThread, INFINITE);

    CloseHandle(initThread);
  }

  StopNotificationCache();
  StopWorker();

  g_runtimeState.store(RuntimeState::Stopped, std::memory_order_release);
}

BOOL Init() {
  g_unloading.store(false, std::memory_order_release);

  g_runtimeCancelEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

  if (!g_runtimeCancelEvent) {
    return FALSE;
  }

  if (!Wh_SetFunctionHook((void *)CreateWindowExW, (void *)CreateWindowExW_Hook,
                          (void **)&g_createWindowExWOriginal)) {
    CloseHandle(g_runtimeCancelEvent);
    g_runtimeCancelEvent = nullptr;
    return FALSE;
  }

  return TRUE;
}

void AfterInit() {
  if (IsCurrentProcessWindow(FindWindowW(L"Shell_TrayWnd", nullptr)) ||
      IsCurrentProcessWindow(GetShellWindow()))
    PromoteCurrentProcessToShellHost();
}

void BeforeUninit() { StopRuntimeBeforeUninit(); }

void Uninit() {
  if (g_runtimeCancelEvent) {
    CloseHandle(g_runtimeCancelEvent);
    g_runtimeCancelEvent = nullptr;
  }
}
} // namespace Activation

namespace Active {
static thread_local bool inLaunch = false;
static std::atomic<bool> stopping{false};
static HANDLE installStop, installThread;
static decltype(&ShellExecuteExW) originalEx;
static decltype(&ShellExecuteW) originalSimple;
using LinkInvoke = HRESULT(WINAPI *)(IContextMenu *, LPCMINVOKECOMMANDINFO);
static LinkInvoke originalLink;

template <class T> using Ptr = ComPtr<T>;
using Apartment = ComApartment;
// The private interface declarations intentionally preserve their ABI slots.
// Unused preceding methods cannot be deleted from a COM vtable declaration.
using Desktop = Activation::IVirtualDesktop;
using View = Activation::IApplicationView;
using Views = Activation::IApplicationViewCollection;
using Manager = Activation::IVirtualDesktopManagerInternal;
struct Services {
  Apartment apartment; // Destroyed last, after all COM pointers.
  Ptr<IServiceProvider> provider;
  Ptr<Manager> manager;
  Ptr<Views> views;
  Ptr<IVirtualDesktopManager> publicManager;
  bool Connect() {
    if (!apartment)
      return false;
    HRESULT hr =
        CoCreateInstance(Activation::kClsidImmersiveShell, nullptr,
                         CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&provider.p));
    if (FAILED(hr) || !provider.p)
      return false;
    hr = provider->QueryService(
        Activation::kClsidVirtualDesktopManagerInternal,
        Activation::kIidVirtualDesktopManagerInternal24H2, (void **)&manager.p);
    if (FAILED(hr) || !manager.p)
      return false;
    return true;
  }
  bool GetView(HWND window, Ptr<View> &view) {
    if (!views.p &&
        (FAILED(provider->QueryService(
             Activation::kIidApplicationViewCollection,
             Activation::kIidApplicationViewCollection, (void **)&views.p)) ||
         !views.p))
      return false;
    return SUCCEEDED(views->GetViewForHwnd(window, &view.p)) && view.p;
  }
};

static DWORD Pid(HWND window) {
  DWORD pid = 0;
  GetWindowThreadProcessId(window, &pid);
  return pid;
}
static bool Empty(PCWSTR text) {
  if (!text)
    return true;
  for (; *text; ++text)
    if (*text != L' ' && *text != L'\t')
      return false;
  return true;
}
using Process::ReadProcess;
enum class Host { Launcher, Shell, Search };
static Host IdentifyHost(DWORD pid) {
  const auto process = ReadProcess(pid);
  wchar_t windows[MAX_PATH];
  if (!GetWindowsDirectoryW(windows, ARRAYSIZE(windows)))
    return Host::Launcher;
  if (!_wcsicmp(process.path.c_str(),
                (std::wstring(windows) + L"\\explorer.exe").c_str()))
    return Host::Shell;
  const std::wstring prefix = std::wstring(windows) + L"\\SystemApps\\";
  if (process.path.size() <= prefix.size() ||
      _wcsnicmp(process.path.c_str(), prefix.c_str(), prefix.size()))
    return Host::Launcher;
  const wchar_t *name = wcsrchr(process.path.c_str(), L'\\');
  return name && (!_wcsicmp(name + 1, L"SearchHost.exe") ||
                  !_wcsicmp(name + 1, L"StartMenuExperienceHost.exe"))
             ? Host::Search : Host::Launcher;
}
static bool ReadLinkTarget(IShellLinkW *link, std::wstring &path) {
  // Only emptiness is needed: do not copy the shortcut's command line.
  wchar_t arguments[2] = {};
  if (FAILED(link->GetArguments(arguments, ARRAYSIZE(arguments))) ||
      arguments[0])
    return false;
  Ptr<IShellLinkDataList> properties;
  DWORD flags = 0;
  if (FAILED(link->QueryInterface(IID_PPV_ARGS(&properties.p))) ||
      !properties.p || FAILED(properties->GetFlags(&flags)) ||
      (flags & (SLDF_RUNAS_USER | SLDF_HAS_DARWINID | SLDF_RUN_WITH_SHIMLAYER |
                SLDF_RUN_IN_SEPARATE)))
    return false;
  wchar_t small[MAX_PATH] = {};
  // GetPath's documented return limit is MAX_PATH. A larger retry buffer
  // cannot extend that contract; QueryFullProcessImageName has its own sizing.
  if (link->GetPath(small, ARRAYSIZE(small), nullptr, SLGP_RAWPATH) != S_OK ||
      !small[0])
    return false;
  path = small;
  return true;
}
static bool HasLocalExtension(const std::wstring &path, PCWSTR extension) {
  return path.size() >= 7 && path[1] == L':' && path[2] == L'\\' &&
         !_wcsicmp(path.c_str() + path.size() - 4, extension);
}
static bool ResolveTarget(PCWSTR file, std::wstring &path) {
  if (!file)
    return false;
  path = file;
  // Existing-process matching proves the target on the reuse path. Cold starts
  // retain Shell's own file validation rather than doing redundant disk I/O.
  if (HasLocalExtension(path, L".exe"))
    return true;
  if (!HasLocalExtension(path, L".lnk"))
    return false;
  Apartment apartment;
  if (!apartment)
    return false;
  Ptr<IShellLinkW> link;
  Ptr<IPersistFile> persist;
  HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&link.p));
  if (SUCCEEDED(hr) && link.p)
    hr = link->QueryInterface(IID_PPV_ARGS(&persist.p));
  if (FAILED(hr) || !persist.p)
    return false;
  return SUCCEEDED(persist->Load(path.c_str(), STGM_READ)) &&
         ReadLinkTarget(link.p, path) && HasLocalExtension(path, L".exe");
}

// Search UI grants the actual shell foreground permission through a bounded,
// event-driven channel. No startup command or user text is transmitted.
struct GrantData {
  volatile LONG sequence, pid, input, granted, reply;
};
static HANDLE grantStop, grantRequest, grantResponse, grantMapping, grantThread;
static GrantData *grantData;
static std::atomic<LONG> nextGrant{0};
static DWORD WINAPI GrantLoop(void *) {
  HANDLE events[] = {grantStop, grantRequest};
  while (WaitForMultipleObjects(2, events, FALSE, INFINITE) ==
         WAIT_OBJECT_0 + 1) {
    const LONG sequence =
        InterlockedCompareExchange(&grantData->sequence, 0, 0);
    const DWORD client = InterlockedCompareExchange(&grantData->pid, 0, 0);
    const DWORD stamp = InterlockedCompareExchange(&grantData->input, 0, 0);
    LASTINPUTINFO input = {sizeof(input)};
    const bool granted =
        sequence && client && client == Pid(GetShellWindow()) &&
        Pid(GetForegroundWindow()) == GetCurrentProcessId() &&
        GetLastInputInfo(&input) && input.dwTime == stamp &&
        InterlockedCompareExchange(&grantData->sequence, 0, 0) == sequence &&
        AllowSetForegroundWindow(client);
    InterlockedExchange(&grantData->granted, granted);
    InterlockedExchange(&grantData->reply, sequence);
    SetEvent(grantResponse);
  }
  return 0;
}
static void ReleaseGrant() {
  if (grantData) {
    UnmapViewOfFile(grantData);
    grantData = nullptr;
  }
  for (HANDLE *handle : {&grantThread, &grantMapping, &grantResponse,
                         &grantRequest, &grantStop}) {
    if (*handle) {
      CloseHandle(*handle);
      *handle = nullptr;
    }
  }
}
static bool StartGrant() {
  const auto suffix = std::to_wstring(GetCurrentProcessId());
  grantStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  grantRequest = CreateEventW(
      nullptr, FALSE, FALSE,
      (L"Local\\ActiveOnCurrentDesktop-Request-" + suffix).c_str());
  grantResponse = CreateEventW(
      nullptr, FALSE, FALSE,
      (L"Local\\ActiveOnCurrentDesktop-Response-" + suffix).c_str());
  grantMapping = CreateFileMappingW(
      INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(GrantData),
      (L"Local\\ActiveOnCurrentDesktop-Data-" + suffix).c_str());
  if (grantMapping)
    grantData = (GrantData *)MapViewOfFile(grantMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0,
                                           0, sizeof(GrantData));
  if (grantStop && grantRequest && grantResponse && grantData)
    grantThread = CreateThread(nullptr, 0, GrantLoop, nullptr, 0, nullptr);
  if (grantThread)
    return true;
  ReleaseGrant();
  return false;
}
static std::wstring GrantNamespace(DWORD host) {
  Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, host));
  HANDLE rawToken = nullptr;
  if (!process || !OpenProcessToken(process.get(), TOKEN_QUERY, &rawToken))
    return {};
  Handle token(rawToken);
  DWORD container = 0, bytes = 0;
  if (!GetTokenInformation(token.get(), TokenIsAppContainer, &container,
                           sizeof(container), &bytes))
    return {};
  std::wstring prefix = L"Local\\";
  if (container) {
    wchar_t path[2048];
    ULONG needed = 0;
    if (!GetAppContainerNamedObjectPath(token.get(), nullptr, ARRAYSIZE(path),
                                        path, &needed))
      return {};
    prefix += std::wstring(path) + L"\\";
  }
  return prefix;
}
static bool WaitForGrant(GrantData *data, HANDLE response, LONG sequence) {
  const DWORD started = GetTickCount();
  while (!stopping.load()) {
    const DWORD elapsed = GetTickCount() - started;
    if (elapsed >= 150 ||
        WaitForSingleObject(response, 150 - elapsed) != WAIT_OBJECT_0)
      return false;
    // A timed-out older request can still signal this auto-reset event.
    // Ignore its reply without extending this request's original deadline.
    if (InterlockedCompareExchange(&data->reply, 0, 0) == sequence)
      return InterlockedCompareExchange(&data->granted, 0, 0) == 1;
  }
  return false;
}
static bool RequestGrant(DWORD host, DWORD input) {
  if (host == GetCurrentProcessId())
    return true;
  const auto suffix = std::to_wstring(host);
  const auto prefix = GrantNamespace(host);
  if (prefix.empty())
    return false;
  Handle mutex(
      CreateMutexW(nullptr, FALSE,
                   (L"Local\\ActiveOnCurrentDesktop-Lock-" + suffix).c_str()));
  if (!mutex)
    return false;
  DWORD wait = WaitForSingleObject(mutex.get(), 100);
  if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED)
    return false;
  struct Unlock {
    HANDLE handle;
    ~Unlock() { ReleaseMutex(handle); }
  } unlock{mutex.get()};
  Handle mapping(OpenFileMappingW(
      FILE_MAP_READ | FILE_MAP_WRITE, FALSE,
      (prefix + L"ActiveOnCurrentDesktop-Data-" + suffix).c_str()));
  Handle request(OpenEventW(
      EVENT_MODIFY_STATE, FALSE,
      (prefix + L"ActiveOnCurrentDesktop-Request-" + suffix).c_str()));
  Handle response(OpenEventW(
      SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE,
      (prefix + L"ActiveOnCurrentDesktop-Response-" + suffix).c_str()));
  if (!mapping || !request || !response)
    return false;
  auto data = (GrantData *)MapViewOfFile(mapping.get(), FILE_MAP_READ | FILE_MAP_WRITE, 0,
                                         0, sizeof(GrantData));
  if (!data)
    return false;
  struct Unmap {
    void *address;
    ~Unmap() { UnmapViewOfFile(address); }
  } unmap{data};
  LONG sequence = ++nextGrant;
  if (!sequence)
    sequence = ++nextGrant;
  ResetEvent(response.get());
  InterlockedExchange(&data->pid, GetCurrentProcessId());
  InterlockedExchange(&data->input, input);
  InterlockedExchange(&data->granted, 0);
  InterlockedExchange(&data->reply, 0);
  InterlockedExchange(&data->sequence, sequence);
  SetEvent(request.get());
  const bool granted = WaitForGrant(data, response.get(), sequence);
  InterlockedExchange(&data->sequence, 0);
  InterlockedExchange(&data->pid, 0);
  return granted;
}

struct Candidate {
  HWND window;
  DWORD pid;
  ULONGLONG created;
  long long area;
};
// The caller has already excluded the empty/cold-start case.
static Candidate SelectCandidate(const std::vector<Candidate> &candidates,
                                 IVirtualDesktopManager *manager) {
  auto selected = candidates.begin();
  for (auto item = candidates.begin(); item != candidates.end(); ++item) {
    if (item->area > selected->area)
      selected = item;
  }
  const long long largest = selected->area;
  if (candidates.size() > 1) {
    for (auto item = candidates.begin(); item != candidates.end(); ++item) {
      if (item->area < largest * 3 / 4)
        continue;
      BOOL current = FALSE;
      if (SUCCEEDED(manager->IsWindowOnCurrentVirtualDesktop(item->window,
                                                             &current)) &&
          current) {
        selected = item;
        break;
      }
    }
  }
  return *selected;
}
struct WindowSearch {
  const std::wstring &target;
  std::vector<Candidate> candidates;
  std::unordered_map<DWORD, ULONGLONG> identities;
};
static BOOL CALLBACK CollectWindow(HWND window, LPARAM parameter) {
  auto &search = *(WindowSearch *)parameter;
  if (!IsWindowVisible(window) || GetWindow(window, GW_OWNER) ||
      GetAncestor(window, GA_ROOT) != window)
    return TRUE;
  const auto style = GetWindowLongPtrW(window, GWL_STYLE);
  const auto extended = GetWindowLongPtrW(window, GWL_EXSTYLE);
  if ((style & WS_CHILD) ||
      ((extended & WS_EX_TOOLWINDOW) && !(extended & WS_EX_APPWINDOW)) ||
      GetWindowTextLengthW(window) == 0)
    return TRUE;
  // Query a process once per request; only matching processes need DWM/COM.
  const DWORD pid = Pid(window);
  auto found = search.identities.find(pid);
  if (found == search.identities.end())
    found =
        search.identities.emplace(pid, ReadProcess(pid, &search.target).created).first;
  if (!found->second)
    return TRUE;
  DWORD cloak = 0;
  if (FAILED(DwmGetWindowAttribute(window, DWMWA_CLOAKED, &cloak,
                                   sizeof(cloak))) ||
      (cloak & DWM_CLOAKED_APP))
    return TRUE;
  RECT rect{};
  WINDOWPLACEMENT placement{sizeof(placement)};
  if (IsIconic(window) && GetWindowPlacement(window, &placement))
    rect = placement.rcNormalPosition;
  else if (!GetWindowRect(window, &rect))
    return TRUE;
  const long long width = rect.right - rect.left,
                  height = rect.bottom - rect.top;
  if (width < 80 || height < 60)
    return TRUE;
  search.candidates.push_back(
      {window, pid, found->second, width * height});
  return TRUE;
}
static bool InputUnchanged(DWORD stamp) {
  LASTINPUTINFO current{sizeof(current)};
  return GetLastInputInfo(&current) && current.dwTime == stamp;
}
static bool ActivateExisting(PCWSTR file, PCWSTR verb, PCWSTR arguments,
                             bool &committed) {
  if (stopping.load() || !Empty(arguments) ||
      (verb && *verb && _wcsicmp(verb, L"open")))
    return false;
  const DWORD sourcePid =
      Pid(GetForegroundWindow()); // Preserve identity even if the popup is
                                  // destroyed.
  if (!sourcePid ||
      (sourcePid != GetCurrentProcessId() && IdentifyHost(sourcePid) != Host::Search))
    return false;
  std::wstring targetPath;
  if (!ResolveTarget(file, targetPath))
    return false;
  const auto mode = Policy::ForPath(targetPath);
  if (mode == Policy::Mode::Original)
    return false;
  const int primaryButton = GetSystemMetrics(SM_SWAPBUTTON) ? VK_RBUTTON : VK_LBUTTON;
  const DWORD started = GetTickCount();
  while ((GetAsyncKeyState(VK_RETURN) & 0x8000) ||
         (GetAsyncKeyState(VK_SPACE) & 0x8000) ||
         (GetAsyncKeyState(primaryButton) & 0x8000)) {
    if (GetTickCount() - started >= 150)
      return false;
    Sleep(2);
  }
  LASTINPUTINFO input{sizeof(input)};
  if (!GetLastInputInfo(&input) || GetTickCount() - input.dwTime > 2000)
    return false;
  WindowSearch search{targetPath, {}, {}};
  EnumWindows(CollectWindow, (LPARAM)&search);
  // A cold start needs no virtual-desktop COM connection or focus grant.
  if (search.candidates.empty() || !InputUnchanged(input.dwTime))
    return false;
  Services services;
  if (!services.Connect())
    return false;
  UINT count = 0;
  if (FAILED(services.manager->GetCount(&count)) || count < 2)
    return false;
  if (FAILED(CoCreateInstance(__uuidof(VirtualDesktopManager), nullptr,
                              CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&services.publicManager.p))) ||
      !services.publicManager.p)
    return false;
  Ptr<Desktop> desktop;
  GUID origin{};
  if (FAILED(services.manager->GetCurrentDesktop(&desktop.p)) || !desktop.p ||
      FAILED(desktop->GetId(&origin)))
    return false;
  const auto generation =
      Activation::g_navigationGeneration.load(std::memory_order_acquire);
  // Only competitive candidates can affect selection. A sole candidate needs
  // no desktop query here; its current state is checked at commit time below.
  const Candidate target =
      SelectCandidate(search.candidates, services.publicManager.p);
  if (!RequestGrant(sourcePid, input.dwTime))
    return false;
  const auto identity = ReadProcess(target.pid, &targetPath);
  if (Pid(target.window) != target.pid || identity.created != target.created)
    return false;
  Ptr<View> view;
  BOOL current = FALSE;
  if (FAILED(services.publicManager->IsWindowOnCurrentVirtualDesktop(
          target.window, &current)))
    return false;
  if (!current && mode == Policy::Mode::Summon) {
    if (!services.GetView(target.window, view))
      return false;
    BOOL canMove = FALSE;
    if (FAILED(services.manager->CanViewMoveDesktops(view.p, &canMove)) ||
        !canMove)
      return false;
  }
  // This is a commit guard, not a diagnostic: a new user action or desktop
  // navigation must cancel an old request before it can move a window.
  Ptr<Desktop> commitDesktop;
  GUID currentId{};
  if (stopping.load() || !InputUnchanged(input.dwTime) ||
      Activation::g_navigationGeneration.load(std::memory_order_acquire) !=
          generation ||
      FAILED(services.manager->GetCurrentDesktop(&commitDesktop.p)) ||
      !commitDesktop.p || FAILED(commitDesktop->GetId(&currentId)) ||
      !IsEqualGUID(currentId, origin))
    return false;
  if (!current && mode == Policy::Mode::Summon &&
      FAILED(services.manager->MoveViewToDesktop(view.p, commitDesktop.p)))
    return false;
  committed =
      true; // No duplicate launch after a move, even if foreground is refused.
  if (IsIconic(target.window))
    ShowWindowAsync(target.window, SW_RESTORE);
  if (InputUnchanged(input.dwTime) &&
      Activation::g_navigationGeneration.load(std::memory_order_acquire) ==
          generation) {
    // Cross-thread activation is asynchronous. An immediate foreground-HWND
    // snapshot can report the old window even when this request succeeded.
    if (!SetForegroundWindow(target.window) && InputUnchanged(input.dwTime) &&
        Pid(target.window) == target.pid &&
        (view.p || services.GetView(target.window, view))) {
      if (!InputUnchanged(input.dwTime) || Pid(target.window) != target.pid ||
          Activation::g_navigationGeneration.load(std::memory_order_acquire) !=
              generation)
        return true;
      CoAllowSetForegroundWindow(services.provider.p, nullptr);
      view->SetFocus();
    }
  }
  return true;
}
static bool HandleLaunch(PCWSTR file, PCWSTR verb, PCWSTR arguments) noexcept {
  bool committed = false;
  try {
    return ActivateExisting(file, verb, arguments, committed);
  } catch (...) {
    return committed;
  }
}
struct LaunchScope {
  LaunchScope() { inLaunch = true; }
  ~LaunchScope() { inLaunch = false; }
};
static BOOL WINAPI HookEx(SHELLEXECUTEINFOW *info) {
  if (inLaunch || !info || info->cbSize < sizeof(*info))
    return originalEx(info);
  LaunchScope scope;
  constexpr ULONG supported =
      SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
  if (!(info->fMask & ~supported) &&
      HandleLaunch(info->lpFile, info->lpVerb, info->lpParameters)) {
    info->hInstApp = (HINSTANCE)33;
    if (info->fMask & SEE_MASK_NOCLOSEPROCESS)
      info->hProcess = nullptr;
    return TRUE;
  }
  return originalEx(info);
}
static HINSTANCE WINAPI HookSimple(HWND owner, PCWSTR verb, PCWSTR file,
                                   PCWSTR arguments, PCWSTR directory,
                                   int show) {
  if (inLaunch)
    return originalSimple(owner, verb, file, arguments, directory, show);
  LaunchScope scope;
  if (HandleLaunch(file, verb, arguments))
    return (HINSTANCE)33;
  return originalSimple(owner, verb, file, arguments, directory, show);
}
static bool OpenVerb(PCSTR verb) {
  return IS_INTRESOURCE(verb) ? LOWORD((ULONG_PTR)verb) == 0
                              : _stricmp(verb, "open") == 0;
}
static HRESULT WINAPI HookLink(IContextMenu *menu, LPCMINVOKECOMMANDINFO info) {
  if (inLaunch || !menu || !info || info->cbSize < sizeof(*info))
    return originalLink(menu, info);
  LaunchScope scope;
  constexpr DWORD supported = CMIC_MASK_PTINVOKE | CMIC_MASK_FLAG_LOG_USAGE |
                              CMIC_MASK_UNICODE | CMIC_MASK_FLAG_NO_UI |
                              CMIC_MASK_NOASYNC;
  if ((info->fMask & ~supported) ||
      (info->lpParameters && *info->lpParameters) || !OpenVerb(info->lpVerb))
    return originalLink(menu, info);
  if (info->fMask & CMIC_MASK_UNICODE) {
    if (info->cbSize < sizeof(CMINVOKECOMMANDINFOEX))
      return originalLink(menu, info);
    auto extended = (const CMINVOKECOMMANDINFOEX *)info;
    if (!Empty(extended->lpParametersW) ||
        (extended->lpVerbW &&
         (IS_INTRESOURCE(extended->lpVerbW)
              ? LOWORD((ULONG_PTR)extended->lpVerbW) != 0
              : _wcsicmp(extended->lpVerbW, L"open") != 0)))
      return originalLink(menu, info);
  }
  try {
    Apartment apartment;
    Ptr<IShellLinkW> link;
    if (apartment && SUCCEEDED(menu->QueryInterface(IID_PPV_ARGS(&link.p))) &&
        link.p) {
      std::wstring path;
      if (ReadLinkTarget(link.p, path) &&
          HandleLaunch(path.c_str(), nullptr, nullptr))
        return S_OK;
    }
  } catch (...) { /* Preserve the original launch on allocation failure. */
  }
  return originalLink(menu, info);
}
static DWORD WINAPI InstallLinkHook(void *) {
  for (int attempt = 0; attempt < 120; ++attempt) {
    if (WaitForSingleObject(installStop, 0) == WAIT_OBJECT_0)
      return 0;
    HMODULE storage = GetModuleHandleW(L"windows.storage.dll");
    if (!storage) {
      if (WaitForSingleObject(installStop, 50) == WAIT_OBJECT_0)
        return 0;
      continue;
    }
    SymbolHook hooks[] = {
        {{L"public: virtual long __cdecl CShellLink::InvokeCommand(struct "
          L"_CMINVOKECOMMANDINFO *)"},
         (void **)&originalLink,
         (void *)HookLink}};
    if (HookSymbols(storage, hooks, ARRAYSIZE(hooks)))
      Wh_ApplyHookOperations();
    return 0;
  }
  return 0;
}
static bool Init(Host host) {
  if (host == Host::Search)
    return StartGrant();
  HMODULE shell = GetModuleHandleW(L"shell32.dll");
  if (!shell)
    shell =
        LoadLibraryExW(L"shell32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!shell ||
      !Wh_SetFunctionHook((void *)GetProcAddress(shell, "ShellExecuteExW"),
                          (void *)HookEx, (void **)&originalEx) ||
      !Wh_SetFunctionHook((void *)GetProcAddress(shell, "ShellExecuteW"),
                          (void *)HookSimple, (void **)&originalSimple))
    return false;
  installStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!installStop)
    return false;
  installThread =
      CreateThread(nullptr, 0, InstallLinkHook, nullptr, 0, nullptr);
  if (installThread)
    return true;
  CloseHandle(installStop);
  installStop = nullptr;
  return false;
}
static void BeforeUninit() {
  stopping.store(true);
  if (grantStop)
    SetEvent(grantStop);
  if (installStop)
    SetEvent(installStop);
  if (grantThread)
    WaitForSingleObject(grantThread, INFINITE);
  if (installThread)
    WaitForSingleObject(installThread, INFINITE);
}
static void Uninit() {
  ReleaseGrant();
  if (installThread) {
    CloseHandle(installThread);
    installThread = nullptr;
  }
  if (installStop) {
    CloseHandle(installStop);
    installStop = nullptr;
  }
}
} // namespace Active

static bool activationStarted = false;
BOOL Wh_ModInit() {
  try {
    Policy::Load();
  } catch (...) {
    return FALSE;
  }
  const auto host = Active::IdentifyHost(GetCurrentProcessId());
  if (host == Active::Host::Shell) {
    if (!Activation::Init())
      return FALSE;
    activationStarted = true;
  }
  if (Active::Init(host))
    return TRUE;
  if (activationStarted) {
    Activation::BeforeUninit();
    Activation::Uninit();
    activationStarted = false;
  }
  return FALSE;
}
void Wh_ModAfterInit() {
  if (activationStarted)
    Activation::AfterInit();
}
void Wh_ModBeforeUninit() {
  Active::BeforeUninit();
  if (activationStarted)
    Activation::BeforeUninit();
}
void Wh_ModUninit() {
  Active::Uninit();
  if (activationStarted)
    Activation::Uninit();
}

BOOL Wh_ModSettingsChanged(BOOL *reload) {
  *reload = TRUE;
  return TRUE;
}
