/**
 * @file ui_observer.cpp
 * @brief AX responsiveness probe, AXObserver dialog capture and the UI Observer actor.
 */
#include "ui_observer/ui_observer.hpp"

#include <string>
#include <vector>

#include "ieso/core/trace.hpp"

namespace ieso::macos {
namespace {
constexpr int kMaxAttachAttempts = 20;                      // x kAttachRetry = 10 s after launch
constexpr std::chrono::milliseconds kAttachRetry{500};      // between AX observer attach attempts
constexpr std::string_view kComponent = "ui";
constexpr std::size_t kMaxNodes = 64;  // bounded BFS over the dialog's element tree
constexpr int kMaxDepth = 4;

/**
 * @brief Copies a string attribute.
 * @param[in] el Element.
 * @param[in] attr Attribute name.
 * @param[out] out UTF-8 value.
 * @return SRESULT::Ok or NotFound.
 */
SRESULT copy_string(AXUIElementRef el, CFStringRef attr, std::string& out) {
  CFTypeRef raw = nullptr;  // C API out-parameter, adopted below
  if (AXUIElementCopyAttributeValue(el, attr, &raw) != kAXErrorSuccess) return SRESULT::NotFound;
  CfRef<CFTypeRef> v(raw);
  if (CFGetTypeID(*v) != CFStringGetTypeID()) return SRESULT::NotFound;
  return to_utf8(static_cast<CFStringRef>(*v), out);
}

/**
 * @brief Copies a boolean attribute.
 * @param[in] el Element.
 * @param[in] attr Attribute name.
 * @param[out] out Value.
 * @return SRESULT::Ok or NotFound.
 */
SRESULT copy_bool(AXUIElementRef el, CFStringRef attr, bool& out) {
  CFTypeRef raw = nullptr;  // C API out-parameter, adopted below
  if (AXUIElementCopyAttributeValue(el, attr, &raw) != kAXErrorSuccess) return SRESULT::NotFound;
  CfRef<CFTypeRef> v(raw);
  if (CFGetTypeID(*v) != CFBooleanGetTypeID()) return SRESULT::NotFound;
  out = CFBooleanGetValue(static_cast<CFBooleanRef>(*v));
  return SRESULT::Ok;
}

/**
 * @brief Collects AXStaticText values below @p root, breadth-first with a bounded queue (no recursion).
 * @param[in] root Window element.
 * @param[out] out Texts joined with " | ".
 * @return SRESULT::Ok.
 */
SRESULT collect_texts(AXUIElementRef root, std::string& out) {
  std::deque<std::pair<CfRef<AXUIElementRef>, int>> queue;
  CfRef<AXUIElementRef> first;
  HS_RETURN_IF_FAILED(CfRef<AXUIElementRef>::Retain(root, first));
  queue.emplace_back(std::move(first), 0);
  std::size_t visited = 0;
  while (!queue.empty() && visited < kMaxNodes) {
    auto [el, depth] = std::move(queue.front());
    queue.pop_front();
    ++visited;
    std::string role;
    (void)copy_string(*el, kAXRoleAttribute, role);  // unknown role: just descend
    if (role == "AXStaticText") {
      std::string text;
      if (copy_string(*el, kAXValueAttribute, text) == SRESULT::Ok && !text.empty()) {
        if (!out.empty()) out += " | ";
        out += text;
      }
    }
    if (depth >= kMaxDepth) continue;
    CFTypeRef raw = nullptr;  // C API out-parameter, adopted below
    if (AXUIElementCopyAttributeValue(*el, kAXChildrenAttribute, &raw) != kAXErrorSuccess) continue;
    CfRef<CFTypeRef> children(raw);
    if (CFGetTypeID(*children) != CFArrayGetTypeID()) continue;
    const auto arr = static_cast<CFArrayRef>(*children);
    for (CFIndex i = 0; i < CFArrayGetCount(arr) && queue.size() < kMaxNodes; ++i) {
      CfRef<AXUIElementRef> child;
      const auto borrowed = static_cast<AXUIElementRef>(const_cast<void*>(CFArrayGetValueAtIndex(arr, i)));
      if (CfRef<AXUIElementRef>::Retain(borrowed, child) == SRESULT::Ok) queue.emplace_back(std::move(child), depth + 1);
    }
  }
  return SRESULT::Ok;
}

/**
 * @brief AXObserver callback (C API signature; exempt from the SRESULT rule).
 * @param[in] element Created window or sheet.
 * @param[in] refcon The AxDialogSource registered with the notification.
 */
void on_ax_notification(AXObserverRef /*observer*/, AXUIElementRef element, CFStringRef /*notification*/,
                        void* refcon) {
  (void)static_cast<AxDialogSource*>(refcon)->queue_window(element);  // always Ok
}
}  // namespace

// ---------------- AxProbeSource ----------------

AxProbeSource::AxProbeSource(EventBus& bus, EventFactory& factory, UiObserverOptions opts)
    : bus_(bus), factory_(factory), opts_(opts) {}

AxProbeSource::~AxProbeSource() { (void)stop(); }

SRESULT AxProbeSource::start() {
  if (running_.exchange(true)) return SRESULT::NoOp;
  if (!AXIsProcessTrusted()) {
    HS_TRACE_WARNING(kComponent,
                     "Accessibility not granted to this process: hang probe and dialog capture are disabled. "
                     "Grant it in System Settings > Privacy & Security > Accessibility (MDM PPPC in production)");
  }
  stop_.store(false);
  thread_ = std::thread([this] { (void)loop(); });  // loop() always returns Ok
  return SRESULT::Ok;
}

SRESULT AxProbeSource::stop() {
  if (!running_.exchange(false)) return SRESULT::NoOp;
  stop_.store(true);
  if (thread_.joinable()) thread_.join();
  return SRESULT::Ok;
}

SRESULT AxProbeSource::set_pid(pid_t pid) {
  pid_.store(pid);
  return SRESULT::Ok;
}

SRESULT AxProbeSource::probe(pid_t pid, std::int64_t& latency_ms, bool& timed_out, bool& permitted) {
  permitted = AXIsProcessTrusted();
  CfRef<AXUIElementRef> app(AXUIElementCreateApplication(pid));
  (void)AXUIElementSetMessagingTimeout(*app, opts_.probe_timeout_s);  // invalid element: next call reports it
  CFTypeRef raw = nullptr;  // C API out-parameter, adopted below
  const auto t0 = std::chrono::steady_clock::now();
  const AXError e = AXUIElementCopyAttributeValue(*app, kAXFocusedWindowAttribute, &raw);
  latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
  CfRef<CFTypeRef> hold(raw);
  permitted = permitted && e != kAXErrorAPIDisabled;
  // CannotComplete = no reply within the messaging timeout: the main run loop is not servicing events.
  timed_out = permitted && e == kAXErrorCannotComplete;
  return SRESULT::Ok;
}

SRESULT AxProbeSource::loop() {
  while (!stop_.load()) {
    const pid_t pid = pid_.load();
    if (pid > 0) {
      std::shared_ptr<ResponsivenessProbed> ev;
      if (factory_.make<ResponsivenessProbed>(ev) == SRESULT::Ok) {
        ev->pid = pid;
        (void)probe(pid, ev->latency_ms, ev->timed_out, ev->permitted);  // always Ok
        HS_TRACE_TRACE(kComponent, "probe pid {}: {} ms timed_out={}", pid, ev->latency_ms, ev->timed_out);
        (void)bus_.post(std::move(ev));  // routine; drops are counted by the bus
      }
    }
    const auto until = std::chrono::steady_clock::now() + opts_.probe_period;
    while (!stop_.load() && std::chrono::steady_clock::now() < until) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
  return SRESULT::Ok;
}

// ---------------- AxDialogSource ----------------

AxDialogSource::AxDialogSource(EventBus& bus, EventFactory& factory, UiObserverOptions opts)
    : bus_(bus), factory_(factory), opts_(opts) {}

AxDialogSource::~AxDialogSource() { (void)stop(); }

SRESULT AxDialogSource::start() {
  if (running_.exchange(true)) return SRESULT::NoOp;
  stop_.store(false);
  thread_ = std::thread([this] { (void)loop(); });  // loop() always returns Ok
  return SRESULT::Ok;
}

SRESULT AxDialogSource::stop() {
  if (!running_.exchange(false)) return SRESULT::NoOp;
  stop_.store(true);
  if (thread_.joinable()) thread_.join();
  return SRESULT::Ok;
}

SRESULT AxDialogSource::set_pid(pid_t pid) {
  want_pid_.store(pid);
  return SRESULT::Ok;
}

SRESULT AxDialogSource::queue_window(AXUIElementRef window) {
  CfRef<AXUIElementRef> w;
  if (CfRef<AXUIElementRef>::Retain(window, w) == SRESULT::Ok) {
    windows_.emplace_back(std::move(w), std::chrono::steady_clock::now());
  }
  return SRESULT::Ok;
}

SRESULT AxDialogSource::attach(pid_t pid) {
  AXObserverRef raw = nullptr;  // C API out-parameter, adopted below
  if (AXObserverCreate(pid, &on_ax_notification, &raw) != kAXErrorSuccess) return SRESULT::PermissionDenied;
  observer_ = CfRef<AXObserverRef>(raw);
  app_ = CfRef<AXUIElementRef>(AXUIElementCreateApplication(pid));
  (void)AXUIElementSetMessagingTimeout(*app_, opts_.probe_timeout_s);  // reading a hung app must not block us
  const AXError a = AXObserverAddNotification(*observer_, *app_, kAXWindowCreatedNotification, this);
  const AXError b = AXObserverAddNotification(*observer_, *app_, kAXSheetCreatedNotification, this);
  if (a != kAXErrorSuccess && b != kAXErrorSuccess) {
    observer_ = CfRef<AXObserverRef>();
    app_ = CfRef<AXUIElementRef>();
    return SRESULT::PermissionDenied;
  }
  CFRunLoopAddSource(CFRunLoopGetCurrent(), AXObserverGetRunLoopSource(*observer_), kCFRunLoopDefaultMode);
  pid_ = pid;
  HS_TRACE_INFO(kComponent, "observing dialogs of pid {}", pid);
  return SRESULT::Ok;
}

SRESULT AxDialogSource::detach() {
  if (observer_) {
    CFRunLoopRemoveSource(CFRunLoopGetCurrent(), AXObserverGetRunLoopSource(*observer_), kCFRunLoopDefaultMode);
  }
  observer_ = CfRef<AXObserverRef>();
  app_ = CfRef<AXUIElementRef>();
  windows_.clear();
  pid_ = 0;
  return SRESULT::Ok;
}

SRESULT AxDialogSource::inspect(AXUIElementRef window) {
  (void)AXUIElementSetMessagingTimeout(window, opts_.probe_timeout_s);  // best-effort
  std::string role, subrole, title;
  bool modal = false;
  (void)copy_string(window, kAXRoleAttribute, role);  // missing attributes are normal
  (void)copy_string(window, kAXSubroleAttribute, subrole);
  (void)copy_string(window, kAXTitleAttribute, title);
  (void)copy_bool(window, kAXModalAttribute, modal);
  const bool dialog = role == "AXSheet" || subrole == "AXDialog" || subrole == "AXSystemDialog" || modal;
  if (!dialog) return SRESULT::NoOp;
  std::string text;
  HS_RETURN_IF_FAILED(collect_texts(window, text));
  if (text.empty() && title.empty()) return SRESULT::NoOp;
  std::shared_ptr<UserVisibleErrorObserved> ev;
  HS_RETURN_IF_FAILED(factory_.make<UserVisibleErrorObserved>(ev));
  ev->pid = pid_;
  ev->window_title = title;
  ev->dialog_text = text;
  HS_TRACE_WARNING(kComponent, "USER-VISIBLE dialog in pid {} ({} {}): {} chars of text", pid_, role, subrole,
                   text.size());  // text itself stays out of INFO+ traces (unsanitized)
  return bus_.post(std::move(ev));
}

SRESULT AxDialogSource::loop() {
  while (!stop_.load()) {
    const pid_t want = want_pid_.load();
    if (want != pid_) {
      const auto now = std::chrono::steady_clock::now();
      if (want != attempt_pid_) {  // new target (or none): start over
        HS_RETURN_IF_FAILED(detach());
        attempt_pid_ = want;
        attempts_ = 0;
        next_attempt_ = now;
      }
      // A just-launched app refuses AX observers until it has finished launching: retry, bounded.
      if (want > 0 && attempts_ < kMaxAttachAttempts && now >= next_attempt_) {
        ++attempts_;
        const bool trusted = AXIsProcessTrusted();
        const SRESULT r = trusted ? attach(want) : SRESULT::PermissionDenied;
        if (HS_FAILED(r)) {
          if (!trusted) attempts_ = kMaxAttachAttempts;  // no Accessibility permission: retrying cannot help
          next_attempt_ = now + kAttachRetry;
          if (attempts_ >= kMaxAttachAttempts) {
            HS_TRACE_WARNING(kComponent, "cannot observe dialogs of pid {}: {} (after {} attempt(s))", want, r, attempts_);
          } else {
            HS_TRACE_DEBUG(kComponent, "attach to pid {} failed ({}), retrying", want, r);
          }
        } else if (attempts_ > 1) {
          HS_TRACE_INFO(kComponent, "dialog observer attached to pid {} after {} attempts", want, attempts_);
        }
      }
    }
    (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, false);  // dispatches AXObserver callbacks
    const auto now = std::chrono::steady_clock::now();
    while (!windows_.empty() && now - windows_.front().second >= opts_.dialog_settle) {
      auto w = std::move(windows_.front().first);
      windows_.pop_front();
      (void)inspect(*w);  // NoOp for ordinary windows
    }
  }
  return detach();
}

// ---------------- UiObserverActor ----------------

UiObserverActor::UiObserverActor(EventBus& bus, EventFactory& factory, UiObserverOptions opts)
    : Actor("ui_observer"), bus_(bus), factory_(factory), opts_(opts) {}

SRESULT UiObserverActor::on_start(ActorContext& ctx) {
  probe_ = std::make_unique<AxProbeSource>(bus_, factory_, opts_);
  dialogs_ = std::make_unique<AxDialogSource>(bus_, factory_, opts_);
  HS_RETURN_IF_FAILED(probe_->start());
  HS_RETURN_IF_FAILED(dialogs_->start());
  return subscribe<TargetLifecycle>(ctx.bus, [this](const auto& e) {
    const pid_t pid = e->phase == "launch" ? static_cast<pid_t>(e->pid) : 0;
    HS_RETURN_IF_FAILED(probe_->set_pid(pid));
    return dialogs_->set_pid(pid);
  });
}

SRESULT UiObserverActor::on_stop() {
  if (probe_) (void)probe_->stop();      // NoOp if not running
  if (dialogs_) (void)dialogs_->stop();  // NoOp if not running
  return Actor::on_stop();
}

}  // namespace ieso::macos
