/**
 * @file subprocess.cpp
 * @brief Subprocess implementation (posix_spawn, poll, waitpid).
 */
#include "ieso/macos/subprocess.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <thread>

#include "ieso/core/trace.hpp"

extern char** environ;  // NOLINT: POSIX-defined process environment

namespace ieso::macos {
namespace {
constexpr std::string_view kComponent = "subprocess";

/**
 * @brief Decodes a waitpid status.
 * @param[in] status Raw status.
 * @param[out] out Exit code, or -1 if signaled.
 * @return SRESULT::Ok.
 */
SRESULT decode_status(int status, int& out) {
  out = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return SRESULT::Ok;
}
}  // namespace

SRESULT Subprocess::Spawn(const std::vector<std::string>& argv, std::unique_ptr<Subprocess>& out) {
  if (argv.empty() || argv[0].empty() || argv[0][0] != '/') return SRESULT::InvalidArgument;
  std::array<int, 2> fds{-1, -1};
  if (pipe(fds.data()) != 0) {
    HS_TRACE_ERROR(kComponent, "pipe failed: {}", std::strerror(errno));
    return SRESULT::IoError;
  }
  (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);  // best-effort: keep the read end out of the child

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, fds[1], STDERR_FILENO);
  posix_spawn_file_actions_addclose(&actions, fds[0]);
  posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);

  std::vector<char*> cargv;  // C API boundary: borrowed pointers into argv strings
  cargv.reserve(argv.size() + 1);
  for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
  cargv.push_back(nullptr);

  pid_t pid = 0;
  const int rc = posix_spawn(&pid, argv[0].c_str(), &actions, nullptr, cargv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  close(fds[1]);
  if (rc != 0) {
    close(fds[0]);
    HS_TRACE_ERROR(kComponent, "posix_spawn {} failed: {}", argv[0], std::strerror(rc));
    return SRESULT::IoError;
  }
  out = std::make_unique<Subprocess>(pid, fds[0]);
  HS_TRACE_DEBUG(kComponent, "spawned {} pid={}", argv[0], pid);
  return SRESULT::Ok;
}

Subprocess::Subprocess(pid_t pid, int fd) : pid_(pid), fd_(fd) {}

Subprocess::~Subprocess() {
  if (pid_ > 0) {
    (void)terminate();  // ask nicely first
    int code = 0;
    if (wait(std::chrono::milliseconds(500), code) != SRESULT::Ok && pid_ > 0) {
      kill(pid_, SIGKILL);
      (void)wait(std::chrono::milliseconds(2000), code);  // reap
    }
  }
  if (fd_ >= 0) close(fd_);
}

SRESULT Subprocess::fill(std::chrono::milliseconds timeout) {
  if (eof_) return SRESULT::Closed;
  pollfd p{fd_, POLLIN, 0};
  const int n = poll(&p, 1, static_cast<int>(timeout.count()));
  if (n == 0) return SRESULT::Timeout;
  if (n < 0) return errno == EINTR ? SRESULT::Timeout : SRESULT::IoError;
  std::array<char, 8192> chunk{};
  const ssize_t got = read(fd_, chunk.data(), chunk.size());
  if (got <= 0) {
    eof_ = true;
    return SRESULT::Closed;
  }
  buf_.append(chunk.data(), static_cast<std::size_t>(got));
  return SRESULT::Ok;
}

SRESULT Subprocess::read_line(std::string& out, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    const auto nl = buf_.find('\n');
    if (nl != std::string::npos) {
      out.assign(buf_, 0, nl);
      buf_.erase(0, nl + 1);
      return SRESULT::Ok;
    }
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0) return SRESULT::Timeout;
    const SRESULT r = fill(left);
    if (r == SRESULT::Closed) {
      if (buf_.empty()) return SRESULT::Closed;
      out.swap(buf_);  // last line without newline
      buf_.clear();
      return SRESULT::Ok;
    }
    if (HS_FAILED(r)) return r;
  }
}

SRESULT Subprocess::terminate() {
  if (pid_ <= 0) return SRESULT::NoOp;
  kill(pid_, SIGTERM);
  return SRESULT::Ok;
}

SRESULT Subprocess::wait(std::chrono::milliseconds timeout, int& exit_code) {
  if (pid_ <= 0) {
    exit_code = exit_code_;
    return SRESULT::Ok;
  }
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    int status = 0;
    const pid_t r = waitpid(pid_, &status, WNOHANG);
    if (r == pid_) {
      HS_RETURN_IF_FAILED(decode_status(status, exit_code_));
      pid_ = 0;
      exit_code = exit_code_;
      return SRESULT::Ok;
    }
    if (r < 0 && errno != EINTR) {
      pid_ = 0;
      exit_code = -1;
      return SRESULT::Ok;
    }
    if (std::chrono::steady_clock::now() >= deadline) return SRESULT::Timeout;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

SRESULT Subprocess::Run(const std::vector<std::string>& argv, std::chrono::milliseconds timeout, std::string& output,
                        int& exit_code) {
  std::unique_ptr<Subprocess> p;
  HS_RETURN_IF_FAILED(Spawn(argv, p));
  output.clear();
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0) {
      HS_TRACE_WARNING(kComponent, "{} timed out after {} ms", argv[0], timeout.count());
      return SRESULT::Timeout;  // destructor kills and reaps
    }
    const SRESULT r = p->fill(std::min(left, std::chrono::milliseconds(100)));
    if (r == SRESULT::Closed) break;
    if (HS_FAILED(r) && r != SRESULT::Timeout) return r;  // Timeout = idle slice, keep waiting
    // Finish on child exit, not only on EOF: helpers it spawned (e.g. sample's symbolicator) may keep the pipe open.
    int code = 0;
    if (p->wait(std::chrono::milliseconds(0), code) == SRESULT::Ok) {
      while (p->fill(std::chrono::milliseconds(50)) == SRESULT::Ok) {
      }  // drain what is already buffered
      output.swap(p->buf_);
      exit_code = code;
      return SRESULT::Ok;
    }
  }
  output.swap(p->buf_);
  return p->wait(std::chrono::milliseconds(2000), exit_code);
}

}  // namespace ieso::macos
