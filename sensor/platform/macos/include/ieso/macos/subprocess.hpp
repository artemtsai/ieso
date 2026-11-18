/**
 * @file subprocess.hpp
 * @brief posix_spawn wrapper with a stdout pipe, line reading with timeouts and RAII cleanup.
 * @details Used for `/usr/bin/log stream`, `/usr/bin/sample` and `/usr/bin/log config`.
 *          Programs are always absolute paths: in zsh `log` is a builtin and `sample` may resolve elsewhere.
 */
#pragma once

#include <sys/types.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "ieso/core/sresult.hpp"

namespace ieso::macos {

/**
 * @brief One child process; stdout and stderr share one pipe.
 * @note Destruction terminates (SIGTERM, then SIGKILL) and reaps the child.
 */
class Subprocess {
 public:
  /**
   * @brief Spawns argv[0] (absolute path) with argv.
   * @param[in] argv Program and arguments.
   * @param[out] out Running child.
   * @return SRESULT::Ok, InvalidArgument or IoError.
   */
  static SRESULT Spawn(const std::vector<std::string>& argv, std::unique_ptr<Subprocess>& out);

  /**
   * @brief Runs to completion and captures output.
   * @param[in] argv Program and arguments.
   * @param[in] timeout Kill after this long.
   * @param[out] output Combined stdout/stderr.
   * @param[out] exit_code Exit code (-1 if signaled).
   * @return SRESULT::Ok, Timeout or IoError.
   */
  static SRESULT Run(const std::vector<std::string>& argv, std::chrono::milliseconds timeout, std::string& output,
                     int& exit_code);

  /// @brief Use Spawn(). @param[in] pid Child pid. @param[in] fd Read end of the pipe.
  Subprocess(pid_t pid, int fd);
  ~Subprocess();
  Subprocess(const Subprocess&) = delete;
  Subprocess& operator=(const Subprocess&) = delete;

  /**
   * @brief Reads one line (without '\n').
   * @param[out] out Line.
   * @param[in] timeout Max wait.
   * @retval SRESULT::Ok
   * @retval SRESULT::Timeout No full line yet.
   * @retval SRESULT::Closed  EOF and no buffered data.
   */
  SRESULT read_line(std::string& out, std::chrono::milliseconds timeout);

  /// @brief Sends SIGTERM. @return SRESULT::Ok or NoOp if already reaped.
  SRESULT terminate();

  /**
   * @brief Waits for exit.
   * @param[in] timeout Max wait.
   * @param[out] exit_code Exit code (-1 if signaled).
   * @return SRESULT::Ok or SRESULT::Timeout.
   */
  SRESULT wait(std::chrono::milliseconds timeout, int& exit_code);

 private:
  /// @brief Reads available bytes into buf_. @param[in] timeout Poll timeout. @return Ok, Timeout or Closed.
  SRESULT fill(std::chrono::milliseconds timeout);

  pid_t pid_;               ///< Child pid (0 once reaped).
  int fd_;                  ///< Pipe read end (-1 once closed).
  std::string buf_;         ///< Unconsumed bytes.
  bool eof_ = false;        ///< Pipe closed by the child.
  int exit_code_ = 0;       ///< Valid once reaped.
};

}  // namespace ieso::macos
