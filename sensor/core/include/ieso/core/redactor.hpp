/**
 * @file redactor.hpp
 * @brief Edge PII redaction rules (DESIGN.md §9.6, NFR-7).
 * @details Hand-written scanners, no std::regex (no exceptions, bounded cost per byte).
 *          Rules: secrets in key=value / Bearer, emails, home-directory user names,
 *          IPv4/IPv6 (salted hash, so equal IPs still correlate), long hex/base64 secrets.
 */
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Stateless, thread-safe text redactor.
 * @note Order of passes: key=value secrets, Bearer tokens, emails, home paths, IPs, long secrets.
 */
class Redactor {
 public:
  /// @brief Max length kept for free text (dialogs, log messages, probe output).
  static constexpr std::size_t kMaxFreeText = 512;

  /**
   * @brief Creates a redactor.
   * @param[in] ip_salt Per-tenant salt for IP hashing; never leaves the endpoint.
   */
  explicit Redactor(std::string ip_salt);

  /**
   * @brief Applies all rules.
   * @param[in] in Raw text.
   * @param[out] out Redacted text.
   * @return SRESULT::Ok.
   */
  SRESULT redact(std::string_view in, std::string& out) const;

  /**
   * @brief Applies all rules, then truncates to kMaxFreeText (marking truncation with "...[truncated]").
   * @param[in] in Raw untrusted text.
   * @param[out] out Redacted text.
   * @return SRESULT::Ok.
   */
  SRESULT redact_free_text(std::string_view in, std::string& out) const;

  /**
   * @brief Salted, truncated hash of an IP literal, e.g. "ip:1a2b3c4d".
   * @param[in] ip IP text.
   * @param[out] out Token.
   * @return SRESULT::Ok.
   */
  SRESULT hash_ip(std::string_view ip, std::string& out) const;

 private:
  /// @brief key=value / key: value secrets. @param[in] in Text. @param[out] out Result. @return Ok.
  SRESULT pass_kv_secrets(std::string_view in, std::string& out) const;
  /// @brief "Bearer <token>". @param[in] in Text. @param[out] out Result. @return Ok.
  SRESULT pass_bearer(std::string_view in, std::string& out) const;
  /// @brief Email addresses. @param[in] in Text. @param[out] out Result. @return Ok.
  SRESULT pass_emails(std::string_view in, std::string& out) const;
  /// @brief /Users/<name> and /home/<name>. @param[in] in Text. @param[out] out Result. @return Ok.
  SRESULT pass_home_paths(std::string_view in, std::string& out) const;
  /// @brief IPv4/IPv6 literals. @param[in] in Text. @param[out] out Result. @return Ok.
  SRESULT pass_ips(std::string_view in, std::string& out) const;
  /// @brief Long hex (>= 32) or base64-ish (>= 40) runs. @param[in] in Text. @param[out] out Result. @return Ok.
  SRESULT pass_long_secrets(std::string_view in, std::string& out) const;

  const std::string salt_;  ///< IP hash salt.
};

}  // namespace ieso
