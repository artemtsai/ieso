/**
 * @file cf_ref.hpp
 * @brief RAII owner for CoreFoundation-style references (CFRelease on destruction).
 * @details The C API boundary is the only place raw CF pointers appear (STYLEGUIDE §6);
 *          they are wrapped here immediately after a Create/Copy call.
 */
#pragma once

#include <CoreFoundation/CoreFoundation.h>

#include <string>

#include "ieso/core/sresult.hpp"

namespace ieso::macos {

/**
 * @brief Owns one +1 CF reference.
 * @tparam T CF reference type (CFStringRef, AXUIElementRef, ...).
 * @note Move-only. operator* yields the borrowed reference for passing to CF APIs.
 */
template <class T>
class CfRef {
 public:
  CfRef() = default;
  /// @brief Adopts a +1 reference (from a Create/Copy call). @param[in] ref Reference or nullptr.
  explicit CfRef(T ref) : ref_(ref) {}
  ~CfRef() {
    if (ref_ != nullptr) CFRelease(ref_);
  }
  CfRef(CfRef&& o) noexcept : ref_(o.ref_) { o.ref_ = nullptr; }
  CfRef& operator=(CfRef&& o) noexcept {
    if (this != &o) {
      if (ref_ != nullptr) CFRelease(ref_);
      ref_ = o.ref_;
      o.ref_ = nullptr;
    }
    return *this;
  }
  CfRef(const CfRef&) = delete;
  CfRef& operator=(const CfRef&) = delete;

  /// @brief Borrowed reference for CF calls (operator: exempt from the SRESULT rule).
  T operator*() const { return ref_; }
  /// @brief True if a reference is held.
  explicit operator bool() const { return ref_ != nullptr; }

  /**
   * @brief Retains and adopts a borrowed (+0) reference.
   * @param[in] ref Borrowed reference.
   * @param[out] out Owner.
   * @return SRESULT::Ok or SRESULT::NullPointer.
   */
  static SRESULT Retain(T ref, CfRef& out) {
    if (ref == nullptr) return SRESULT::NullPointer;
    CFRetain(ref);
    out = CfRef(ref);
    return SRESULT::Ok;
  }

 private:
  T ref_ = nullptr;  ///< Owned reference.
};

/**
 * @brief Converts a CFString to UTF-8.
 * @param[in] s String (may be null).
 * @param[out] out UTF-8 text.
 * @return SRESULT::Ok, NullPointer or CorruptData.
 */
SRESULT to_utf8(CFStringRef s, std::string& out);

}  // namespace ieso::macos
