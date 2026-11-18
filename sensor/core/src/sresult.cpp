/**
 * @file sresult.cpp
 * @brief Name table for SRESULT codes.
 */
#include "ieso/core/sresult.hpp"

namespace ieso {

SRESULT to_string(SRESULT code, std::string_view& out) noexcept {
  switch (code) {
    case SRESULT::Ok: out = "Ok"; break;
    case SRESULT::NoOp: out = "NoOp"; break;
    case SRESULT::Dropped: out = "Dropped"; break;
    case SRESULT::Spilled: out = "Spilled"; break;
    case SRESULT::Adjusted: out = "Adjusted"; break;
    case SRESULT::InvalidArgument: out = "InvalidArgument"; break;
    case SRESULT::NullPointer: out = "NullPointer"; break;
    case SRESULT::OutOfMemory: out = "OutOfMemory"; break;
    case SRESULT::CapacityExceeded: out = "CapacityExceeded"; break;
    case SRESULT::NotFound: out = "NotFound"; break;
    case SRESULT::AlreadyExists: out = "AlreadyExists"; break;
    case SRESULT::InvalidState: out = "InvalidState"; break;
    case SRESULT::Timeout: out = "Timeout"; break;
    case SRESULT::IoError: out = "IoError"; break;
    case SRESULT::CorruptData: out = "CorruptData"; break;
    case SRESULT::Unsupported: out = "Unsupported"; break;
    case SRESULT::PermissionDenied: out = "PermissionDenied"; break;
    case SRESULT::RateLimited: out = "RateLimited"; break;
    case SRESULT::BudgetExhausted: out = "BudgetExhausted"; break;
    case SRESULT::Expired: out = "Expired"; break;
    case SRESULT::Closed: out = "Closed"; break;
    case SRESULT::Internal: out = "Internal"; break;
    default: out = "Unknown"; break;
  }
  return SRESULT::Ok;
}

}  // namespace ieso
