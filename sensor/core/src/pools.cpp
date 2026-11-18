/**
 * @file pools.cpp
 * @brief CappedResource and Pools implementation (the only raw-memory code in the sensor).
 */
#include "ieso/core/pools.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "pools";

}  // namespace

CappedResource::CappedResource(std::size_t cap_bytes, std::pmr::memory_resource& upstream)
    : cap_(cap_bytes), upstream_(upstream) {}

SRESULT CappedResource::in_use(std::size_t& out) const {
  out = in_use_.load(std::memory_order_relaxed);
  return SRESULT::Ok;
}

void* CappedResource::do_allocate(std::size_t bytes, std::size_t align) {
  const std::size_t before = in_use_.fetch_add(bytes, std::memory_order_relaxed);
  if (before + bytes > cap_) {
    HS_TRACE_FATAL(kComponent, "pool hard cap breached: in_use={} request={} cap={}", before, bytes, cap_);
  }
  return upstream_.allocate(bytes, align);
}

void CappedResource::do_deallocate(void* p, std::size_t bytes, std::size_t align) {
  upstream_.deallocate(p, bytes, align);
  in_use_.fetch_sub(bytes, std::memory_order_relaxed);
}

bool CappedResource::do_is_equal(const std::pmr::memory_resource& other) const noexcept { return this == &other; }

SRESULT Pools::Create(std::size_t cap_bytes, std::unique_ptr<Pools>& out) {
  if (cap_bytes < 2 * config::kPoolHeadroomBytes || cap_bytes > config::kEventPoolHardCap) {
    HS_TRACE_ERROR(kComponent, "invalid pool cap {} (allowed {}..{})", cap_bytes, 2 * config::kPoolHeadroomBytes,
                   config::kEventPoolHardCap);
    return SRESULT::InvalidArgument;
  }
  out = std::make_unique<Pools>(cap_bytes);
  HS_TRACE_INFO(kComponent, "event pool ready: cap={} bytes", cap_bytes);
  return SRESULT::Ok;
}

Pools::Pools(std::size_t cap_bytes)
    : cap_(cap_bytes),
      capped_(cap_bytes, *std::pmr::new_delete_resource()),
      pool_(std::pmr::pool_options{16, 4096}, &capped_),  // small chunks stay below headroom
      counted_(pool_) {}

SRESULT Pools::stats(PoolStats& out) const {
  out.cap_bytes = cap_;
  HS_RETURN_IF_FAILED(capped_.in_use(out.in_use_bytes));
  HS_RETURN_IF_FAILED(counted_.live(out.live_bytes));
  out.allocations = allocations_.load(std::memory_order_relaxed);
  out.refusals = refusals_.load(std::memory_order_relaxed);
  return SRESULT::Ok;
}

}  // namespace ieso
