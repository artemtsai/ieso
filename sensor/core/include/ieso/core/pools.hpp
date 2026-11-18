/**
 * @file pools.hpp
 * @brief Pre-sized, capped std::pmr pool for hot-path events (DESIGN.md §3 "Memory pooling").
 * @details This is the ONLY layer allowed to touch raw memory (docs/STYLEGUIDE.md §2).
 *          Callers never see raw pointers: they get std::shared_ptr from allocate_shared().
 *          The cap is enforced before allocating (OutOfMemory), never by throwing.
 */
#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <memory_resource>

#include "ieso/core/config.hpp"
#include "ieso/core/sresult.hpp"
#include "ieso/core/trace.hpp"

namespace ieso {

/// @brief Pool counters (NFR-2, NFR-9).
struct PoolStats {
  std::size_t cap_bytes = 0;        ///< Configured cap.
  std::size_t in_use_bytes = 0;     ///< Bytes held from upstream (pool chunks, never shrinks).
  std::size_t live_bytes = 0;       ///< Bytes in live objects (drives the headroom check).
  std::uint64_t allocations = 0;    ///< Successful allocate_shared calls.
  std::uint64_t refusals = 0;       ///< Calls refused with OutOfMemory.
};

/**
 * @brief Memory resource that counts bytes and enforces a hard cap over an upstream resource.
 * @warning Exceeding the cap inside do_allocate is a bug (callers pre-check headroom) and is FATAL.
 */
class CappedResource final : public std::pmr::memory_resource {
 public:
  /**
   * @brief Wraps @p upstream.
   * @param[in] cap_bytes Hard cap.
   * @param[in] upstream Source of memory; must outlive this object.
   */
  CappedResource(std::size_t cap_bytes, std::pmr::memory_resource& upstream);

  /**
   * @brief Bytes currently held from upstream.
   * @param[out] out Byte count.
   * @return SRESULT::Ok.
   */
  SRESULT in_use(std::size_t& out) const;

 private:
  // std::pmr-mandated interface (exempt from the SRESULT rule).
  void* do_allocate(std::size_t bytes, std::size_t align) override;
  void do_deallocate(void* p, std::size_t bytes, std::size_t align) override;
  bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override;

  const std::size_t cap_;                  ///< Hard cap.
  std::pmr::memory_resource& upstream_;    ///< Underlying memory.
  std::atomic<std::size_t> in_use_{0};     ///< Bytes outstanding.
};

/**
 * @brief Forwarding resource that counts bytes currently allocated through it.
 * @note The pool keeps freed chunks for reuse, so upstream usage only grows; live bytes do shrink.
 */
class CountingResource final : public std::pmr::memory_resource {
 public:
  /// @brief Wraps @p inner (must outlive this). @param[in] inner Resource to forward to.
  explicit CountingResource(std::pmr::memory_resource& inner) : inner_(inner) {}

  /**
   * @brief Bytes currently allocated and not yet freed.
   * @param[out] out Byte count.
   * @return SRESULT::Ok.
   */
  SRESULT live(std::size_t& out) const {
    out = live_.load(std::memory_order_relaxed);
    return SRESULT::Ok;
  }

 private:
  // std::pmr-mandated interface (exempt from the SRESULT rule).
  void* do_allocate(std::size_t bytes, std::size_t align) override {
    void* p = inner_.allocate(bytes, align);
    live_.fetch_add(bytes, std::memory_order_relaxed);
    return p;
  }
  void do_deallocate(void* p, std::size_t bytes, std::size_t align) override {
    inner_.deallocate(p, bytes, align);
    live_.fetch_sub(bytes, std::memory_order_relaxed);
  }
  bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }

  std::pmr::memory_resource& inner_;   ///< Pool.
  std::atomic<std::size_t> live_{0};   ///< Live bytes.
};

/**
 * @brief Event memory pool created in main() before the runtime starts.
 * @note Thread-safe (synchronized_pool_resource). Not movable: the layers reference each other.
 * @note Layers: counted_ (live bytes) -> pool_ (size classes) -> capped_ (hard cap, FATAL) -> new_delete.
 */
class Pools {
 public:
  /**
   * @brief Builds a pool after validating the cap.
   * @param[in] cap_bytes Pool cap; must be within [2 x headroom, kEventPoolHardCap].
   * @param[out] out New pool.
   * @retval SRESULT::Ok
   * @retval SRESULT::InvalidArgument Cap out of range.
   */
  static SRESULT Create(std::size_t cap_bytes, std::unique_ptr<Pools>& out);

  /// @brief Use Create(). @param[in] cap_bytes Validated cap.
  explicit Pools(std::size_t cap_bytes);
  Pools(const Pools&) = delete;
  Pools& operator=(const Pools&) = delete;

  /**
   * @brief Allocates a T (and its control block) from the pool.
   * @tparam T Object type.
   * @tparam A Constructor argument types.
   * @param[out] out New object; untouched on failure.
   * @param[in] args Forwarded to T's constructor.
   * @retval SRESULT::Ok
   * @retval SRESULT::OutOfMemory Live bytes + kPoolHeadroomBytes would exceed the cap.
   */
  template <class T, class... A>
  SRESULT allocate_shared(std::shared_ptr<T>& out, A&&... args) {
    std::size_t used = 0;
    HS_RETURN_IF_FAILED(counted_.live(used));
    if (used + config::kPoolHeadroomBytes > cap_) {
      const auto n = refusals_.fetch_add(1, std::memory_order_relaxed);
      if ((n & (n + 1)) == 0) {  // trace on 1st, 2nd, 4th, 8th... refusal to avoid floods
        HS_TRACE_WARNING("pools", "event pool exhausted: used={} cap={} refusals={}", used, cap_, n + 1);
      }
      return SRESULT::OutOfMemory;
    }
    out = std::allocate_shared<T>(std::pmr::polymorphic_allocator<T>(&counted_), std::forward<A>(args)...);
    allocations_.fetch_add(1, std::memory_order_relaxed);
    return SRESULT::Ok;
  }

  /**
   * @brief Reads pool counters.
   * @param[out] out Stats snapshot.
   * @return SRESULT::Ok.
   */
  SRESULT stats(PoolStats& out) const;

 private:
  const std::size_t cap_;                          ///< Cap in bytes.
  CappedResource capped_;                          ///< Counts and caps upstream use.
  std::pmr::synchronized_pool_resource pool_;      ///< Size-class pools over capped_.
  CountingResource counted_;                       ///< Live-byte accounting over pool_.
  std::atomic<std::uint64_t> allocations_{0};      ///< Successful allocations.
  std::atomic<std::uint64_t> refusals_{0};         ///< OutOfMemory refusals.
};

}  // namespace ieso
