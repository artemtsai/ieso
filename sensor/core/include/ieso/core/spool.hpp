/**
 * @file spool.hpp
 * @brief Durable store-and-forward spool for sanitized envelopes (FR-8, NFR-2, NFR-5, DESIGN.md §9.7).
 * @details One file per envelope: "<prio>_<enqueue_ms>_<id>.rec", so lexical order is incidents first,
 *          then oldest first. Writes go to a temp file and are renamed into place (crash-safe).
 *          Delivery is at-least-once: ids are stable, re-spooling an id rewrites it in place.
 *          Only CloudEventSanitized can be stored, so everything on disk is already sanitized.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "ieso/core/clock.hpp"
#include "ontology/events.hpp"
#include "ieso/core/codec.hpp"
#include "ieso/core/config.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/// @brief Spool configuration.
struct SpoolOptions {
  std::filesystem::path dir;                                  ///< Spool directory (created if missing).
  std::uint64_t max_bytes = config::kSpoolMaxBytes;           ///< Size cap (<= hard cap).
  std::chrono::milliseconds ttl_routine = config::kTtlRoutine;    ///< Routine TTL.
  std::chrono::milliseconds ttl_incident = config::kTtlIncident;  ///< Incident/control TTL.
};

/// @brief One drained envelope.
struct SpoolItem {
  std::shared_ptr<const CloudEventSanitized> envelope;  ///< Restored envelope.
  std::uint32_t attempts = 0;                           ///< Send attempts so far.
};

/// @brief Spool counters (self-telemetry).
struct SpoolStats {
  std::uint64_t bytes = 0;          ///< Bytes on disk.
  std::uint64_t count = 0;          ///< Records.
  std::uint64_t in_flight = 0;      ///< Drained, awaiting ack.
  std::uint64_t evicted = 0;        ///< Routine records evicted for space.
  std::uint64_t purged = 0;         ///< Records expired by TTL.
  std::uint64_t corrupt = 0;        ///< Records dropped as unreadable.
  std::int64_t oldest_enqueue_ms = 0;  ///< Enqueue time of the oldest record (0 if empty).
};

/**
 * @brief The spool.
 * @warning Not thread-safe; owned by the Spooler actor.
 */
class Spool {
 public:
  /**
   * @brief Opens (or creates) a spool and rebuilds its index from disk.
   * @param[in] opts Options.
   * @param[in] clock Time source; must outlive the spool.
   * @param[in] codec Payload codec.
   * @param[out] out Ready spool.
   * @retval SRESULT::Ok
   * @retval SRESULT::InvalidArgument Bad options or empty codec.
   * @retval SRESULT::IoError         Directory not usable.
   */
  static SRESULT Create(const SpoolOptions& opts, const IClock& clock, std::shared_ptr<const ICodec> codec,
                        std::unique_ptr<Spool>& out);

  /// @brief Use Create(). @param[in] opts Options. @param[in] clock Clock. @param[in] codec Codec.
  Spool(SpoolOptions opts, const IClock& clock, std::shared_ptr<const ICodec> codec);

  /**
   * @brief Stores an envelope; an existing id is rewritten in place (attempts updated, in-flight cleared).
   * @param[in] env Envelope.
   * @param[in] attempts Send attempts so far.
   * @retval SRESULT::Ok
   * @retval SRESULT::CapacityExceeded Full and nothing routine left to evict.
   * @retval SRESULT::IoError          Write failed.
   */
  SRESULT put(const CloudEventSanitized& env, std::uint32_t attempts);

  /**
   * @brief Returns up to @p max pending envelopes (incidents first, oldest first) and marks them in-flight.
   * @param[in] max Max items.
   * @param[out] out Items.
   * @retval SRESULT::Ok
   * @retval SRESULT::NoOp Nothing pending.
   */
  SRESULT drain(std::size_t max, std::vector<SpoolItem>& out);

  /**
   * @brief Deletes a delivered envelope.
   * @param[in] id Envelope id.
   * @retval SRESULT::Ok
   * @retval SRESULT::NotFound Not in the spool (e.g. delivered live).
   */
  SRESULT ack(const std::string& id);

  /// @brief Marks all in-flight records pending again (e.g. went offline). @return SRESULT::Ok.
  SRESULT release_in_flight();

  /**
   * @brief Deletes records older than their class TTL.
   * @param[out] purged Number deleted.
   * @return SRESULT::Ok.
   */
  SRESULT purge_expired(std::size_t& purged);

  /**
   * @brief Reads counters.
   * @param[out] out Stats.
   * @return SRESULT::Ok.
   */
  SRESULT stats(SpoolStats& out) const;

 private:
  /// @brief Index entry for one record file.
  struct Entry {
    std::string id;                        ///< Envelope id.
    EventClass cls = EventClass::Routine;  ///< Class (TTL, eviction).
    std::int64_t enqueue_ms = 0;           ///< First enqueue time.
    std::uint64_t size = 0;                ///< File size.
    bool in_flight = false;                ///< Drained, awaiting ack.
  };

  /// @brief Scans the directory, rebuilds the index, removes temp/corrupt files. @return Ok or IoError.
  SRESULT open();
  /**
   * @brief Serializes one record.
   * @param[in] env Envelope.
   * @param[in] attempts Attempts.
   * @param[in] enqueue_ms Enqueue time.
   * @param[out] out Record bytes.
   * @return SRESULT::Ok or codec failure.
   */
  SRESULT encode_record(const CloudEventSanitized& env, std::uint32_t attempts, std::int64_t enqueue_ms,
                        std::string& out) const;
  /**
   * @brief Parses and verifies one record.
   * @param[in] data Record bytes.
   * @param[out] item Restored envelope.
   * @param[out] entry Index fields (id, cls, enqueue_ms, size).
   * @retval SRESULT::Ok
   * @retval SRESULT::CorruptData Bad magic, length, CRC or codec.
   */
  SRESULT decode_record(const std::string& data, SpoolItem& item, Entry& entry) const;
  /// @brief Atomically writes @p data to @p file. @param[in] file Name. @param[in] data Bytes. @return Ok or IoError.
  SRESULT write_file(const std::string& file, const std::string& data);
  /// @brief Reads a record file. @param[in] file Name. @param[out] out Bytes. @return Ok or IoError.
  SRESULT read_file(const std::string& file, std::string& out) const;
  /// @brief Deletes a record and its index entry. @param[in] file Name. @return SRESULT::Ok.
  SRESULT remove(const std::string& file);
  /**
   * @brief Frees space by evicting oldest routine records.
   * @param[in] needed Bytes to fit.
   * @param[in] keep File being rewritten; never evicted.
   * @retval SRESULT::Ok
   * @retval SRESULT::CapacityExceeded Cannot free enough.
   */
  SRESULT make_room(std::uint64_t needed, const std::string& keep);

  const SpoolOptions opts_;                                  ///< Options.
  const IClock& clock_;                                      ///< Time.
  const std::shared_ptr<const ICodec> codec_;                ///< Payload codec.
  std::map<std::string, Entry> by_file_;                     ///< Ordered index (drain order).
  std::unordered_map<std::string, std::string> file_by_id_;  ///< id -> file name.
  std::uint64_t bytes_ = 0;                                  ///< Total size.
  SpoolStats counters_;                                      ///< evicted/purged/corrupt.
};

}  // namespace ieso
