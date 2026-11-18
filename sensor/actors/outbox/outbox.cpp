/**
 * @file outbox.cpp
 * @brief FileOutboxActor implementation.
 */
#include "outbox/outbox.hpp"

#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "outbox";
}  // namespace

FileOutboxActor::FileOutboxActor(EventBus& bus, EventFactory& factory, std::filesystem::path path)
    : Actor("file_outbox"), bus_(bus), factory_(factory), path_(std::move(path)) {}

SRESULT FileOutboxActor::on_start(ActorContext& ctx) {
  std::error_code ec;
  if (path_.has_parent_path()) std::filesystem::create_directories(path_.parent_path(), ec);
  out_.open(path_, std::ios::binary | std::ios::app);
  if (!out_.is_open()) {
    HS_TRACE_ERROR(kComponent, "cannot open outbox {}", path_.string());
    return SRESULT::IoError;
  }
  HS_TRACE_INFO(kComponent, "delivering sanitized events to {}", path_.string());
  return subscribe<CloudEventSanitized>(ctx.bus, [this](const auto& e) { return deliver(e); });
}

SRESULT FileOutboxActor::on_stop() {
  out_.close();
  return Actor::on_stop();
}

SRESULT FileOutboxActor::deliver(const std::shared_ptr<const CloudEventSanitized>& env) {
  std::string json;
  HS_RETURN_IF_FAILED(env->to_json(json));
  json.push_back('\n');
  out_.write(json.data(), static_cast<std::streamsize>(json.size()));
  out_.flush();
  if (!out_.good()) {
    HS_TRACE_ERROR(kComponent, "write to {} failed", path_.string());
    return SRESULT::IoError;
  }
  HS_TRACE_DEBUG(kComponent, "delivered {} {}", env->type, env->hdr.id);
  std::shared_ptr<TelemetryDelivered> ack;
  HS_RETURN_IF_FAILED(factory_.make<TelemetryDelivered>(ack));
  ack->ids.push_back(env->hdr.id);
  const SRESULT r = bus_.post(std::move(ack));
  return r == SRESULT::NoOp ? SRESULT::Ok : r;
}

}  // namespace ieso
