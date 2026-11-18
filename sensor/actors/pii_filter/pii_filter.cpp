/**
 * @file pii_filter.cpp
 * @brief PII Filter implementation.
 */
#include "pii_filter/pii_filter.hpp"

#include "ieso/core/json.hpp"
#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "pii";
}  // namespace

PiiFilter::PiiFilter(EventBus& bus, EventFactory& factory, Redactor redactor)
    : Actor("pii_filter"), bus_(bus), factory_(factory), redactor_(std::move(redactor)) {}

SRESULT PiiFilter::on_start(ActorContext& ctx) {
  std::string endpoint;
  HS_RETURN_IF_FAILED(factory_.endpoint_id(endpoint));
  source_ = "ieso://endpoint/" + endpoint;
  return subscribe_all(ctx.bus, AllEvents{});
}

SRESULT PiiFilter::sanitize(const Event& ev, std::shared_ptr<CloudEventSanitized>& out) const {
  if (!ev.hdr.egress) {
    HS_TRACE_ERROR(kComponent, "non-egress event {} reached the filter", ev.hdr.id);
    return SRESULT::InvalidArgument;
  }
  Fields fields;
  HS_RETURN_IF_FAILED(ev.fields(fields));
  for (Field& f : fields) {
    if (!f.verbatim && std::holds_alternative<std::string>(f.value)) {
      std::string& s = std::get<std::string>(f.value);
      std::string clean;
      HS_RETURN_IF_FAILED(f.free_text ? redactor_.redact_free_text(s, clean) : redactor_.redact(s, clean));
      s = std::move(clean);
    }
  }
  std::string data;
  HS_RETURN_IF_FAILED(fields_to_json(fields, data));
  std::string_view type_name;
  HS_RETURN_IF_FAILED(ev.type_name(type_name));

  std::shared_ptr<CloudEventSanitized> env;
  HS_RETURN_IF_FAILED(factory_.make<CloudEventSanitized>(env, CloudEventSanitized::Key{}, source_,
                                                         "com.ieso." + std::string(type_name), std::move(data)));
  // Keep the source identity and routing so retries dedupe and incidents keep their priority.
  env->hdr.id = ev.hdr.id;
  env->hdr.ts = ev.hdr.ts;
  env->hdr.cls = ev.hdr.cls;
  env->hdr.overflow = ev.hdr.overflow;
  out = std::move(env);
  return SRESULT::Ok;
}

SRESULT PiiFilter::on_event(const Event& ev) {
  std::shared_ptr<CloudEventSanitized> env;
  HS_RETURN_IF_FAILED(sanitize(ev, env));
  sanitized_.fetch_add(1, std::memory_order_relaxed);
  HS_TRACE_TRACE(kComponent, "sanitized {} {}", env->type, env->hdr.id);
  const SRESULT r = bus_.post(std::move(env));
  return r == SRESULT::NoOp ? SRESULT::Ok : r;  // no Cloud Client yet is not an error
}

SRESULT PiiFilter::sanitized_count(std::uint64_t& out) const {
  out = sanitized_.load(std::memory_order_relaxed);
  return SRESULT::Ok;
}

}  // namespace ieso
