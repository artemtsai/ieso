# C++ Style Guide (sensor)

Mandatory for all C++ in this repo (`sensor/`, and any C++ in `demo-app/`). Applies to new code and to any code
touched by a change. Python (`backend/`, `investigator/`, `sim/`) is out of scope.

## 0. Language level

- **C++17** (`CMAKE_CXX_STANDARD 17`, no compiler extensions). No C++20 features: no `std::jthread`/`stop_token`,
  `std::format`, concepts/`requires`, `std::span`, `std::erase_if`, `starts_with`/`contains`, chrono calendar,
  template lambdas, designated initializers.
- Formatting uses `{fmt}` (pinned, header-only, `FMT_EXCEPTIONS=0`); same `{}` syntax as std::format.
- Threads: `std::thread` + explicit stop flag + `std::condition_variable`; constraints: `static_assert` + type traits.

## 1. Documentation (Doxygen)

- Every header and implementation file starts with `@file` and `@brief`.
- Every class, struct, interface, enum, function and method has a Doxygen block.
- Use the essential tags only: `@file`, `@brief`, `@details`, `@tparam`, `@param[in|out|in,out]`, `@return`,
  `@retval`, `@pre`, `@post`, `@note`, `@warning`, `@see`.
- Keep it short and informative: **at most 12 short sentences per tag**. Say *why* and *contract*, not the obvious.
- `@return` on SRESULT functions lists the notable codes with `@retval`.
- Tests: `@file` + `@brief` per file, one-line `///` comment per `TEST`.

```cpp
/**
 * @brief Posts an event to all subscribers of its type.
 * @param[in] ev Immutable event; must not be null.
 * @retval SRESULT::Ok        Delivered or queued for every subscriber.
 * @retval SRESULT::Dropped   Routine event dropped by overflow policy (counted).
 * @retval SRESULT::Spilled   Never-drop queue full; event handed to the spill sink.
 * @note Never blocks the caller.
 */
[[nodiscard]] SRESULT post(std::shared_ptr<const Event> ev);
```

## 2. Memory

- No explicit `new`, `delete`, `malloc`, `calloc`, `realloc`, `free`.
- **Only exception:** the memory-pool layer (`sensor/core/.../pools.*`), which implements `std::pmr` resources.
- Allocate with `std::make_shared`, `std::make_unique`, `std::allocate_shared` (pmr allocator), or containers.
- Types that must restrict construction use the **passkey idiom**, not a private ctor + `friend` (keeps
  `make_shared` usable).

## 3. Error handling: `SRESULT`

- Every function and method returns `SRESULT`. No `void`, `bool`, `int` or other error schemes.
- `SRESULT` is declared `enum class [[nodiscard]]`, so ignoring a result is a compile error (`-Werror`).
  Do not repeat `[[nodiscard]]` per function. Discard deliberately only with `(void)expr;  // reason`.
- `SRESULT` is an `enum class` in `ieso/core/sresult.hpp`; every code is enumerated there with `to_string()`.
  Add new codes there only, never local ones.
- Outputs go through out-parameters (`T& out`), written only on success.
- Helpers: `HS_SUCCEEDED(r)`, `HS_FAILED(r)`, `HS_RETURN_IF_FAILED(expr)`.
- **Exempt (language-forced only):** constructors, destructors, operators (incl. comparison/hash functors),
  move/copy special members, `main()`, callables whose signature the standard library dictates
  (thread bodies, comparators, `fmt::formatter` members), callbacks whose signature an OS C API dictates
  (FSEvents, AXObserver, CFRunLoop), and GoogleTest `TEST` bodies.
- Constructors must not fail. Fallible construction uses a factory:
  `static SRESULT Create(..., std::shared_ptr<T>& out);`
- Callbacks/handlers passed to the bus also return `SRESULT`.

## 4. Tracing

- Use the facade in `ieso/core/trace.hpp`; never `printf`/`std::cout`/`std::cerr` directly (except `main` usage text).
- Levels: `FATAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`, `TRACE` via `HS_TRACE_FATAL(...)` … `HS_TRACE_TRACE(...)`.
- Each record carries level, timestamp, thread, component, file:line and message.
- Trace a failure **once, where it originates**, at ERROR or WARNING; callers just propagate the SRESULT.
- INFO for lifecycle (start/stop/config applied), DEBUG for decisions, TRACE for per-event detail.
- FATAL means unrecoverable: trace, then abort (launchd KeepAlive restarts the agent).
- Never trace unsanitized PII at INFO or above.

## 5. No exceptions

- No `throw`, `try`, `catch`. Core builds with `-fno-exceptions`.
- Use only non-throwing standard APIs: `std::filesystem` `error_code` overloads, `std::from_chars`,
  `operator[]` with checked bounds instead of `.at()`, `std::nothrow`-free designs.
- Allocation failure is fatal (abort). Pool caps are enforced by returning `SRESULT::OutOfMemory`
  before allocating, not by throwing.
- GoogleTest is built with `GTEST_HAS_EXCEPTIONS=0`.

## 6. Ownership, RTTI, pointers

- RTTI is on (the bus routes by `std::type_index`). Prefer `std::dynamic_pointer_cast` over raw `dynamic_cast`.
- Ownership is always a smart pointer: `std::unique_ptr` by default, `std::shared_ptr` when shared
  (events are `std::shared_ptr<const T>`).
- **No naked owning pointers.** Non-owning access uses references or `std::weak_ptr`.
- Raw pointers are allowed only at C API boundaries (libproc, CoreFoundation, kqueue) and must be wrapped in
  an RAII type immediately.

## 7. No recursion

- No explicit recursion (direct or mutual): stack depth is then bounded by input, which an agent cannot trust.
- Use iteration with an explicit, bounded work list: `std::vector` as a stack (DFS), `std::deque` as a queue (BFS),
  or a state machine. Cap the work list size or depth and return `SRESULT::CapacityExceeded` when exceeded.
- Applies to parsers (JSON, .ips), tree walks (Accessibility hierarchies, directories) and any nested data.
