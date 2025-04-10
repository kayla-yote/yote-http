#pragma once

#include <memory>

namespace yote {

using std::move;
using std::array;
using std::vector;
using std::string;
using std::optional;
using std::unique_ptr;
using std::shared_ptr;
namespace chrono = std::chrono;
namespace fs = std::filesystem;

// Rust has *such* better names.
using f32 = float;
using i32 = int32_t;
using u32 = uint32_t;
using f64 = double;
using i64 = int64_t;
using u64 = uint64_t;
using usize = size_t;

// -

#define REL_ASSERT(X,M) \
   do { \
      if (X) {} else { \
         dout() << __FILE__ << ":" << __LINE__ << ": ASSERT (" << #X << ") FAILED: " M; \
         std::abort(); \
      } \
   } while (false);

// -

template<class CallableT>
class ScopeExitT final {
    const CallableT callable;
    bool skip_calling = false;

public:
    ScopeExitT(CallableT&& callable)
        : callable(std::move(callable)) {}

    ~ScopeExitT() {
        if (skip_calling) return;
        callable();
    }
    void release() {
        skip_calling = true;
    }
};

template<class CallableT>
auto scope_exit(CallableT&& callable) {
    return ScopeExitT<CallableT>(move(callable));
}

// -

template<class E>
class result_error {
public:
   E err;

   result_error(E&& err) : err(move(err)) {}
};

/// E.g. result<Data,string>
template<class T, class E>
class result : protected std::variant<T, E> {
public:
   result(T&& val) : std::variant<T, E>{move(val)} {}
   result(E&& err) : std::variant<T, E>{move(err)} {}
   result(result_error<E>&& err) : std::variant<T, E>{move(err.err)} {}

   constexpr operator bool() noexcept {
      return bool(val());
   }
   constexpr T& operator*() const {
      return *val();
   }
   constexpr T* operator->() const {
      return val();
   }

   constexpr T* val() noexcept {
      return std::get_if<0>(this);
   }
   constexpr E* err() noexcept {
      return std::get_if<1>(this);
   }
};

// -

// C++23:
template<class Enum>
inline constexpr auto to_underlying(const Enum v) {
   return static_cast<std::underlying_type_t<Enum>>(v);
}

// -

} // namespace yote
