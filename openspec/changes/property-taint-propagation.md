# Property Taint Propagation

**Change:** `property-taint-propagation`  
**Priority:** P1  
**Size:** L (1 week)  
**Created:** 2026-05-17  
**Status:** Phase 1 Implemented ✓

## Context

Current taint propagation tracks variable-level assignments (`x = y`, `x = f(y)`) but fails when taint flows through **object properties**. This causes false negatives where vulnerable sinks are not detected.

### Problem Example (NOW FIXED)

```crystal
# Before: taint tracked for `url` but NOT for `uri` or `uri.request_target`
url = params["url"]           # ← Taint source
uri = URI.parse(url)          # url → uri NOW tracked
client.get(uri.request_target)  # ← NOW detected as SSRF
```

## Implementation Status

### ✅ Phase 1: URI/URL Property Tracking (DONE 2026-05-17)

**Files Modified:**

- `lib/catseye_engine/propagate.ml` - Added `propagate_uri_properties` and `propagate_aliases`
- `lib/catseye_engine/db.ml` - Fixed dedup to allow same var with different fields
- `lib/catseye_engine/seed.ml` - Always seed params that match known sources

**Key Changes:**

1. **URI constructor taint propagation** (`propagate_uri_properties`)
   - Detects `URI.parse(x)` where `x` is tainted
   - Marks `result.host`, `result.request_target`, `result.path`, `result.query` as tainted
   - Also handles `URI.new`, `URL.parse`, `URL.new`

2. **Alias propagation** (`propagate_aliases`)
   - When `other = uri` and `uri` has tainted properties
   - `other` inherits the same tainted properties
   - Enables: `other.request_target` detection

3. **Seed fix** (`seed.ml`)
   - Now seeds function params matching known sources (`url`, `params`, etc.) unconditionally
   - Previously required a tainted assignment in the function first

4. **DB dedup fix** (`db.ml`)
   - Changed dedup from `var_name` only to `(var_name, field)` pair
   - Allows recording both `uri` (variable-level) and `uri.request_target` (field-level)

### ✅ Phase 1 Testing

```bash
# All test cases now pass:
# Test 1: def proxy_request(url) with uri = URI.parse(url) → SSRF detected ✓
# Test 2: params["url"] pattern → SSRF detected ✓
# Test 3: Aliasing (other = uri) → SSRF detected ✓
# Test 4: real codebase (quickheadlines) → 2 SSRFs detected ✓
```

---

## Remaining: Phase 2 & 3

### Phase 2: String Operation Taint (TODO)

Propagate taint through common string methods:

```crystal
# These should propagate taint:
tainted = params["input"]
result = tainted.upcase          # tainted -> result
result = tainted.split(",")     # tainted -> result[0], result[1], etc.
result = tainted.gsub("a", "b") # tainted -> result
result = "#{tainted} suffix"    # tainted -> result
```

### Phase 3: Object Aliasing (TODO)

Partially done via `propagate_aliases`. May need enhancement for:

- Method call chains: `uri = URI.parse(url); client = HTTP::Client.new(uri.host)`
- Multiple levels of aliasing

---

## Files Modified

| File                              | Change                                                   |
| --------------------------------- | -------------------------------------------------------- |
| `lib/catseye_engine/propagate.ml` | Added `propagate_uri_properties` and `propagate_aliases` |
| `lib/catseye_engine/db.ml`        | Fixed dedup to allow field-level records                 |
| `lib/catseye_engine/seed.ml`      | Always seed params matching known sources                |

---

## Related

- **Cross-file taint propagation**: Will benefit from property tracking
- **Object sensitivity**: Future: track distinct object instances
- **Path sensitivity**: Track conditionals that may sanitize values

---

_Updated: 2026-05-17 (Phase 1 completed)_
