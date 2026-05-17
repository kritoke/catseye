# Property Taint Propagation

**Change:** `property-taint-propagation`  
**Priority:** P1  
**Size:** L (1 week)  
**Created:** 2026-05-17  
**Status:** Phase 1 & 2 Implemented ✓

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

### ✅ Phase 2: String Operation Taint (DONE 2026-05-17)

**Files Modified:**

- `lib/catseye_engine/propagate.ml` - Added `propagate_string_ops` and related helpers
- `lib/catseye_engine/db.ml` - Added `get_tainted_records` function

**Key Changes:**

1. **String method taint propagation** (`propagate_string_ops`)
   - Detects assignments like `result = tainted.upcase`, `result = tainted.split(",")`
   - Marks the assign target as tainted at variable level
   - Also marks common string property fields (`length`, `size`, `empty`, `bytesize`)

2. **Enhanced alias propagation** (`propagate_aliases`)
   - Now propagates ALL tainted properties from source to target
   - Handles method call results (e.g., `parts[0]` inherits from `parts`)
   - Uses `Db.get_tainted_records` to find all field-level taints

3. **Helper functions**
   - `is_string_taint_method`: checks if method is in taint-propagating list
   - `extract_method_name`: extracts method name from "receiver.method" format
   - `get_call_receiver`: extracts receiver variable from call node

**Supported string methods:**
`upcase`, `downcase`, `capitalize`, `strip`, `lstrip`, `rstrip`, `reverse`, `chomp`, `chop`, `squeeze`, `gsub`, `sub`, `replace`, `split`, `lines`, `chars`, `bytes`, `tr`, `delete`, `prepend`, `concat`, `encode`, `decode`

### ✅ Phase 1 & 2 Testing

```bash
# All test cases now pass:
# Test 1: def proxy_request(url) with uri = URI.parse(url) → SSRF detected ✓
# Test 2: params["url"] pattern → SSRF detected ✓
# Test 3: Aliasing (other = uri) → SSRF detected ✓
# Test 4: real codebase (quickheadlines) → 2 SSRFs detected ✓
# Test 5: url.split("/") + parts[0] → SSRF detected ✓
# Test 6: url.upcase, url.gsub, url.strip → SSRF detected ✓
```

---

## Remaining: Phase 3

### Phase 3: Advanced Taint Patterns (TODO)

- **Cross-file taint propagation**: Track taint across file boundaries
- **Hub-like Module detection**: Classes with high fan-out to many other classes
- **Shotgun Surgery detection**: Single responsibility violation (one change affects many classes)

---

## Files Modified

| File                              | Change                                                   |
| --------------------------------- | -------------------------------------------------------- |
| `lib/catseye_engine/propagate.ml` | Added string op taint, enhanced alias propagation         |
| `lib/catseye_engine/db.ml`        | Added `get_tainted_records`, fixed field-level dedup      |
| `lib/catseye_engine/seed.ml`      | Always seed params matching known sources                |

---

## Related

- **Cross-file taint propagation**: Will benefit from property tracking
- **Object sensitivity**: Future: track distinct object instances
- **Path sensitivity**: Track conditionals that may sanitize values

---

_Updated: 2026-05-17 (Phase 1 & 2 completed)_