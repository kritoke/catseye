# Property Taint Propagation

**Change:** `property-taint-propagation`  
**Priority:** P1  
**Size:** L (1 week)  
**Created:** 2026-05-17  
**Status:** Proposed

## Context

Current taint propagation tracks variable-level assignments (`x = y`, `x = f(y)`) but fails when taint flows through **object properties**. This causes false negatives where vulnerable sinks are not detected.

### Problem Example

```crystal
# Current: taint tracked for `url` but NOT for `uri` or `uri.request_target`
url = params["url"]           # ← Taint source
uri = URI.parse(url)          # url → uri NOT tracked
client.get(uri.request_target)  # ← SSRF sink not detected

# Also problematic:
query = request.params["q"]   # ← Taint source
url = "https://api.example.com?q=#{query}"
HTTP.get(url)                 # ← Should flag, but url isn't tracked
```

### Why Property Tracking Is Hard

1. **Object identity**: When `uri = URI.parse(url)`, we need to know that `uri` represents the parsed URL
2. **Field access**: `uri.request_target` should inherit taint from `url` because they're derived
3. **Method returns**: Need heuristics for what `URI.parse`, `.split`, `.gsub`, etc. return
4. **Aliasing**: Multiple variables may reference the same object

## Goals

1. Track taint through common property access patterns
2. Detect taint in string interpolation/concatenation
3. Reduce false negatives in SSRF, command injection, path traversal rules
4. Maintain low false positive rate

---

## Design

### 1. Property Taint Database

```ocaml
(* Extend the taint DB to track object-level taint *)
type property_key = {
  var : string;      (* Variable name *)
  field : string;    (* Field/property accessed *)
  file : string;
}

(* Add to Db.t *)
type t = {
  (* Existing: variable-level taint *)
  var_records : var_record list;
  
  (* NEW: property-level taint *)
  property_records : property_record list;
}

and property_record = {
  prop_key : property_key;
  source_var : string;
  source_file : string;
  origin : taint_origin;
}
```

### 2. Property Propagation Rules

#### Rule 1: Constructor Taint

When a built-in function creates an object, taint its properties:

```ocaml
(* URI.parse(url) → uri.request_target is tainted if url is tainted *)
let constructor_taint_rules = [
  ("URI", "parse", ["request_target"]);
  ("URL", "parse", ["host"; "path"; "query"]);
  ("Path", "new", ["name"]);
]
```

#### Rule 2: String Operations

String operations preserve taint for derived strings:

```crystal
url = params["url"]                # url is tainted
url_with_param = "#{url}?page=1"   # url_with_param is tainted
base_url = url.split("?").first    # base_url is tainted
```

#### Rule 3: Assignment Chains

```crystal
uri = URI.parse(url)      # uri.request_target inherits from url
parsed = uri               # parsed.request_target also tainted
```

### 3. Taint Origin Tracking

```ocaml
type taint_origin =
  | From_param of string           (* HTTP parameter *)
  | From_env                       (* Environment variable *)
  | From_constructor of string * string  (* Constructor(tainted_arg) *)
  | From_interpolation of string   (* "#{var}" *)
  | From_string_op of string       (* .split, .gsub, etc. *)
```

---

## Implementation Phases

### Phase 1: URI/URL Property Tracking (1-2 days)

Add special handling for URI/URL objects:

1. **URI.parse taint propagation**
2. **URL constructor taint propagation**
3. **Property access through accessor methods**

```ocaml
(* In propagate.ml *)
let propagate_uri_properties (nodes : Security_node.t list) (db : Db.t) : Db.t =
  (* When URI.parse(arg) is called and arg is tainted:
     - Mark arg.request_target as tainted
     - Mark arg.host as tainted
     - etc. *)
```

### Phase 2: String Operation Taint (2-3 days)

Propagate taint through common string methods:

```crystal
# These should all propagate taint:
tainted = params["input"]
result = tainted.upcase          # tainted -> result
result = tainted.split(",")     # tainted -> result[0], result[1], etc.
result = tainted.gsub("a", "b") # tainted -> result
result = "#{tainted} suffix"    # tainted -> result
```

**Strategy**: String methods that return strings likely preserve taint from the receiver.

### Phase 3: Object Aliasing (2-3 days)

Track when multiple variables reference the same object:

```crystal
uri1 = URI.parse(url)
uri2 = uri1                      # uri2 is alias of uri1
# uri2.request_target should also be tainted
```

---

## Files to Modify

| File | Change |
|------|--------|
| `lib/catseye_engine/db.ml` | Add property_record type, extend Db.t |
| `lib/catseye_engine/propagate.ml` | Add property propagation rules |
| `lib/catseye_engine/engine.ml` | Call new propagation phases |
| `lib/catseye_engine/constants.ml` | Add constructor taint rules |
| `lib/catseye_rules/ssrf.kdl` | Update rule to check property taint |

---

## Testing

### Unit Tests

```bash
# Test URI property tracking
catseye test/samples/property_taint/uri_taint.cr --rules=ssrf
# Should flag: HTTP.get(uri.request_target) where uri = URI.parse(params["url"])
```

### Test Fixtures

```
test/samples/property_taint/
├── uri_taint.cr              # URI.parse propagation
├── string_taint.cr           # String operation propagation
├── alias_taint.cr            # Object aliasing
└── ssrf_real.cr              # Real-world SSRF patterns
```

### Expected Behavior

| Input | Before | After |
|-------|--------|-------|
| `url = params["url"]; uri = URI.parse(url); HTTP.get(uri.request_target)` | Not flagged | Flagged |
| `input = params["q"]; url = "https://#{input}"` | Not flagged | Flagged |
| `url = params["u"]; base = url.split("?"); HTTP.get(base[0])` | Not flagged | Flagged |

---

## Performance Considerations

- Property tracking adds overhead to propagation
- Use lazy evaluation: only track properties when needed
- Cache property lookups per object instance
- Limit recursion depth for nested property access

---

## Open Questions

1. **False positive rate**: How aggressive should property taint be?
   - Option A: Only propagate for known-unsafe operations (conservative)
   - Option B: Propagate broadly for all string operations (aggressive)

2. **Precision vs recall**: SSRF rules may become noisy with aggressive tracking
   - May need per-rule tuning

3. **Type information**: Crystal has type inference, but we don't have access to it
   - Heuristics based on method names may be necessary

---

## Related

- **Cross-file taint propagation**: Will benefit from property tracking
- **Object sensitivity**: Future: track distinct object instances
- **Path sensitivity**: Track conditionals that may sanitize values

---

_Created: 2026-05-17_