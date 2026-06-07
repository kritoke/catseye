(* src/ocaml/lib/ai_linter/crystal_rules.ml
   Crystal-specific AST rules — composition layer

   Composes detectors from focused category modules. See each category
   file for what lives where.

   Public API: Crystal_rules.analyze_module : t -> Types.finding list
 *)

open Base
open Catseye_ast.Types

module T = Types

include Crystal_rules_helpers

module Ghost              = Crystal_rules_ghost
module Foreigner          = Crystal_rules_foreigner
module Happy_path         = Crystal_rules_happy_path
module Security           = Crystal_rules_security
module Quality            = Crystal_rules_quality
module Complexity         = Crystal_rules_complexity
module Exception_safety   = Crystal_rules_exception_safety
module Type_network       = Crystal_rules_type_network
module Style              = Crystal_rules_style

let all () = [
  ("hallucinated-stdlib", T.Error, Ghost.detect_hallucinated_stdlib);
  ("deprecated-syntax", T.Warning, Ghost.detect_deprecated_syntax);
  ("manual-loop", T.Hint, Foreigner.detect_manual_loop);
  ("primitive-obsession", T.Hint, Foreigner.detect_primitive_obsession);
  ("nil-chaser", T.Warning, Happy_path.detect_nil_chaser);
  ("ignored-return", T.Warning, Happy_path.detect_ignored_return);
  ("unsafe-pointer", T.Error, Happy_path.detect_unsafe_pointers);
  ("sleep-in-prod", T.Warning, Happy_path.detect_sleep_in_prod);
  ("redundant-conversion", T.Hint, Security.detect_redundant_conversion);
  ("hardcoded-secrets", T.Error, Security.detect_hardcoded_secrets);
  ("hardcoded-urls", T.Warning, Security.detect_hardcoded_urls);
  ("blanket-rescue", T.Warning, Quality.detect_blanket_rescue);
  ("duplicate-validation", T.Hint, Quality.detect_duplicate_validation);
  ("magic-string", T.Hint, Quality.detect_magic_string);
  ("debug-require", T.Warning, Quality.detect_debug_require);
  ("empty-catch", T.Warning, Quality.detect_empty_catch);
  ("flag-argument", T.Hint, Quality.detect_flag_argument);
  ("long-method", T.Warning, Quality.detect_long_method);
  ("infinite-recursion", T.Error, Quality.detect_infinite_recursion);
  ("debug-print", T.Warning, Quality.detect_debug_print);
  ("string-interpolation-query", T.Error, Quality.detect_string_interpolation_in_query);
  ("complex-conditional", T.Hint, Complexity.detect_complex_conditional);
  ("message-chain", T.Hint, Complexity.detect_message_chain);
  ("nested-ternary", T.Warning, Complexity.detect_nested_ternary);
  ("data-clump", T.Hint, Complexity.detect_data_clump);
  ("feature-envy", T.Hint, Complexity.detect_feature_envy);
  ("callback-hell", T.Warning, Complexity.detect_callback_hell);
  ("repeated-regex", T.Hint, Complexity.detect_repeated_regex);
  ("too-many-params", T.Hint, Complexity.detect_too_many_params);
  ("non-atomic-file-op", T.Hint, Exception_safety.detect_non_atomic_file_op);
  ("unbounded-file-read", T.Warning, Exception_safety.detect_unbounded_file_read);
  ("open-rescue", T.Warning, Exception_safety.detect_open_rescue);
  ("missing-else", T.Hint, Exception_safety.detect_missing_else);
  ("reassignment-in-condition", T.Warning, Exception_safety.detect_reassignment_in_condition);
  ("unreachable-code", T.Warning, Exception_safety.detect_unreachable_code);
  ("dead-code-after-error", T.Warning, Exception_safety.detect_dead_code_after_error);
  ("type-checker-abuse", T.Hint, Type_network.detect_type_checker_abuse);
  ("hardcoded-port", T.Warning, Type_network.detect_hardcoded_port);
  ("unless-with-else", T.Hint, Style.detect_unless_with_else);
  ("global-variable", T.Warning, Style.detect_global_variable);
  ("float-equality", T.Warning, Style.detect_float_equality);
  ("sequential-blocking", T.Hint, Style.detect_sequential_blocking);
  ("empty-string-comparison", T.Hint, Style.detect_empty_string_comparison);
  ("negated-comparison", T.Hint, Style.detect_negated_comparison);
  ("string-concat-loop", T.Hint, Style.detect_string_concat_loop);
  ("nilable-ivar-access", T.Hint, Style.detect_nilable_ivar_access);
  ("redundant-self", T.Hint, Style.detect_redundant_self);
]

let test_file_skip_rules = [
  "deprecated-syntax";
  "ignored-return";
  "primitive-obsession";
  "too-many-params";
  "debug-print";
  "hallucinated-stdlib";
]

let analyze_module (m : t) : Types.finding list =
  let file_path = m.mod_path in
  let is_test = Crystal_rules_helpers.is_test_or_spec_file file_path in

  List.concat_map (fun (rule_id, sev, detector) ->
    if is_test && List.mem rule_id test_file_skip_rules then []
    else List.map (fun (msg, line) ->
      { Types.file = file_path;
        Types.line = line;
        Types.rule_id = rule_id;
        Types.severity = sev;
        Types.message = msg;
        Types.suggestion = None; }
    ) (detector m)
  ) (all ())
