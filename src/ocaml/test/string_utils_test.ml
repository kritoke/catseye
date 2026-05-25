(* test/string_utils_test.ml *)
(* Tests for Catseye_engine.String_utils *)

let Alcotest = Alcotest

let test_is_test_suffix () =
  Alcotest.(check bool) \"is_test_suffix test\" true
    (Catseye_engine.String_utils.is_test_suffix \"foo_test.ml\" ~suffix_list:[\"_test\"; \"_tests\"]);
  Alcotest.(check bool) \"is_test_suffix spec\" true
    (Catseye_engine.String_utils.is_test_suffix \"bar_spec.cr\" ~suffix_list:[\"_spec\"; \"_specs\"]);
  Alcotest.(check bool) \"is_test_suffix negative\" false
    (Catseye_engine.String_utils.is_test_suffix \"main.cr\" ~suffix_list:[\"_test\"; \"_tests\"]);

let test_is_test_prefix () =
  Alcotest.(check bool) \"is_test_prefix\" true
    (Catseye_engine.String_utils.is_test_prefix \"test_foo.ml\" ~prefix_list:[\"test_\"; \"tests_\"]);
  Alcotest.(check bool) \"is_test_prefix negative\" false
    (Catseye_engine.String_utils.is_test_prefix \"foo_test.ml\" ~prefix_list:[\"test_\"; \"tests_\"]);

let test_is_containing () =
  Alcotest.(check bool) \"is_containing\" true
    (Catseye_engine.String_utils.is_containing \"my_test_file.ml\" ~substring_list:[\"test\"; \"spec\"]);
  Alcotest.(check bool) \"is_containing negative\" false
    (Catseye_engine.String_utils.is_containing \"main.ml\" ~substring_list:[\"test\"; \"spec\"]);

let test_is_test_file () =
  Alcotest.(check bool) \"is_test_file suffix\" true
    (Catseye_engine.String_utils.is_test_file \"foo_test.ml\");
  Alcotest.(check bool) \"is_test_file spec\" true
    (Catseye_engine.String_utils.is_test_file \"bar_spec.cr\");
  Alcotest.(check bool) \"is_test_file negative\" false
    (Catseye_engine.String_utils.is_test_file \"main.cr\");

let test_matches_prefix () =
  Alcotest.(check bool) \"matches_prefix exact\" true
    (Catseye_engine.String_utils.matches_prefix \"HTTP::Client\" ~pattern_list:[\"HTTP::Client\"]);
  Alcotest.(check bool) \"matches_prefix method\" true
    (Catseye_engine.String_utils.matches_prefix \"HTTP::Client.get\" ~pattern_list:[\"HTTP::Client\"]);
  Alcotest.(check bool) \"matches_prefix negative\" false
    (Catseye_engine.String_utils.matches_prefix \"Foo::Bar\" ~pattern_list:[\"HTTP::Client\"]);

let test_matches_suffix () =
  Alcotest.(check bool) \"matches_suffix exact\" true
    (Catseye_engine.String_utils.matches_suffix \"readFileSync\" ~pattern_list:[\"readFileSync\"]);
  Alcotest.(check bool) \"matches_suffix partial\" true
    (Catseye_engine.String_utils.matches_suffix \"foo_readFileSync\" ~pattern_list:[\"readFileSync\"]);
  Alcotest.(check bool) \"matches_suffix negative\" false
    (Catseye_engine.String_utils.matches_suffix \"writeFileSync\" ~pattern_list:[\"readFileSync\"]);

let test_count_substring () =
  Alcotest.(check int) \"count_substring simple\" 2
    (Catseye_engine.String_utils.count_substring \"a && b || c\" ~substring:\"&&\");
  Alcotest.(check int) \"count_substring empty\" 0
    (Catseye_engine.String_utils.count_substring \"no operators here\" ~substring:\"\");
  Alcotest.(check int) \"count_substring not found\" 0
    (Catseye_engine.String_utils.count_substring \"hello world\" ~substring:\"xyz\");

let test_safe_take () =
  Alcotest.(check string) \"safe_take normal\" \"hello\"
    (Catseye_engine.String_utils.safe_take \"hello world\" 5);
  Alcotest.(check string) \"safe_take longer\" \"hello world\"
    (Catseye_engine.String_utils.safe_take \"hello world\" 100);
  Alcotest.(check string) \"safe_take zero\" \"\"
    (Catseye_engine.String_utils.safe_take \"hello world\" 0);
  Alcotest.(check string) \"safe_take negative\" \"\"
    (Catseye_engine.String_utils.safe_take \"hello world\" (-1));

let () =
  Alcotest.run \"string_utils\" [
    \"is_test_suffix\", [`Quick, test_is_test_suffix];
    \"is_test_prefix\", [`Quick, test_is_test_prefix];
    \"is_containing\", [`Quick, test_is_containing];
    \"is_test_file\", [`Quick, test_is_test_file];
    \"matches_prefix\", [`Quick, test_matches_prefix];
    \"matches_suffix\", [`Quick, test_matches_suffix];
    \"count_substring\", [`Quick, test_count_substring];
    \"safe_take\", [`Quick, test_safe_take];
  ]