(* SilentErrorSwallow: detect OCaml try/with empty handlers.
   Each function below has a distinct try/with pattern; the rule should
   fire on the _ -> () rescue clauses (silent error swallow). *)

let silent_swallow_with_var x =
  try
    Some (process x)
  with
  | _ -> ()

let silent_swallow_with_exn x =
  try
    Some (process x)
  with
  | exn -> ()

(* Non-silent — has logging, should NOT fire *)
let noisy_swallow x =
  try
    Some (process x)
  with
  | exn -> Printf.printf "error: %s" (Printexc.to_string exn); None

(* No rescue at all — should NOT fire *)
let no_rescue x =
  try
    Some (process x)
  with
  | Invalid_argument _ -> raise (Failure "bad arg")
