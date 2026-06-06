(* Triangulation fixture: SilentErrorSwallow should STILL fire on OCaml.
   This proves the languages { include "ocaml" } filter is not over-broad. *)

let silently_swallow x =
  try
    Some (process x)
  with
  | _ -> ()
