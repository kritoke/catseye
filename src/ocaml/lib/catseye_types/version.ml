(* lib/catseye_types/version.ml
   Version information — stampable at build time via BUILD_VERSION env var,
   or read from the version file shipped with the source. *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

let version =
  try Stdlib.Sys.getenv "BUILD_VERSION"
  with Stdlib.Not_found -> "0.4.0"

let git_hash =
  try Stdlib.Sys.getenv "BUILD_GIT_HASH"
  with Stdlib.Not_found -> "dev"

let version_string () =
  Printf.sprintf "%s (%s)" version git_hash
