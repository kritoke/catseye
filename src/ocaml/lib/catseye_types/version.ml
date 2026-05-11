(* lib/catseye_types/version.ml
   Version information — stampable at build time via BUILD_VERSION env var. *)

let version =
  try Sys.getenv "BUILD_VERSION"
  with Not_found -> "0.3.0"

let git_hash =
  try Sys.getenv "BUILD_GIT_HASH"
  with Not_found -> "dev"

let version_string () =
  Printf.sprintf "%s (%s)" version git_hash
