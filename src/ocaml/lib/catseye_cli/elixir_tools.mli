(* lib/catseye_cli/elixir_tools.mli *)

(** Tool status for discovery *)
type tool_status =
  | Available
  | NotInstalled
  | ProjectNotMix

type tool_info = {
  name : string;
  version : string option;
  status : tool_status;
}

(** Elixir-specific configuration *)
type elixir_config = {
  enabled : bool;
  run_sobelow : bool;
  run_credo : bool;
  run_reach : bool;
  threshold : [ `Low | `Medium | `High ];
}

val default_elixir_config : elixir_config

val check_tools : ?mix_path:string -> string -> tool_info list

val is_mix_project : string -> bool

val run_sobelow :
  ?config:elixir_config ->
  project_dir:string ->
  unit ->
  Catseye_types.Finding.t list

val run_credo :
  ?config:elixir_config ->
  project_dir:string ->
  unit ->
  Catseye_types.Finding.t list

val run_reach :
  ?config:elixir_config ->
  project_dir:string ->
  unit ->
  Catseye_types.Finding.t list

val run_all_tools :
  ?config:elixir_config ->
  project_dir:string ->
  unit ->
  Catseye_types.Finding.t list

val report_tool_status : tool_info list -> unit