(* Fixture: Jane Street Base stdlib usage — must produce ZERO hallucinated-method
   findings. Regression guard for the Base whitelist (self-scan-hardening REQ-3). *)
open Base

let f1 (s : string) : string = String.strip s
let f2 (s : string) : string = String.capitalize s
let f3 (s : string) : int = String.length s
let f4 (l : int list) : int = List.length l
let f5 (l : int list) : int list = List.filter ~f:(fun x -> x > 0) l
let f6 (l : int list) : int list = List.map ~f:(fun x -> x * 2) l
let f7 (l : int list) : int = List.fold_left ~init:0 ~f:(fun acc x -> acc + x) l
let f8 (s : string) : string = String.trim s
let f9 (o : int option) : int = Option.value o ~default:0
let f10 (o : int option) : int option = Option.map ~f:(fun x -> x + 1) o
let f11 (r : (int, string) result) : bool = Result.is_ok r
let f12 (r : (int, string) result) : string option =
  match r with Ok _ -> None | Error e -> Some (String.trim e)
let f13 () : Buffer.t = Buffer.create 64
let f14 () : string = Int.to_string 42
let f15 (b : Buffer.t) : string = b |> Buffer.contents

(* Real hallucination that MUST still be caught (guard the guard):
   bare Haskell/Python-isms that OCaml does not have. *)
let bug1 (l : int list) : int list = reverse l
let bug2 (l : int list) (f : int -> int) : int list = mapM (fun x -> [ f x ]) l
