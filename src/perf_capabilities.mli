open! Core
open! Async

type t = private Int63.t [@@deriving sexp_of]

include Flags.S with type t := t

val configurable_psb_period : t
val kernel_tracing : t
val kcore : t
val snapshot_on_exit : t
val last_branch_record : t
val dlfilter : t
val ctlfd : t
val detect_exn : unit -> t Deferred.t

(** Whether we can collect physical addresses in PEBS samples.
    Requires root or perf_event_paranoid <= 0. *)
val can_collect_phys_addr : bool Lazy.t

(** Whether this is a hybrid CPU (Intel Alder Lake and later) with separate
    P-core and E-core PMUs. PEBS events on hybrid CPUs require explicit PMU
    specification (cpu_core or cpu_atom). *)
val is_hybrid_cpu : bool Lazy.t
