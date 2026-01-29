open! Core
open! Async

let saturating_sub_i64 a b =
  match Int64.(to_int (a - b)) with
  | None -> Int.max_value
  | Some offset -> offset
;;

let perf_event_header_re =
  Re.Perl.re
    {|^ *([0-9]+)/([0-9]+) +([0-9]+)\.([0-9]+): +([0-9]+) +([a-z\-_\.]+)(/[a-z=0-9\._,]+)?(/[a-zA-Z]*)?:([a-zA-Z]+:)?(.*)$|}
  |> Re.compile
;;

let perf_extra_sampled_event_re =
  Re.Perl.re {|^ *([0-9]+) +([0-9a-f]+) (.*)$|} |> Re.compile
;;

let perf_callstack_entry_re = Re.Perl.re "^\t *([0-9a-f]+) (.*)$" |> Re.compile

let perf_branches_event_re =
  Re.Perl.re
    {|^ *(call|return|tr strt(?: jmp)?|syscall|sysret|hw int|iret|int|tx abrt|tr end|tr strt tr end|tr end  (?:async|call|return|syscall|sysret|iret)|jmp|jcc) +(\(x\) +)?([0-9a-f]+) (.*) => +([0-9a-f]+) (.*)$|}
  |> Re.compile
;;

let perf_cbr_event_re =
  Re.Perl.re {|^ *([a-z )(]*)? +cbr: +([0-9]+ +freq: +([0-9]+) MHz)?(.*)$|} |> Re.compile
;;

let trace_error_re =
  Re.Posix.re
    {|^ instruction trace error type [0-9]+ (time ([0-9]+)\.([0-9]+) )?cpu [\-0-9]+ pid ([\-0-9]+) tid ([\-0-9]+) ip (0x[0-9a-fA-F]+|0) code [0-9]+: (.*)$|}
  |> Re.compile
;;

let symbol_and_offset_re = Re.Perl.re {|^(.*)\+(0x[0-9a-f]+)\s+\(.*\)$|} |> Re.compile
let unknown_symbol_dso_re = Re.Perl.re {|^\[unknown\]\s+\((.*)\)|} |> Re.compile

(* PEBS fields: addr, data_src, weight, ip, symbol, and optionally phys_addr
   Format from perf script (positional, not labeled):
   addr  data_src  |OP X|LVL Y|SNP Z|TLB W|LCK V|BLK U   weight ins_lat retire_lat  ip  sym+off (dso)  [phys_addr]
   Example:
   7f01de205f28  1e05080022 |OP LOAD|LVL N/A|...|BLK  N/A  0  0  0  7f01de1ede8a _dl_start+0x9a (/lib/...) [1c08609f28]

   Note: The pipe fields have the format |KEY VALUE| for all but the last one which is just
   KEY  VALUE (extra space, no trailing pipe). Each field is separated by |.

   Groups:
   1: addr (memory address)
   2: data_src (data source hex)
   3: weight (latency cycles)
   4: ip (instruction pointer)
   5: symbol+offset (dso)
   6: phys_addr (optional)
*)
let perf_pebs_line_re =
  Re.Perl.re
    {|^ *([0-9a-f]+) +([0-9a-f]+) +\|[^|]+\|[^|]+\|[^|]+\|[^|]+\|[^|]+\|[A-Z]+[ ]+[^ ]+ +([0-9]+)(?: +[0-9]+)?(?: +[0-9]+)? +([0-9a-f]+) +([^ ]+ +\([^)]+\))(?: +([0-9a-f]+))?$|}
  |> Re.compile
;;

let decode_data_source (data_src : int64) : Event.Ok.Pebs_data.data_source =
  (* PERF_MEM_LVL_* bits from linux/perf_event.h:
     LVL_L1 = 0x08, LVL_LFB = 0x10, LVL_L2 = 0x20, LVL_L3 = 0x40,
     LVL_LOC_RAM = 0x80, LVL_REM_RAM1 = 0x100, LVL_REM_RAM2 = 0x200, LVL_REM_CCE1 = 0x400 *)
  if Int64.(data_src land 0x08L <> 0L)
  then L1_hit
  else if Int64.(data_src land 0x20L <> 0L)
  then L2_hit
  else if Int64.(data_src land 0x40L <> 0L)
  then L3_hit
  else if Int64.(data_src land 0x80L <> 0L)
  then Local_dram
  else if Int64.(data_src land 0x700L <> 0L) (* REM_RAM1 | REM_RAM2 | REM_CCE1 *)
  then Remote_dram
  else Unknown
;;

type pebs_parsed =
  { pebs_data : Event.Ok.Pebs_data.t
  ; instruction_pointer : string
  ; symbol_and_offset : string
  }

let parse_pebs_line line : pebs_parsed option =
  match Re.exec_opt perf_pebs_line_re line with
  | None -> None
  | Some groups ->
    let phys =
      try Some (Int64.of_string ("0x" ^ Re.Group.get groups 6)) with
      | _ -> None
    in
    let pebs_data =
      { Event.Ok.Pebs_data.latency_cycles = Some (Int.of_string (Re.Group.get groups 3))
      ; data_source =
          Some (decode_data_source (Int64.of_string ("0x" ^ Re.Group.get groups 2)))
      ; memory_address = Some (Int64.of_string ("0x" ^ Re.Group.get groups 1))
      ; physical_address = phys
      }
    in
    Some
      { pebs_data
      ; instruction_pointer = Re.Group.get groups 4
      ; symbol_and_offset = Re.Group.get groups 5
      }
;;

type header =
  | Trace_error
  | Event of
      { thread : Event.Thread.t
      ; time : Time_ns.Span.t
      ; period : int
      ; event :
          [ `Branches
          | `Cbr
          | `Psb
          | `Cycles
          | `Branch_misses
          | `Cache_misses
          | `Mem_loads
          | `Mem_stores
          ]
      ; remaining_line : string
      }

let maybe_pid_of_string = function
  | "0" -> None
  | pid -> Some (Pid.of_string pid)
;;

let parse_time ~time_hi ~time_lo =
  let time_lo =
    (* In practice, [time_lo] seems to always be 9 decimal places, but it seems
       good to guard against other possibilities. *)
    let num_decimal_places = String.length time_lo in
    match Ordering.of_int (Int.compare num_decimal_places 9) with
    | Less -> Int.of_string time_lo * Int.pow 10 (9 - num_decimal_places)
    | Equal -> Int.of_string time_lo
    | Greater -> Int.of_string (String.prefix time_lo 9)
  in
  let time_hi = Int.of_string time_hi in
  time_lo + (time_hi * 1_000_000_000) |> Time_ns.Span.of_int_ns
;;

let parse_event_header line =
  if String.is_prefix line ~prefix:" instruction trace error"
  then Trace_error
  else (
    match Re.Group.all (Re.exec perf_event_header_re line) with
    | [| _
       ; pid
       ; tid
       ; time_hi
       ; time_lo
       ; period
       ; event_name
       ; event_config
       ; _event_selector
       ; _selector
       ; remaining_line
      |] ->
      let pid = maybe_pid_of_string pid in
      let tid = maybe_pid_of_string tid in
      let time = parse_time ~time_hi ~time_lo in
      let period = Int.of_string period in
      (* Event config contains the full event path like /mem_inst_retired.all_loads *)
      let full_event =
        if String.is_empty event_config
        then event_name
        else String.chop_prefix_if_exists event_config ~prefix:"/"
      in
      let event =
        match event_name, full_event with
        | "branches", _ -> `Branches
        | "cbr", _ -> `Cbr
        | "psb", _ -> `Psb
        | "cycles", _ -> `Cycles
        | "branch-misses", _ -> `Branch_misses
        | "cache-misses", _ -> `Cache_misses
        | "mem_inst_retired", _ -> `Mem_loads
        | _, event when String.is_substring event ~substring:"mem_inst_retired.all_loads" ->
          `Mem_loads
        | _, event when String.is_substring event ~substring:"mem_inst_retired.all_stores" ->
          `Mem_stores
        | "cpu_core", event when String.is_substring event ~substring:"mem_inst_retired" ->
          (* Hybrid CPU format: cpu_core/mem_inst_retired.all_loads/... *)
          if String.is_substring event ~substring:"all_stores"
          then `Mem_stores
          else `Mem_loads
        | _ ->
          raise_s
            [%message
              "Unexpected event type when parsing perf output"
                (event_name : string)
                (event_config : string)]
      in
      Event { thread = { pid; tid }; time; period; event; remaining_line }
    | results ->
      Core.print_endline "[failed]";
      raise_s
        [%message
          "Regex of perf output did not match expected fields" (results : string array)])
;;

let parse_symbol_and_offset ?perf_maps pid str ~addr : Symbol.t * int =
  match Re.Group.all (Re.exec symbol_and_offset_re str) with
  | [| _; symbol; offset |] ->
    let offset =
      (* Sometimes [perf] reports symbols and offsets like
         [memcpy@plt+0xffffffffff22f000], which are definitely wrong (the implied
         execution address lies in kernel space, but we're in userspace).

         This is a [perf] bug, but we need to be resililent to it.

         [int_trunc_of_hex_string] will drop the leading 1 bit, resulting in a differently
         wrong offset, but won't crash. We don't want to use [int64_of_hex_string] here to
         avoid the extra allocation. *)
      Util.int_trunc_of_hex_string ~remove_hex_prefix:true offset
    in
    From_perf symbol, offset
  | _ | (exception _) ->
    let failed = Symbol.Unknown, 0 in
    (match perf_maps, pid with
     | None, _ | _, None ->
       (match Re.Group.all (Re.exec unknown_symbol_dso_re str) with
        | [| _; dso |] ->
          (* CR-someday tbrindus: ideally, we would subtract the DSO base offset
             from [offset] here. *)
          From_perf [%string "[unknown @ %{addr#Int64.Hex} (%{dso})]"], 0
        | _ | (exception _) -> failed)
     | Some perf_map, Some pid ->
       (match Perf_map.Table.symbol ~pid perf_map ~addr with
        | None -> failed
        | Some location ->
          (* It's strange that perf isn't resolving these symbols. It says on the
             tin that it supports perf map files! *)
          let offset = saturating_sub_i64 addr location.start_addr in
          From_perf_map location, offset))
;;

let trace_error_to_event line : Event.Decode_error.t =
  match Re.Group.all (Re.exec trace_error_re line) with
  | [| _; _; time_hi; time_lo; pid; tid; ip; message |] ->
    let pid = maybe_pid_of_string pid in
    let tid = maybe_pid_of_string tid in
    let instruction_pointer =
      if String.( = ) ip "0"
      then None
      else Some (Util.int64_of_hex_string ~remove_hex_prefix:true ip)
    in
    let time =
      if String.is_empty time_hi && String.is_empty time_lo
      then Time_ns_unix.Span.Option.none
      else Time_ns_unix.Span.Option.some (parse_time ~time_hi ~time_lo)
    in
    { thread = { pid; tid }; instruction_pointer; message; time }
  | results ->
    raise_s
      [%message
        "Regex of trace error did not match expected fields" (results : string array)]
;;

let parse_perf_cbr_event thread time line : Event.t =
  match Re.Group.all (Re.exec perf_cbr_event_re line) with
  | [| _; _; _; freq; _ |] ->
    Ok
      { thread; time; data = Power { freq = Int.of_string freq }; in_transaction = false }
  | results ->
    raise_s
      [%message
        "Regex of perf cbr event did not match expected fields" (results : string array)]
;;

let parse_location ?perf_maps ~pid instruction_pointer symbol_and_offset
  : Event.Location.t
  =
  let instruction_pointer = Util.int64_of_hex_string instruction_pointer in
  let symbol, symbol_offset =
    parse_symbol_and_offset ?perf_maps pid symbol_and_offset ~addr:instruction_pointer
  in
  { instruction_pointer; symbol; symbol_offset }
;;

let parse_callstack_entry ?perf_maps (thread : Event.Thread.t) line : Event.Location.t =
  match Re.Group.all (Re.exec perf_callstack_entry_re line) with
  | [| _; instruction_pointer; symbol_and_offset |] ->
    parse_location ?perf_maps ~pid:thread.pid instruction_pointer symbol_and_offset
  | results ->
    raise_s
      [%message
        "perf output did not match expected regex when parsing callstack entry"
          (results : string array)]
;;

let parse_perf_cycles_event ?perf_maps (thread : Event.Thread.t) time lines : Event.t =
  let callstack =
    List.map lines ~f:(parse_callstack_entry ?perf_maps thread) |> List.rev
  in
  Ok { thread; time; data = Stacktrace_sample { callstack }; in_transaction = false }
;;

let parse_perf_branches_event ?perf_maps (thread : Event.Thread.t) time line : Event.t =
  match Re.Group.all (Re.exec perf_branches_event_re line) with
  | [| _
     ; kind
     ; aux_flags
     ; src_instruction_pointer
     ; src_symbol_and_offset
     ; dst_instruction_pointer
     ; dst_symbol_and_offset
    |] ->
    let src_instruction_pointer = Util.int64_of_hex_string src_instruction_pointer in
    let dst_instruction_pointer = Util.int64_of_hex_string dst_instruction_pointer in
    let src_symbol, src_symbol_offset =
      parse_symbol_and_offset
        ?perf_maps
        thread.pid
        src_symbol_and_offset
        ~addr:src_instruction_pointer
    in
    let dst_symbol, dst_symbol_offset =
      parse_symbol_and_offset
        ?perf_maps
        thread.pid
        dst_symbol_and_offset
        ~addr:dst_instruction_pointer
    in
    let starts_trace, kind =
      match String.chop_prefix kind ~prefix:"tr strt" with
      | None -> false, kind
      | Some rest ->
        ( true
        , String.lstrip
            ~drop:Char.is_whitespace
            (match String.chop_prefix rest ~prefix:" jmp" with
             | None -> rest
             | Some r -> r) )
    in
    let ends_trace, kind =
      match String.chop_prefix kind ~prefix:"tr end" with
      | None -> false, kind
      | Some rest -> true, String.lstrip ~drop:Char.is_whitespace rest
    in
    let trace_state_change : Trace_state_change.t option =
      match starts_trace, ends_trace with
      | true, false -> Some Start
      | false, true -> Some End
      | false, false
      (* "tr strt tr end" happens when someone `go run`s ./demo/demo.go. But
         that trace is pretty broken for other reasons, so it's hard to say if
         this is truly necessary. Regardless, it's slightly more user friendly
         to show a broken trace instead of crashing here. *)
      | true, true -> None
    in
    (* record the flag indicating we're within a transaction *)
    let in_transaction = String.contains aux_flags 'x' in
    let kind : Event.Kind.t option =
      match String.strip kind with
      | "call" -> Some Call
      | "return" -> Some Return
      | "int" -> Some Interrupt
      | "jmp" -> Some Jump
      | "jcc" -> Some Jump
      | "syscall" -> Some Syscall
      | "hw int" -> Some Hardware_interrupt
      | "iret" -> Some Iret
      | "sysret" -> Some Sysret
      | "async" -> Some Async
      | "tx abrt" -> Some Tx_abort
      | "" -> None
      | _ ->
        printf "Warning: skipping unrecognized perf output: %s\n%!" line;
        None
    in
    Ok
      { thread
      ; time
      ; data =
          Trace
            { trace_state_change
            ; kind
            ; src =
                { instruction_pointer = src_instruction_pointer
                ; symbol = src_symbol
                ; symbol_offset = src_symbol_offset
                }
            ; dst =
                { instruction_pointer = dst_instruction_pointer
                ; symbol = dst_symbol
                ; symbol_offset = dst_symbol_offset
                }
            }
      ; in_transaction
      }
  | results ->
    raise_s
      [%message "Regex of expected perf output did not match." (results : string array)]
;;

let parse_perf_extra_sampled_event
  ?perf_maps
  (thread : Event.Thread.t)
  time
  period
  line
  lines
  name
  : Event.t
  =
  let (location : Event.Location.t) =
    match lines with
    | [] ->
      (match Re.Group.all (Re.exec perf_extra_sampled_event_re line) with
       | [| _str; _; instruction_pointer; symbol_and_offset |] ->
         parse_location ?perf_maps ~pid:thread.pid instruction_pointer symbol_and_offset
       | results ->
         raise_s
           [%message
             "Regex of perf event did not match expected fields" (results : string array)])
    | lines -> List.hd_exn lines |> parse_callstack_entry ?perf_maps thread
  in
  Ok
    { thread
    ; time
    ; data = Event_sample { location; count = period; name; pebs_data = None }
    ; in_transaction = false
    }
;;

let parse_perf_pebs_event
  ?perf_maps
  (thread : Event.Thread.t)
  time
  period
  line
  lines
  name
  : Event.t
  =
  let location, pebs_data =
    match lines with
    | [] ->
      (match parse_pebs_line line with
       | Some { pebs_data; instruction_pointer; symbol_and_offset } ->
         let location =
           parse_location ?perf_maps ~pid:thread.pid instruction_pointer symbol_and_offset
         in
         location, Some pebs_data
       | None ->
         (* Fallback to regular sampled event parsing if PEBS format doesn't match *)
         (match Re.Group.all (Re.exec perf_extra_sampled_event_re line) with
          | [| _str; _; instruction_pointer; symbol_and_offset |] ->
            let location =
              parse_location
                ?perf_maps
                ~pid:thread.pid
                instruction_pointer
                symbol_and_offset
            in
            location, None
          | results ->
            raise_s
              [%message
                "Regex of perf event did not match expected fields"
                  (results : string array)]))
    | lines ->
      let location = List.hd_exn lines |> parse_callstack_entry ?perf_maps thread in
      location, None
  in
  Ok
    { thread
    ; time
    ; data = Event_sample { location; count = period; name; pebs_data }
    ; in_transaction = false
    }
;;

let to_event ?perf_maps lines : Event.t option =
  try
    match lines with
    | [] -> raise_s [%message "Unexpected line while parsing perf output."]
    | first_line :: lines ->
      let header = parse_event_header first_line in
      (match header with
       | Trace_error -> Some (Error (trace_error_to_event first_line))
       | Event { thread; time; period; event; remaining_line } ->
         (match event with
          | `Branches ->
            Some (parse_perf_branches_event ?perf_maps thread time remaining_line)
          | `Cbr ->
            (* cbr (core-to-bus ratio) are events which show frequency changes. *)
            Some (parse_perf_cbr_event thread time remaining_line)
          | `Psb -> (* Ignore psb (packet stream boundary) packets *) None
          | `Cycles -> Some (parse_perf_cycles_event ?perf_maps thread time lines)
          | `Branch_misses ->
            Some
              (parse_perf_extra_sampled_event
                 ?perf_maps
                 thread
                 time
                 period
                 remaining_line
                 lines
                 Branch_misses)
          | `Cache_misses ->
            Some
              (parse_perf_extra_sampled_event
                 ?perf_maps
                 thread
                 time
                 period
                 remaining_line
                 lines
                 Cache_misses)
          | `Mem_loads ->
            Some
              (parse_perf_pebs_event
                 ?perf_maps
                 thread
                 time
                 period
                 remaining_line
                 lines
                 Mem_loads)
          | `Mem_stores ->
            Some
              (parse_perf_pebs_event
                 ?perf_maps
                 thread
                 time
                 period
                 remaining_line
                 lines
                 Mem_stores)))
  with
  | exn ->
    raise_s
      [%message
        "BUG: exception raised while parsing perf output. Please report this to \
         https://github.com/janestreet/magic-trace/issues/"
          (exn : exn)
          ~perf_output:(lines : string list)]
;;

let split_line_pipe pipe : string list Pipe.Reader.t =
  let reader, writer = Pipe.create () in
  don't_wait_for
    (let%bind acc =
       Pipe.fold pipe ~init:[] ~f:(fun acc line ->
         let should_acc = not String.(line = "") in
         let should_write =
           String.(line = "") || not (Char.equal (String.get line 0) '\t')
         in
         let%map () =
           if List.length acc > 0 && should_write
           then Pipe.write writer (List.rev acc)
           else Deferred.return ()
         in
         let prev_acc = if should_write then [] else acc in
         if should_acc then line :: prev_acc else prev_acc)
     in
     let%map () =
       if List.length acc > 0
       then Pipe.write writer (List.rev acc)
       else Deferred.return ()
     in
     Pipe.close writer);
  reader
;;

let to_events ?perf_maps pipe =
  let pipe = split_line_pipe pipe in
  (* Every route of filtering on streams in an async way seems to be deprecated,
     including converting to pipes which says that the stream creation should be
     switched to a pipe creation. Changing Async_shell is out-of-scope, and I also
     can't see a reason why filter_map would lead to memory leaks. *)
  Pipe.map pipe ~f:(to_event ?perf_maps) |> Pipe.filter_map ~f:Fn.id
;;

module%test _ = struct
  open Core

  let check s =
    to_event (String.split ~on:'\n' s) |> [%sexp_of: Event.t option] |> print_s
  ;;

  let%expect_test "C symbol" =
    check
      {| 25375/25375 4509191.343298468:                            1   branches:uH:   call                     7f6fce0b71f4 __clock_gettime+0x24 (foo.so) =>     7ffd193838e0 __vdso_clock_gettime+0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (25375)) (tid (25375)))) (time 52d4h33m11.343298468s)
           (data (Trace (kind Call) (src 0x7f6fce0b71f4) (dst 0x7ffd193838e0)))))) |}]
  ;;

  let%expect_test "C symbol trace start" =
    check
      {| 25375/25375 4509191.343298468:                            1   branches:uH:   tr strt                             0 [unknown] (foo.so) =>     7f6fce0b71d0 __clock_gettime+0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (25375)) (tid (25375)))) (time 52d4h33m11.343298468s)
           (data (Trace (trace_state_change Start) (src 0x0) (dst 0x7f6fce0b71d0)))))) |}]
  ;;

  let%expect_test "C symbol trace start jump" =
    check
      {| 25375/25375 4509191.343298468:                            1   branches:uH:   tr strt jmp                         0 [unknown] (foo.so) =>     7f6fce0b71d0 __clock_gettime+0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (25375)) (tid (25375)))) (time 52d4h33m11.343298468s)
           (data (Trace (trace_state_change Start) (src 0x0) (dst 0x7f6fce0b71d0)))))) |}]
  ;;

  let%expect_test "C++ symbol" =
    check
      {| 7166/7166  4512623.871133092:                            1   branches:uH:   call                           9bc6db a::B<a::C, a::D<a::E>, a::F, a::F, G::H, a::I>::run+0x1eb (foo.so) =>           9f68b0 J::K<int, std::string>+0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (7166)) (tid (7166)))) (time 52d5h30m23.871133092s)
           (data (Trace (kind Call) (src 0x9bc6db) (dst 0x9f68b0)))))) |}]
  ;;

  let%expect_test "OCaml symbol" =
    check
      {|2017001/2017001 761439.053336670:                            1   branches:uH:   call                     56234f77576b Base.Comparable.=_2352+0xb (foo.so) =>     56234f4bc7a0 caml_apply2+0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (2017001)) (tid (2017001)))) (time 8d19h30m39.05333667s)
           (data (Trace (kind Call) (src 0x56234f77576b) (dst 0x56234f4bc7a0)))))) |}]
  ;;

  (* CR-someday wduff: Leaving this concrete example here for when we support this. See my
     comment above as well.

     {[
       let%expect_test "Unknown Go symbol" =
         check
           {|2118573/2118573 770614.599007116:                                branches:uH:   tr strt tr end                      0 [unknown] (foo.so) =>           4591e1 [unknown] (foo.so)|};
         [%expect]
       ;;
     ]}
  *)

  let%expect_test "manufactured example 1" =
    check
      {|2017001/2017001 761439.053336670:                            1   branches:uH:   call                     56234f77576b x => +0xb (foo.so) =>     56234f4bc7a0 caml_apply2+0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (2017001)) (tid (2017001)))) (time 8d19h30m39.05333667s)
           (data (Trace (kind Call) (src 0x56234f77576b) (dst 0x56234f4bc7a0)))))) |}]
  ;;

  let%expect_test "manufactured example 2" =
    check
      {|2017001/2017001 761439.053336670:                            1   branches:uH:   call                     56234f77576b x => +0xb (foo.so) =>     56234f4bc7a0 => +0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (2017001)) (tid (2017001)))) (time 8d19h30m39.05333667s)
           (data (Trace (kind Call) (src 0x56234f77576b) (dst 0x56234f4bc7a0)))))) |}]
  ;;

  let%expect_test "manufactured example 3" =
    check
      {|2017001/2017001 761439.053336670:                            1   branches:uH:   call                     56234f77576b + +0xb (foo.so) =>     56234f4bc7a0 caml_apply2+0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (2017001)) (tid (2017001)))) (time 8d19h30m39.05333667s)
           (data (Trace (kind Call) (src 0x56234f77576b) (dst 0x56234f4bc7a0)))))) |}]
  ;;

  let%expect_test "unknown symbol in DSO" =
    check
      {|2017001/2017001 761439.053336670:                            1   branches:uH:   call                     56234f77576b [unknown] (foo.so) =>     56234f4bc7a0 caml_apply2+0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (2017001)) (tid (2017001)))) (time 8d19h30m39.05333667s)
           (data (Trace (kind Call) (src 0x56234f77576b) (dst 0x56234f4bc7a0)))))) |}]
  ;;

  let%expect_test "DSO with spaces in it" =
    check
      {|2017001/2017001 761439.053336670:                            1   branches:uH:   call                     56234f77576b [unknown] (this is a spaced dso.so) =>     56234f4bc7a0 caml_apply2+0x0 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (2017001)) (tid (2017001)))) (time 8d19h30m39.05333667s)
           (data (Trace (kind Call) (src 0x56234f77576b) (dst 0x56234f4bc7a0)))))) |}]
  ;;

  let%expect_test "software interrupts" =
    check
      "1907478/1909463 457407.880965552:          1                                \
       branches:uH:   int                      564aa58813d4 Builtins_RunMicrotasks+0x554 \
       (/usr/local/bin/workload) =>     564aa584fa00 \
       Builtins_Call_ReceiverIsNotNullOrUndefined+0x0 (/usr/local/bin/workload)";
    [%expect
      {|
        ((Ok
          ((thread ((pid (1907478)) (tid (1909463)))) (time 5d7h3m27.880965552s)
           (data (Trace (kind Interrupt) (src 0x564aa58813d4) (dst 0x564aa584fa00)))))) |}]
  ;;

  let%expect_test "decode error with a timestamp" =
    check
      " instruction trace error type 1 time 47170.086912826 cpu -1 pid 293415 tid 293415 \
       ip 0x7ffff7327730 code 7: Overflow packet";
    [%expect
      {|
          ((Error
            ((thread ((pid (293415)) (tid (293415)))) (time (13h6m10.086912826s))
             (instruction_pointer (0x7ffff7327730)) (message "Overflow packet")))) |}]
  ;;

  let%expect_test "decode error without a timestamp" =
    check
      " instruction trace error type 1 cpu -1 pid 293415 tid 293415 ip 0x7ffff7327730 \
       code 7: Overflow packet";
    [%expect
      {|
          ((Error
            ((thread ((pid (293415)) (tid (293415)))) (time ())
             (instruction_pointer (0x7ffff7327730)) (message "Overflow packet")))) |}]
  ;;

  let%expect_test "lost trace data" =
    check
      " instruction trace error type 1 time 2651115.104731379 cpu -1 pid 1801680 tid \
       1801680 ip 0 code 8: Lost trace data";
    [%expect
      {|
          ((Error
            ((thread ((pid (1801680)) (tid (1801680)))) (time (30d16h25m15.104731379s))
             (instruction_pointer ()) (message "Lost trace data")))) |}]
  ;;

  let%expect_test "never-ending loop" =
    check
      " instruction trace error type 1 time 406036.830210719 cpu -1 pid 114362 tid \
       114362 ip 0xffffffffb0999ed5 code 10: Never-ending loop (refer perf config \
       intel-pt.max-loops)";
    [%expect
      {|
          ((Error
            ((thread ((pid (114362)) (tid (114362)))) (time (4d16h47m16.830210719s))
             (instruction_pointer (-0x4f66612b))
             (message "Never-ending loop (refer perf config intel-pt.max-loops)")))) |}]
  ;;

  let%expect_test "power event cbr" =
    check
      "2937048/2937048 448556.689322817:                                   1    \
       cbr:                        cbr: 46 freq: 4606 MHz (159%)                   \
       0                0 [unknown] ([unknown])";
    [%expect
      {|
        ((Ok
          ((thread ((pid (2937048)) (tid (2937048)))) (time 5d4h35m56.689322817s)
           (data (Power (freq 4606)))))) |}]
  ;;

  (* Perf seems to change spacing when frequency is small and our regex was
     crashing on this case. *)
  let%expect_test "cbr event with double spaces" =
    check
      "2420596/2420596 525062.244538101:          \
       1                                        cbr:   syscall              cbr:  8 \
       freq:  801 MHz ( 28%)                   0     7f77dc9f4646 __nanosleep+0x16 \
       (/usr/lib64/libc-2.28.so)";
    [%expect
      {|
        ((Ok
          ((thread ((pid (2420596)) (tid (2420596)))) (time 6d1h51m2.244538101s)
           (data (Power (freq 801)))))) |}]
  ;;

  let%expect_test "cbr event with tr end" =
    check
      "21302/21302 82318.700445693:         1           cbr:  tr end               cbr: \
       45 freq: 4500 MHz (118%)                   0          5368e58 __symbol+0x168 \
       (/dev/foo.exe)";
    [%expect
      {|
        ((Ok
          ((thread ((pid (21302)) (tid (21302)))) (time 22h51m58.700445693s)
           (data (Power (freq 4500)))))) |}]
  ;;

  (* Expected [None] because we ignore these events currently. *)
  let%expect_test "power event psb offs" =
    check
      "2937048/2937048 448556.689403475:                             1          \
       psb:                        psb offs: 0x4be8                                0     \
       7f068fbfd330 mmap64+0x50 (/usr/lib64/ld-2.28.so)";
    [%expect {|
        () |}]
  ;;

  let%expect_test "sampled callstack" =
    check
      "2060126/2060126 178090.391624068:     555555 cycles:u:\n\
       \tffffffff97201100 [unknown] ([unknown])\n\
       \t7f9bd48c1d80 _dl_setup_hash+0x0 (/usr/lib64/ld-2.28.so)\n\
       \t7f9bd48bd18f _dl_map_object_from_fd+0xb8f (/usr/lib64/ld-2.28.so)\n\
       \t7f9bd48bf6b0 _dl_map_object+0x1e0 (/usr/lib64/ld-2.28.so)\n\
       \t7f9bd48ca184 dl_open_worker_begin+0xa4 (/usr/lib64/ld-2.28.so)\n\
       \t7f9bd44521a2 _dl_catch_exception+0x82 (/usr/lib64/libc-2.28.so)\n\
       \t7f9bd48c9ac2 dl_open_worker+0x32 (/usr/lib64/ld-2.28.so)\n\
       \t7f9bd44521a2 _dl_catch_exception+0x82 (/usr/lib64/libc-2.28.so)\n\
       \t7f9bd48c9d0c _dl_open+0xac (/usr/lib64/ld-2.28.so)\n\
       \t7f9bd46ae1e8 dlopen_doit+0x58 (/usr/lib64/libdl-2.28.so)\n\
       \t7f9bd44521a2 _dl_catch_exception+0x82 (/usr/lib64/libc-2.28.so)\n\
       \t7f9bd445225e _dl_catch_error+0x2e (/usr/lib64/libc-2.28.so)\n\
       \t7f9bd46ae964 _dlerror_run+0x64 (/usr/lib64/libdl-2.28.so)\n\
       \t7f9bd46ae285 dlopen@@GLIBC_2.2.5+0x45 (/usr/lib64/libdl-2.28.so)\n\
       \t4008de main+0x87 (/home/demo)";
    [%expect
      {|
        ((Ok
          ((thread ((pid (2060126)) (tid (2060126)))) (time 2d1h28m10.391624068s)
           (data
            (Stacktrace_sample
             (callstack
              (0x4008de 0x7f9bd46ae285 0x7f9bd46ae964 0x7f9bd445225e 0x7f9bd44521a2
               0x7f9bd46ae1e8 0x7f9bd48c9d0c 0x7f9bd44521a2 0x7f9bd48c9ac2
               0x7f9bd44521a2 0x7f9bd48ca184 0x7f9bd48bf6b0 0x7f9bd48bd18f
               0x7f9bd48c1d80 -0x68dfef00))))))) |}]
  ;;

  let%expect_test "cache-misses event with ipt" =
    check
      "3871580/3871580 430720.265503976:         50                   \
       cache-misses/period=50/u:                                      0     7fca9945c595 \
       __sleep+0x55 (/usr/lib64/libc-2.28.so)";
    [%expect
      {|
        ((Ok
          ((thread ((pid (3871580)) (tid (3871580)))) (time 4d23h38m40.265503976s)
           (data
            (Event_sample (location 0x7fca9945c595) (count 50) (name Cache_misses)))))) |}]
  ;;

  let%expect_test "cache-misses event with sampling" =
    check
      "3871580/3871580 431043.387175119:         50 cache-misses/period=50/u: \n\
       \t7fca999481a0 _dl_unmap+0x0 (/usr/lib64/ld-2.28.so)\n\
       \t7fca999454cc _dl_close_worker+0x83c (/usr/lib64/ld-2.28.so)\n\
       \t7fca99945dbd _dl_close+0x2d (/usr/lib64/ld-2.28.so)\n\
       \t7fca994cc1a2 _dl_catch_exception+0x82 (/usr/lib64/libc-2.28.so)\n\
       \t7fca994cc25e _dl_catch_error+0x2e (/usr/lib64/libc-2.28.so)\n\
       \t7fca99728964 _dlerror_run+0x64 (/usr/lib64/libdl-2.28.so)\n\
       \t7fca99728313 dlclose+0x23 (/usr/lib64/libdl-2.28.so)\n\
       \t4009b7 main+0x160 (/usr/local/home/demo)\n";
    [%expect
      {|
        ((Ok
          ((thread ((pid (3871580)) (tid (3871580)))) (time 4d23h44m3.387175119s)
           (data
            (Event_sample (location 0x7fca999481a0) (count 50) (name Cache_misses)))))) |}]
  ;;

  let%expect_test "branch-misses event with ipt" =
    check
      "3871580/3871580 431228.526799230:         50                  \
       branch-misses/period=50/u:                                      0     \
       7fca99943c60 _dl_open+0x0 (/usr/lib64/ld-2.28.so)";
    [%expect
      {|
        ((Ok
          ((thread ((pid (3871580)) (tid (3871580)))) (time 4d23h47m8.52679923s)
           (data
            (Event_sample (location 0x7fca99943c60) (count 50) (name Branch_misses)))))) |}]
  ;;

  let%expect_test "perf reports a garbage symbol offset" =
    check
      {| 25375/25375 4509191.343298468:                            1   branches:uH:   call                     7f6fce0b71f4 [unknown] (foo.so) =>     7ffd193838e0 memcpy@plt+0xffffffffff22f000 (foo.so)|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (25375)) (tid (25375)))) (time 52d4h33m11.343298468s)
           (data (Trace (kind Call) (src 0x7f6fce0b71f4) (dst 0x7ffd193838e0)))))) |}]
  ;;

  let%expect_test "tr end  async" =
    check
      {| 25375/25375 4509191.343298468:                            1   branches:uH:   tr end  async                     7f6fce0b71f4 [unknown] (foo.so) =>     0 [unknown] ([unknown])|};
    [%expect
      {|
        ((Ok
          ((thread ((pid (25375)) (tid (25375)))) (time 52d4h33m11.343298468s)
           (data
            (Trace (trace_state_change End) (kind Async) (src 0x7f6fce0b71f4)
             (dst 0x0)))))) |}]
  ;;

  let%expect_test "PEBS mem-loads event without phys_addr" =
    (* Actual perf script output format with PEBS fields *)
    check
      "1234/1234 1000.123456789:       1000 cpu_core/mem_inst_retired.all_loads,period=1000/uP:     \
       7fff12345678      80 |OP LOAD|LVL N/A|SNP N/A|TLB N/A|LCK N/A|BLK  N/A               156               0               0     7f123456 malloc+0x20 (/lib64/libc.so.6)";
    [%expect
      {|
      ((Ok
        ((thread ((pid (1234)) (tid (1234)))) (time 16m40.123456789s)
         (data
          (Event_sample (location 0x7f123456) (count 1000) (name Mem_loads)
           (pebs_data
            ((latency_cycles (156)) (data_source (Local_dram))
             (memory_address (0x7fff12345678)) (physical_address ()))))))))
      |}]
  ;;

  let%expect_test "PEBS mem-loads event with phys_addr" =
    (* Actual perf script output format with PEBS fields including phys_addr *)
    check
      "1234/1234 1000.123456789:       1000 cpu_core/mem_inst_retired.all_loads,period=1000/uP:     \
       7fff12345678      8 |OP LOAD|LVL L1|SNP N/A|TLB N/A|LCK N/A|BLK  N/A               42               0               0     7f123456 malloc+0x20 (/lib64/libc.so.6)               123456789abc";
    [%expect
      {|
      ((Ok
        ((thread ((pid (1234)) (tid (1234)))) (time 16m40.123456789s)
         (data
          (Event_sample (location 0x7f123456) (count 1000) (name Mem_loads)
           (pebs_data
            ((latency_cycles (42)) (data_source (L1_hit))
             (memory_address (0x7fff12345678)) (physical_address (0x123456789abc)))))))))
      |}]
  ;;
end

module For_testing = struct
  let to_event = to_event
  let split_line_pipe = split_line_pipe
end
