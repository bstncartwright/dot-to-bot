import Base
import ./bend/policy.bend as Policy

law no_grant_no_send:
  for hop: Nat
  {Policy.admit(False{}, hop) == False{} : Bool}

law exhausted_depth:
  for tail: Nat
  {Policy.within(1n+tail, 0n) == False{} : Bool}

law seven_hops_rejected:
  for tail: Nat
  {Policy.admit(True{}, 7n+tail) == False{} : Bool}
