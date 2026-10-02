import Base

# Admission is pure: an operator grant and a bounded reply depth.
def within(hop: Nat, fuel: Nat) -> Bool:
  match hop:
    case 0n:
      True{}
    case 1n+h:
      match fuel:
        case 0n:
          False{}
        case 1n+f:
          within(h, f)

def admit(granted: Bool, hop: Nat) -> Bool:
  match granted:
    case False{}:
      False{}
    case True{}:
      within(hop, 6n)

def show(decision: Bool) -> IO(Unit):
  match decision:
    case True{}:
      IO.print("allow")
    case False{}:
      IO.print("deny")

def parse(grant: String, hop: Maybe<&2, Nat>) -> IO(Unit):
  match hop:
    case None{}:
      IO.print("deny")
    case Some{h}:
      show(admit(String.eq(grant, "yes"), h))

def main() -> IO(Unit):
  do IO<Unit>:
    grant : String <- IO.try(String, IO.get_env("RELAY_GRANTED"))
    hop : String <- IO.try(String, IO.get_env("RELAY_HOP"))
    parse(grant, Nat.read(hop))
