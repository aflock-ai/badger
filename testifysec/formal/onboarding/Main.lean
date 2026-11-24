import Onboarding.Vectors

/-- `onboarding-vectors`: print the conformance vectors (vectors/onboarding-vectors.json). -/
def main : IO UInt32 := do
  if !Onboarding.Vectors.finalStatesSound then
    IO.eprintln "onboarding-vectors: a trace ends in a state that breaks a proved invariant"
    return 1
  if !Onboarding.Vectors.auditSound then
    IO.eprintln "onboarding-vectors: a step appended the wrong number of audit records"
    return 1
  IO.print Onboarding.Vectors.document
  return 0
