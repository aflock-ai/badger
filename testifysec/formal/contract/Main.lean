import Contract.Vectors

/-- `contract-vectors`: print the conformance vectors (vectors/contract-vectors.json). -/
def main : IO UInt32 := do
  if !Contract.Vectors.flowSound then
    IO.eprintln "contract-vectors: the Go composition allows a send the contract denies"
    return 1
  if !Contract.Vectors.backendsAgree then
    IO.eprintln "contract-vectors: the portal and the platform disagree on a backend case"
    return 1
  IO.print Contract.Vectors.document
  return 0
