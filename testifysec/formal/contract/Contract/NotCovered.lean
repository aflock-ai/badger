/-
  Contract.NotCovered: what this model abstracts away or leaves out. Each item is a place a bug
  could hide that no theorem here would catch.

  Markings
    * Parsing. Banners and portion marks are parsed by `marking.Parse`/`ParseContent`; the model
      starts from the parsed struct. Token order, the character set, repeated parts, refusal of
      retired markings and unknown tokens are covered by the Go table tests, not here.
    * The token tables. One tetragraph (FVEY) is modelled; the vectors check its members against
      tokens.json. ACGU and NATO expand the same way but are not exercised.
    * `String()` rendering of a banner. A banner that dominates correctly can still print wrong.
    * Well-formedness: proofs about `Join` assume a REL TO list contains USA (`WF`), which the
      parser enforces. A hand-built struct without it is outside the theorems.
    * Display is an audience (release plus DISPLAY ONLY, expanded). Below confidential a DISPLAY
      ONLY list also restricts release to USA; that is Go's rule and the model's.
    * Result banners: a result's banner is the connector's own marking (`result_is_connector`);
      the credential check on it is an opaque predicate (`noCred`), and rendering is not modelled.
    * A join that sits above UNCLASSIFIED and below CONFIDENTIAL with FGI, atomic-energy or
      non-IC markings has no banner and is refused (decision on #224: refuse rather than
      raise to CONFIDENTIAL). A session whose join is refused delivers nothing afterwards; how the
      gateway reports that is not modelled.
    * `Join`'s other refusal, `ErrBannerTooLong` (a joined banner longer than the 512 characters
      Parse accepts), depends on the rendered banner, which is not modelled. It is the parameter
      `long`: `flowGo_no_write_down` holds for every `long`, and `joinChecked_long_only_refuses`
      shows a length refusal only removes a join and never changes one. The vectors use `noLong`,
      so a Go refusal on a vector join that the contract does not predict fails the replay.
  Flow
    * The gateway, write-tool and pushgate checks that will consume `Dominates` and `Join`
      (CONNECTORS.md) are not built. The model and the vectors fix what they must compute.
    * Where a label comes from: a connector misconfigured with too low a marking under-reports, and
      no theorem can see that.
  Admission
    * Cryptography. Signature validity is the boolean `sigValid`; the native verifier's code, its
      trust bundle format and its key handling are not modelled.
    * Executable custody: the digest pin on the native verifier, file ownership, link counts, the
      5-second timeout and the output size cap in `admit`/`verifyAdmission`.
    * Strict JSON decoding (duplicate keys, unknown fields, lossy numbers) and RFC 3339 parsing.
      The vectors use well-formed output only.
    * Time is an integer and the clock is trusted. Window boundaries are tested one hour away
      from now, never at now, because the Go code reads the wall clock.
    * Digest injectivity is a hypothesis (`asbuilt_pin_blocks_rollback`), not a fact.
    * The device high-water mark: specified (`Spec.admit`), built nowhere yet. Its vectors
      (`admissionSequence`) have no Go consumer.
  Backends (Backends.lean)
    * Certificate-chain cryptography: path building, intermediates, name and extended-key-usage
      matching are the booleans `leaf.root` and `identityOk`. No CRLs (decided); revocation of a
      signing leaf is its expiry.
    * Timestamping. Signatures are judged by the signed window against the leaf's validity, not by
      a trusted timestamp. OPEN: a platform whose leaves live minutes cannot sign a 7-day
      activation under the window-inside-the-leaf rule (`step_inside_leaf`); its artifacts would
      expire with the leaf. Either admission accepts a trusted RFC 3161 timestamp as proof the
      signature was made inside the leaf's life, or the platform issues 7-day leaves for these
      artifacts. The vector "signed window outside the leaf" fixes today's rule.
    * Device enrollment and proof of possession: enclave PKI certificates and hardware-bound keys
      are an `IdentityKind` the workstation never reads; how each is issued, attested and bound to
      the pull request is not modelled. `serve` is the only revocation property.
    * Persistence of the high-water: the state file, the first-install marker, fsync ordering and
      the TPM counter. A device administrator who deletes both state and marker falls back to the
      compiled floor; nothing here sees that.
    * Two-person approval before signing, and who holds the signing key, are backend matters the
      workstation cannot observe.
    * The migration requirement (carry the activation floor above every device's high-water) is
      an operational step on the new backend, proved necessary and sufficient here
      (`migration_restart_refused`, `migration_carried_admitted`), not enforced by anything.
  Platform
    * Publish and the API surface: see Portal.lean, a stub until the API lands.
    * Anything about a particular platform's internals. The contract is the boundary.
-/
