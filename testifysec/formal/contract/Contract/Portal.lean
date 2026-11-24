/-
  Contract.Portal: the platform side of the profile lifecycle. A STUB.

  The portal API (testifysec/PORTAL.md and testifysec/portal/api/) is being designed and is not
  committed, so nothing here cites it. What is modelled is the one rule the device contract needs
  from any platform, read from the in-flight design: the platform, never the client, assigns each
  new version of a profile its sequence, which starts at a floor compiled into the deployment's
  admission trust and strictly increases. With the device's high-water check (Spec.admit), that is
  what makes publishing a new version always admissible and replaying an old one never.

  TODO once the API is pinned, and the questions it must answer:
    1. Rollback. Is "roll back to version N" a republish of N's content as a new, higher sequence
       (the device's high-water stays monotone), or a re-pin of N's digest (which a device keeping
       a high-water mark refuses, and today's Go admits: AsBuilt `asbuilt_repin_rolls_back`)?
    2. Revocation. Is a revoked device refused where profiles are delivered, so it never receives a
       new profile? What bounds an offline revoked device other than the profile's expiry?
    3. Enrollment. What binds a device id to its tenant and deployment, and who signs the
       assignment the broker reads (today the service administrator writes it locally)?
    4. Trust. Is the portal's signing key in the trust root the native verifier holds, and how is
       it rotated?
    5. High-water. Where does a device keep its high-water sequence across restarts, and who may
       reset it? (No Go code keeps one today.)
    6. Floor. Does the native verifier enforce the minimum sequence compiled into its trust?
-/
import Contract.Spec

namespace Contract.Portal

/-- The sequence the platform assigns to the next version of a profile. -/
def nextSeq (floor : Nat) : Option Nat → Nat
  | none => floor
  | some last => max floor (last + 1)

/-- `k` publishes after `last`: the sequences assigned, in order. -/
def publish (floor : Nat) : Option Nat → Nat → List Nat
  | _, 0 => []
  | last, k + 1 => nextSeq floor last :: publish floor (some (nextSeq floor last)) k

theorem publish_above (floor : Nat) (k : Nat) :
    ∀ last, ∀ x ∈ publish floor last k, floor ≤ x ∧ ∀ l, last = some l → l < x := by
  induction k with
  | zero => intro _ _ h; exact nomatch h
  | succ k ih =>
    intro last x hx
    rcases List.mem_cons.1 hx with rfl | hx
    · cases last with
      | none => exact ⟨Nat.le_refl _, fun _ h => nomatch h⟩
      | some l =>
        refine ⟨Nat.le_max_left _ _, fun l' h => ?_⟩
        cases h; exact Nat.lt_of_lt_of_le (Nat.lt_succ_self _) (Nat.le_max_right _ _)
    · obtain ⟨h1, h2⟩ := ih _ x hx
      refine ⟨h1, fun l h => Nat.lt_trans ?_ (h2 _ rfl)⟩
      cases h
      exact Nat.lt_of_lt_of_le (Nat.lt_succ_self _) (Nat.le_max_right _ _)

/-- Published sequences strictly increase. -/
theorem publish_increasing (floor k : Nat) :
    ∀ last, (publish floor last k).Pairwise (· < ·) := by
  induction k with
  | zero => intro _; exact List.Pairwise.nil
  | succ k ih =>
    intro last
    exact List.pairwise_cons.2 ⟨fun x hx => (publish_above floor k _ x hx).2 _ rfl, ih _⟩

/-- A device that has admitted at most the last published sequence admits the next one, as far
    as the sequence goes. -/
theorem next_not_rollback (floor hw last : Nat) (h : hw ≤ last) : hw ≤ nextSeq floor (some last) :=
  Nat.le_trans h (Nat.le_trans (Nat.le_succ _) (Nat.le_max_right _ _))

end Contract.Portal
