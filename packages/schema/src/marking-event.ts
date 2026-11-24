export * as MarkingEvent from "./marking-event.js"

import { Schema } from "effect"
import { Event } from "./event.js"

/**
 * This workspace's label rose: a connector call was allowed that lifts it. `label` is the new label
 * as a banner in the deployment's scheme. A client reads the server's marking again on it rather
 * than trust a value carried by an event it may have missed others of.
 */
export const LabelRaised = Event.ephemeral({
  type: "marking.label.raised",
  schema: {
    label: Schema.String,
  },
})

export const Definitions = Event.inventory(LabelRaised)
