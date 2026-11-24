import type { NativeAsset } from "./native-assets"

// Ordinary upstream/source builds resolve this module without a custom loader.
// Only the product builder replaces this exact file with pinned embedded assets.
export const assets: NativeAsset[] = []
