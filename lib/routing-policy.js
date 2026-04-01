'use strict'

/**
 * Interface- and peer-scoped routing policy (ingress / egress × capability flags).
 * Presets `fullTunnel` and `relay` set both directions; callers can merge finer patches later.
 *
 * Runtime today (primary direct pool in the web control plane): **egress.fullTunnel** applies
 * client split routes (see `full-tunnel`). **ingress.fullTunnel** applies server forwarding + NAT
 * for the pool subnet when at least one such peer has a live stream. Topic interfaces store policy
 * only. Relay flags are stored for future Hyperswarm / signaling work.
 */

/** @returns {import('./routing-policy').RoutingSidePolicy} */
function emptySide () {
  return { fullTunnel: false, relay: false }
}

/** @returns {import('./routing-policy').RoutingInterfacePolicy} */
function createInterfacePolicy () {
  return {
    ingress: emptySide(),
    egress: emptySide()
  }
}

/** @type {Record<string, RoutingInterfacePolicy>} */
const PRESETS = {
  none: createInterfacePolicy(),
  fullTunnel: {
    ingress: { fullTunnel: true, relay: false },
    egress: { fullTunnel: true, relay: false }
  },
  relay: {
    ingress: { fullTunnel: false, relay: true },
    egress: { fullTunnel: false, relay: true }
  }
}

/**
 * @typedef {{ fullTunnel: boolean, relay: boolean }} RoutingSidePolicy
 * @typedef {{ ingress: RoutingSidePolicy, egress: RoutingSidePolicy }} RoutingInterfacePolicy
 */

/**
 * @param {RoutingInterfacePolicy} p
 * @returns {RoutingInterfacePolicy}
 */
function clonePolicy (p) {
  return {
    ingress: { ...p.ingress },
    egress: { ...p.egress }
  }
}

/**
 * @param {RoutingSidePolicy} base
 * @param {Partial<RoutingSidePolicy> | undefined} patch
 */
function mergeSide (base, patch) {
  if (!patch) return { ...base }
  return {
    fullTunnel: patch.fullTunnel !== undefined ? Boolean(patch.fullTunnel) : base.fullTunnel,
    relay: patch.relay !== undefined ? Boolean(patch.relay) : base.relay
  }
}

/**
 * @param {RoutingInterfacePolicy} base
 * @param {Partial<{ ingress: Partial<RoutingSidePolicy>, egress: Partial<RoutingSidePolicy> }> | null | undefined} patch
 * @returns {RoutingInterfacePolicy}
 */
function mergeInterfacePatch (base, patch) {
  if (!patch) return clonePolicy(base)
  return {
    ingress: mergeSide(base.ingress, patch.ingress),
    egress: mergeSide(base.egress, patch.egress)
  }
}

/**
 * @param {RoutingInterfacePolicy} ifaceDefaults
 * @param {Partial<{ ingress: Partial<RoutingSidePolicy>, egress: Partial<RoutingSidePolicy> }> | null | undefined} peerPatch
 * @returns {RoutingInterfacePolicy}
 */
function resolvePeerPolicy (ifaceDefaults, peerPatch) {
  return mergeInterfacePatch(ifaceDefaults, peerPatch || undefined)
}

/**
 * @param {string} name
 * @returns {RoutingInterfacePolicy}
 */
function presetPolicy (name) {
  const n = String(name || '').toLowerCase()
  if (n === 'fulltunnel' || n === 'full_tunnel') return clonePolicy(PRESETS.fullTunnel)
  if (n === 'relay') return clonePolicy(PRESETS.relay)
  if (n === 'none' || n === '') return clonePolicy(PRESETS.none)
  throw new Error(`Unknown policy preset: ${name}`)
}

/**
 * @param {unknown} body
 * @returns {{ preset?: string, patch?: Partial<{ ingress: Partial<RoutingSidePolicy>, egress: Partial<RoutingSidePolicy> }> }}
 */
function parsePolicyUpdateBody (body) {
  if (!body || typeof body !== 'object') return {}
  const o = /** @type {Record<string, unknown>} */ (body)
  const preset = typeof o.preset === 'string' ? o.preset : undefined
  const patch =
    o.ingress != null || o.egress != null
      ? {
          ingress: o.ingress && typeof o.ingress === 'object' ? /** @type {Partial<RoutingSidePolicy>} */ (o.ingress) : undefined,
          egress: o.egress && typeof o.egress === 'object' ? /** @type {Partial<RoutingSidePolicy>} */ (o.egress) : undefined
        }
      : undefined
  return { preset, patch }
}

/**
 * Apply preset then optional patch.
 * @param {RoutingInterfacePolicy} current
 * @param {unknown} body
 * @returns {RoutingInterfacePolicy}
 */
function applyPolicyUpdate (current, body) {
  const { preset, patch } = parsePolicyUpdateBody(body)
  let next = preset ? presetPolicy(preset) : clonePolicy(current)
  if (patch) next = mergeInterfacePatch(next, patch)
  return next
}

/**
 * Merge sparse peer-level overrides (only keys the client set). Does not add false defaults.
 * @param {Record<string, unknown> | null | undefined} prev
 * @param {Partial<{ ingress: Partial<RoutingSidePolicy>, egress: Partial<RoutingSidePolicy> }> | undefined} patch
 */
function accumulatePeerPatch (prev, patch) {
  const p = prev && typeof prev === 'object' ? prev : {}
  if (!patch) return { ...p }
  const out = { ...p, ingress: { ...p.ingress }, egress: { ...p.egress } }
  if (patch.ingress) out.ingress = { ...out.ingress, ...patch.ingress }
  if (patch.egress) out.egress = { ...out.egress, ...patch.egress }
  return out
}

module.exports = {
  PRESETS,
  createInterfacePolicy,
  clonePolicy,
  mergeInterfacePatch,
  resolvePeerPolicy,
  presetPolicy,
  parsePolicyUpdateBody,
  applyPolicyUpdate,
  accumulatePeerPatch
}
