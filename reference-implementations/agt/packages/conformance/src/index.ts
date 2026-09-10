export {
  AGT_POINTS,
  AGT_VERDICTS,
  everyCell,
  type CellStatus,
  type CoverageCell,
  type CoverageMatrix,
  type MappingTable,
} from "./cells.ts";
export { diffSurfaces, type SurfaceDiff } from "./diff-surfaces.ts";
export { resolveExitCode } from "./exit-code.ts";
export { checkDenyFailsClosed } from "./failure-domains.ts";
export { fetchUpstreamSurfaces, UPSTREAM_AGT_CLONE_ENV } from "./fetch-upstream.ts";
export {
  canonicalIdentity,
  checkEnforcedBinding,
  checkInputIdentity,
  coverageCellsFromIdentity,
  measureIdentity,
  type EnforcedBindingCheck,
  type IdentityFinding,
  type InputIdentityCheck,
} from "./identity.ts";
export {
  checkInterventionPoints,
  coverageCellsFromInterventionPoints,
  type PointRoundTrip,
} from "./intervention-points.ts";
export { mergeCells } from "./merge-cells.ts";
export { checkPolicyInputSchema, PINNED_AGT_CLONE_ENV, type SchemaLegResult } from "./policy-input-schema.ts";
export { renderCoverageMatrix, renderMappingTable, renderTraceRows, type RenderOptions } from "./render.ts";
export { renderUpstreamDiff } from "./render-upstream-diff.ts";
export {
  asPinned,
  asUpstream,
  readSurfaces,
  SURFACE_NAMES,
  type PinnedSurfaces,
  type SurfaceName,
  type SurfaceSnapshot,
  type UpstreamSurfaces,
} from "./surfaces.ts";
export { checkToolsAgainstRegistry, renderToolsRegistryReport, type UnregisteredTool } from "./tools-registry.ts";
export { checkTracePillar, type TraceRow } from "./trace-pillar.ts";
export { checkVerdicts, invertVerdicts } from "./verdicts.ts";
