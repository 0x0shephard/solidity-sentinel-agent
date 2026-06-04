from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from sentinel.schemas.static import SourceEvidence


SourceKind = Literal["regex", "static_fact", "slither", "solc_ast", "derived"]


class StateVariableIR(BaseModel):
    name: str
    type_name: str | None = None
    visibility: str | None = None
    contract_name: str | None = None
    file_path: str
    line: int | None = None
    source: SourceKind = "regex"


class ModifierIR(BaseModel):
    name: str
    contract_name: str | None = None
    file_path: str
    line: int | None = None
    source: SourceKind = "regex"


class FunctionIR(BaseModel):
    name: str
    contract_name: str | None = None
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    signature: str = ""
    visibility: str | None = None
    modifiers: list[str] = Field(default_factory=list)
    reads: list[str] = Field(default_factory=list)
    writes: list[str] = Field(default_factory=list)
    calls: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    payable: bool = False
    source: SourceKind = "regex"


class ContractIR(BaseModel):
    name: str
    file_path: str
    inherits: list[str] = Field(default_factory=list)
    functions: list[FunctionIR] = Field(default_factory=list)
    state_variables: list[StateVariableIR] = Field(default_factory=list)
    modifiers: list[ModifierIR] = Field(default_factory=list)
    source: SourceKind = "regex"


class CallEdge(BaseModel):
    from_contract: str | None = None
    from_function: str | None = None
    to_contract: str | None = None
    to_function: str | None = None
    receiver_symbol: str | None = None
    file_path: str
    line: int | None = None
    expression: str
    call_kind: Literal["internal", "external", "low_level", "delegatecall", "unknown"] = "unknown"
    source: SourceKind = "derived"


class StorageAccess(BaseModel):
    contract_name: str | None = None
    function_name: str | None = None
    variable_name: str
    access: Literal["read", "write"]
    file_path: str
    line: int | None = None
    expression: str
    source: SourceKind = "derived"


class AssetFlow(BaseModel):
    contract_name: str | None = None
    function_name: str | None = None
    asset_symbol: str | None = None
    asset_kind: Literal["erc20", "erc721", "erc1155", "native", "unknown"] = "unknown"
    from_expr: str | None = None
    to_expr: str | None = None
    amount_expr: str | None = None
    file_path: str
    line: int | None = None
    expression: str
    source: SourceKind = "derived"


class AuthConstraint(BaseModel):
    contract_name: str | None = None
    function_name: str | None = None
    role: str | None = None
    expression: str
    file_path: str
    line: int | None = None
    source: SourceKind = "derived"


class LifecycleTransition(BaseModel):
    contract_name: str | None = None
    function_name: str | None = None
    transition: str
    state_variables: list[str] = Field(default_factory=list)
    file_path: str
    line: int | None = None
    expression: str
    source: SourceKind = "derived"


class TrustBoundary(BaseModel):
    contract_name: str | None = None
    function_name: str | None = None
    boundary_kind: Literal["external_call", "delegatecall", "asset_transfer", "oracle_read", "untrusted_input"] = "external_call"
    expression: str
    file_path: str
    line: int | None = None
    source: SourceKind = "derived"


class ProtocolIR(BaseModel):
    repo_path: str
    contracts: list[ContractIR] = Field(default_factory=list)
    call_edges: list[CallEdge] = Field(default_factory=list)
    storage_accesses: list[StorageAccess] = Field(default_factory=list)
    asset_flows: list[AssetFlow] = Field(default_factory=list)
    auth_constraints: list[AuthConstraint] = Field(default_factory=list)
    lifecycle_transitions: list[LifecycleTransition] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    completeness_gaps: list[str] = Field(default_factory=list)
    source: SourceKind = "derived"

    def contract_names(self) -> list[str]:
        return [contract.name for contract in self.contracts]

    def function_names(self) -> list[str]:
        seen: list[str] = []
        for contract in self.contracts:
            for function in contract.functions:
                if function.name not in seen:
                    seen.append(function.name)
        return seen


class IRCompletenessReport(BaseModel):
    source_mode: Literal["slither", "solc_ast", "regex_fallback"] = "regex_fallback"
    missing_capabilities: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class GraphSlice(BaseModel):
    slice_id: str
    entry_contract: str | None = None
    entry_function: str | None = None
    entry_file: str
    entry_line: int | None = None
    reachable_functions: list[str] = Field(default_factory=list)
    call_edges: list[CallEdge] = Field(default_factory=list)
    storage_accesses: list[StorageAccess] = Field(default_factory=list)
    asset_flows: list[AssetFlow] = Field(default_factory=list)
    auth_constraints: list[AuthConstraint] = Field(default_factory=list)
    lifecycle_transitions: list[LifecycleTransition] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    evidence: list[SourceEvidence] = Field(default_factory=list)
    proof_status: Literal[
        "static_proof_complete",
        "strong_local_path",
        "missing_counterevidence",
        "setup_required",
        "rejected_by_counterevidence",
    ] = "setup_required"
    missing_proof: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)


class AttackPathCandidate(BaseModel):
    attack_path_id: str
    invariant_family: str
    graph_slice_id: str
    summary: str
    proof_status: Literal[
        "static_proof_complete",
        "strong_local_path",
        "missing_counterevidence",
        "setup_required",
        "rejected_by_counterevidence",
    ] = "setup_required"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ProtocolGraph(BaseModel):
    repo_path: str
    slices: list[GraphSlice] = Field(default_factory=list)
    attack_paths: list[AttackPathCandidate] = Field(default_factory=list)
    completeness: IRCompletenessReport = Field(default_factory=IRCompletenessReport)
