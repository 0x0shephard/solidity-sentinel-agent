class SentinelError(Exception):
    """Base class for all Sentinel errors."""


class ConfigurationError(SentinelError):
    """Invalid runtime configuration."""


class ToolValidationError(SentinelError):
    """Tool input or output failed schema validation."""


class UnknownToolError(SentinelError):
    """Requested tool does not exist in the registry."""


class ToolExecutionError(SentinelError):
    """Tool failed during execution."""


class RetryableExternalError(SentinelError):
    """Transient external error that can be retried."""


class NonRetryableExternalError(SentinelError):
    """External error that should not be retried."""


class SandboxViolationError(SentinelError):
    """Tool attempted to access paths or commands outside its allowed scope."""


class BuildFailure(SentinelError):
    """Build or test command failed because of the target repository."""


class SubgraphIsolationError(SentinelError):
    """A subgraph received forbidden state or tools."""


class EvaluationFailure(SentinelError):
    """Evaluation harness failed."""


class RAGIndexIncompatibleError(SentinelError):
    """RAG index metadata is incompatible with the active embedding configuration."""
