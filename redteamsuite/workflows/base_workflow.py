from __future__ import annotations

from abc import ABC, abstractmethod

from redteamsuite.core.context import TargetContext


class BaseWorkflow(ABC):
    def __init__(self, ctx: TargetContext):
        self.ctx = ctx

    @abstractmethod
    def run(self) -> None:
        raise NotImplementedError
