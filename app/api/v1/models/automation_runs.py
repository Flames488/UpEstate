"""
Runaway Loop Detection and Prevention System

Critical safety mechanism to prevent:
- Recursive automation chains
- Trigger cascades
- Logic bugs causing infinite loops
- Uncontrolled cloud costs from runaway processes
"""

from __future__ import annotations
import logging
import signal
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

Base = declarative_base()
logger = logging.getLogger(__name__)


class RunStatus(str, Enum):
    """Automation run status enumeration."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    LOOP_DETECTED = "LOOP_DETECTED"


class AutomationRun(Base):
    """Model for tracking automation executions with depth monitoring."""
    __tablename__ = "automation_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    automation_id = Column(String(36), nullable=False, index=True)
    trigger_id = Column(String(36), nullable=True, index=True)
    parent_run_id = Column(String(36), nullable=True, index=True)
    
    # Loop detection metrics
    run_depth = Column(Integer, default=0, nullable=False)
    execution_path = Column(String(500), default="", nullable=False)  # For debugging
    
    # Execution metadata
    status = Column(String(20), default=RunStatus.PENDING.value, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    timeout_seconds = Column(Integer, default=30, nullable=False)
    
    # Safety flags
    is_safety_checked = Column(Boolean, default=False, nullable=False)
    loop_detected = Column(Boolean, default=False, nullable=False)
    
    # Performance metrics
    total_child_runs = Column(Integer, default=0, nullable=False)


@dataclass
class RunContext:
    """Context container for automation execution with safety controls."""
    run_id: UUID
    automation_id: UUID
    parent_run_id: Optional[UUID] = None
    depth: int = 0
    execution_path: str = ""
    timeout_seconds: int = 30


class RunawayLoopException(Exception):
    """Raised when a potential infinite loop is detected."""
    pass


class AutomationTimeoutException(Exception):
    """Raised when an automation exceeds its time limit."""
    pass


class LoopDetector:
    """
    Safety controller for preventing recursive automations and trigger chains.
    
    Implements multiple layers of protection:
    1. Depth-based chain detection
    2. Timeout protection
    3. Execution path tracking
    4. Rate limiting integration
    """
    
    # Safety thresholds (configurable)
    MAX_RUN_DEPTH = 5
    MAX_TIMEOUT_SECONDS = 120
    MAX_CHILDREN_PER_RUN = 20
    
    def __init__(self, db_session: Session):
        self.db_session = db_session
        self._timeout_registry: Dict[UUID, int] = {}
        
    def create_run_context(
        self,
        automation_id: UUID,
        parent_run_id: Optional[UUID] = None,
        trigger_id: Optional[UUID] = None
    ) -> RunContext:
        """
        Create a new execution context with loop detection safeguards.
        
        Args:
            automation_id: ID of the automation being executed
            parent_run_id: Optional parent run ID for chain tracking
            trigger_id: Optional trigger that initiated this run
            
        Returns:
            RunContext configured with safety parameters
        """
        # Check if parent exists and get its depth
        depth = 0
        execution_path = str(automation_id)
        
        if parent_run_id:
            parent_run = self._get_run(parent_run_id)
            if parent_run:
                depth = parent_run.run_depth + 1
                execution_path = f"{parent_run.execution_path} -> {automation_id}"
                
                # Check child creation rate
                if parent_run.total_child_runs >= self.MAX_CHILDREN_PER_RUN:
                    raise RunawayLoopException(
                        f"Automation {parent_run.automation_id} created too many "
                        f"children ({parent_run.total_child_runs})"
                    )
        
        # Create the run record
        run = AutomationRun(
            automation_id=str(automation_id),
            trigger_id=str(trigger_id) if trigger_id else None,
            parent_run_id=str(parent_run_id) if parent_run_id else None,
            run_depth=depth,
            execution_path=execution_path,
            status=RunStatus.PENDING.value
        )
        
        self.db_session.add(run)
        self.db_session.commit()
        
        return RunContext(
            run_id=UUID(run.id),
            automation_id=automation_id,
            parent_run_id=parent_run_id,
            depth=depth,
            execution_path=execution_path,
            timeout_seconds=run.timeout_seconds
        )
    
    def validate_execution_safety(self, context: RunContext) -> None:
        """
        Perform all safety checks before allowing automation execution.
        
        Raises:
            RunawayLoopException: If any safety check fails
        """
        run = self._get_run(context.run_id)
        if not run:
            raise ValueError(f"Run {context.run_id} not found")
        
        # 1. Depth chain protection
        if run.run_depth > self.MAX_RUN_DEPTH:
            self._mark_as_loop_detected(run, f"Maximum depth {self.MAX_RUN_DEPTH} exceeded")
            raise RunawayLoopException(
                f"Automation chain too deep (depth: {run.run_depth}). "
                f"Execution path: {run.execution_path}"
            )
        
        # 2. Circular reference detection
        if self._has_circular_reference(run):
            self._mark_as_loop_detected(run, "Circular reference detected")
            raise RunawayLoopException(
                f"Circular reference detected in execution chain. "
                f"Path: {run.execution_path}"
            )
        
        # 3. Timeout validation
        if run.timeout_seconds > self.MAX_TIMEOUT_SECONDS:
            logger.warning(
                f"Run {run.id} timeout {run.timeout_seconds}s exceeds maximum, "
                f"capping to {self.MAX_TIMEOUT_SECONDS}s"
            )
            run.timeout_seconds = self.MAX_TIMEOUT_SECONDS
        
        run.is_safety_checked = True
        run.status = RunStatus.RUNNING.value
        self.db_session.commit()
    
    @contextmanager
    def execution_timeout(self, context: RunContext):
        """
        Context manager for enforcing execution time limits.
        
        Usage:
            with detector.execution_timeout(context):
                execute_automation()
        """
        def timeout_handler(signum, frame):
            raise AutomationTimeoutException(
                f"Automation {context.automation_id} timed out after "
                f"{context.timeout_seconds} seconds"
            )
        
        # Set timeout alarm
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(context.timeout_seconds)
        
        try:
            yield
        except AutomationTimeoutException:
            self._mark_as_timed_out(context.run_id)
            raise
        finally:
            # Disable the alarm
            signal.alarm(0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
    
    def complete_run(self, run_id: UUID, success: bool = True) -> None:
        """Mark a run as completed successfully or failed."""
        run = self._get_run(run_id)
        if run:
            if success:
                run.status = RunStatus.COMPLETED.value
            else:
                run.status = RunStatus.FAILED.value
            run.completed_at = datetime.utcnow()
            
            # Update parent's child count if applicable
            if run.parent_run_id:
                parent = self._get_run(UUID(run.parent_run_id))
                if parent:
                    parent.total_child_runs += 1
            
            self.db_session.commit()
    
    def _get_run(self, run_id: UUID) -> Optional[AutomationRun]:
        """Retrieve a run by ID."""
        return self.db_session.query(AutomationRun).filter_by(id=str(run_id)).first()
    
    def _has_circular_reference(self, run: AutomationRun) -> bool:
        """Detect if this run creates a circular reference chain."""
        if not run.parent_run_id:
            return False
        
        # Walk up the chain looking for duplicates
        visited = {str(run.automation_id)}
        current_id = run.parent_run_id
        
        while current_id:
            parent = self._get_run(UUID(current_id))
            if not parent:
                break
            
            # Check if we've seen this automation before in the chain
            if str(parent.automation_id) in visited:
                return True
            
            visited.add(str(parent.automation_id))
            current_id = parent.parent_run_id
        
        return False
    
    def _mark_as_loop_detected(self, run: AutomationRun, reason: str) -> None:
        """Mark a run as failed due to loop detection."""
        run.status = RunStatus.LOOP_DETECTED.value
        run.loop_detected = True
        run.completed_at = datetime.utcnow()
        logger.error(
            f"Runaway loop detected for run {run.id}: {reason}. "
            f"Execution path: {run.execution_path}"
        )
        self.db_session.commit()
    
    def _mark_as_timed_out(self, run_id: UUID) -> None:
        """Mark a run as timed out."""
        run = self._get_run(run_id)
        if run:
            run.status = RunStatus.TIMED_OUT.value
            run.completed_at = datetime.utcnow()
            self.db_session.commit()


# Example usage in automation execution
def execute_automation_with_safety(
    detector: LoopDetector,
    automation_id: UUID,
    parent_run_id: Optional[UUID] = None,
    trigger_id: Optional[UUID] = None
) -> Dict[str, Any]:
    """
    Safe wrapper for executing automations with built-in loop prevention.
    
    Returns:
        Dict with execution results or error information
    """
    try:
        # 1. Create context with safety tracking
        context = detector.create_run_context(
            automation_id=automation_id,
            parent_run_id=parent_run_id,
            trigger_id=trigger_id
        )
        
        # 2. Validate all safety constraints
        detector.validate_execution_safety(context)
        
        # 3. Execute with timeout protection
        with detector.execution_timeout(context):
            # Your automation logic here
            result = _execute_automation_logic(context)
            
            # 4. Mark as completed successfully
            detector.complete_run(context.run_id, success=True)
            
            return {
                "success": True,
                "run_id": context.run_id,
                "depth": context.depth,
                "result": result
            }
            
    except RunawayLoopException as e:
        logger.critical(f"Runaway loop prevented: {e}")
        return {
            "success": False,
            "error": "runaway_loop_detected",
            "message": str(e),
            "critical": True
        }
    except AutomationTimeoutException as e:
        logger.warning(f"Automation timeout: {e}")
        return {
            "success": False,
            "error": "execution_timeout",
            "message": str(e)
        }
    except Exception as e:
        logger.exception(f"Automation execution failed: {e}")
        if 'context' in locals():
            detector.complete_run(context.run_id, success=False)
        return {
            "success": False,
            "error": "execution_failed",
            "message": str(e)
        }


def _execute_automation_logic(context: RunContext) -> Any:
    """
    Your actual automation implementation goes here.
    This is just a placeholder.
    """
    # Implement your automation business logic
    # This function runs within the safety context
    pass


# Configuration constants for easy tuning
SAFETY_CONFIG = {
    "MAX_RUN_DEPTH": 5,           # Maximum allowed chain depth
    "MAX_TIMEOUT_SECONDS": 30,    # Default execution timeout
    "MAX_CHILDREN_PER_RUN": 20,   # Prevent explosion of child processes
    "ENABLE_TIMEOUT": True,       # Master switch for timeout protection
    "ENABLE_DEPTH_CHECK": True,   # Master switch for depth checking
}