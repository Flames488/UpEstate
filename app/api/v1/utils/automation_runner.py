from services.abuse_detector import AbuseDetector, AccountLockedError


class AutomationRunner:
    """Enhanced automation runner with built-in abuse protection."""
    
    def __init__(self, user_id: int):
        self.user_id = user_id
        self.detector = AbuseDetector()
    
    def execute(self, automation_func, *args, **kwargs):
        """
        Execute automation with automatic abuse checking.
        
        Args:
            automation_func: The automation function to execute
            *args, **kwargs: Arguments for the function
            
        Returns:
            Result of the automation function
            
        Raises:
            AccountLockedError: If user is locked
            AutomationError: If automation fails
        """
        # Check access before running
        self.detector.enforce_access(self.user_id)
        
        try:
            result = automation_func(*args, **kwargs)
            return result
            
        except Exception as e:
            # Record failed automation
            self.detector.record_event(
                self.user_id,
                event_type='failed_automation',
                severity='medium'
            )
            raise AutomationError(f"Automation failed: {str(e)}")
    
    def safe_execute(self, automation_func, *args, **kwargs):
        """
        Safe execution that returns None instead of raising on lock.
        
        Returns:
            Tuple of (success: bool, result: any, error: str)
        """
        try:
            result = self.execute(automation_func, *args, **kwargs)
            return True, result, None
        except AccountLockedError as e:
            return False, None, str(e)
        except Exception as e:
            return False, None, f"Execution error: {str(e)}"


class AutomationError(Exception):
    """Exception for automation failures."""
    pass