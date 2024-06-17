import sys
import logging
import functools

class GlobalLogger:
    """
    A class that provides logging functionality for the application.

    Attributes:
        logger: The logger instance used for logging.
        log_exec: The decorator function used to log function execution and results.
        log: The logger instance used for logging.

    Methods:
        __init__: Initializes the GlobalLogger with the specified log file.
        log_exec: Decorator function to log function execution and results.
        get_logger: Returns the logger instance.
        initialize: Initializes the GlobalLogger class with the specified log file.
    """

    def __init__(self, log_file='application.log'):
        """
        Initializes the GlobalLogger with the specified log file.

        Args:
            log_file (str): The path to the log file. Defaults to 'application.log'.
        """
        # Initialize logging with the specified format and handlers
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                            handlers=[logging.FileHandler(log_file),
                                      logging.StreamHandler(sys.stdout)])
        self.logger = logging.getLogger()

    def log_exec(self, func):
        """
        Decorator function to log function execution and results.

        Args:
            func (function): The function to be decorated.

        Returns:
            function: The decorated function.
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            self.logger.info(f"Executing {func.__name__}")
            result = func(*args, **kwargs)
            self.logger.info(f"Finished Executing {func.__name__}")
            self.logger.info(f"result is {result}")
            return result

        return wrapper

    def get_logger(self):
        """
        Returns the logger instance.

        Returns:
            logging.Logger: The logger instance.
        """
        return self.logger

    @classmethod
    def initialize(cls, log_file='application.log'):
        """
        Initializes the GlobalLogger class with the specified log file.

        Args:
            log_file (str): The path to the log file. Defaults to 'application.log'.
        """
        instance = cls(log_file)
        cls.logger = instance
        cls.log_exec = instance.log_exec
        cls.log = instance.get_logger()


# Initialize the class variables
GlobalLogger.initialize()