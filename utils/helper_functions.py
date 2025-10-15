from utils.logger import Logger
from utils.exception_handler import ExceptionHandler
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

from datetime import datetime

import string
import re

class HelperFunctions:
    logger = Logger(create_log_file=False)
    
    @staticmethod
    def get_today_date_yyyymmdd():
        return datetime.today().strftime('%Y%m%d')

    @staticmethod
    def get_lbu_name_simple(app_name):
        """
        Extracts the LBU name directly after 'pru-' in the given project_name.
        Does not validate against any JSON list.
        """
        match = re.search(r'^pru-([\w]+)', app_name, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        
        return "Pru"

    @staticmethod
    def is_readable(text):
        # Check if all characters in a string are readable (printable)
        if all(char in string.printable for char in text):
            return True
        return False
    
    @staticmethod
    def get_nested(data, keys, default=None):
        """
        Safely access nested dictionary keys.
        
        :param data: The dictionary to traverse.
        :param keys: A list of keys representing the path.
        :param default: Value to return if any key is missing.
        :return: The value at the nested key or default.
        """
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key, default)
            else:
                return default
        return data
    
    @staticmethod
    def shorten_strings_middle(s, front=6, back=4):
        return s if len(s) <= (front + back) else s[:front] + "..." + s[-back:]
    
    @staticmethod
    @ExceptionHandler.handle_exception_with_retries(logger=logger)
    def get_future_date(time_text: str) -> str:
        # Get current UTC datetime
        now = datetime.utcnow()

        # Normalize input text
        time_text = time_text.strip().lower()

        # Extract numeric value
        parts = time_text.split()
        if len(parts) < 2:
            raise ValueError("Input must include both number and unit (e.g., '15 days')")

        try:
            number = int(parts[0])
        except ValueError:
            raise ValueError("The first part must be a number (e.g., '15 days')")

        unit = parts[1]
        
        # Compute based on unit
        if "day" in unit:
            future_date = now + timedelta(days=number)
        elif "week" in unit:
            future_date = now + timedelta(weeks=number)
        elif "month" in unit:
            future_date = now + relativedelta(months=number)
        else:
            raise ValueError("Unsupported time unit. Use 'days', 'weeks', or 'months'.")

        # Return ISO 8601 format with milliseconds and 'Z'
        return future_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

