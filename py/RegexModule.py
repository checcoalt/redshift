import re

class RegexModule:
    def __init__(self, pattern):
        self.pattern = pattern
    
    def is_valid(self):
        """Check if the regular expression is valid."""
        try:
            # Try compiling the regular expression
            re.compile(self.pattern)
            return True
        except re.error:
            # If an error occurs, the regular expression is invalid
            return False

    def test_match(self, text):
        """Check if the regular expression finds a match in the text."""
        if not self.is_valid():
            return "The regular expression is not valid."
        
        # Use the regular expression to search for a match in the text
        match = re.search(self.pattern, text)
        return True if match else False
