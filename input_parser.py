"""
Input parser to handle various input formats:
- Product name only: "Slack"
- Company + Product: "Slack Technologies Inc., Slack"
- SHA1 hash: "f53f36c766c615f665dd00de30dc12d2ed4195b9"
"""
import re
from typing import Dict, Optional


class InputParser:
    """Parse and normalize various input formats."""
    
    @staticmethod
    def is_sha1(text: str) -> bool:
        """Check if input is a SHA1 hash (40 hex characters)."""
        text = text.strip()
        return bool(re.match(r'^[a-fA-F0-9]{40}$', text))
    
    @staticmethod
    def parse_input(input_text: str) -> Dict[str, Optional[str]]:
        """
        Parse input and return structured data.
        
        Returns:
            {
                'input_type': 'sha1' | 'product' | 'vendor_product',
                'product_name': str or None,
                'vendor': str or None,
                'sha1': str or None,
                'raw_input': str
            }
        """
        input_text = input_text.strip()
        
        # Check if SHA1 hash
        if InputParser.is_sha1(input_text):
            return {
                'input_type': 'sha1',
                'product_name': None,
                'vendor': None,
                'sha1': input_text.lower(),
                'raw_input': input_text
            }
        
        # Check if contains comma (likely vendor, product format)
        if ',' in input_text:
            # Handle CSV-style format: "Vendor Name", Product or Vendor, Product
            # Try to parse as CSV first (handles quoted strings)
            import csv
            import io
            try:
                reader = csv.reader(io.StringIO(input_text))
                parts = next(reader)
                if len(parts) >= 2:
                    vendor = parts[0].strip()
                    product = parts[1].strip()
                    return {
                        'input_type': 'vendor_product',
                        'product_name': product,
                        'vendor': vendor,
                        'sha1': None,
                        'raw_input': input_text
                    }
            except:
                pass
            
            # Fallback: simple comma split
            parts = [p.strip() for p in input_text.rsplit(',', 1)]  # Split from right to handle vendor commas
            if len(parts) == 2:
                vendor, product = parts
                return {
                    'input_type': 'vendor_product',
                    'product_name': product,
                    'vendor': vendor,
                    'sha1': None,
                    'raw_input': input_text
                }
        
        # Default: treat as product name only
        return {
            'input_type': 'product',
            'product_name': input_text,
            'vendor': None,
            'sha1': None,
            'raw_input': input_text
        }
    
    @staticmethod
    def format_for_assessment(parsed_input: Dict) -> Dict[str, Optional[str]]:
        """
        Convert parsed input to format expected by SecurityAssessor.
        
        Returns:
            {
                'product_name': str,
                'vendor': str or None
            }
        """
        if parsed_input['input_type'] == 'sha1':
            # For SHA1, we need to look up the product/vendor from a dataset
            # For now, return sha1 as product_name with note
            return {
                'product_name': f"[SHA1: {parsed_input['sha1'][:8]}...]",
                'vendor': None,
                'sha1': parsed_input['sha1']
            }
        
        return {
            'product_name': parsed_input['product_name'],
            'vendor': parsed_input['vendor'],
            'sha1': None
        }


# Example usage and tests
if __name__ == "__main__":
    parser = InputParser()
    
    test_inputs = [
        "Slack",
        "Slack Technologies Inc., Slack",
        "f53f36c766c615f665dd00de30dc12d2ed4195b9",
        "1Password",
        "GoTo Group, Inc., LastPass",
        "ä¸­æ–‡äº§å",  # Chinese characters
    ]
    
    print("Input Parser Test Results:")
    print("=" * 60)
    for inp in test_inputs:
        result = parser.parse_input(inp)
        print(f"\nInput: {inp}")
        print(f"Type: {result['input_type']}")
        print(f"Product: {result['product_name']}")
        print(f"Vendor: {result['vendor']}")
        print(f"SHA1: {result['sha1']}")
