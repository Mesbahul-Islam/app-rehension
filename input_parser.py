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
    
    def __init__(self, virustotal_api=None):
        """
        Initialize the parser with optional VirusTotal API client.
        
        Args:
            virustotal_api: VirusTotalAPI instance for hash lookups
        """
        self.virustotal_api = virustotal_api
    
    @staticmethod
    def is_sha1(text: str) -> bool:
        """Check if input is a SHA1 hash (40 hex characters)."""
        text = text.strip()
        return bool(re.match(r'^[a-fA-F0-9]{40}$', text))
    
    def parse_input(self, input_text: str) -> Dict[str, Optional[str]]:
        """
        Parse input and return structured data.
        
        Returns:
            {
                'input_type': 'sha1' | 'product' | 'vendor_product',
                'product_name': str or None,
                'vendor': str or None,
                'sha1': str or None,
                'raw_input': str,
                'virustotal_data': dict or None  # If SHA1 lookup was performed
            }
        """
        input_text = input_text.strip()
        
        # Check if SHA1 hash
        if InputParser.is_sha1(input_text):
            result = {
                'input_type': 'sha1',
                'product_name': None,
                'vendor': None,
                'sha1': input_text.lower(),
                'raw_input': input_text,
                'virustotal_data': None
            }
            
            # If VirusTotal API is available, perform lookup
            if self.virustotal_api:

                vt_data = self.virustotal_api.lookup_hash(input_text)
                
                if vt_data:
                    result['virustotal_data'] = vt_data
                    result['product_name'] = vt_data.get('product')
                    result['vendor'] = vt_data.get('vendor')
                else:
                    pass
            
            return result
        
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
                        'raw_input': input_text,
                        'virustotal_data': None
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
                    'raw_input': input_text,
                    'virustotal_data': None
                }
        
        # Default: treat as product name only
        return {
            'input_type': 'product',
            'product_name': input_text,
            'vendor': None,
            'sha1': None,
            'raw_input': input_text,
            'virustotal_data': None
        }
    
    def format_for_assessment(self, parsed_input: Dict) -> Dict[str, Optional[str]]:
        """
        Convert parsed input to format expected by SecurityAssessor.
        
        Returns:
            {
                'product_name': str,
                'vendor': str or None,
                'virustotal_data': dict or None
            }
        """
        if parsed_input['input_type'] == 'sha1':
            # If VirusTotal lookup was successful, use that data
            if parsed_input.get('virustotal_data'):
                vt_data = parsed_input['virustotal_data']
                return {
                    'product_name': parsed_input['product_name'] or vt_data.get('primary_name', f"[SHA1: {parsed_input['sha1'][:8]}...]"),
                    'vendor': parsed_input['vendor'],
                    'sha1': parsed_input['sha1'],
                    'virustotal_data': vt_data
                }
            else:
                # No VirusTotal data available
                return {
                    'product_name': f"[SHA1: {parsed_input['sha1'][:8]}...]",
                    'vendor': None,
                    'sha1': parsed_input['sha1'],
                    'virustotal_data': None
                }
        
        return {
            'product_name': parsed_input['product_name'],
            'vendor': parsed_input['vendor'],
            'sha1': parsed_input.get('sha1'),
            'virustotal_data': parsed_input.get('virustotal_data')
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
