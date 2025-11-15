"""
Example script demonstrating how to use the Security Assessor programmatically
"""
import json
import logging
from config import Config
from assessor import SecurityAssessor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    """Run example assessments"""
    
    print("🛡️  Security Assessor - Example Usage")
    print("=" * 50)
    print()
    
    # Check if API key is configured
    if not Config.GEMINI_API_KEY or Config.GEMINI_API_KEY == 'your_gemini_api_key_here':
        print("❌ ERROR: GEMINI_API_KEY not configured")
        print("Please add your Gemini API key to the .env file")
        print("Get your key from: https://makersuite.google.com/app/apikey")
        return
    
    # Initialize assessor
    print("Initializing Security Assessor...")
    assessor = SecurityAssessor(Config)
    print("✓ Assessor initialized\n")
    
    # Example products to assess
    products = [
        "Slack",
        "Microsoft Teams",
        "Zoom"
    ]
    
    # Run assessments
    for product in products:
        print(f"\n{'='*50}")
        print(f"Assessing: {product}")
        print('='*50)
        
        try:
            # Run assessment (use_cache=True to reuse previous results if available)
            assessment = assessor.assess_product(product, use_cache=True)
            
            # Display key results
            print(f"\n📊 Results for {assessment['entity']['product_name']}:")
            print(f"   Vendor: {assessment['entity']['vendor']}")
            print(f"   Category: {assessment['classification']['category']}")
            print(f"   Trust Score: {assessment['trust_score']['total_score']}/100")
            print(f"   Risk Level: {assessment['trust_score']['risk_level'].upper()}")
            print(f"   CVEs Found: {assessment['security_posture']['vulnerability_summary']['total_cves']}")
            print(f"   KEVs Found: {assessment['security_posture']['vulnerability_summary']['total_kevs']}")
            print(f"   Exploitation Risk: {assessment['security_posture']['vulnerability_summary']['exploitation_risk']}")
            
            # Display scoring breakdown
            print(f"\n   📊 Trust Score Components:")
            for component_name, component_data in assessment['trust_score']['components'].items():
                score = component_data['score']
                max_points = component_data['max_points']
                percentage = component_data['percentage']
                print(f"   • {component_name.replace('_', ' ').title()}: {score:.1f}/{max_points} pts ({percentage}% weight)")            
            # Display top recommendation
            if assessment['recommendations']:
                rec = assessment['recommendations'][0]
                print(f"\n   Top Recommendation ({rec['priority']}):")
                print(f"   → {rec['action']}")
            
            # Display alternatives
            if assessment['alternatives']:
                print(f"\n   Safer Alternatives:")
                for alt in assessment['alternatives']:
                    print(f"   • {alt['product_name']} ({alt['vendor']})")
            
            # Save full assessment to file
            filename = f"assessment_{product.lower().replace(' ', '_')}.json"
            with open(filename, 'w') as f:
                json.dump(assessment, f, indent=2)
            print(f"\n   ✓ Full assessment saved to: {filename}")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\n" + "="*50)
    print("✅ Example assessments complete!")
    print("\nView full results in the generated JSON files")
    print("Or start the web UI with: python app.py")
    print("="*50)

if __name__ == "__main__":
    main()
