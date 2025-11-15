"""
Flask web application for Security Assessor
"""
from flask import Flask, render_template, request, jsonify, redirect, url_for
import logging
import json
from datetime import datetime

from config import Config
from assessor import SecurityAssessor
from input_parser import InputParser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize assessor
try:
    assessor = SecurityAssessor(Config)
    logger.info("Security Assessor initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Security Assessor: {e}")
    assessor = None


@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@app.route('/assess', methods=['POST'])
def assess():
    """Run security assessment"""
    
    if not assessor:
        return jsonify({
            'error': 'Assessment service is not available. Please check configuration.'
        }), 503
    
    try:
        # Get input
        data = request.get_json() if request.is_json else request.form
        input_text = data.get('input_text', '').strip()
        use_cache = data.get('use_cache', 'true') == 'true' 
        
        if not input_text:
            return jsonify({'error': 'Please provide a product name, vendor, SHA1 hash, or URL'}), 400
        
        logger.info(f"Assessment request for: {input_text}")
        
        # Parse input to detect format
        parsed = InputParser.parse_input(input_text)
        logger.info(f"Parsed input type: {parsed['input_type']}")
        
        # For SHA1, we could look it up in a dataset first
        # For now, we'll assess using the SHA1 as identifier
        if parsed['input_type'] == 'sha1':
            logger.warning(f"SHA1 hash provided: {parsed['sha1'][:8]}... - Cannot directly assess. Need product/vendor name.")
            return jsonify({
                'error': 'SHA1 hash detected. Please provide the product name or vendor instead. SHA1-based assessment requires additional dataset mapping.',
                'input_type': 'sha1',
                'sha1': parsed['sha1']
            }), 400
        
        # For vendor_product format, pass the product name only
        # The assessor will try to resolve the vendor internally via LLM
        if parsed['input_type'] == 'vendor_product':
            # Use product name for assessment, but log vendor for reference
            logger.info(f"Vendor detected: {parsed['vendor']}, Product: {parsed['product_name']}")
            assessment_input = parsed['product_name']
        else:
            assessment_input = input_text
        
        # Run assessment
        result = assessor.assess_product(assessment_input, use_cache=use_cache)
        
        # Add input metadata to result
        result['_input_metadata'] = {
            'raw_input': input_text,
            'parsed_type': parsed['input_type'],
            'detected_vendor': parsed.get('vendor'),
            'detected_product': parsed.get('product_name')
        }
        
        return jsonify({
            'success': True,
            'assessment': result
        })
        
    except Exception as e:
        logger.error(f"Error during assessment: {e}", exc_info=True)
        return jsonify({
            'error': f'Assessment failed: {str(e)}'
        }), 500


@app.route('/history')
def history():
    """View assessment history"""
    
    if not assessor:
        return render_template('error.html', 
                             error='Assessment service is not available.')
    
    try:
        assessments = assessor.get_assessment_history(limit=100)
        return render_template('history.html', assessments=assessments)
        
    except Exception as e:
        logger.error(f"Error fetching history: {e}")
        return render_template('error.html', error=str(e))


@app.route('/compare')
def compare():
    """Compare multiple products"""
    return render_template('compare.html')


@app.route('/api/health')
def health():
    """Health check endpoint"""
    
    health_status = {
        'status': 'healthy' if assessor else 'unhealthy',
        'timestamp': datetime.now().isoformat(),
        'components': {
            'assessor': assessor is not None,
            'gemini_api': bool(Config.GEMINI_API_KEY),
            'producthunt_api': bool(Config.PRODUCTHUNT_API_KEY)
        }
    }
    
    status_code = 200 if assessor else 503
    return jsonify(health_status), status_code


@app.errorhandler(404)
def not_found(e):
    """404 error handler"""
    return render_template('error.html', error='Page not found'), 404


@app.errorhandler(500)
def server_error(e):
    """500 error handler"""
    logger.error(f"Server error: {e}")
    return render_template('error.html', error='Internal server error'), 500


if __name__ == '__main__':
    if not Config.GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set! Please configure in .env file")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=Config.DEBUG
    )
