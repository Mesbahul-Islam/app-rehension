"""
Flask web application for Security Assessor
"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response
import logging
import json
import queue
import threading
from datetime import datetime

from config import Config
from assessor import SecurityAssessor
from input_parser import InputParser
from data_sources import VirusTotalAPI

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
    
    # Initialize VirusTotal API if key is available
    virustotal_api = None
    if Config.VIRUSTOTAL_API_KEY:
        virustotal_api = VirusTotalAPI(Config.VIRUSTOTAL_API_KEY)
        logger.info("VirusTotal API initialized successfully")
    else:
        logger.warning("VirusTotal API key not configured - SHA1 hash lookups will not be available")
    
    # Initialize input parser with VirusTotal API
    input_parser = InputParser(virustotal_api=virustotal_api)
    
    logger.info("Security Assessor initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Security Assessor: {e}")
    assessor = None
    input_parser = InputParser()  # Fallback without VirusTotal

# Store progress queues for each assessment (keyed by session ID)
progress_queues = {}
# Store completed results (keyed by session ID)
completed_results = {}


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
        session_id = data.get('session_id', str(datetime.now().timestamp()))
        
        if not input_text:
            return jsonify({'error': 'Please provide a product name, vendor, SHA1 hash, or URL'}), 400
        
        logger.info(f"Assessment request for: {input_text} [session: {session_id}]")
        
        # Check if input is SHA1 - must have VirusTotal configured
        from input_parser import InputParser as StaticParser
        if StaticParser.is_sha1(input_text):
            if not virustotal_api:
                logger.error("SHA1 hash provided but VirusTotal API is not configured")
                return jsonify({
                    'error': 'SHA1 hash detected but VirusTotal API is not configured. Please add VIRUSTOTAL_API_KEY to your .env file. Get a free API key at: https://www.virustotal.com/gui/join-us',
                    'input_type': 'sha1',
                    'sha1': input_text.strip().lower(),
                    'setup_required': True
                }), 400
        
        # Parse input to detect format (will perform VirusTotal lookup for SHA1)
        parsed = input_parser.parse_input(input_text)
        logger.info(f"Parsed input type: {parsed['input_type']}")
        
        # For SHA1 hashes, VirusTotal lookup is MANDATORY
        if parsed['input_type'] == 'sha1':
            if not parsed.get('virustotal_data'):
                # This means VirusTotal lookup failed or hash not found
                logger.warning(f"SHA1 hash provided: {parsed['sha1'][:8]}... - No VirusTotal data available")
                return jsonify({
                    'error': f'SHA1 hash {parsed["sha1"][:8]}... not found in VirusTotal database. The file may not have been scanned yet. Please upload the file to VirusTotal first, or provide the product name directly.',
                    'input_type': 'sha1',
                    'sha1': parsed['sha1'],
                    'virustotal_url': f"https://www.virustotal.com/gui/file/{parsed['sha1']}",
                    'suggestion': 'Try uploading the file at https://www.virustotal.com/gui/home/upload'
                }), 404
            
            # VirusTotal data is available - proceed with assessment
            vt_data = parsed['virustotal_data']
            logger.info(f"✓ VirusTotal lookup successful for SHA1: {parsed['sha1'][:8]}...")
            logger.info(f"  File: {vt_data.get('primary_name', 'Unknown')}")
            logger.info(f"  Detection ratio: {vt_data.get('detection_ratio', 'N/A')}")
            logger.info(f"  File type: {vt_data.get('type', 'Unknown')}")
            
            # Use product name from VirusTotal if available
            if parsed['product_name']:
                assessment_input = parsed['product_name']
            else:
                # Fall back to primary file name
                assessment_input = vt_data.get('primary_name', f"[SHA1: {parsed['sha1'][:8]}...]")
            
            logger.info(f"Using assessment input from VirusTotal: {assessment_input}")
        
        # For vendor_product format, pass the product name only
        # The assessor will try to resolve the vendor internally via LLM
        if parsed['input_type'] == 'vendor_product':
            # Use product name for assessment, but log vendor for reference
            logger.info(f"Vendor detected: {parsed['vendor']}, Product: {parsed['product_name']}")
            assessment_input = parsed['product_name']
        else:
            assessment_input = input_text
        
        # Create progress queue for this session
        progress_queue = queue.Queue()
        progress_queues[session_id] = progress_queue
        
        # Define progress callback
        def progress_callback(progress_data):
            try:
                progress_queue.put(progress_data)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")
        
        # Run assessment in background thread
        result_container = {}
        error_container = {}
        
        def run_assessment():
            try:
                result = assessor.assess_product(
                    assessment_input, 
                    use_cache=use_cache,
                    progress_callback=progress_callback,
                    virustotal_data=parsed.get('virustotal_data')  # Pass VirusTotal data if available
                )
                
                # Add input metadata to result
                result['_input_metadata'] = {
                    'raw_input': input_text,
                    'parsed_type': parsed['input_type'],
                    'detected_vendor': parsed.get('vendor'),
                    'detected_product': parsed.get('product_name'),
                    'sha1': parsed.get('sha1'),
                    'virustotal_data': parsed.get('virustotal_data')
                }
                
                # Store result for later retrieval
                completed_results[session_id] = result
                
                # Signal completion
                progress_queue.put({"stage": "complete", "status": "completed", "details": "Assessment finished"})
            except Exception as e:
                logger.error(f"Error during assessment: {e}", exc_info=True)
                error_container['error'] = str(e)
                progress_queue.put({"stage": "error", "status": "failed", "details": str(e)})
        
        assessment_thread = threading.Thread(target=run_assessment)
        assessment_thread.start()
        
        # Return session ID for progress tracking
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': 'Assessment started. Connect to /progress/{session_id} for updates.'
        })
        
    except Exception as e:
        logger.error(f"Error starting assessment: {e}", exc_info=True)
        return jsonify({
            'error': f'Assessment failed: {str(e)}'
        }), 500


@app.route('/progress/<session_id>')
def progress(session_id):
    """Server-Sent Events endpoint for progress updates"""
    
    def generate():
        # Get the progress queue for this session
        progress_queue = progress_queues.get(session_id)
        
        if not progress_queue:
            yield f"data: {json.dumps({'error': 'Session not found'})}\n\n"
            return
        
        try:
            while True:
                # Wait for progress update (timeout after 30 seconds)
                try:
                    progress_data = progress_queue.get(timeout=30)
                    
                    # Send progress update
                    yield f"data: {json.dumps(progress_data)}\n\n"
                    
                    # If complete or error, stop streaming
                    if progress_data.get('stage') in ['complete', 'error']:
                        break
                        
                except queue.Empty:
                    # Send keepalive
                    yield f": keepalive\n\n"
                    
        except GeneratorExit:
            logger.info(f"Client disconnected from progress stream: {session_id}")
        finally:
            # Cleanup
            if session_id in progress_queues:
                del progress_queues[session_id]
    
    return Response(generate(), mimetype='text/event-stream')


@app.route('/result/<session_id>')
def get_result(session_id):
    """Get the final assessment result"""
    
    if session_id in completed_results:
        result = completed_results[session_id]
        
        # Clean up after retrieval
        del completed_results[session_id]
        
        return jsonify({
            'success': True,
            'assessment': result
        })
    else:
        return jsonify({
            'error': 'Result not found or not yet available'
        }), 404


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
