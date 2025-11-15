import axios from 'axios';

// Base URL for API - will be proxied by Vite in development
const API_BASE_URL = '/api';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 120000, // 2 minutes for long-running assessments
});

// API Service
export const assessmentAPI = {
  /**
   * Submit a new security assessment
   * @param {Object} data - Assessment request data
   * @param {string} data.input_text - Product name, vendor, SHA1, or URL
   * @param {boolean} data.use_cache - Whether to use cached results
   * @param {string} data.session_id - Optional session ID
   * @returns {Promise} Assessment result
   */
  submitAssessment: async (data) => {
    try {
      const response = await api.post('/assess', data);
      return response.data;
    } catch (error) {
      throw handleAPIError(error);
    }
  },

  /**
   * Get assessment history
   * @returns {Promise<Array>} List of past assessments
   */
  getHistory: async () => {
    try {
      const response = await api.get('/history');
      return response.data;
    } catch (error) {
      throw handleAPIError(error);
    }
  },

  /**
   * Get a specific assessment by ID
   * @param {string} assessmentId - Assessment ID
   * @returns {Promise<Object>} Assessment details
   */
  getAssessmentById: async (assessmentId) => {
    try {
      const response = await api.get(`/assessment/${assessmentId}`);
      return response.data;
    } catch (error) {
      throw handleAPIError(error);
    }
  },

  /**
   * Delete an assessment
   * @param {string} assessmentId - Assessment ID to delete
   * @returns {Promise}
   */
  deleteAssessment: async (assessmentId) => {
    try {
      const response = await api.delete(`/assessment/${assessmentId}`);
      return response.data;
    } catch (error) {
      throw handleAPIError(error);
    }
  },

  /**
   * Compare two products
   * @param {string} product1 - First product name
   * @param {string} product2 - Second product name
   * @returns {Promise<Object>} Comparison results
   */
  compareProducts: async (product1, product2) => {
    try {
      const response = await api.post('/compare', { product1, product2 });
      return response.data;
    } catch (error) {
      throw handleAPIError(error);
    }
  },

  /**
   * Get progress for a session (Server-Sent Events)
   * @param {string} sessionId - Session ID
   * @returns {EventSource} SSE connection
   */
  getProgressStream: (sessionId) => {
    return new EventSource(`${API_BASE_URL}/stream/${sessionId}`);
  },
};

/**
 * Handle API errors consistently
 * @param {Error} error - Axios error object
 * @returns {Object} Formatted error
 */
function handleAPIError(error) {
  if (error.response) {
    // Server responded with error status
    return {
      message: error.response.data.error || 'An error occurred',
      status: error.response.status,
      data: error.response.data,
    };
  } else if (error.request) {
    // Request was made but no response received
    return {
      message: 'Unable to connect to the server. Please check your connection.',
      status: 0,
    };
  } else {
    // Something else happened
    return {
      message: error.message || 'An unexpected error occurred',
      status: -1,
    };
  }
}

export default api;
