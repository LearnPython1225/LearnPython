// Security utilities for Monaco Editor
const securityUtils = {
    // Validate code before execution
    validateCode(code) {
      const blacklistedKeywords = [
        'import os',
        'import sys',
        'import subprocess',
        '__import__',
        'eval(',
        'exec(',
        'open(',
      ]
  
      // Check for blacklisted keywords
      for (const keyword of blacklistedKeywords) {
        if (code.includes(keyword)) {
          throw new Error(`Forbidden keyword or operation: ${keyword}`)
        }
      }
  
      // Check code length
      if (code.length > 5000) {
        throw new Error('Code length exceeds maximum limit of 5000 characters')
      }
  
      return true
    },
  
    // Sanitize output
    sanitizeOutput(output) {
      // Remove any HTML tags
      return output.replace(/<[^>]*>/g, '')
    },
  
    // Rate limiting
    createRateLimiter(maxRequests = 10, timeWindow = 60000) {
      const requests = new Map()
      
      return function checkLimit(userId) {
        const now = Date.now()
        const userRequests = requests.get(userId) || []
        
        // Remove old requests
        const validRequests = userRequests.filter(time => now - time < timeWindow)
        
        if (validRequests.length >= maxRequests) {
          throw new Error('Rate limit exceeded. Please wait before trying again.')
        }
        
        validRequests.push(now)
        requests.set(userId, validRequests)
        return true
      }
    }
  }