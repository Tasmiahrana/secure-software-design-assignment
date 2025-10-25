package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.dto.ErrorDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Catches all unhandled exceptions (Task 8 / API7).
 * This prevents detailed stack traces from leaking to the client.
 */
@RestControllerAdvice
public class GlobalErrorHandler {

    // 1. Set up a secure, server-side logger
    private static final Logger log = LoggerFactory.getLogger(GlobalErrorHandler.class);

    /**
     * This is the "catch-all" handler. It runs for any Exception
     * that isn't handled by a more specific @ExceptionHandler.
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) // Always return a 500
    public ErrorDTO handleGenericException(Exception ex) {
        
        // 2. Log the FULL stack trace on the SERVER for debugging
        log.error("Unhandled exception caught by GlobalErrorHandler: {}", ex.getMessage(), ex);
        
        // 3. Return a GENERIC, safe message to the CLIENT
        return new ErrorDTO("An internal server error occurred. Please try again later.");
    }
}