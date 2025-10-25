package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

// VULNERABILITY(API7): overly verbose error responses
@ControllerAdvice
public class GlobalErrorHandler {

   @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
   public ResponseEntity<?> handleAccessDenied(org.springframework.security.access.AccessDeniedException e) {
       Map<String, String> errorMap = new HashMap<>();
       errorMap.put("error", "Access Denied");
       errorMap.put("message", e.getMessage());
       return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorMap);
   }

   @ExceptionHandler(RuntimeException.class)
   public ResponseEntity<?> handleRuntimeException(RuntimeException e) {
       Map<String, String> errorMap = new HashMap<>();
       errorMap.put("error", "Not Found");
       errorMap.put("message", e.getMessage());
       return ResponseEntity.status(HttpStatus.NOT_FOUND)
               .body(errorMap);
   }

   @ExceptionHandler(DataAccessException.class)
   public ResponseEntity<?> db(DataAccessException e) {
       Map<String, String> errorMap = new HashMap<>();
       errorMap.put("error", "Database Error");
       errorMap.put("message", "A database error occurred");
       return ResponseEntity.status(500).body(errorMap);
   }

   @ExceptionHandler(Exception.class)
   public ResponseEntity<?> handleAll(Exception e) {
       Map<String, String> errorMap = new HashMap<>();
       errorMap.put("error", "Internal Server Error");
       errorMap.put("message", "An unexpected error occurred");
       return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
               .body(errorMap);
   }

}