package com.securelabs.vulnerable.auth;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * VULNERABLE: Session Manager
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A02: Weak session token generation
 * - A07: No session expiration
 * - A07: No session invalidation on logout
 * - A07: Session fixation vulnerability
 */
public class SessionManager {

    // VULNERABLE: In-memory session store without cleanup
    private static final Map<String, SessionData> sessions = new HashMap<>();

    /**
     * VULNERABLE: Weak session token generation
     * UUID.randomUUID() is not cryptographically secure for session tokens
     */
    public static String createSession(String userId) {
        // VULNERABLE: Predictable session ID
        String sessionId = UUID.randomUUID().toString();

        SessionData session = new SessionData();
        session.setUserId(userId);
        session.setCreatedAt(System.currentTimeMillis());
        // VULNERABLE: No expiration set

        sessions.put(sessionId, session);

        // VULNERABLE: Logging session token
        System.out.println("Session created: " + sessionId + " for user: " + userId);

        return sessionId;
    }

    /**
     * VULNERABLE: Sequential session ID generation
     */
    private static int sessionCounter = 1000;

    public static String createWeakSession(String userId) {
        // VULNERABLE: Sequential, predictable session ID
        String sessionId = "SESSION_" + (++sessionCounter);

        SessionData session = new SessionData();
        session.setUserId(userId);
        sessions.put(sessionId, session);

        return sessionId;
    }

    /**
     * VULNERABLE: No session validation
     */
    public static String getUserFromSession(String sessionId) {
        SessionData session = sessions.get(sessionId);

        if (session == null) {
            return null;
        }

        // VULNERABLE: No expiration check
        // VULNERABLE: No IP/User-Agent binding validation

        return session.getUserId();
    }

    /**
     * VULNERABLE: Session not properly invalidated
     */
    public static void invalidateSession(String sessionId) {
        // VULNERABLE: Session data may still be accessible due to race conditions
        sessions.remove(sessionId);
        // VULNERABLE: No cookie invalidation on client side
    }

    /**
     * VULNERABLE: Session fixation - accepts externally provided session ID
     */
    public static String createSessionWithId(String sessionId, String userId) {
        // VULNERABLE: Allows attacker to set session ID before victim logs in
        SessionData session = new SessionData();
        session.setUserId(userId);
        sessions.put(sessionId, session);
        return sessionId;
    }

    /**
     * VULNERABLE: No concurrent session limit
     */
    public static boolean hasActiveSession(String userId) {
        // VULNERABLE: Allows unlimited concurrent sessions
        for (SessionData session : sessions.values()) {
            if (userId.equals(session.getUserId())) {
                return true;
            }
        }
        return false;
    }

    /**
     * VULNERABLE: Debug endpoint exposing all sessions
     */
    public static Map<String, SessionData> getAllSessions() {
        // VULNERABLE: Exposes all active sessions
        return new HashMap<>(sessions);
    }

    /**
     * VULNERABLE: Session data without security controls
     */
    public static class SessionData {
        private String userId;
        private long createdAt;
        private String ipAddress;
        private String userAgent;

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public long getCreatedAt() { return createdAt; }
        public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    }
}
