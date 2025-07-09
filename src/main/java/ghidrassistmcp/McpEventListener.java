/* 
 * 
 */
package ghidrassistmcp;

/**
 * Event listener interface for MCP operations.
 * This allows decoupling between the backend and UI components.
 */
public interface McpEventListener {
    
    /**
     * Called when a tool request is received.
     * @param toolName The name of the tool being called
     * @param parameters The request parameters (may be truncated for logging)
     */
    void onToolRequest(String toolName, String parameters);
    
    /**
     * Called when a tool response is generated.
     * @param toolName The name of the tool that was called
     * @param response The response content (may be truncated for logging)
     */
    void onToolResponse(String toolName, String response);
    
    /**
     * Called when a session event occurs.
     * @param event The session event description
     */
    void onSessionEvent(String event);
    
    /**
     * Called for general logging messages.
     * @param message The log message
     */
    void onLogMessage(String message);
}