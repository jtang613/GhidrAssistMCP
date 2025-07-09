/* 
 * 
 */
package ghidrassistmcp;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Interface for the MCP backend that handles tool management and execution.
 * This provides separation between the HTTP transport layer and business logic.
 */
public interface McpBackend {
    
    /**
     * Register a new MCP tool
     */
    void registerTool(McpTool tool);
    
    /**
     * Unregister an MCP tool by name
     */
    void unregisterTool(String toolName);
    
    /**
     * Get list of all available tools
     */
    List<McpSchema.Tool> getAvailableTools();
    
    /**
     * Execute a tool with given arguments
     */
    McpSchema.CallToolResult callTool(String toolName, Map<String, Object> arguments);
    
    /**
     * Notify backend when a program is activated
     */
    void onProgramActivated(Program program);
    
    /**
     * Notify backend when a program is deactivated
     */
    void onProgramDeactivated(Program program);
    
    /**
     * Get server implementation info
     */
    McpSchema.Implementation getServerInfo();
    
    /**
     * Get server capabilities
     */
    McpSchema.ServerCapabilities getCapabilities();
}