/* 
 * 
 */
package ghidrassistmcp;

import java.util.Map;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Interface for individual MCP tools that can be registered with the backend.
 */
public interface McpTool {
    
    /**
     * Get the tool name (used for MCP tool calls)
     */
    String getName();
    
    /**
     * Get the tool description
     */
    String getDescription();
    
    /**
     * Get the input schema for this tool
     */
    McpSchema.JsonSchema getInputSchema();
    
    /**
     * Execute the tool with given arguments and current program context
     */
    McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram);
    
    /**
     * Execute the tool with given arguments, program context, and plugin reference for UI access.
     * @deprecated Use execute(arguments, currentProgram, backend) instead
     */
    @Deprecated
    default McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPPlugin plugin) {
        // Default implementation delegates to the original method for backward compatibility
        return execute(arguments, currentProgram);
    }

    /**
     * Execute the tool with given arguments, program context, and backend reference for multi-program access.
     * Tools that need to access all open programs or query programs by name should override this method.
     */
    default McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        // Default implementation delegates to the original method for backward compatibility
        return execute(arguments, currentProgram);
    }
}