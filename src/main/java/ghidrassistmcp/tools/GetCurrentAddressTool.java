/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets the current cursor address in Ghidra.
 */
public class GetCurrentAddressTool implements McpTool {
    
    @Override
    public String getName() {
        return "get_current_address";
    }
    
    @Override
    public String getDescription() {
        return "Get the current cursor address in Ghidra";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(),
            List.of(), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // Fallback for when plugin reference is not available
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        return McpSchema.CallToolResult.builder()
            .addTextContent("Current address functionality requires plugin context. " +
                          "Program minimum address: " + currentProgram.getMinAddress())
            .build();
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPPlugin plugin) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        if (plugin == null) {
            return execute(arguments, currentProgram);
        }
        
        Address currentAddress = plugin.getCurrentAddress();
        if (currentAddress == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No current address available (cursor may not be positioned in the listing)")
                .build();
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Current Address: ").append(currentAddress).append("\n");
        result.append("Program: ").append(currentProgram.getName()).append("\n");
        result.append("Address Space: ").append(currentAddress.getAddressSpace().getName());
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }
}