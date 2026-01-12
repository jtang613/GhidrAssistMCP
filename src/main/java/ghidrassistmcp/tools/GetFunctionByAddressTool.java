/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets function information by address.
 */
public class GetFunctionByAddressTool implements McpTool {
    
    @Override
    public String getName() {
        return "get_function_by_address";
    }
    
    @Override
    public String getDescription() {
        return "Get function information for the function containing a specific address";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String addressStr = (String) arguments.get("address");
        if (addressStr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }
        
        // Parse the address
        Address address;
        try {
            address = currentProgram.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addressStr)
                .build();
        }
        
        // Find the function containing this address
        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No function found containing address: " + addressStr)
                .build();
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Function at address ").append(addressStr).append(":\n\n");
        result.append("Name: ").append(function.getName()).append("\n");
        result.append("Entry Point: ").append(function.getEntryPoint()).append("\n");
        result.append("Address Range: ").append(function.getBody().getMinAddress())
              .append(" - ").append(function.getBody().getMaxAddress()).append("\n");
        result.append("Parameter Count: ").append(function.getParameterCount()).append("\n");
        result.append("Return Type: ").append(function.getReturnType().getDisplayName()).append("\n");
        result.append("Calling Convention: ").append(function.getCallingConventionName()).append("\n");
        result.append("Signature: ").append(function.getSignature()).append("\n");
        
        if (function.getComment() != null) {
            result.append("Comment: ").append(function.getComment()).append("\n");
        }
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }
}