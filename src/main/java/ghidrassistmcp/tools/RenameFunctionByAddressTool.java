/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that renames a function by its address.
 */
public class RenameFunctionByAddressTool implements McpTool {
    
    @Override
    public String getName() {
        return "rename_function_by_address";
    }
    
    @Override
    public String getDescription() {
        return "Rename a function by its address";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "new_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address", "new_name"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String addressStr = (String) arguments.get("address");
        String newName = (String) arguments.get("new_name");
        
        if (addressStr == null || newName == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address and new_name parameters are required")
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
        
        // Find the function at this address
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            // Try to find function containing this address
            function = currentProgram.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No function found at address: " + addressStr)
                    .build();
            }
        }
        
        String oldName = function.getName();
        
        // Rename the function
        try {
            function.setName(newName, SourceType.USER_DEFINED);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully renamed function at " + addressStr + 
                              " from '" + oldName + "' to '" + newName + "'")
                .build();
        } catch (DuplicateNameException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function with name '" + newName + "' already exists")
                .build();
        } catch (InvalidInputException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid function name: " + newName)
                .build();
        }
    }
}