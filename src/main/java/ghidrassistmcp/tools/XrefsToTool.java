/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that finds cross-references TO a specific address.
 */
public class XrefsToTool implements McpTool {
    
    @Override
    public String getName() {
        return "xrefs_to";
    }
    
    @Override
    public String getDescription() {
        return "Get cross-references TO a specific memory address";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
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
        
        // Parse optional offset and limit
        int offset = 0;
        int limit = 100; // Default limit
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        
        // Parse the address
        Address targetAddress;
        try {
            targetAddress = currentProgram.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addressStr)
                .build();
        }
        
        // Get cross-references TO this address
        StringBuilder result = new StringBuilder();
        result.append("Cross-references TO address ").append(addressStr).append(":\n\n");
        
        ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(targetAddress);
        
        int count = 0;
        int totalCount = 0;
        
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            totalCount++;
            
            // Apply offset
            if (totalCount <= offset) {
                continue;
            }
            
            // Apply limit
            if (count >= limit) {
                break;
            }
            
            Address fromAddr = ref.getFromAddress();
            String refType = ref.getReferenceType().toString();
            
            result.append("From: ").append(fromAddr)
                  .append(" (").append(refType).append(")\n");
            
            count++;
        }
        
        if (totalCount == 0) {
            result.append("No cross-references found to this address.");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" references");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
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