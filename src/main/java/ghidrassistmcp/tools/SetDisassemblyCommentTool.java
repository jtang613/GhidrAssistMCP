/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that sets a comment on an instruction or data in the disassembly.
 */
public class SetDisassemblyCommentTool implements McpTool {
    
    @Override
    public String getName() {
        return "set_disassembly_comment";
    }
    
    @Override
    public String getDescription() {
        return "Set a comment on an instruction or data in the disassembly";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "comment", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "comment_type", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address", "comment"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String addressStr = (String) arguments.get("address");
        String comment = (String) arguments.get("comment");
        String commentTypeStr = (String) arguments.get("comment_type");
        
        if (addressStr == null || comment == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address and comment parameters are required")
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
        
        // Determine comment type (default to EOL comment)
        CommentType commentType = CommentType.EOL;
        if (commentTypeStr != null) {
            switch (commentTypeStr.toLowerCase()) {
                case "pre":
                case "pre_comment":
                    commentType = CommentType.PRE;
                    break;
                case "post":
                case "post_comment":
                    commentType = CommentType.POST;
                    break;
                case "plate":
                case "plate_comment":
                    commentType = CommentType.PLATE;
                    break;
                case "repeatable":
                case "repeatable_comment":
                    commentType = CommentType.REPEATABLE;
                    break;
                case "eol":
                case "eol_comment":
                default:
                    commentType = CommentType.EOL;
                    break;
            }
        }
        
        // Get the code unit at the address
        CodeUnit codeUnit = currentProgram.getListing().getCodeUnitAt(address);
        if (codeUnit == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No code unit found at address: " + addressStr)
                .build();
        }
        
        // Set the comment within a transaction
        int transactionID = currentProgram.startTransaction("Set Disassembly Comment");
        try {
            // Set the comment
            codeUnit.setComment(commentType, comment);
            currentProgram.endTransaction(transactionID, true);
            
            String commentTypeName = getCommentTypeName(commentType);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully set " + commentTypeName + " comment at " + addressStr + 
                              ": \"" + comment + "\"")
                .build();
        } catch (Exception e) {
            currentProgram.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error setting comment: " + e.getMessage())
                .build();
        }
    }
    
    private String getCommentTypeName(CommentType commentType) {
        switch (commentType) {
            case PRE:
                return "pre";
            case POST:
                return "post";
            case PLATE:
                return "plate";
            case REPEATABLE:
                return "repeatable";
            case EOL:
            default:
                return "EOL";
        }
    }
}