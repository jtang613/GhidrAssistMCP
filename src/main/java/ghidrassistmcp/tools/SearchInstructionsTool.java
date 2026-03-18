/*
 * MCP tool for searching assembly instructions by mnemonic pattern.
 * Used by ExploreBinaryNode and the instruction pattern catalog.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.utils.McpUtils;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that searches for assembly instructions matching a mnemonic pattern.
 *
 * <p>Supports glob-style wildcards ({@code *}) for mnemonic matching. For example,
 * {@code SVC*} matches {@code SVC}, {@code SVC 0}, etc. The search is case-insensitive.</p>
 *
 * <p>Can optionally scope the search to a single function, or search the entire binary.
 * Binary-wide searches are marked as long-running.</p>
 */
public class SearchInstructionsTool implements McpTool {

    @Override
    public String getName() {
        return "search_instructions";
    }

    @Override
    public String getDescription() {
        return "Search for assembly instructions matching a mnemonic pattern (glob wildcards supported)";
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public boolean includeContext() {
        // Structured JSON response should not be prepended with a prose context header
        return false;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "mnemonic_pattern", Map.of(
                    "type", "string",
                    "description", "Mnemonic glob pattern (e.g., 'SVC*', 'SYSCALL', 'BL*'). Case-insensitive."
                ),
                "operand_filter", Map.of(
                    "type", "string",
                    "description", "Optional: substring match on operand text"
                ),
                "function", Map.of(
                    "type", "string",
                    "description", "Optional: scope search to a single function (name or address)"
                ),
                "limit", Map.of(
                    "type", "integer",
                    "description", "Maximum results to return (default 1000)",
                    "default", 1000
                ),
                "offset", Map.of(
                    "type", "integer",
                    "description", "Pagination offset (default 0)",
                    "default", 0
                )
            ),
            List.of("mnemonic_pattern"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String mnemonicPattern = (String) arguments.get("mnemonic_pattern");
        String operandFilter = (String) arguments.get("operand_filter");
        String functionScope = (String) arguments.get("function");

        int limit = 1000;
        int offset = 0;

        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }

        if (mnemonicPattern == null || mnemonicPattern.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("mnemonic_pattern is required")
                .build();
        }

        // Convert glob pattern to a simple matcher
        String patternLower = mnemonicPattern.toLowerCase();

        Listing listing = currentProgram.getListing();
        InstructionIterator instrIter;

        // Scope to function if specified
        if (functionScope != null && !functionScope.isEmpty()) {
            Function func = McpUtils.findFunction(currentProgram, functionScope);
            if (func == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Function not found: " + functionScope)
                    .build();
            }
            AddressSetView body = func.getBody();
            instrIter = listing.getInstructions(body, true);
        } else {
            instrIter = listing.getInstructions(true);
        }

        StringBuilder json = new StringBuilder();
        json.append("[");

        int totalFound = 0;
        int emitted = 0;

        while (instrIter.hasNext() && emitted < limit) {
            Instruction instr = instrIter.next();
            String mnemonic = instr.getMnemonicString().toLowerCase();

            // Glob match
            if (!globMatch(mnemonic, patternLower)) {
                continue;
            }

            // Operand filter
            if (operandFilter != null && !operandFilter.isEmpty()) {
                String operands = getOperandText(instr);
                if (!operands.toLowerCase().contains(operandFilter.toLowerCase())) {
                    continue;
                }
            }

            totalFound++;

            // Apply offset
            if (totalFound <= offset) {
                continue;
            }

            // Get function context
            Address addr = instr.getAddress();
            Function containingFunc = currentProgram.getFunctionManager().getFunctionContaining(addr);
            String funcName = containingFunc != null ? containingFunc.getName() : "";

            // Emit match
            if (emitted > 0) {
                json.append(",");
            }
            json.append("{\"address\":\"0x").append(addr.toString())
                .append("\",\"mnemonic\":\"").append(McpUtils.escapeJson(instr.getMnemonicString()))
                .append("\",\"operands\":\"").append(McpUtils.escapeJson(getOperandText(instr)))
                .append("\",\"function\":\"").append(McpUtils.escapeJson(funcName))
                .append("\"}");
            emitted++;
        }

        json.append("]");

        return McpSchema.CallToolResult.builder()
            .addTextContent(json.toString())
            .build();
    }

    /**
     * Simple glob matching: only supports '*' wildcard.
     * e.g., "svc*" matches "svc", "svc 0", etc.
     */
    private boolean globMatch(String text, String pattern) {
        if (pattern.equals("*")) {
            return true;
        }

        // Split pattern by '*' and match segments in order
        String[] segments = pattern.split("\\*", -1);

        int textIdx = 0;
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            if (segment.isEmpty()) {
                continue;
            }

            int foundIdx = text.indexOf(segment, textIdx);
            if (foundIdx == -1) {
                return false;
            }

            // First segment must match at start if pattern doesn't start with *
            if (i == 0 && !pattern.startsWith("*") && foundIdx != 0) {
                return false;
            }

            textIdx = foundIdx + segment.length();
        }

        // Last segment must match at end if pattern doesn't end with *
        if (!pattern.endsWith("*") && segments.length > 0) {
            String lastSegment = segments[segments.length - 1];
            if (!lastSegment.isEmpty() && !text.endsWith(lastSegment)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get concatenated operand text for an instruction.
     */
    private String getOperandText(Instruction instr) {
        int numOperands = instr.getNumOperands();
        if (numOperands == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < numOperands; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            String rep = instr.getDefaultOperandRepresentation(i);
            if (rep != null) {
                sb.append(rep);
            }
        }
        return sb.toString();
    }
}
