/*
 * MCP tool for exporting all function call edges in the binary.
 * Used by TopologyAnalyzerNode for PageRank, SCC, hub/leaf detection.
 */
package ghidrassistmcp.tools;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that exports all function-level call edges in the binary.
 *
 * <p>Unlike {@link GetCallGraphTool} which traverses callers/callees for a single
 * function with configurable depth, this tool returns ALL call edges across the
 * entire binary in a single call. The output is a JSON array of {from, to} objects
 * suitable for building a networkx DiGraph.</p>
 *
 * <p>Supports pagination via {@code offset} and {@code limit} parameters.
 * Marked as long-running because large binaries can have 250K+ call references.</p>
 */
public class GetAllCallEdgesTool implements McpTool {

    @Override
    public String getName() {
        return "get_all_call_edges";
    }

    @Override
    public String getDescription() {
        return "Export all function-level call edges (caller → callee) as a JSON array for topology analysis";
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
                "limit", Map.of(
                    "type", "integer",
                    "description", "Maximum number of edges to return (default 250000)",
                    "default", 250000
                ),
                "offset", Map.of(
                    "type", "integer",
                    "description", "Pagination offset (default 0)",
                    "default", 0
                )
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        int limit = 250000;
        int offset = 0;

        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }

        FunctionManager functionManager = currentProgram.getFunctionManager();

        // Collect unique call edges as "from_addr->to_addr" strings to deduplicate
        Set<String> edgeKeys = new HashSet<>();
        StringBuilder json = new StringBuilder();
        json.append("[");

        int totalFound = 0;
        int emitted = 0;

        // HIGH PERFORMANCE REFACTOR: Instead of iterating all references in the binary (O(N_refs)),
        // iterate all functions (O(N_funcs)) and query the indexed references TO them.
        FunctionIterator funcIter = functionManager.getFunctions(true);

        outerLoop:
        while (funcIter.hasNext()) {
            Function callee = funcIter.next();
            Address entryPoint = callee.getEntryPoint();

            // Get all references pointing to the entry point of this function
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(entryPoint);

            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (emitted >= limit) {
                    break outerLoop;
                }

                RefType refType = ref.getReferenceType();
                // Only include call-type references
                if (!refType.isCall()) {
                    continue;
                }

                Address callerAddr = ref.getFromAddress();
                Function callerFunc = functionManager.getFunctionContaining(callerAddr);

                if (callerFunc == null) {
                    continue;
                }

                // Get function entry points
                String fromEntry = callerFunc.getEntryPoint().toString();
                String toEntry = callee.getEntryPoint().toString();

                // Skip self-references (e.g., recursive calls)
                if (fromEntry.equals(toEntry)) {
                    continue;
                }

                // Deduplicate at function level
                String edgeKey = fromEntry + "->" + toEntry;
                if (!edgeKeys.add(edgeKey)) {
                    continue;
                }

                totalFound++;

                // Apply offset
                if (totalFound <= offset) {
                    continue;
                }

                // Emit edge
                if (emitted > 0) {
                    json.append(",");
                }
                json.append("{\"from\":\"0x").append(fromEntry)
                    .append("\",\"to\":\"0x").append(toEntry).append("\"}");
                emitted++;
            }
        }

        json.append("]");

        return McpSchema.CallToolResult.builder()
            .addTextContent(json.toString())
            .build();
    }
}
