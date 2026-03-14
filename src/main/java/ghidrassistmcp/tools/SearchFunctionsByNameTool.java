package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class SearchFunctionsByNameTool implements McpTool {

    @Override
    public boolean isCacheable() { return true; }

    @Override
    public String getName() { return "search_functions_by_name"; }

    @Override
    public String getDescription() { return "Search for functions whose name contains the search term"; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "search_term", Map.of("type", "string", "description", "Search term to match against function names"),
                "limit", Map.of("type", "integer", "description", "Maximum results (default 100)")
            ),
            List.of("search_term"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addTextContent("No program currently loaded").build();
        }

        String searchTerm = (String) arguments.get("search_term");
        if (searchTerm == null || searchTerm.isEmpty()) {
            return McpSchema.CallToolResult.builder().addTextContent("search_term is required").build();
        }

        int limit = 100;
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        String searchLower = searchTerm.toLowerCase();
        StringBuilder result = new StringBuilder();
        result.append("Functions matching \"").append(searchTerm).append("\":\n\n");

        int count = 0;
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            if (func.getName().toLowerCase().contains(searchLower)) {
                result.append("- ").append(func.getName())
                      .append(" @ ").append(func.getEntryPoint())
                      .append(" (").append(func.getParameterCount()).append(" params)\n");
                count++;
                if (count >= limit) break;
            }
        }

        if (count == 0) {
            result.append("No functions found matching: ").append(searchTerm);
        } else {
            result.append("\nFound ").append(count).append(" matching functions");
        }

        return McpSchema.CallToolResult.builder().addTextContent(result.toString()).build();
    }
}
