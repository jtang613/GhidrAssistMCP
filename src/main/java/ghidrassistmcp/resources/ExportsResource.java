/*
 * MCP Resource for exports table.
 */
package ghidrassistmcp.resources;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

/**
 * Resource that provides the export table from the program.
 */
public class ExportsResource implements McpResource {

    private static final Pattern URI_PATTERN = Pattern.compile("ghidra://program/([^/]+)/exports");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getUriPattern() {
        return "ghidra://program/{name}/exports";
    }

    @Override
    public String getName() {
        return "exports";
    }

    @Override
    public String getDescription() {
        return "Export table from the program";
    }

    @Override
    public String getMimeType() {
        return "application/json";
    }

    @Override
    public boolean canHandle(String uri) {
        return URI_PATTERN.matcher(uri).matches();
    }

    @Override
    public Map<String, String> extractParams(String uri) {
        Map<String, String> params = new HashMap<>();
        Matcher matcher = URI_PATTERN.matcher(uri);
        if (matcher.matches()) {
            params.put("name", matcher.group(1));
        }
        return params;
    }

    @Override
    public String readContent(Program program, Map<String, String> uriParams) {
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        try {
            ObjectNode json = objectMapper.createObjectNode();
            json.put("program", program.getName());

            ArrayNode exportsArray = objectMapper.createArrayNode();
            int count = 0;

            // Get exported functions (entry points marked as global)
            for (Function function : program.getFunctionManager().getFunctions(true)) {
                Symbol symbol = function.getSymbol();
                if (symbol != null && symbol.isGlobal() && !symbol.isExternal()) {
                    // Check if it's an entry point or explicitly exported
                    boolean isEntryPoint = program.getSymbolTable().isExternalEntryPoint(function.getEntryPoint());

                    if (isEntryPoint || function.getEntryPoint().equals(program.getMinAddress())) {
                        ObjectNode exportNode = objectMapper.createObjectNode();
                        exportNode.put("name", function.getName());
                        exportNode.put("address", function.getEntryPoint().toString());
                        exportNode.put("signature", function.getPrototypeString(false, false));
                        exportNode.put("is_entry_point", isEntryPoint);

                        exportsArray.add(exportNode);
                        count++;
                    }
                }
            }

            json.put("count", count);
            json.set("exports", exportsArray);

            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);

        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }
}
