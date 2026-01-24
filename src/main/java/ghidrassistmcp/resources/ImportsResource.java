/*
 * MCP Resource for imports table.
 */
package ghidrassistmcp.resources;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

/**
 * Resource that provides the import table from the program.
 */
public class ImportsResource implements McpResource {

    private static final Pattern URI_PATTERN = Pattern.compile("ghidra://program/([^/]+)/imports");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getUriPattern() {
        return "ghidra://program/{name}/imports";
    }

    @Override
    public String getName() {
        return "imports";
    }

    @Override
    public String getDescription() {
        return "Import table from the program";
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

            ArrayNode importsArray = objectMapper.createArrayNode();
            int count = 0;

            SymbolIterator symbolIter = program.getSymbolTable().getSymbolIterator();
            while (symbolIter.hasNext()) {
                Symbol symbol = symbolIter.next();

                if (symbol.isExternal() &&
                    (symbol.getSymbolType() == SymbolType.FUNCTION ||
                     symbol.getSymbolType() == SymbolType.LABEL)) {

                    ObjectNode importNode = objectMapper.createObjectNode();
                    importNode.put("name", symbol.getName());
                    importNode.put("address", symbol.getAddress().toString());
                    importNode.put("type", symbol.getSymbolType().toString());

                    if (symbol.getParentNamespace() != null) {
                        importNode.put("library", symbol.getParentNamespace().getName());
                    }

                    importsArray.add(importNode);
                    count++;
                }
            }

            json.put("count", count);
            json.set("imports", importsArray);

            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);

        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }
}
