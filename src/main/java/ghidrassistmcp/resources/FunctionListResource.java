/*
 * MCP Resource for function list.
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

/**
 * Resource that provides a list of all functions in the program.
 */
public class FunctionListResource implements McpResource {

    private static final Pattern URI_PATTERN = Pattern.compile("ghidra://program/([^/]+)/functions");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getUriPattern() {
        return "ghidra://program/{name}/functions";
    }

    @Override
    public String getName() {
        return "function_list";
    }

    @Override
    public String getDescription() {
        return "List of all functions in the program with addresses and signatures";
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

            ArrayNode functionsArray = objectMapper.createArrayNode();
            int count = 0;

            for (Function function : program.getFunctionManager().getFunctions(true)) {
                ObjectNode funcNode = objectMapper.createObjectNode();
                funcNode.put("name", function.getName());
                funcNode.put("address", function.getEntryPoint().toString());
                funcNode.put("signature", function.getPrototypeString(false, false));
                funcNode.put("is_thunk", function.isThunk());
                funcNode.put("is_external", function.isExternal());
                funcNode.put("param_count", function.getParameterCount());

                if (function.getComment() != null) {
                    funcNode.put("comment", function.getComment());
                }

                functionsArray.add(funcNode);
                count++;
            }

            json.put("count", count);
            json.set("functions", functionsArray);

            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);

        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }
}
