/*
 * MCP Resource for strings table.
 */
package ghidrassistmcp.resources;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;

/**
 * Resource that provides the string table from the program.
 */
public class StringsResource implements McpResource {

    private static final Pattern URI_PATTERN = Pattern.compile("ghidra://program/([^/]+)/strings");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getUriPattern() {
        return "ghidra://program/{name}/strings";
    }

    @Override
    public String getName() {
        return "strings";
    }

    @Override
    public String getDescription() {
        return "String table from the program";
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

            ArrayNode stringsArray = objectMapper.createArrayNode();
            int count = 0;

            DataIterator dataIter = program.getListing().getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();

                if (data.hasStringValue()) {
                    String stringValue = data.getDefaultValueRepresentation();
                    String stringText = extractStringText(stringValue);

                    if (stringText != null && stringText.length() >= 4) {
                        ObjectNode stringNode = objectMapper.createObjectNode();
                        stringNode.put("address", data.getAddress().toString());
                        stringNode.put("value", stringText);
                        stringNode.put("length", stringText.length());
                        stringNode.put("type", data.getDataType().getName());

                        stringsArray.add(stringNode);
                        count++;
                    }
                }
            }

            json.put("count", count);
            json.set("strings", stringsArray);

            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);

        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }

    private static String extractStringText(String defaultValueRepresentation) {
        if (defaultValueRepresentation == null) {
            return null;
        }
        int firstQuote = defaultValueRepresentation.indexOf('"');
        int lastQuote = defaultValueRepresentation.lastIndexOf('"');
        if (firstQuote >= 0 && lastQuote > firstQuote) {
            return defaultValueRepresentation.substring(firstQuote + 1, lastQuote);
        }
        return defaultValueRepresentation;
    }
}
