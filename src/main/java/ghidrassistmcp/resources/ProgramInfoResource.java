/*
 * MCP Resource for program information.
 */
package ghidrassistmcp.resources;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.listing.Program;

/**
 * Resource that provides program metadata and information.
 */
public class ProgramInfoResource implements McpResource {

    private static final Pattern URI_PATTERN = Pattern.compile("ghidra://program/([^/]+)/info");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getUriPattern() {
        return "ghidra://program/{name}/info";
    }

    @Override
    public String getName() {
        return "program_info";
    }

    @Override
    public String getDescription() {
        return "Program metadata including name, path, language, compiler, and memory information";
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
            json.put("name", program.getName());
            json.put("path", program.getExecutablePath());
            json.put("format", program.getExecutableFormat());

            // Language info
            var language = program.getLanguage();
            ObjectNode langNode = objectMapper.createObjectNode();
            langNode.put("id", language.getLanguageID().toString());
            langNode.put("processor", language.getProcessor().toString());
            langNode.put("endian", language.isBigEndian() ? "big" : "little");
            langNode.put("size", language.getLanguageDescription().getSize());
            json.set("language", langNode);

            // Compiler info
            var compilerSpec = program.getCompilerSpec();
            ObjectNode compilerNode = objectMapper.createObjectNode();
            compilerNode.put("id", compilerSpec.getCompilerSpecID().toString());
            json.set("compiler", compilerNode);

            // Memory info
            var memory = program.getMemory();
            ObjectNode memNode = objectMapper.createObjectNode();
            memNode.put("num_blocks", memory.getNumAddressRanges());
            memNode.put("min_address", memory.getMinAddress().toString());
            memNode.put("max_address", memory.getMaxAddress().toString());
            json.set("memory", memNode);

            // Analysis info
            ObjectNode analysisNode = objectMapper.createObjectNode();
            analysisNode.put("function_count", program.getFunctionManager().getFunctionCount());
            analysisNode.put("symbol_count", program.getSymbolTable().getNumSymbols());
            json.set("analysis", analysisNode);

            // Timestamps
            json.put("creation_date", program.getCreationDate().toString());
            json.put("modification_number", program.getModificationNumber());

            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);

        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }
}
