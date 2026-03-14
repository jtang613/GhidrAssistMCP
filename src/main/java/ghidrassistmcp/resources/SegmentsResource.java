package ghidrassistmcp.resources;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class SegmentsResource implements McpResource {

    private static final Pattern URI_PATTERN = Pattern.compile("ghidra://program/([^/]+)/segments");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getUriPattern() { return "ghidra://program/{name}/segments"; }

    @Override
    public String getName() { return "segments"; }

    @Override
    public String getDescription() { return "Memory segments/blocks in the program"; }

    @Override
    public String getMimeType() { return "application/json"; }

    @Override
    public boolean canHandle(String uri) { return URI_PATTERN.matcher(uri).matches(); }

    @Override
    public Map<String, String> extractParams(String uri) {
        Map<String, String> params = new HashMap<>();
        Matcher matcher = URI_PATTERN.matcher(uri);
        if (matcher.matches()) params.put("name", matcher.group(1));
        return params;
    }

    @Override
    public String readContent(Program program, Map<String, String> uriParams) {
        if (program == null) return "{\"error\": \"No program loaded\"}";

        try {
            ObjectNode json = objectMapper.createObjectNode();
            json.put("program", program.getName());

            ArrayNode segmentsArray = objectMapper.createArrayNode();
            int count = 0;

            for (MemoryBlock block : program.getMemory().getBlocks()) {
                ObjectNode segNode = objectMapper.createObjectNode();
                segNode.put("name", block.getName());
                segNode.put("start", block.getStart().toString());
                segNode.put("end", block.getEnd().toString());
                segNode.put("size", block.getSize());
                segNode.put("read", block.isRead());
                segNode.put("write", block.isWrite());
                segNode.put("execute", block.isExecute());
                segNode.put("volatile", block.isVolatile());
                segNode.put("initialized", block.isInitialized());

                String permissions = (block.isRead() ? "r" : "-") +
                                   (block.isWrite() ? "w" : "-") +
                                   (block.isExecute() ? "x" : "-");
                segNode.put("permissions", permissions);

                segmentsArray.add(segNode);
                count++;
            }

            json.put("count", count);
            json.set("segments", segmentsArray);

            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }
}
