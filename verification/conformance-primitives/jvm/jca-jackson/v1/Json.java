import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The JSON reader the operation bridge ({@link Bridge}) uses: an object
 * model over Jackson's tree model. Jackson does the parsing, and the code here
 * gives the result the shape the bridge reads.
 *
 * The JDK ships no JSON parser, so the lane pins Jackson through
 * `install-toolchain` and compiles and runs against those jars. Jackson reads
 * the bytes and {@link ObjectNode} holds the result; the accessors below hand
 * the bridge Java values, so no operation touches a Jackson type.
 *
 * Malformed input throws {@link JsonException}. Nothing is repaired and nothing
 * is guessed: a batch that does not parse leaves the bridge unable to answer,
 * which is what it then reports.
 */
public final class Json {

    /**
     * One mapper, configured once. Trailing tokens fail the read, so a batch
     * with a second document after the first is malformed here rather than
     * silently answered from its first half. Everything else is Jackson's
     * default reading of RFC 8259: no comments, no single quotes, no trailing
     * commas, no NaN and no leading zero.
     */
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    /**
     * A JSON null member. Present, so {@link OMap#has} returns true, and not a
     * string, so {@link OMap#str} returns "". Java's own null means absent here,
     * and the two have to stay apart: `{"x": null}` names a member, and an
     * object without `x` does not. The Go bridge keeps the same distinction by
     * reading an object as `map[string]json.RawMessage`, where a member written
     * null is present carrying the bytes `null`.
     */
    public static final Object NULL = new Object() {
        @Override
        public String toString() {
            return "null";
        }
    };

    private Json() {
    }

    /** Parses one JSON object, the shape the request batch and every key inside it has. */
    public static OMap parse(String text) {
        Object value = parseValue(text);
        if (!(value instanceof OMap map)) {
            throw new JsonException("the top-level value is not a JSON object");
        }
        return map;
    }

    /** Parses one JSON value of any kind, for the arrays and scalars inside a batch. */
    public static Object parseValue(String text) {
        if (text == null) {
            throw new JsonException("no input");
        }
        JsonNode node;
        try {
            node = MAPPER.readTree(text);
        } catch (JacksonException e) {
            throw new JsonException(e.getOriginalMessage());
        }
        // Jackson reads empty input as a missing node rather than throwing, and
        // empty input has no JSON value.
        if (node == null || node.isMissingNode()) {
            throw new JsonException("no JSON value");
        }
        return value(node);
    }

    /** Malformed input, named. Unchecked so one caller catches it at one place. */
    public static final class JsonException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        JsonException(String message) {
            super(message);
        }
    }

    // ---- the object model --------------------------------------------------

    /**
     * A JSON object, read through the node Jackson parsed.
     *
     * Values come back as the Java shapes the bridge reads: {@link OMap} for an
     * object, {@link List} for an array, String, Boolean, Long or Double for a
     * number, and {@link Json#NULL} for a JSON null. The typed accessors answer
     * "" or null for a member that is absent or of another kind, so a reader
     * never has to test the kind first.
     */
    public static final class OMap {

        private final ObjectNode node;

        OMap(ObjectNode node) {
            this.node = node;
        }

        /** Member names in the order the object wrote them, one entry per name. */
        public List<String> keys() {
            List<String> names = new ArrayList<>(node.size());
            for (Map.Entry<String, JsonNode> member : node.properties()) {
                names.add(member.getKey());
            }
            return List.copyOf(names);
        }

        /** Whether the object carries this name at all, including one written as null. */
        public boolean has(String key) {
            return node.has(key);
        }

        /** The value as parsed, or null when the name is absent. For arrays and nested values. */
        public Object raw(String key) {
            JsonNode member = node.get(key);
            return member == null ? null : value(member);
        }

        /** A string member, or "" when it is absent or is not a string. */
        public String str(String key) {
            JsonNode member = node.get(key);
            return member != null && member.isTextual() ? member.textValue() : "";
        }

        /** An object member, or null when it is absent or is not an object. */
        public OMap obj(String key) {
            JsonNode member = node.get(key);
            return member instanceof ObjectNode object ? new OMap(object) : null;
        }

        /** An array member, or null when it is absent or is not an array. */
        public List<Object> list(String key) {
            JsonNode member = node.get(key);
            return member != null && member.isArray() ? elements(member) : null;
        }
    }

    // ---- node to Java value ------------------------------------------------

    /**
     * One parsed node as the Java value the bridge reads. An integral number
     * inside a long comes back as Long so a count prints as 3 and not 3.0;
     * anything else numeric comes back as Double, which is the one number type
     * JSON has.
     */
    private static Object value(JsonNode node) {
        if (node instanceof ObjectNode object) {
            return new OMap(object);
        }
        if (node.isArray()) {
            return elements(node);
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isNull()) {
            return NULL;
        }
        if (node.isIntegralNumber() && node.canConvertToLong()) {
            return node.longValue();
        }
        if (node.isNumber()) {
            return node.doubleValue();
        }
        throw new JsonException("a JSON value of kind " + node.getNodeType() + " is not one this reader answers");
    }

    /**
     * An array's elements, as an immutable snapshot rather than a view on the
     * parsed document: nothing here mutates what was parsed, and an immutable
     * answer keeps it that way. The elements are never Java null, so copyOf is
     * safe on them.
     */
    private static List<Object> elements(JsonNode array) {
        List<Object> out = new ArrayList<>(array.size());
        for (JsonNode element : array) {
            out.add(value(element));
        }
        return List.copyOf(out);
    }
}
