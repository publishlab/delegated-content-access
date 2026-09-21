// The JSON reading and writing this probe uses. The JDK ships no JSON parser, and the
// probe reads one fixture and writes one observation object, so the reading half
// is a small recursive descent over the fixture's own grammar and the writing
// half prints an ordered map.

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class Json {
    private final String text;
    private int at;

    private Json(String text) {
        this.text = text;
    }

    static Object parse(String text) {
        Json reader = new Json(text);
        reader.skipSpace();
        Object value = reader.value();
        reader.skipSpace();
        if (reader.at != text.length()) {
            throw new IllegalArgumentException("trailing text at " + reader.at);
        }
        return value;
    }

    private void skipSpace() {
        while (at < text.length() && Character.isWhitespace(text.charAt(at))) {
            at++;
        }
    }

    private Object value() {
        char c = text.charAt(at);
        switch (c) {
            case '{': return object();
            case '[': return array();
            case '"': return string();
            case 't': at += 4; return Boolean.TRUE;
            case 'f': at += 5; return Boolean.FALSE;
            case 'n': at += 4; return null;
            default: return number();
        }
    }

    private Map<String, Object> object() {
        Map<String, Object> out = new LinkedHashMap<>();
        at++; // {
        skipSpace();
        if (text.charAt(at) == '}') {
            at++;
            return out;
        }
        while (true) {
            skipSpace();
            String key = string();
            skipSpace();
            at++; // :
            skipSpace();
            out.put(key, value());
            skipSpace();
            char c = text.charAt(at++);
            if (c == '}') {
                return out;
            }
            if (c != ',') {
                throw new IllegalArgumentException("expected , or } at " + at);
            }
        }
    }

    private List<Object> array() {
        List<Object> out = new ArrayList<>();
        at++; // [
        skipSpace();
        if (text.charAt(at) == ']') {
            at++;
            return out;
        }
        while (true) {
            skipSpace();
            out.add(value());
            skipSpace();
            char c = text.charAt(at++);
            if (c == ']') {
                return out;
            }
            if (c != ',') {
                throw new IllegalArgumentException("expected , or ] at " + at);
            }
        }
    }

    private String string() {
        StringBuilder out = new StringBuilder();
        at++; // "
        while (true) {
            char c = text.charAt(at++);
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char escape = text.charAt(at++);
            switch (escape) {
                case 'n': out.append('\n'); break;
                case 't': out.append('\t'); break;
                case 'r': out.append('\r'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case 'u':
                    out.append((char) Integer.parseInt(text.substring(at, at + 4), 16));
                    at += 4;
                    break;
                default: out.append(escape);
            }
        }
    }

    private Object number() {
        int start = at;
        while (at < text.length() && "+-.eE0123456789".indexOf(text.charAt(at)) >= 0) {
            at++;
        }
        String raw = text.substring(start, at);
        if (raw.indexOf('.') < 0 && raw.indexOf('e') < 0 && raw.indexOf('E') < 0) {
            return Long.valueOf(raw);
        }
        return Double.valueOf(raw);
    }

    // The writing half: two-space indentation, insertion order, and the escapes
    // this observation shape can produce.
    static String write(Object value, int indent) {
        String pad = " ".repeat(indent);
        String inner = " ".repeat(indent + 2);
        if (value instanceof Map<?, ?> map) {
            if (map.isEmpty()) {
                return "{}";
            }
            StringBuilder out = new StringBuilder("{\n");
            int left = map.size();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                out.append(inner).append(quote(String.valueOf(entry.getKey()))).append(": ")
                   .append(write(entry.getValue(), indent + 2)).append(--left > 0 ? ",\n" : "\n");
            }
            return out.append(pad).append('}').toString();
        }
        if (value instanceof String text) {
            return quote(text);
        }
        return String.valueOf(value);
    }

    private static String quote(String text) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.append('"').toString();
    }
}
