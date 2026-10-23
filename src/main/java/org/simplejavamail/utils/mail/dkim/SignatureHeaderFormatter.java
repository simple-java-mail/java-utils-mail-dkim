package org.simplejavamail.utils.mail.dkim;

import java.util.Map;

/** Header formatting for the finalized-byte facade; the legacy wire format stays stable. */
final class SignatureHeaderFormatter {
    private static final int MAX_HEADER_LINE_LENGTH = 78;
    private static final String DKIM_SIGNATURE = "DKIM-Signature";
    private SignatureHeaderFormatter() { }
    static String serializeTags(final Map<String, String> tags) {
        int position = DKIM_SIGNATURE.length() + 2;
        final StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> tag : tags.entrySet()) {
            final String entry = tag.getKey() + "=" + tag.getValue() + ";";
            final int separatorLength = builder.length() == 0 ? 0 : 1;
            if ("h".equals(tag.getKey())) {
                if (position + separatorLength + 2 + firstHeaderNameLength(tag.getValue()) + 1 > MAX_HEADER_LINE_LENGTH) {
                    builder.append("\r\n\t");
                    position = 1;
                } else if (separatorLength > 0) {
                    builder.append(' ');
                    position++;
                }
                position = appendHeaderListTag(builder, tag.getValue(), position);
            } else {
                if (position + separatorLength + entry.length() > MAX_HEADER_LINE_LENGTH) {
                    builder.append("\r\n\t");
                    position = 1;
                } else if (separatorLength > 0) {
                    builder.append(' ');
                    position++;
                }
                builder.append(entry);
                position += entry.length();
            }
        }
        return builder.append("\r\n\tb=").toString();
    }

    private static int appendHeaderListTag(final StringBuilder builder, final String value, int position) {
        builder.append("h=");
        position += 2;
        final String[] headerNames = value.split(":");
        for (int i = 0; i < headerNames.length; i++) {
            final int separatorLength = i == 0 ? 0 : 1;
            if (i > 0 && position + separatorLength + headerNames[i].length() + 1 > MAX_HEADER_LINE_LENGTH) {
                builder.append(":\r\n\t");
                position = 1;
            } else if (i > 0) {
                builder.append(':');
                position++;
            }
            builder.append(headerNames[i]);
            position += headerNames[i].length();
        }
        builder.append(';');
        return position + 1;
    }

    private static int firstHeaderNameLength(final String value) {
        final int separator = value.indexOf(':');
        return separator >= 0 ? separator : value.length();
    }

    static String fold(final String value, int offset) {
        int position = 0;
        final StringBuilder folded = new StringBuilder();
        while (position < value.length()) {
            final int available = offset > 0
                    ? MAX_HEADER_LINE_LENGTH - 1 - offset
                    : MAX_HEADER_LINE_LENGTH - 1;
            final int end = Math.min(value.length(), position + available);
            if (position > 0 || offset == 0) {
                folded.append("\r\n\t");
            }
            folded.append(value, position, end);
            position = end;
            offset = 0;
        }
        return folded.toString();
    }

}
