#include "XmlPretty.h"
#include "Platform.h"    // wideToUtf8
#include <sstream>

namespace elf {

// Pretty-print a single-line XML document: one tag per line, 2-space
// indentation per nesting level. Walks the string with a cursor and emits
// newlines + indentation between tags. Handles:
//   - opening tags <tag ...>
//   - closing tags </tag>
//   - self-closing tags <tag ... />
//   - text content between tags (on its own line when non-whitespace)
//   - comments <!-- ... -->
//   - CDATA <![CDATA[ ... ]]>
//
// Attributes are left untouched (kept on the same line as the tag name).
// The depth counter tracks nesting; a self-closing tag does not change
// depth. On any structural surprise we bail out and return the raw UTF-8
// conversion so the caller still gets usable (if ugly) output.
std::string prettyPrintXml(const std::wstring& xml) {
    if (xml.empty()) return std::string();

    std::ostringstream out;
    size_t i = 0;
    const size_t n = xml.size();
    int depth = 0;

    auto indent = [&]() {
        for (int k = 0; k < depth; ++k) out << "  ";
    };

    while (i < n) {
        // Skip whitespace between tags.
        while (i < n && (xml[i] == L' ' || xml[i] == L'\t' ||
                         xml[i] == L'\r' || xml[i] == L'\n')) {
            ++i;
        }
        if (i >= n) break;

        if (xml[i] != L'<') {
            // Text content until the next '<'. Emit on its own indented
            // line if it's non-whitespace.
            size_t start = i;
            while (i < n && xml[i] != L'<') ++i;
            std::wstring text = xml.substr(start, i - start);
            // Trim.
            size_t a = text.find_first_not_of(L" \t\r\n");
            size_t b = text.find_last_not_of(L" \t\r\n");
            if (a != std::wstring::npos) {
                out << "\n";
                indent();
                // Convert the trimmed text to UTF-8 inline.
                std::wstring trimmed = text.substr(a, b - a + 1);
                out << wideToUtf8(trimmed);
            }
            continue;
        }

        // We're at a '<'. Find the matching '>'.
        size_t end = xml.find(L'>', i);
        if (end == std::wstring::npos) {
            // Malformed; bail to raw conversion.
            return wideToUtf8(xml);
        }

        std::wstring tag = xml.substr(i, end - i + 1); // includes <...>

        // Comment?
        if (tag.compare(0, 4, L"<!--") == 0) {
            // Find the closing -->.
            size_t cend = xml.find(L"-->", i);
            if (cend == std::wstring::npos) return wideToUtf8(xml);
            std::wstring comment = xml.substr(i, cend + 3 - i);
            out << "\n";
            indent();
            out << wideToUtf8(comment);
            i = cend + 3;
            continue;
        }

        // CDATA?
        if (tag.compare(0, 9, L"<![CDATA[") == 0) {
            size_t cend = xml.find(L"]]>", i);
            if (cend == std::wstring::npos) return wideToUtf8(xml);
            std::wstring cdata = xml.substr(i, cend + 3 - i);
            out << "\n";
            indent();
            out << wideToUtf8(cdata);
            i = cend + 3;
            continue;
        }

        // Closing tag </tag>?
        if (tag.size() >= 2 && tag[1] == L'/') {
            if (depth > 0) --depth;
            out << "\n";
            indent();
            out << wideToUtf8(tag);
            i = end + 1;
            continue;
        }

        // Opening or self-closing tag. Detect self-closing (ends with />).
        bool selfClose = (tag.size() >= 2 && tag[tag.size() - 2] == L'/');
        out << "\n";
        indent();
        out << wideToUtf8(tag);
        if (!selfClose) ++depth;
        i = end + 1;
    }

    // The leading newline (from the first indent() call) is harmless for a
    // file append, but trim it for cleanliness so the payload starts with
    // the root tag directly.
    std::string s = out.str();
    if (!s.empty() && s[0] == '\n') s.erase(s.begin());
    return s;
}

} // namespace elf
