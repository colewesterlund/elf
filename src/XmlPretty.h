#pragma once

#include <string>

namespace elf {

// Pretty-print a single-line XML string (as produced by EvtRender) so each
// tag sits on its own line with 2-space indentation. The input is the
// rendered event XML (UTF-16 wstring); the output is UTF-8.
//
// This is a minimal string-scan formatter, NOT a validating XML parser. It
// handles the shape EvtRender produces (well-formed, no internal
// newlines, attributes quoted with "). If the input is malformed it falls
// back to returning the raw UTF-8 conversion.
std::string prettyPrintXml(const std::wstring& xml);

} // namespace elf
