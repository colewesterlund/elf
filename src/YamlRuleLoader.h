#pragma once

#include "Rule.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace elf {

// A store of reusable lists loaded from a directory of newline-separated
// text files. Each file is one list; the file name (without extension) is
// the list name. Rules reference lists via `@@name` in field values.
//
// File format: one value per line. Lines starting with `#` are comments
// (ignored). Blank lines are skipped. Each remaining line is trimmed of
// trailing CR/whitespace and stored as one value.
//
// A missing list (no file) or an empty list (only comments/blanks) resolves
// to zero values. A field that references such a list matches nothing.
class ListStore {
public:
    // Load every *.txt file from `dir` into the store. Missing directory is
    // not an error (returns an empty store) so an agent with no lists dir
    // still loads rules; `@@` references just resolve to nothing.
    void loadFromDirectory(const std::string& dir);

    // Resolve a list by name. Returns nullptr if the list doesn't exist.
    const std::vector<std::string>* resolve(const std::string& name) const;

    // True if any list with this name exists (even if empty).
    bool exists(const std::string& name) const;

private:
    std::unordered_map<std::string, std::vector<std::string>> m_lists;
};

// Outcome of loading a rules directory. `rules` holds every rule that
// parsed and is enabled; the counters say what else was in the directory.
// Callers apply `rules` unless `dirMissing` (nothing could be read at all)
// or the pathological "nothing parsed but something failed" case; one bad
// file out of thousands must not freeze the whole ruleset (an all-or-nothing
// policy would keep every agent on its stale ruleset for as long as a single
// SigmaHQ rule that yaml-cpp rejects stays in the directory).
struct LoadSummary {
    std::vector<Detection> rules;
    size_t parsed = 0;     // files that produced an enabled rule
    size_t disabled = 0;   // parsed but status deprecated/unsupported
    size_t failed = 0;     // parse error, missing id, no valid actions, ...
    size_t missing = 0;    // vanished mid-enumeration (benign race)
    std::vector<std::string> failedFiles;  // first 20 failed paths
    bool dirMissing = false;

    // Whether the result should replace the current ruleset.
    bool applicable() const {
        return !dirMissing && !(parsed == 0 && disabled == 0 && failed > 0);
    }
};

// Load every *.yaml/*.yml in `dir` (expanding `@@list` references from
// `listsDir` when non-empty). Logs ONE summary line (not one per rule) and,
// if anything failed, one error line naming up to 20 failed files.
LoadSummary loadRules(const std::string& dir, const std::string& listsDir);

// Loads all `*.yaml` rule files from a directory. Each file contains exactly
// one detection (one rule per file). Returns the parsed detections;
// disabled rules are skipped.
//
// Uses yaml-cpp (added via CMake FetchContent). On parse error for a single
// file, that file is skipped with a warning printed to stderr; the rest are
// still loaded.
std::vector<Detection> loadRulesFromDirectory(const std::string& dir);

// Same as loadRulesFromDirectory, but also reports whether every YAML file in
// the directory parsed successfully. `allParsed` is set to false if any file
// failed to parse (syntax error, missing detection, or missing id). Use this
// for hot-reload: only swap in the new ruleset when allParsed is true, so a
// typo in one rule file doesn't silently drop an already-loaded rule.
std::vector<Detection> loadRulesFromDirectory(const std::string& dir, bool& allParsed);

// Same as above, but also loads reusable lists from `listsDir` and expands
// `@@list` references in field values. Use this overload when lists are
// available (the normal agent path). The lists-only overloads above remain
// for callers that don't have a lists directory.
std::vector<Detection> loadRulesFromDirectory(const std::string& dir,
                                               const std::string& listsDir,
                                               bool& allParsed);

// Convenience overload: load rules + lists without reporting allParsed
// (used for the initial local load at startup). Discards the parse-status
// flag; a single bad rule file is still skipped with a warning.
std::vector<Detection> loadRulesFromDirectory(const std::string& dir,
                                               const std::string& listsDir);

// Result of loading a single rule file.
enum class LoadResult {
    Ok,        // parsed successfully
    Failed,    // file exists but failed to parse (syntax error, missing id, etc.)
    Missing,   // file vanished before we could open it (benign TOCTOU race
               // with the poll thread's writeRulesToDisk, which deletes rule
               // files the server no longer includes). The caller should skip
               // this file WITHOUT marking the whole reload as failed.
};

// Load a single rule file. Exposed for unit testing. `lists` is optional;
// when provided, `@@list` references in field values are expanded from it.
LoadResult loadRuleFile(const std::string& path, Detection& out,
                        const ListStore* lists = nullptr);

// Backward-compatible wrapper: returns true if the file parsed successfully.
// Kept for any external callers that don't care about the Missing case.
inline bool loadRuleFileOk(const std::string& path, Detection& out) {
    return loadRuleFile(path, out) == LoadResult::Ok;
}

} // namespace elf
