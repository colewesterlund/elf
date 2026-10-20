#pragma once

// A systemd journal entry and its rendering in the agent's event form.
//
// The rule engine, buffer, formats and tests all work on the Windows event
// XML envelope (<Event><System>...</System><EventData><Data Name=..>...),
// so a journal entry is rendered into that shape: the syslog identifier (or
// "audit" for the audit transport) is the Channel, the audit record type
// number is the EventID, the journal fields become <Data> elements, and
// the microsecond timestamp doubles as the record id.
//
// Kernel audit events arrive as several journal entries that share an
// _AUDIT_ID (SYSCALL, EXECVE, CWD, PATH, PROCTITLE, EOE). AuditJoiner holds
// them together so each record is rendered with its siblings' fields, which
// is what lets an EXECVE rule see the executable and the audit key from the
// SYSCALL record.

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

struct sd_journal;

namespace elf {

struct JournalEntry {
    // KEY -> value in journal order. Values are bytes as stored (MESSAGE
    // may hold anything); rendering treats them as UTF-8.
    std::vector<std::pair<std::string, std::string>> fields;
    uint64_t realtimeUsec = 0;
    std::string cursor;

    const std::string* get(const std::string& key) const;
    bool isAudit() const;          // _TRANSPORT=audit
    std::string auditId() const;   // _AUDIT_ID, "" when absent
    int auditType() const;         // _AUDIT_TYPE as a number, -1 when absent
};

// Read the entry at the journal's current position. False on a read error.
bool readJournalEntry(sd_journal* j, JournalEntry& out);

// Channel of an entry: "audit" for the audit transport, else the syslog
// identifier, else the sending command, else the transport name.
std::string journalChannel(const JournalEntry& e);

// EventID of an entry: the audit record type number, 0 for everything else.
int journalEventId(const JournalEntry& e);

// Render the entry as event XML. `siblings` are the other records of the
// same audit event; their fields are merged into EventData where the
// entry has no field of the same name. Empty on failure.
std::wstring journalEntryToXml(const JournalEntry& e,
                               const std::vector<const JournalEntry*>& siblings);

// Groups audit records by _AUDIT_ID and emits each record with its
// siblings once the group is complete (EOE record), a different audit id
// arrives, the group has been idle, or the joiner is flushed. Non-audit
// entries pass straight through. EOE records are consumed, not emitted.
class AuditJoiner {
public:
    using Emit = std::function<void(const JournalEntry& e,
                                    const std::vector<const JournalEntry*>& siblings)>;
    explicit AuditJoiner(Emit emit) : m_emit(std::move(emit)) {}
    void push(JournalEntry e);
    void flushIfIdle(std::chrono::milliseconds idle);
    void flushAll();
private:
    void flushGroup();
    Emit m_emit;
    std::string m_groupId;
    std::vector<JournalEntry> m_group;
    std::chrono::steady_clock::time_point m_groupStarted;
};

// "2026-10-01T00:00:00Z" (optional fraction) -> journal microseconds.
bool parseIsoUtcUsec(const std::string& iso, uint64_t& usec);

} // namespace elf
