#pragma once

#include <windows.h>
#include <winevt.h>
#include <string>

namespace elf {

// Render an event handle to its XML representation via EvtRender.
// Shared by EventCollector (push subscription callback) and EventQueryCollector
// (historical EvtQuery pull) so both produce identical event XML.
// Returns an empty wstring on failure.
std::wstring renderEventXml(EVT_HANDLE hEvent);

} // namespace elf
