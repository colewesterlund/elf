#include "EventRender.h"

namespace elf {

std::wstring renderEventXml(EVT_HANDLE hEvent) {
    DWORD bufSize = 0, bufUsed = 0, propCount = 0;
    EvtRender(nullptr, hEvent, EvtRenderEventXml, bufSize, nullptr, &bufUsed, &propCount);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return L"";

    bufSize = bufUsed;
    std::wstring xml;
    xml.resize(bufSize / sizeof(WCHAR));
    if (EvtRender(nullptr, hEvent, EvtRenderEventXml, bufSize, &xml[0], &bufUsed, &propCount)) {
        xml.resize(bufUsed / sizeof(WCHAR));
        return xml;
    }
    return L"";
}

} // namespace elf
