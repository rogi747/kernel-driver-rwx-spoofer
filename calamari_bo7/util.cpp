#include "globals.h"
#include <stdarg.h>

void DbgLog(const char* Format, ...)
{
    va_list args;
    va_start(args, Format);

    char inner[495];
    int written = _vsnprintf(inner, sizeof(inner) - 1, Format, args);
    if (written < 0 || (unsigned)written >= sizeof(inner))
        inner[sizeof(inner) - 1] = '\0';

    va_end(args);

    char outer[600];
    SafeVsnprintf(outer, sizeof(outer), "[calamari] %s\r\n", inner);

    DbgPrintEx(0, 0, "%s", outer);
}

void SafeVsnprintf(char* Dest, SIZE_T MaxLen, const char* Format, ...)
{
    va_list args;
    va_start(args, Format);

    if (!MaxLen) {
        va_end(args);
        return;
    }

    SIZE_T limit = MaxLen - 1;
    int result = _vsnprintf(Dest, limit, Format, args);
    if (result < 0 || (SIZE_T)result >= limit)
        Dest[limit] = '\0';

    va_end(args);
}
