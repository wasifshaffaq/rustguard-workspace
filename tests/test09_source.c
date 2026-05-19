// Test 09: C source with known vulnerabilities
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

void buffer_overflow(char *dst, const char *src) {
    strcpy(dst, src);  // CWE-120: no bounds check
}

void use_after_free() {
    int *p = (int *)malloc(sizeof(int));
    *p = 42;
    free(p);
    printf("%d\n", *p);  // CWE-416: use after free
}

void double_free() {
    int *p = (int *)malloc(sizeof(int));
    free(p);
    free(p);  // CWE-415: double free
}

int null_deref(int *p) {
    if (p)
        return *p;
    return *p;  // CWE-476: null deref
}

int integer_overflow() {
    int x = 2147483647;
    unsigned int y = x + 1;  // CWE-190: integer overflow
    return y;
}

void format_string(char *user_input) {
    printf(user_input);  // CWE-134: format string
}

void memory_leak() {
    int *p = (int *)malloc(100 * sizeof(int));
    // never freed — CWE-401
}

int shared_counter = 0;
void *thread_func(void *arg) {
    shared_counter++;  // CWE-362: race condition
    return NULL;
}

int oob_read(int *arr, int idx) {
    return arr[idx];  // CWE-125: no bounds check
}

int main() {
    char buf[10];
    buffer_overflow(buf, "this is way too long for the buffer");
    return 0;
}
