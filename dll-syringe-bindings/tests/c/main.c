#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../bindings/c/dll-syringe.h"

int main(int argc, char** argv) {
    assert(argc == 3);

    uint32_t pid = (uint32_t)strtoul(argv[1], NULL, 10);
    const char* dll = argv[2];

    void* s = syringe_for_process(pid);
    assert(s != NULL);

    bool ok = syringe_inject(s, dll);
    assert(ok);

    syringe_free(s);
    return 0;
}
