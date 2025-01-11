#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <Windows.h>
#include <ebpf_api.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <api_internal.h>
#include <iostream>
#include <cstring>
#include <io.h>
#include <fcntl.h>

