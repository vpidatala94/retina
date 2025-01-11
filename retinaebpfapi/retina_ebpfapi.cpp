// retina_ebpfapi.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "retina_ebpfapi.h"

/// <summary>
/// Callback function for the events map
/// </summary>
/// <param name="ctx">The context</param>
/// <param name="data">The data</param>
/// <param name="size">The size of the data</param>
/// <returns></returns>
int
events_map_callback(void* ctx, void* data, size_t size)
{
    ringBuffer_Callback callBack = (ringBuffer_Callback)ctx;
    callBack(data, size);
    return 0;
}


/// <summary>
/// Enumerate the cilium metrics map
/// </summary>
/// <param name="enumCallBack">The callback function that is invoked for each record in the metrics map.</param>
/// <returns>NOERROR on succcess else the error code.</returns>
DWORD 
enumerate_cilium_metricsmap(
    _In_ mapEnum_Callback enumCallBack
    )
{
   
    metrics_map_key* old_key = nullptr;
    metrics_map_value* value = nullptr;
    metrics_map_key key = {};
    int result;
    int nr_cpus;
    nr_cpus = libbpf_num_possible_cpus();

    std::string map_name = CILIUM_METRICS_MAP;
    auto full_map_name = CILIUM_MAP_PIN_PATH_PREFIX + map_name;
    fd_t map_fd = bpf_obj_get(full_map_name.c_str());

    if (map_fd == ebpf_fd_invalid) {
        return ERROR_FILE_NOT_FOUND;
    }

    value = (metrics_map_value*)malloc(sizeof(metrics_map_value) * nr_cpus);
    
    if (value == nullptr) {
        return ERROR_OUTOFMEMORY;
    }

    while (bpf_map_get_next_key(map_fd, old_key, &key) == 0) {
        result = bpf_map_lookup_elem(map_fd, &key, value);

        if (result != EBPF_SUCCESS) {
            return result;
        }

        enumCallBack(&key, value, nr_cpus);
        old_key = &key;
    }

    if (map_fd != ebpf_fd_invalid) {
        _close(map_fd);
    }

    if (value != nullptr) {
        free(value);
    }
    
    return 0;
}

/// <summary>
/// Register a callback for the cilium events map
/// </summary>
/// <param name="RingBufferCallback"></param>
/// <param name="RingBuffer"></param>
/// <returns></returns>
DWORD
register_cilium_eventsmap_callback(
    _In_ ringBuffer_Callback RingBufferCallback,
    _Out_ void** RingBuffer
    )
{
    std::string map_name = CILIUM_EVENTS_MAP;
    auto full_map_name = CILIUM_MAP_PIN_PATH_PREFIX + map_name;

    if (RingBuffer == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    *RingBuffer = nullptr;

    fd_t map_fd = bpf_obj_get(full_map_name.c_str());

    if (map_fd == ebpf_fd_invalid) {
        return ERROR_FILE_NOT_FOUND;
    }

    // Subscribe our callback to the EVENTS_MAP ring buffer map.
    auto eventsRingBufferMap = ring_buffer__new(map_fd, 
                                    events_map_callback,
                                    (void*)RingBufferCallback, 
                                    nullptr);

    if (eventsRingBufferMap == nullptr) {
        return E_OUTOFMEMORY;
    }

    *RingBuffer = eventsRingBufferMap;
    return 0;
}

DWORD
unregister_cilium_eventsmap_callback(
    _In_ void* RingBuffer
    )
{
    if (RingBuffer == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    
    ring_buffer__free((ring_buffer*)RingBuffer);
    return 0;
}