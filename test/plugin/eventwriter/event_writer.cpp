#include <winsock2.h>
#include <iphlpapi.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <vector>
#include "event_writer.h"
#include <vector>

std::vector<std::pair<int, struct bpf_link*>> link_list;
bpf_object* obj = NULL;

int
set_filter(struct filter* flt) {
    uint8_t key = 0;
    int map_flt_fd = 0;

    // Attempt to open the pinned map
    map_flt_fd = bpf_obj_get(FILTER_MAP_PIN_PATH);
    if (map_flt_fd < 0) {
        fprintf(stderr, "%s - failed to lookup filter_map\n", __FUNCTION__);
        return 1;
    }
    if (bpf_map_update_elem(map_flt_fd, &key, flt, 0) != 0) {
        fprintf(stderr, "%s - failed to update filter\n", __FUNCTION__);
        return 1;
    }
    return 0;
}

int pin_map(const char* pin_path, bpf_map* map) {
    int map_fd = 0;
    // Attempt to open the pinned map
    map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        // Get the file descriptor of the map
        map_fd = bpf_map__fd(map);

        if (map_fd < 0) {
            fprintf(stderr, "%s - failed to get map file descriptor\n", __FUNCTION__);
            return 1;
        }

        if (bpf_obj_pin(map_fd, pin_path) < 0) {
            fprintf(stderr, "%s - failed to pin map to %s\n", pin_path, __FUNCTION__);
            return 1;
        }

        printf("%s - map successfully pinned at %s\n", pin_path, __FUNCTION__);
    } else {
        printf("%s -pinned map found at %s\n", pin_path, __FUNCTION__);
    }
    return 0;
}

std::vector<int> get_physical_interface_indices()
{
    std::vector<int> physical_indices;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG family = AF_UNSPEC;
    ULONG outBufLen = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

    // Get the size needed for the buffer
    if (GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    }

    // Get the actual data
    if (GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if (pCurrAddresses->IfType == IF_TYPE_ETHERNET_CSMACD && pCurrAddresses->OperStatus == IfOperStatusUp) {
                physical_indices.push_back(pCurrAddresses->IfIndex);
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }

    if (pAddresses) {
        free(pAddresses);
    }

    return physical_indices;
}

int
attach_program_to_interface(int ifindx) {
    printf("%s - Attaching program to interface with ifindex %d\n", ifindx, __FUNCTION__);
    struct bpf_program* prg = bpf_object__find_program_by_name(obj, "event_writer");
    bpf_link* link = NULL;
    if (prg == NULL) {
        fprintf(stderr, "%s - failed to find event_writer program", __FUNCTION__);
        return 1;
    }

    link = bpf_program__attach_xdp(prg, ifindx);
    if (link == NULL) {
        fprintf(stderr, "%s - failed to attach to interface with ifindex %d\n", __FUNCTION__, ifindx);
        return 1;
    }

    link_list.push_back(std::pair<int, bpf_link*>{ifindx, link});
    return 0;
}

int
pin_maps_load_programs(void) {
    struct bpf_program* prg = NULL;
    struct bpf_map *map_ev, *map_met, *map_fvt, *map_flt;
    struct filter flt;
    // Load the BPF object file
    obj = bpf_object__open("bpf_event_writer.sys");
    if (obj == NULL) {
        fprintf(stderr, "%s - failed to open BPF sys file\n", __FUNCTION__);
        return 1;
    }

    // Load cilium_events map and tcp_connect bpf program
    if (bpf_object__load(obj) < 0) {
        fprintf(stderr, "%s - failed to load BPF sys\n", __FUNCTION__);
        bpf_object__close(obj);
        return 1;
    }

    // Find the map by its name
    map_ev = bpf_object__find_map_by_name(obj, "cilium_events");
    if (map_ev == NULL) {
        fprintf(stderr, "%s - failed to find cilium_events by name\n", __FUNCTION__);
        bpf_object__close(obj);
        return 1;
    }
    if (pin_map(EVENTS_MAP_PIN_PATH, map_ev) != 0) {
        return 1;
    }

    // Find the map by its name
    map_met = bpf_object__find_map_by_name(obj, "cilium_metrics");
    if (map_met == NULL) {
        fprintf(stderr, "%s - failed to find cilium_metrics by name\n", __FUNCTION__);
        bpf_object__close(obj);
        return 1;
    }
    if (pin_map(METRICS_MAP_PIN_PATH, map_ev) != 0) {
        return 1;
    }

    // Find the map by its name
    map_fvt = bpf_object__find_map_by_name(obj, "five_tuple_map");
    if (map_fvt == NULL) {
        fprintf(stderr, "%s - failed to find five_tuple_map by name\n", __FUNCTION__);
        bpf_object__close(obj);
        return 1;
    }
    if (pin_map(FIVE_TUPLE_MAP_PIN_PATH, map_fvt) != 0) {
        return 1;
    }

    // Find the map by its name
    map_flt = bpf_object__find_map_by_name(obj, "filter_map");
    if (map_flt == NULL) {
        fprintf(stderr, "%s - failed to lookup filter_map\n", __FUNCTION__);
        return 1;
    }
    if (pin_map(FILTER_MAP_PIN_PATH, map_flt) != 0) {
        return 1;
    }

    memset(&flt, 0, sizeof(flt));
    flt.event = 4; // TRACE
    if (set_filter(&flt) != 0) {
        return 1;
    }

    return 0; // Return success
}

// Function to unload programs and detach
int
unload_programs_detach() {
    for (auto it = link_list.begin(); it != link_list.end(); it ++) {
        auto ifidx = it->first;
        auto link = it->second;
        auto link_fd = bpf_link__fd(link);
        if (bpf_link_detach(link_fd) != 0) {
            fprintf(stderr, "%s - failed to detach link %d\n", __FUNCTION__, ifidx);
        }
        if (bpf_link__destroy(link) != 0) {
            fprintf(stderr, "%s - failed to destroy link %d", __FUNCTION__, ifidx);
        }
    }

    if (obj != NULL) {
        bpf_object__close(obj);
    }

    return 0;
}

int main(int argc, char* argv[]) {
    int ret;

    printf ("Starting event writer\n");
    ret = pin_maps_load_programs();
    if (ret != 0) {
        return ret;
    }
    std::vector<int> interface_indices = get_physical_interface_indices();
    for (int ifindx : interface_indices) {
        ret = attach_program_to_interface(ifindx);
        if (ret != 0) {
            return ret;
        }
    }

    //Sleep for 10 minutes
    Sleep(600000);
    unload_programs_detach();
    return 0;
}