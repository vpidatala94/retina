FROM mcr.microsoft.com/oss/kubernetes/windows-host-process-containers-base-image:v1.0.0 As base

# build stages
COPY ./x64/Release/bpf_event_writer.sys C:/bpf_event_writer.sys
COPY ./x64/Release/event_writer.exe C:/event_writer.exe