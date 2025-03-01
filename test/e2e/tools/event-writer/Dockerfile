FROM mcr.microsoft.com/windows/servercore:ltsc2022 As base

# build stages
COPY ./x64/Release/bpf_event_writer.sys ./bpf_event_writer.sys
COPY ./x64/Release/event_writer.exe ./event_writer.exe