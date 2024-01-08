# syntax=docker/dockerfile:1
#
# docker buildx build --pull --platform linux/amd64 --load --tag northstar-runtime:amd64 .
# docker buildx build --pull --platform linux/arm64 --load --tag northstar-runtime:arm64 .
# docker run --rm  --network host -itv /path/to/northstar/installation:/mnt northstar-runtime:amd64 -dedicated +setplaylist aitdm +launchplaylist aitdm +ns_should_return_to_lobby 0
# note: you can extract /opt/northstar-runtime from the container and run it on most recent glibc-based distros

# get the latest debian bookworm ca-certificates and tzdata
# - https://sourcegraph.com/github.com/wine-mirror/wine@wine-9.0-rc3/-/blob/dlls/crypt32/unixlib.c?L616 (/etc/ssl/certs)
# - https://sourcegraph.com/github.com/wine-mirror/wine@wine-9.0-rc3/-/blob/dlls/ntdll/unix/system.c?L2348 (libc licaltime function)
FROM --platform=linux/amd64 docker.io/debian:bookworm AS build-data
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates tzdata && apt-get clean

# patch the winehq amd64 packages and generate the wineprefix
FROM --platform=linux/amd64 docker.io/debian:bookworm AS build-wine

# install full winehq package
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates && apt-get clean
RUN dpkg --add-architecture i386 && \
    echo 'deb [trusted=yes] https://dl.winehq.org/wine-builds/debian bookworm main' > /etc/apt/sources.list.d/winehq.list && \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y winehq-devel=9.0~rc3~bookworm-1 wine-devel=9.0~rc3~bookworm-1 wine-devel-amd64=9.0~rc3~bookworm-1 wine-devel-i386=9.0~rc3~bookworm-1 && apt-get clean && \
    rm /etc/apt/sources.list.d/winehq.list

# install some tools
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y xxd bsdmainutils gawk binutils-mingw-w64 pax-utils && apt-get clean

# rename wine dir
RUN mv /opt/wine-devel /opt/northstar-runtime

# remove wine32
RUN rm -rf /opt/northstar-runtime/lib

# remove manpages
RUN rm -vrf /opt/northstar-runtime/share/man

# remove desktop launchers
RUN rm -vrf /opt/northstar-runtime/share/applications

# only keep essential wine64 executables
RUN ls -1 /opt/northstar-runtime/bin | \
    grep -Fvx \
        -e wine64 \
        -e wine64-preloader \
        -e wineserver \
    | \
    xargs printf "/opt/northstar-runtime/bin/%s\0" | \
    xargs -0 rm -v

# remove unused static libs
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/*.a

# remove directshow filters
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-windows/*.ax

# remove wine mono stub
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/mscoree.*

# remove wine gecko stub
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/mshtml.*

# remove wine desktop launcher builder
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/winemenubuilder.*

# patch default graphics driver list "mac,x11" (utf-16) to "null"
# note: this is the only way other than recompiling to get it to use nulldrv during prefix initialization
RUN hexdump -ve '1/1 "%.2x "' /opt/northstar-runtime/lib64/wine/x86_64-windows/explorer.exe > /opt/northstar-runtime/lib64/wine/x86_64-windows/explorer.exe.hex && \
    f="00 6d 00 61 00 63 00 2c 00 78 00 31 00 31 00 00 00" && \
    r="00 6e 00 75 00 6c 00 6c 00 00 00 00 00 00 00 00 00" && \
    grep -q "$f" /opt/northstar-runtime/lib64/wine/x86_64-windows/explorer.exe.hex && \
    sed -i "s/$f/$r/g" /opt/northstar-runtime/lib64/wine/x86_64-windows/explorer.exe.hex && \
    xxd -r -ps /opt/northstar-runtime/lib64/wine/x86_64-windows/explorer.exe.hex /opt/northstar-runtime/lib64/wine/x86_64-windows/explorer.exe && \
    rm /opt/northstar-runtime/lib64/wine/x86_64-windows/explorer.exe.hex

# remove unnecessary drivers
# - keep mountmgr since it's used internally for a lot of stuff (e.g., virtual drive info, creating links)
# note: for necessary ones, if any, add a line like "whatever.drv) continue ;; \"
RUN for drv in /opt/northstar-runtime/lib64/wine/x86_64-windows/*.sys /opt/northstar-runtime/lib64/wine/x86_64-windows/*.drv ; do case "$(basename "$drv")" in \
        ksecdd.sys) ;; \
        winspool.drv) ;; \
        winebus.sys) ;; \
        tdi.sys) ;; \
        usbd.sys) ;; \
        nsiproxy.sys) ;; \
        msacm32.drv) continue ;; \
        cng.sys) ;; \
        ndis.sys) ;; \
        http.sys) ;; \
        winehid.sys) ;; \
        hidparse.sys) ;; \
        winepulse.drv) ;; \
        wineusb.sys) ;; \
        wineps.drv) ;; \
        scsiport.sys) ;; \
        fltmgr.sys) ;; \
        winealsa.drv) ;; \
        winexinput.sys) ;; \
        winex11.drv) ;; \
        hidclass.sys) ;; \
        netio.sys) ;; \
        winewayland.drv) ;; \
        mountmgr.sys) continue ;; \
        *) echo "FIXME: is $(basename $drv) necessary?" ; exit 1 ;; \
    esac ; rm -vf "$drv" "/opt/northstar-runtime/lib64/wine/x86_64-unix/$(basename "$drv" | cut -d. -f1).so" ; done

# remove d3d/d2d/ddraw/dmusic/opengl/opencl/vulkan stuff (it's big, and it's definitely completely useless without the non-nulldrv graphics drivers anyways)
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/d3d* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/d2d* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/dxgi* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/ddraw* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/dmusic* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/dplay* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/qedit* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/winevulkan* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/wined3d* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/opencl* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/opengl* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/vulkan*

# also remove xaudio/xactengine/xapofx/x3daudio
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/xaudio* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/xactengine* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/xapofx* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/x3daudio*

# remove wow64
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/wow64*

# remove print/scan/telephony/smartcard/media/speech/webcam stuff
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/tapi32.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/sane.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/twain_32.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/gphoto2.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/wiaservc.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/sapi.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/twinapi.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/winprint.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/localspl.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/winscard.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/ctapi32.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/winegstreamer.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/wmphoto.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/msttsengine.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/qcap.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/wmp.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/windows.gaming.input.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/windows.media.speech.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/mfmediaengine.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/mfreadwrite.*

# remove misc stuff
RUN rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/msi.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/dwrite.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/gdiplus.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/winhlp32.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/oledb32.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/odbc32.* && \
    rm -v /opt/northstar-runtime/lib64/wine/x86_64-*/wpcap.*

# remove binaries which depend on the stuff we just removed
RUN pass=0 ; \
    touch /tmp/did_remove_binary ; \
    while test -f /tmp/did_remove_binary ; \
    do \
        pass=$((pass+1)) ; \
        echo "pass $pass" ; \
        rm -f /tmp/did_remove_binary ; \
        find /opt/northstar-runtime/lib64/wine/x86_64-windows/ -name '*.exe' -or -name '*.dll' | \
            while read pe ; \
            do \
                x86_64-w64-mingw32-objdump -x "$pe" | \
                    grep 'DLL Name:' | \
                    cut -d: -f2 | \
                    tr -d ' ' | \
                    while read import ; \
                    do \
                        if ! find /opt/northstar-runtime/lib64/wine/x86_64-windows/ -iname $import | grep -q . ; \
                        then \
                            touch /tmp/did_remove_binary ; \
                            echo "removing '$pe' since we don't have '$import'" ; \
                            rm -f "$pe" "/opt/northstar-runtime/lib64/wine/x86_64-unix/$(basename "$pe" | cut -d. -f1).so" ; \
                            break ; \
                        fi ; \
                    done ; \
            done ; \
    done

# patch wine.inf (mostly so wineboot doesn't complain as much or error out, and a little bit of extra tidying)
RUN gawk -i inplace '{ if (match($0, /^\[(.+)\]$/, m)) { header=1 ; section=m[1] } else { header=0 } } \
    (match(section, /Install\.(NT|ntarm|ntarm64|ntx86)(|\.Services)$/)) { next } \
    (match(section, /^CurrentVersionWow64\./)) { next } \
    (!header) { sub(/CurrentVersionWow64\.[^.]+,/, "") } \
    (!header && section == "Wow64") { next } \
    (!header && section == "FakeDllsWow64") { next } \
    (!header && section == "FakeDllsWin32") { next } \
    (!header && section == "Tapi") { next } \
    (!header && section == "DirectX") { next } \
    (!header && match($0, /^wineps.drv/)) { next } \
    (!header && match($0, /^(sane|gphoto2)\.ds/)) { next } \
    (!header && match($0, /^(input|winebus|winehid|wineusb|winexinput)\.inf/)) { next } \
    (!header && match($0, /(oledb32|msdaps|msdasql|msado15|winprint|sapi)\.dll/)) { next } \
    (!header && match($0, /(wmplayer|wordpad|iexplore)\.exe/)) { next } \
    (!header && match($0, /winemenubuilder/)) { next } \
    (!header && match($0, /^system\.ini,\s*(mci|drivers32|mail)/)) { next } \
    (match(section, /^(BITS|EventLog|HTTP|MSI|NDIS|NsiProxy|ScardSvr|Spooler|Winmgmt|Sti|PlugPlay|WPFFontCache|LanmanServer|FontCache|TaskScheduler|wuau|Terminal)(Services?|ServiceKeys)$/)) { next } \
    (!header && match($0, /^AddService=.+,(BITS|EventLog|HTTP|MSI|NDIS|NsiProxy|ScardSvr|Spooler|Winmgmt|Sti|PlugPlay|WPFFontCache|LanmanServer|FontCache|TaskScheduler|wuau|Terminal)(Services?)$/)) { next } \
    1' /opt/northstar-runtime/share/wine/wine.inf

# create a wineprefix and disable automatic prefix updates
ENV WINEARCH=win64 WINEPREFIX=/opt/northstar-runtime/prefix USER=nswrap
RUN WINEDEBUG=err-ole,fixme-actctx /opt/northstar-runtime/bin/wine64 wineboot --init && /opt/northstar-runtime/bin/wineserver --wait
RUN echo disable > $WINEPREFIX/.update-timestamp

# clean up empty dirs
RUN find /opt/northstar-runtime/prefix/drive_c -type d -empty -print -delete

# replace duplicated files in the prefix with symlinks
RUN find /opt/northstar-runtime/prefix/drive_c/windows -type f | \
    while read x ; \
    do \
        if cmp -s "/opt/northstar-runtime/lib64/wine/x86_64-windows/$(basename "$x")" "$x" ; \
        then ln -vsf --relative "/opt/northstar-runtime/lib64/wine/x86_64-windows/$(basename "$x")" "$x" ; \
        elif cmp -s "/opt/northstar-runtime/share/wine/nls/$(basename "$x")" "$x" ; \
        then ln -vsf --relative "/opt/northstar-runtime/share/wine/nls/$(basename "$x")" "$x" ; \
        fi ; \
    done

# set some registry keys required for nswrap
RUN /opt/northstar-runtime/bin/wine64 reg add 'HKCU\Software\Wine\WineDbg' /v 'ShowCrashDialog' /t REG_DWORD /d 0 /f && \
    /opt/northstar-runtime/bin/wine64 reg add 'HKLM\System\CurrentControlSet\Services\WineBus' /v 'DisableHidraw' /t REG_DWORD /d 1 /f && \
    /opt/northstar-runtime/bin/wine64 reg add 'HKLM\System\CurrentControlSet\Services\WineBus' /v 'DisableInput' /t REG_DWORD /d 1 /f && \
    /opt/northstar-runtime/bin/wine64 reg add 'HKLM\System\CurrentControlSet\Services\WineBus' /v 'Enable SDL' /t REG_DWORD /d 0 /f && \
    /opt/northstar-runtime/bin/wineserver --wait

# note: we could using inotify while exec'ing northstar and waiting for it to
# load, then remove everything not used, which saves another few hundred
# megabytes of space, but it's probably not worth it for now since we're using a
# common runtime base image for the versioned docker images, and it's better to
# keep some more libs for future-proofing stuff
#
# inotifywait --out-file /tmp/inotify.log --event open --csv --recursive /opt/northstar-runtime/prefix/drive_c/windows
# ...

# ensure we have some must-have dlls for northstar (based on inotify on ns1.21.0 with wine9.0-rc2)
RUN for x in \
        actxprxy.dll advapi32.dll avifil32.dll bcrypt.dll combase.dll comctl32.dll \
        coml2.dll concrt140.dll conhost.exe crypt32.dll dbghelp.dll \
        dnsapi.dll dsound.dll explorer.exe gdi32.dll hid.dll imm32.dll iphlpapi.dll \
        kerberos.dll kernel32.dll kernelbase.dll mmdevapi.dll msacm32.dll \
        msv1_0.dll msvcp110.dll msvcp140.dll msvcr110.dll msvcrt.dll msvfw32.dll \
        netapi32.dll nsi.dll ntoskrnl.exe ole32.dll oleaut32.dll psapi.dll rpcrt4.dll \
        rsaenh.dll schannel.dll sechost.dll secur32.dll services.exe setupapi.dll \
        shcore.dll shell32.dll shlwapi.dll tzres.dll ucrtbase.dll user32.dll userenv.dll \
        uxtheme.dll vcruntime140_1.dll vcruntime140.dll version.dll wevtsvc.dll win32u.dll \
        wineboot.exe winmm.dll ws2_32.dll wsock32.dll xinput9_1_0.dll ; \
    do \
        if [ ! -f /opt/northstar-runtime/prefix/drive_c/windows/system32/$x ] ; \
        then \
            echo "missing $x" ; \
            exit 1 ; \
        fi ; \
    done

# copy non-libc libraries into our lib dir
RUN grep --text -Paro 'lib[A-Za-z0-9_.]+\.so[.0-9]+\x00' /opt/northstar-runtime/lib64/wine/x86_64-unix | tr -d "\0" | \
    grep -Fve :libc.so -e :libm.so -e :libnetapi.so -e :libOSMesa.so -e :libgssapi_krb5.so -e :libkrb5.so | cut -d: -f2 | \
    xargs printf "/lib/x86_64-linux-gnu/%s\n" | xargs lddtree --list | \
    grep -Fv -e /libc.so -e /ld-linux -e /libm.so -e /libpthread -e /libgcc | sort -u | \
    xargs cp -vt /opt/northstar-runtime/lib64/

# ensure we have some libs we know we need
RUN for lib in libgnutls libfontconfig libfreetype libunwind ; do \
    if [ ! -f /opt/northstar-runtime/lib64/$lib.so* ] ; then \
    echo "missing lib $lib (why wasn't it copied earlier?)" ; exit 1 ; fi ; done

# build box64 for arm64
# - patch: no lscpu process spawning nonsense (it slows down startup and doesn't even work properly)
# - patch: no rcfiles (we don't want external options interfering with the ones from nswrap)
FROM --platform=linux/amd64 docker.io/debian:bookworm AS build-box64-arm64
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates gcc-12-aarch64-linux-gnu cmake git ninja-build python3-minimal && apt-get clean
WORKDIR /src
RUN git init && \
    git remote add origin https://github.com/ptitSeb/box64.git && \
    git fetch https://github.com/ptitSeb/box64.git 9b23c3272bd6e0cffef50e811627301e0b64ea42 --depth=1 && \
    git checkout FETCH_HEAD
RUN sed -i 's/popen("lscpu/NULL; \/\/ popen("lscpu/g' src/tools/my_cpuid.c && \
    if git diff --exit-code src/tools/my_cpuid.c ; \
    then echo "nothing changed!?!" ; exit 1 ; fi
RUN sed -i 's/static void load_rcfiles()/static void load_rcfiles(){} static void load_rcfiles_old()/g' src/main.c && \
    if git diff --exit-code src/main.c ; \
    then echo "nothing changed!?!" ; exit 1 ; fi
RUN cmake -B/build -GNinja -DARM_DYNAREC=1 -DCMAKE_INSTALL_PREFIX=/opt/northstar-runtime -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc-12 /build && \
    ninja -C/build
RUN install -Dm755 /build/box64 /opt/northstar-runtime/bin/box64/box64

# build nswrap for amd64
FROM --platform=linux/amd64 docker.io/debian:bookworm AS build-nswrap-amd64
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y gcc-12 && apt-get clean
COPY ./nswrap.c /
RUN mkdir -p /opt/northstar-runtime/bin
RUN gcc-12 -Wall -Wextra /nswrap.c -o /opt/northstar-runtime/bin/nswrap

# build nswrap for arm64
FROM --platform=linux/amd64 docker.io/debian:bookworm AS build-nswrap-arm64
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y gcc-12-aarch64-linux-gnu && apt-get clean
COPY ./nswrap.c /
COPY ./nswrap-box64-shim.c /
RUN mkdir -p /opt/northstar-runtime/bin/box64
RUN aarch64-linux-gnu-gcc-12 -Wall -Wextra /nswrap.c -o /opt/northstar-runtime/bin/nswrap
RUN aarch64-linux-gnu-gcc-12 -Wall -Wextra /nswrap-box64-shim.c -o /opt/northstar-runtime/bin/box64/wine64 -DSHIM_BINARY=wine64
RUN aarch64-linux-gnu-gcc-12 -Wall -Wextra /nswrap-box64-shim.c -o /opt/northstar-runtime/bin/box64/wine64-preloader -DSHIM_BINARY=wine64-preloader
RUN aarch64-linux-gnu-gcc-12 -Wall -Wextra /nswrap-box64-shim.c -o /opt/northstar-runtime/bin/box64/wineserver -DSHIM_BINARY=wineserver

# merge the architecture-specific amd64 files
FROM scratch AS stage-arch-amd64
COPY --link --from=build-nswrap-amd64 /opt/northstar-runtime/ /opt/northstar-runtime

# merge the architecture-specific arm64 files
FROM scratch AS stage-arch-arm64
COPY --link --from=build-nswrap-arm64 /opt/northstar-runtime/ /opt/northstar-runtime
COPY --link --from=build-box64-arm64 /opt/northstar-runtime/ /opt/northstar-runtime

# choose the architecture-specific files based on the buildkit multi-arch target
FROM --platform=linux/amd64 docker.io/debian:bookworm AS stage-arch
ARG TARGETARCH
RUN --mount=type=bind,from=stage-arch-amd64,source=/,target=/mnt/amd64 \
    --mount=type=bind,from=stage-arch-arm64,source=/,target=/mnt/arm64 \
    cp -r /mnt/${TARGETARCH}/opt/northstar-runtime /opt/northstar-runtime

# merge the data files into a single layer
FROM scratch AS stage-data
COPY --link --from=build-data /etc/ssl/certs /etc/ssl/certs
COPY --link --from=build-data /usr/share/zoneinfo /usr/share/zoneinfo

# create the final image
FROM --platform=$TARGETPLATFORM docker.io/debian:bookworm-slim
COPY --link --from=stage-data / /
COPY --link --from=build-wine /opt/northstar-runtime /opt/northstar-runtime
COPY --link --from=stage-arch /opt/northstar-runtime /opt/northstar-runtime
COPY --link ./compat /opt/northstar-runtime/compat
WORKDIR /mnt
ENTRYPOINT ["/opt/northstar-runtime/bin/nswrap"]
CMD ["-dedicated"]
