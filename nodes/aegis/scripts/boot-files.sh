#!/bin/bash
# Shared Bash 3.2+ helpers for updating Raspberry Pi boot partition files
# (config.txt and cmdline.txt) on either macOS (/Volumes/bootfs) or Linux (/boot/firmware).

update_boot_config_file() {
    local config_file="$1"
    local gpu_mem="${AEGIS_GPU_MEM:-16}"
    local disable_wifi="${AEGIS_DISABLE_WIFI:-true}"
    local disable_bt="${AEGIS_DISABLE_BLUETOOTH:-true}"
    local tmp_file last_section

    tmp_file="$(mktemp)"
    echo "==> Updating $config_file (gpu_mem=${gpu_mem}, disable_wifi=${disable_wifi}, disable_bt=${disable_bt})"

    # Strip any prior NAL block, top-level gpu_mem overrides, and trailing blank lines idempotently.
    if ! awk '
        /^# --- BEGIN NAL AEGIS ---$/ { skip=1; next }
        /^# --- END NAL AEGIS ---$/   { skip=0; next }
        skip { next }
        /^[[:space:]]*gpu_mem=/ { next }
        /^[[:space:]]*$/ { blanks++; next }
        {
            for (i = 0; i < blanks; i++) print ""
            blanks = 0
            print
        }
    ' "$config_file" > "$tmp_file"; then
        rm -f "$tmp_file"
        return 1
    fi

    # Ensure our block falls under [all] regardless of preceding [pi4]/[pi5] filters.
    last_section="$(awk '
        /^[[:space:]]*\[[^][#]+\][[:space:]]*(#.*)?$/ {
            sub(/^[[:space:]]*/, "")
            sub(/[[:space:]]*(#.*)?$/, "")
            gsub(/[[:space:]]+/, "")
            last = $0
        }
        END { print last }
    ' "$tmp_file")"
    {
        echo ""
        if [[ "$last_section" != "[all]" ]]; then
            echo "[all]"
            echo ""
        fi
        echo "# --- BEGIN NAL AEGIS ---"
        echo "gpu_mem=${gpu_mem}"
        if [[ "$disable_wifi" == "true" ]]; then
            echo "dtoverlay=disable-wifi"
        fi
        if [[ "$disable_bt" == "true" ]]; then
            echo "dtoverlay=disable-bt"
        fi
        echo "# --- END NAL AEGIS ---"
    } >> "$tmp_file"

    # Overwrite in place because FAT32 boot partitions can reject chmod/chown (EPERM).
    if ! cat "$tmp_file" > "$config_file"; then
        rm -f "$tmp_file"
        return 1
    fi
    rm -f "$tmp_file"
}

update_cmdline_cgroups_file() {
    local cmdline_file="$1"
    local line updated token

    # Convert line breaks to spaces so stray newlines never glue adjacent kernel flags together.
    line="$(tr '\r\n' '  ' < "$cmdline_file" | awk '{$1=$1; print}')"
    updated="$line"

    for token in cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory; do
        if [[ ! " $updated " == *" $token "* ]]; then
            updated="$updated $token"
        fi
    done

    if [[ "$updated" != "$line" ]]; then
        echo "==> Enabling memory cgroups in $cmdline_file"
        printf '%s\n' "$updated" > "$cmdline_file"
    else
        echo "==> Memory cgroups already enabled in $cmdline_file"
    fi
}
