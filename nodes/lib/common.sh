#!/bin/bash
# Shared macOS Bash 3.2+ helpers for node provisioning scripts under nodes/.

append_path_dir() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        case ":${PATH:-}:" in
            *":${dir}:"*) ;;
            *) PATH="${PATH:+$PATH:}${dir}" ;;
        esac
    fi
}

ensure_macos_paths() {
    append_path_dir "/opt/homebrew/bin"
    append_path_dir "/usr/local/bin"
    append_path_dir "${HOME}/.orbstack/bin"
    export PATH
}

trim_ws() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

expand_tilde() {
    local path="$1"
    if [[ "$path" == "~" ]]; then
        printf '%s' "$HOME"
    elif [[ "$path" == "~/"* ]]; then
        printf '%s' "${HOME}${path#\~}"
    else
        printf '%s' "$path"
    fi
}

parse_env_value() {
    local env_file="$1" raw="$2" line_no="$3"
    local trimmed val="" i len ch next
    trimmed="${raw#"${raw%%[![:space:]]*}"}"

    if [[ -z "$trimmed" || "$trimmed" == \#* ]]; then
        printf '%s' ""
        return 0
    fi

    if [[ "$trimmed" == \'* ]]; then
        local sq_re="^'([^']*)'([[:space:]]*(#.*)?)?$"
        if [[ "$trimmed" =~ $sq_re ]]; then
            printf '%s' "${BASH_REMATCH[1]}"
            return 0
        fi
        echo "Error: malformed single-quoted value in $env_file:$line_no." >&2
        return 1
    fi

    if [[ "$trimmed" == \"* ]]; then
        len="${#trimmed}"
        i=1
        while (( i < len )); do
            ch="${trimmed:$i:1}"
            if [[ "$ch" == "\\" ]]; then
                if (( i + 1 >= len )); then
                    echo "Error: trailing backslash in $env_file:$line_no." >&2
                    return 1
                fi
                next="${trimmed:$((i + 1)):1}"
                val="${val}${next}"
                i=$((i + 2))
                continue
            fi
            if [[ "$ch" == '"' ]]; then
                local suffix="${trimmed:$((i + 1))}"
                local suffix_re='^[[:space:]]*(#.*)?$'
                if [[ "$suffix" =~ $suffix_re ]]; then
                    printf '%s' "$val"
                    return 0
                fi
                echo "Error: unexpected trailing characters after quoted value in $env_file:$line_no." >&2
                return 1
            fi
            val="${val}${ch}"
            i=$((i + 1))
        done
        echo "Error: unterminated double-quoted value in $env_file:$line_no." >&2
        return 1
    fi

    # Unquoted values allow literal '$' and strip trailing `<ws>#...` comments.
    trimmed="${trimmed%%[[:space:]]#*}"
    trim_ws "$trimmed"
}

load_env_file() {
    local env_file="$1"
    if [[ ! -e "$env_file" ]]; then
        return 0
    fi
    if [[ ! -f "$env_file" || ! -r "$env_file" ]]; then
        echo "Error: env file '$env_file' is not readable." >&2
        exit 1
    fi

    local line trimmed key val line_no=0
    local export_re='^export[[:space:]]+(.*)$'
    local kv_re='^([A-Za-z_][A-Za-z0-9_]*)=(.*)$'
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_no=$((line_no + 1))
        line="${line%$'\r'}"
        trimmed="$(trim_ws "$line")"
        [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
        if [[ "$trimmed" =~ $export_re ]]; then
            trimmed="${BASH_REMATCH[1]}"
        fi
        if [[ ! "$trimmed" =~ $kv_re ]]; then
            echo "Error: invalid syntax in $env_file:$line_no." >&2
            exit 1
        fi
        key="${BASH_REMATCH[1]}"
        val="$(parse_env_value "$env_file" "${BASH_REMATCH[2]}" "$line_no")" || exit 1
        printf -v "$key" '%s' "$val"
    done < "$env_file"
}

validate_bool() {
    local name="$1" val="$2"
    if [[ "$val" != "true" && "$val" != "false" ]]; then
        echo "Error: $name must be 'true' or 'false' (got '$val')." >&2
        exit 1
    fi
}

validate_node_name() {
    local name="$1" val="$2"
    if [[ ! "$val" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        echo "Error: $name must be a valid lowercase RFC 1123 label (got '$val')." >&2
        exit 1
    fi
}

validate_ipv4() {
    local name="$1" val="$2"
    if [[ ! "$val" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "Error: $name must be a valid IPv4 address (got '$val')." >&2
        exit 1
    fi
    local IFS='.' octet
    local -a octets
    read -r -a octets <<< "$val"
    for octet in "${octets[@]}"; do
        if [[ "$octet" =~ ^0[0-9]+$ ]] || (( 10#$octet > 255 )); then
            echo "Error: $name contains an invalid IPv4 octet '$octet' (got '$val')." >&2
            exit 1
        fi
    done
    if [[ "$val" == "0.0.0.0" || "$val" == "255.255.255.255" || "$val" == 127.* ]]; then
        echo "Error: $name cannot be '$val' (must be a routable LAN IPv4)." >&2
        exit 1
    fi
}

write_env_vars() {
    local dest="$1"
    shift
    chmod 600 "$dest"
    : > "$dest"
    local var
    for var in "$@"; do
        printf '%s=%q\n' "$var" "${!var:-}" >> "$dest"
    done
}
