# Sourced by the scripts that build or test: makes CMake and Ninja findable, whichever way they were installed.
#
# MacPorts (the supported way) installs into /opt/local/bin, which apps launched from the Dock or VS Code often don't
# have on their PATH. The MacPorts directories (and the usual Homebrew ones, as a fallback) are APPENDED to PATH, so the
# tools macOS ships (curl, openssl/LibreSSL, swiftc, python3) keep precedence.
for _dir in /opt/local/bin /opt/local/sbin /opt/homebrew/bin /usr/local/bin; do
  if [ -d "$_dir" ]; then
    case ":$PATH:" in *":$_dir:"*) ;; *) PATH="$PATH:$_dir" ;; esac
  fi
done
unset _dir
export PATH

# need_build_tools: returns 0 when cmake and ninja are available; otherwise prints how to install them and returns 1.
need_build_tools() {
  local missing=() t
  for t in cmake ninja; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
  [ ${#missing[@]} -eq 0 ] && return 0
  echo "missing build tools: ${missing[*]}"
  echo "  install MacPorts (https://www.macports.org/install.php, the installer for your macOS version), then:"
  echo "    sudo port selfupdate && sudo port install cmake ninja"
  return 1
}
