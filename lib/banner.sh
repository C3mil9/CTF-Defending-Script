#!/usr/bin/env bash
# Startup art transcribed from the image supplied for this project.
# A quoted heredoc preserves backslashes and prevents command interpolation.
render_banner() {
    cat <<'CTF_BANNER'
      /
     /\     ___
    /  \   \\\\\              __________
   |    \ /O )))        _--~~~ ________/
   |     \ |=  /     _-~__--~~~ _____/
   |_____ \_|_|___ /  ____---~~~~__/
<--E---<<</E______)  ______---~~_/
   |~~~~~~/|    | |  _______--_/
   |     / |    |  \  ____--_/  ____
   |    / /      ---)      /--.==\\\\
    \  / |          ~~~--~/   )  ))))
     \/   |                    |  ((((
      \ _-~\|  /     _____\   /   )))
       ( ---| /--~~~~  \ \v\ (    (((
       ||   ||          \ > \ >    ((
       ||_  (|          //  ||      ))
        \_| ||         //   ||
           /_|        /_|  /_|
CTF_BANNER
    printf '\nCTF Defense Kit v%s\n\n' "$VERSION"
}

# Keep redirected reports and automated checks free of terminal decoration.
# Interactive users still see the art before the command starts.
show_banner() {
    [[ -t 2 ]] || return 0
    render_banner >&2
}
