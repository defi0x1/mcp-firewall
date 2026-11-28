# The README demo: install, turn the guard on, watch it with `guard top`.
# Record from the repo root with: vhs docs/demo/demo.tape
# It runs in a throwaway HOME, so your own Claude Code settings are not touched.

Output docs/demo/demo.gif

Set Shell "bash"
Set Theme "Dracula"
Set FontFamily "Fira Code"
Set FontSize 16
Set Width 1280
Set Height 720
Set Padding 24
Set TypingSpeed 45ms
Set WindowBar Colorful
Set CursorBlink false

Hide
Type "export FEED=$PWD/docs/demo/feed.sh; rm -rf /tmp/demo; mkdir /tmp/demo; export HOME=/tmp/demo; export PATH=/tmp/demo/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin COLORTERM=truecolor AGENT_GUARD_THEME=dark PS1='$ '; cd ~ && clear"
Enter
Show

Sleep 600ms
Type "curl -fsSL https://raw.githubusercontent.com/defi0x1/agent-guard/main/install.sh | sh"
Sleep 400ms
Enter
Wait+Screen /guard selftest/
Sleep 1.5s

Type "guard install"
Sleep 300ms
Enter
Sleep 3s

Type "guard status"
Sleep 300ms
Enter
Sleep 3s

Hide
Type "clear && (sh $FEED &) "
Enter
Show

Type "guard top"
Sleep 300ms
Enter
Sleep 9s

# Look at the red call.
Type "1"
Sleep 2s
Enter
Sleep 4s
Escape
Sleep 1s

# Everything, then quit.
Space
Sleep 4s
Type "q"
Sleep 500ms
