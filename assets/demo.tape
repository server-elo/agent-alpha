# VHS tape for the README demo.
#   vhs assets/demo.tape
#
# Records a real session against a real local model (Ollama). Nothing here is
# staged: the agent reads the files, and the answer is whatever it says.
# ALPHA_ENV_FILE=/dev/null keeps the recording free of the operator's own
# config, so what is shown is what a new user gets.

Output assets/demo.gif

Set Shell zsh
Set FontFamily "Menlo"
Set FontSize 16
Set Width 1100
Set Height 620
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "cd /tmp/demo-proj && clear" Enter
Sleep 1s
Show

Type "alpha --provider ollama" Enter
Sleep 6s

Type "why does the build fail?"
Sleep 700ms
Enter
Sleep 75s

Type "/exit" Enter
Sleep 2s
