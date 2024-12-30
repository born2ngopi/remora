#!/bin/bash

# check current path any .git dir
if [ ! -d .git ]; then
    echo "Not a git repository"
    exit 1
fi

# check remora is installed by running `remora version`
if ! command -v remora &> /dev/null
then
    echo "remora could not be found, please install first"
    exit 1
fi

HOOK_PATH=".git/hooks/pre-push"


if [ -f "$HOOK_PATH" ]; then
    echo "found pre-push hook, append to it."
else
    echo "create pre-push hook"
    echo "#!/bin/bash" > "$HOOK_PATH"
fi

if grep -q "remora " "$HOOK_PATH"; then
    sed -i '' 's|remora .*|remora check -g=true -C=1 -H=4 -M=6|' "$HOOK_PATH"
    echo "update pre-push hook"
else
    cat <<EOT >> "$HOOK_PATH"

remora check -g=true -C=1 -H=4 -M=6

if [ \$? -eq 1 ]; then
    echo "Check lagi Cuy, install mulu ngga maintenance"
    exit 1  
fi
EOT
fi

# Pastikan hook executable
chmod +x "$HOOK_PATH"
echo "set pre-push done"

