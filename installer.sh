#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "\n\n"
echo -e "${RED}
░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░▒▓██████▓▒░    ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░
${NC}"
echo -e "\n\n"

# List of required Python modules (installation_name:import_name)
REQUIRED_MODULES=(
    "scapy:scapy"
    "termcolor:termcolor"
    "netifaces:netifaces"
    "psutil:psutil"
    "pillow:PIL"
    "tk:tkinter"
)

# Function to check if a module is installed
check_module() {
    python3 -c "import $1" &>/dev/null
    return $?
}

# Function to check if python3 is installed
check_python() {
    command -v python3 &>/dev/null
    return $?
}

# Function to check if pip is installed
check_pip() {
    command -v pip3 &>/dev/null
    return $?
}

MISSING_MODULES=()


echo -e "\n${GREEN}Checking for Python 3...${NC}"
if ! check_python; then
    echo -e "${RED}Python 3 is not installed.${NC}"
    exit 1
else
    echo -e "${GREEN}Python 3 is already installed.${NC}"
fi

echo -e "\n${GREEN}Checking for pip...${NC}"
if ! check_pip; then
    echo -e "${RED}pip is not installed.${NC}"
    exit 1
else
    echo -e "${GREEN}pip is already installed.${NC}"
fi

# Check modules
echo -e "\n${GREEN}Checking Python modules...${NC}"
for module_pair in "${REQUIRED_MODULES[@]}"; do
    IFS=":" read -r install_name import_name <<< "$module_pair"
    if ! check_module "$import_name"; then
        echo -e "${RED}Module '$import_name' not installed.${NC}"
        MISSING_MODULES+=("$install_name")
    else
        echo -e "${GREEN}Module '$import_name' is already installed.${NC}"
    fi
done

if [ ${#MISSING_MODULES[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}Installing missing modules...${NC}"
    for module in "${MISSING_MODULES[@]}"; do
        echo -e "${YELLOW}Installing $module...${NC}"
        pip3 install "$module"
    done
    echo -e "\n${GREEN}All modules installed successfully!${NC}"
else
    echo -e "\n${GREEN}All required modules are already installed!${NC}"
fi



## Add an alias for redshift

# Detect the user's shell
USER_SHELL=$(basename "$SHELL")

# Set the alias file based on the shell
if [[ "$USER_SHELL" == "bash" ]]; then
    ALIAS_FILE="$HOME/.bash_aliases"
elif [[ "$USER_SHELL" == "zsh" ]]; then
    ALIAS_FILE="$HOME/.zshrc"
else
    echo "Unsupported shell: $USER_SHELL"
    exit 1
fi

# Create the alias file if it does not exist
if [ ! -f "$ALIAS_FILE" ]; then
    touch "$ALIAS_FILE"
    echo "# Alias file for $USER_SHELL" > "$ALIAS_FILE"
fi

# Define the alias
NEW_ALIAS="alias redshift='sudo python3 $(pwd)/py/redshift.py'"

# Check if the alias already exists
if ! grep -qxF "$NEW_ALIAS" "$ALIAS_FILE"; then
    echo "$NEW_ALIAS" >> "$ALIAS_FILE"
fi

# Restart
echo -e "\n${GREEN}Installation completed.${NC}"
exec $SHELL
