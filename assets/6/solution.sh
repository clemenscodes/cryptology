#/bin/sh

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

CIPHERTEXT_FILE="./ciphertext.txt"
OUTPUT_FILE="./plaintext.txt"
XOR_OUTPUT_FILE="./xor.txt"

FIRST_CIPHERTEXT=$(sed -n '1p' "$CIPHERTEXT_FILE")
SECOND_CIPHERTEXT=$(sed -n '2p' "$CIPHERTEXT_FILE")
THIRD_CIPHERTEXT=$(sed -n '3p' "$CIPHERTEXT_FILE")
FOURTH_CIPHERTEXT=$(sed -n '4p' "$CIPHERTEXT_FILE")
FIFTH_CIPHERTEXT=$(sed -n '5p' "$CIPHERTEXT_FILE")
SIXTH_CIPHERTEXT=$(sed -n '6p' "$CIPHERTEXT_FILE")
SEVENTH_CIPHERTEXT=$(sed -n '7p' "$CIPHERTEXT_FILE")
EIGTH_CIPHERTEXT=$(sed -n '8p' "$CIPHERTEXT_FILE")
NINETH_CIPHERTEXT=$(sed -n '9p' "$CIPHERTEXT_FILE")
TENTH_CIPHERTEXT=$(sed -n '10p' "$CIPHERTEXT_FILE")
ELEVENTH_CIPHERTEXT=$(sed -n '11p' "$CIPHERTEXT_FILE")
TWELFTH_CIPHERTEXT=$(sed -n '12p' "$CIPHERTEXT_FILE")
THIRTEENTH_CIPHERTEXT=$(sed -n '13p' "$CIPHERTEXT_FILE")

decrypt() {
  local ciphertext="$1"
  local ascii
  local plaintext
  ascii=$(echo -n "$ciphertext" | cargo run --quiet -- decrypt one-time-pad --key "$KEY" --raw-input --raw-key)
  plaintext=$(echo -n "$ascii" | cargo run --quiet -- hex --raw --ascii)
  echo "$plaintext"
}

xor() {
  local alpha="$1"
  local beta="$2"
  local alpha_file="./alpha.txt"
  local beta_file="./beta.txt"
  echo "$alpha" > "$alpha_file"
  echo "$beta" > "$beta_file"
  cargo run --quiet -- xor --alpha "$alpha_file" --beta "$beta_file" --raw-alpha --raw-beta
}

{
  xor "$FIRST_CIPHERTEXT" "$SECOND_CIPHERTEXT"
} > "$XOR_OUTPUT_FILE"

cat "$XOR_OUTPUT_FILE"
