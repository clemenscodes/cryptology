#/bin/sh

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

PLAINTEXT="  attack at dawn"
CIPHERTEXT_FILE="./ciphertext-otp1.txt"
OUTPUT_FILE="./plaintext-otp1.txt"

FIRST_CIPHERTEXT=$(sed -n '1p' "$CIPHERTEXT_FILE")
SECOND_CIPHERTEXT=$(sed -n '2p' "$CIPHERTEXT_FILE")
THIRD_CIPHERTEXT=$(sed -n '3p' "$CIPHERTEXT_FILE")
FOURTH_CIPHERTEXT=$(sed -n '$p' "$CIPHERTEXT_FILE")

KEY=$(echo -n "$FIRST_CIPHERTEXT" | cargo run --quiet -- decrypt one-time-pad --key "$PLAINTEXT" --raw-input)

decrypt() {
  local ciphertext="$1"
  local ascii
  local plaintext
  ascii=$(echo -n "$ciphertext" | cargo run --quiet -- decrypt one-time-pad --key "$KEY" --raw-input --raw-key)
  plaintext=$(echo -n "$ascii" | cargo run --quiet -- hex --raw --ascii)
  echo "$plaintext"
}

{
  decrypt "$FIRST_CIPHERTEXT"
  decrypt "$SECOND_CIPHERTEXT"
  decrypt "$THIRD_CIPHERTEXT"
  decrypt "$FOURTH_CIPHERTEXT"
} > "$OUTPUT_FILE"

cat "$OUTPUT_FILE"
