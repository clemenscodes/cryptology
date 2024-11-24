#/bin/sh

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

PLAINTEXT="a hidden message"
CIPHERTEXT_FILE="./ciphertext-otp2.txt"
OUTPUT_FILE="./plaintext-otp2.txt"

FIRST_CIPHERTEXT=$(sed -n '1p' "$CIPHERTEXT_FILE")
SECOND_CIPHERTEXT=$(sed -n '2p' "$CIPHERTEXT_FILE")
THIRD_CIPHERTEXT=$(sed -n '3p' "$CIPHERTEXT_FILE")
FOURTH_CIPHERTEXT=$(sed -n '$p' "$CIPHERTEXT_FILE")

FIRST_KEY=$(echo -n "$FIRST_CIPHERTEXT" | cargo run --quiet -- decrypt one-time-pad --key "$PLAINTEXT" --raw-input)
SECOND_KEY=$(echo -n "$SECOND_CIPHERTEXT" | cargo run --quiet -- decrypt one-time-pad --key "$PLAINTEXT" --raw-input)
THIRD_KEY=$(echo -n "$THIRD_CIPHERTEXT" | cargo run --quiet -- decrypt one-time-pad --key "$PLAINTEXT" --raw-input)
FOURTH_KEY=$(echo -n "$FOURTH_CIPHERTEXT" | cargo run --quiet -- decrypt one-time-pad --key "$PLAINTEXT" --raw-input)

decrypt() {
  local ciphertext="$1"
  local key="$2"
  local ascii
  local plaintext
  ascii=$(echo -n "$ciphertext" | cargo run --quiet -- decrypt one-time-pad --key "$key" --raw-input --raw-key)
  plaintext=$(echo -n "$ascii" | cargo run --quiet -- hex --raw --ascii)
  echo "$plaintext"
}

{
  decrypt "$FIRST_CIPHERTEXT" "$FIRST_KEY"
  decrypt "$SECOND_CIPHERTEXT" "$SECOND_KEY"
  decrypt "$THIRD_CIPHERTEXT" "$THIRD_KEY"
  decrypt "$FOURTH_CIPHERTEXT" "$FOURTH_KEY"
} > "$OUTPUT_FILE"

cat "$OUTPUT_FILE"
