# include `.env` file and export its env vars
# (-include to ignore error if it does not exist)
-include .env

# build & test
build           :; cargo build --features all