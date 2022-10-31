PLUGIN_DIR=$1
PLUGIN_NAME=$2
PLUGIN_MOUNT=$3
GOOGLE_TEST_CREDENTIALS=$4

# Try to clean-up previous runs
vault plugin deregister "$PLUGIN_NAME"
vault auth disable "$PLUGIN_MOUNT"
killall "$PLUGIN_NAME"

# Give a bit of time for the binary file to be released so we can copy over it
sleep 3

# Copy the binary so text file is not busy when rebuilding & the plugin is registered
cp ./bin/"$PLUGIN_NAME" "$PLUGIN_DIR"/"$PLUGIN_NAME"

# Sets up the binary with local changes
vault plugin register \
      -sha256="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')" \
      auth "$PLUGIN_NAME"
vault auth enable --plugin-name="$PLUGIN_NAME" --path="$PLUGIN_MOUNT" plugin
vault write auth/"$PLUGIN_MOUNT"/config credentials=@"$GOOGLE_TEST_CREDENTIALS"
