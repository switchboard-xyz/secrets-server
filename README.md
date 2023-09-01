# Switchboard Secrets Server
Welcome to the Switchboard Secrets server repository.

This repository can help you store secrets securely outside of your Switchboard functions to only ever be loaded inside your functions runtime.

You may wonder how, if all Switchboard oracles must retrieve secrets from this server, that they are not revealed to any adversary.

Simply put, this server authenticates requests by ingesting a message from SGX machines known as "quotes".

These quotes signify example which code has made the request for the secrets and what encryption key is safe to use to deliver back the secrets.

To use this secrets server you must do the following:

- Initialize a kubernets cluster with the provided helm manifest to retrieve the allocated static IP for your cluster
- In your function, call `sb_functions_sdk::secrets::fetch_secrets("http://<YOUR_SERVER_IP>`).await`
- Build your Switchboard Function to retrieve the `MR_ENCLAVE` of your function
- Add this `MR_ENCLAVE` to the `allowedMrEnclaves` configs in `secrets-server-chart/configs.jsonc`
- Add all the secrets you wish to deliver to your function as key/value pairs under the `keys` config
- Deploy your secrets server
- All your secrets will then be securely communicated with your function enclave, completely encrypted to anything outside of your function's enclave
