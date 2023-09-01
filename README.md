<div align="center">

![Switchboard Logo](https://github.com/switchboard-xyz/core-sdk/raw/main/website/static/img/icons/switchboard/avatar.png)

# Switchboard Secrets Server

> Kubernets manifests for hosting your own secrets for Switchboard functions

  <p>
    <a href="https://discord.gg/switchboardxyz">
      <img alt="Discord" src="https://img.shields.io/discord/841525135311634443?color=blueviolet&logo=discord&logoColor=white" />
    </a>
    <a href="https://twitter.com/switchboardxyz">
      <img alt="Twitter" src="https://img.shields.io/twitter/follow/switchboardxyz?label=Follow+Switchboard" />
    </a>
  </p>

  <h4>
    <strong>Documentation: </strong><a href="https://docs.switchboard.xyz">docs.switchboard.xyz</a>
  </h4>
</div>

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

<div align="center">
  <img src="https://showme.redstarplugin.com/d/d:tV50j0we" alt="Sequence Diagram">
</div>
