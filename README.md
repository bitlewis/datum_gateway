# DATUM Gateway
**Decentralized Alternative Templates for Universal Mining**
(c) 2024-2025 Bitcoin Ocean, LLC, Jason Hughes, and individual contributors

The DATUM Gateway implements lightweight efficient client side decentralized block template creation for true solo mining.

It reaches out to a local Bitcoin node for block templates, generates and distributes work for mining hardware, and submits solved blocks to the network directly.

For miners wanting to pool rewards, it facilitates communication with a DATUM-supporting pool in addition to the above.  The pool is responsible for coordinating the block reward split based on work done for the pool by the miner, but does not create work for the miner.

The work provided by the gateway to mining hardware is generated only from the local node generating templates for the miner. The real miner is always whoever is running the Bitcoin node. With DATUM, that's not the pool. As the protocol is intended solely for mining of decentralized block templates, the DATUM protocol has no mechanisms for the pool providing the information needed to construct work or a block template.

Currently the DATUM Gateway supports communication with mining hardware using the Stratum v1 protocol with version rolling extensions (aka "ASICBoost").  Communication with the Bitcoin node is via RPC and must support GBT ("getblocktemplate").  Finally, communication with the pool is via the DATUM protocol.

**Using Bitcoin Knots is highly recommended**. This gives miners fine controls over how they wish to construct their block templates.  Other node implementations that support GBT can also be used.  This includes Bitcoin Core, but it is severely lacking in template control options.  That is unfortunately a centralizing force which partly defeats the purpose of decentralizing block template creation in the first place.

The DATUM Gateway only supports mining Bitcoin.  Modifying the code to support non-Bitcoin is not straightforward, as many optimizations and design considerations are tightly tied to Bitcoin-specific restraints for efficiency.  (This fork also mines eCash and Bitcoin Cash II, both Bitcoin-derived SHA-256 chains; see [About this fork](#about-this-fork).)

## About this fork

This is BlockFab's fork of OCEAN's DATUM Gateway, currently **v0.5.3-rc+drivechains**. It is the gateway behind the pools at [blockfab.org](https://blockfab.org) and [epool.cash](https://epool.cash). Everything upstream does still works as described below; this section lists what the fork adds and changes. The design notes for the drivechain work are in [doc/bip300-integration.md](doc/bip300-integration.md).

A gateway built from this fork mines with a pool that runs stock DATUM too. The extra messages it sends are ones an upstream pool ignores, and it only asks for the extended payout format when the pool offers it.

### One codebase, three chains

The same build mines all of these, deciding from what the node's block template contains rather than from a coin setting:

| Chain | Node | What the gateway does |
|---|---|---|
| Bitcoin | Knots or Core | Exactly what upstream does. |
| eCash (BIP300/301 drivechains) | eCash node, optionally behind a [bip300301_enforcer](https://github.com/LayerTwo-Labs/bip300301_enforcer) | Carries the pool's sidechain votes and merged-mining commitments in the coinbase (see below). |
| Bitcoin Cash II (SegWit off) | BitcoincashII node | Builds blocks without a witness commitment. |

**Chains without SegWit.** A template that neither lists the `segwit` rule nor carries `default_witness_commitment` is accepted, and every coinbase built from it has one output fewer: no commitment output, and no witness data. A template that does list `segwit` must still carry the commitment, so nothing changes on Bitcoin or eCash. Stock DATUM refuses every such template, so it cannot mine Bitcoin Cash II.

### Drivechains (BIP300/301)

- **Coinbase commitments from the pool.** The pool sends BIP300 governance messages (M2 sidechain acks, M4 bundle acks) and BIP301 accepts (M7) along with the payout list, in an extended coinbaser format with two-byte lengths, so wide M4 votes fit. The gateway places them without interpreting them, so a new BIP300 message needs no gateway change. Their size is taken from the coinbase budget before any payout, and a set that does not fit is left out whole rather than cut short. A cut-short set would be a partial vote, or a vote that silently did not happen.
- **Several acks per block.** Every M2 carries the same tag. The merge now replaces the template's messages once per tag rather than once per message, so a pool acking two proposals puts both acks in the block.
- **Templates from an enforcer.** Point `bitcoind.rpcurl` at a bip300301_enforcer and the gateway takes the enforcer's coinbase value and commitments, then builds the coinbase from the pool's payout list as DATUM always does. The enforcer's own payout output is discarded. Every RPC is sent as JSON-RPC 2.0, which the enforcer requires.
- **Merged-mining safety.** A BMM accept (M7) answers a request (M8) that is an ordinary transaction in the same block. A block with an accept but no matching request is accepted by plain nodes and rejected by every enforcer, so the gateway guards against producing one:
  - an accept whose request is not in the block is refused, whether it came from the template or from the pool;
  - on a template that did not come from an enforcer, BMM bids are dropped along with their fees and dependents, and the witness commitment is recomputed over what is left;
  - a gateway whose own template already carries accepts keeps them rather than taking the pool's;
  - a miner whose coinbase type is too small to carry an accept gets empty work (no transactions, so no request to answer) until one fits;
  - a template over 16,383 transactions is refused rather than truncated, because truncation can drop a request while keeping its accept.
- **preciousblock follows the block.** The tie-break is sent to the node the block was actually submitted to. An enforcer does not implement preciousblock, so list your node in `extra_block_submissions` to keep it.
- The user agent carries `+drivechains`, which is how a pool knows it may send the extended format.

### The stratum password

The password field now does three things. Several settings can be combined with commas, for example `d=65536,cb=respect`.

- **`d=NNNN`: a difficulty floor.** Vardiff may still raise the rig above it, so a mistyped value cannot flood the pool with shares. It is rounded down to a power of two.
- **`cb=TYPE`: a coinbase type**, for a rig whose firmware can carry more (or less) than its fingerprint suggests. The types are `tiny` (500 B), `default` (755 B), `antmain2` (2,250 B), `respect` (6,500 B) and `yuge` (16,000 B), or their numbers 1–5.
- **Anything else is forwarded to the pool** once per connection (DATUM sub-command `0x30`), padded like every other message. A pool that keeps accounts stores it hashed, as proof that the address is yours. This matters for miners who pay to an exchange and hold no key to sign with. A password that is a `d=` or `cb=` setting is never forwarded, an empty one sends nothing, and an over-long one is dropped rather than truncated.

### Coinbase types by user agent

`stratum.coinbase_types` maps a miner's user agent to a coinbase type without a rebuild. These rules are checked before the built-in fingerprints, and the first match wins. `prefix=type` matches the start of the user agent, and `*text=type` matches anywhere in it:

```json
"stratum": {
  "coinbase_types": ["NerdQAxe=antmain2", "*bosminer=respect"]
}
```

NerdQAxe and NerdOctaxe (ESP-Miner forks) are now recognised and given the 2,250-byte type. The gateway logs one line per subscribe saying which type each client gets.

### Robustness

- The coinbase always declares exactly the number of outputs it writes, at every budget; a test sweeps the budgets to check this.
- While the pool restarts, miners that redial are no longer refused.
- The gateway logs its version and commit at startup, so you can check which build is actually running.
- `./datum_gateway --test` runs the gateway's own checks, including the drivechain and no-SegWit cases.

## DATUM Protocol
The DATUM Gateway's communication with the mining pool is via the DATUM Protocol.  This is an encrypted communication link between the DATUM Gateway (client) and DATUM Prime (pool side).

The protocol itself was made from the ground up as a custom protocol.  Its specification is evolving, subject to change, and will be published elsewhere.

The core concepts of the protocol:

 - Encrypt communications between the Gateway and pool
 - Obfuscate the communications somewhat so a MITM is unable to glean useful or accurate insight into the miner's operation via analysis of the still-ciphered communications.
 - Retrieve proper generation transaction payout splits from the pool for locally constructed templates
 - Submit work to the pool with sufficient data to efficiently validate and accept the work for proper rewards
 - Communicate minimal guardrails and requirements for a valid template to earn pooled rewards

With the current version of the protocol, the pool does block validation after coordinating with the miner. This is strictly to ensure miners are not accidentally creating invalid blocks while DATUM is still undergoing testing. In a future version of the protocol, the pool will not be in charge of this function and will be almost completely blinded to the contents of the miner's block template.

The protocol is not specific to a pooled reward system, as the Gateway coordinates the appropriate generation transaction with the pool.  However, in the spirit of maximum decentralization, the pool should implement rewarding miners directly from generated payouts, such as with OCEAN's TIDES reward system.

![DATUM v0 2-beta recommended setup - network diagram](doc/DATUM_recommended_setup-network_diagram.svg)

## Requirements

 - 64-bit AMD or Intel system. Other systems may work, but at this time it is at your own risk.
 - Linux-based operating system. Other OSs will be supported in the future.
 - Bitcoin full node ([Bitcoin Knots](https://bitcoinknots.org/) recommended) fully synced with the Bitcoin network.
 - Fast storage recommended for the Bitcoin node.
 - Stable internet connection for both the Bitcoin node and Gateway's communication with the pool.
 - CPU powerful enough to run the Bitcoin node without validation delays.
 - Approximately 1GB/RAM, plus 1GB/RAM per 1000 Stratum clients, plus Bitcoin node RAM requirements.
 - Bitcoin mining hardware able to reach the system running the DATUM Gateway.

This list is not extensive, but the main goal is the have a stable system for your Bitcoin node and the Gateway such that your node is processing new incoming blocks and getting templates to the Gateway as quickly as possible.  While this may all work on relatively low end hardware, your mileage may vary.

No modifications to the Bitcoin node source code is required for the Gateway, as it uses the standard GBT mechanism for template fetch.

The following external libraries are required:
 - libcurl
 - libjansson
 - libmicrohttpd
 - libsodium

## Node Configuration
Your Bitcoin node must be configured to construct blocks as you desire.  Bitcoin Knots provides many options for configuring your node's policy and is highly recommended.

At this time, you must also reserve some block space for the pool's generation transaction.  The following options are currently recommended:

    blockmaxsize=3985000
    blockmaxweight=3985000

Note: This reservation requirement will be removed for Bitcoin Knots users in a future version of the DATUM Gateway thanks to support for on-the-fly specification of these metrics by the client in Knots.

To avoid mining stale work, you will need to ensure the DATUM Gateway receives new block notifications from your node. It is suggested you run the DATUM Gateway as the same user as your full node and utilize the following configuration line in your bitcoin.conf:

    blocknotify=killall -USR1 datum_gateway

Ensure you have "killall" installed on your system (*psmisc* package on many OSs).

If the node and Gateway are on different systems, you may need to utilize the "NOTIFY" endpoint on the Gateway's dashboard/API instead.

Finally, the Gateway must have RPC access to your node, and you must add an RPC user to your configuration to facilitate this, as well as ensuring the service running the Gateway is whitelisted for RPC access (if not on the same machine).

Some additional recommendations:

    maxmempool=1000
    blockreconstructionextratxn=1000000

As a true miner, you'll most likely want as many valid transactions as possible in your mempool which meet your node's policies.

## Installation
Install and fully sync your Bitcoin full node. Instructions for this are beyond the scope of this document.

Configure your node to create block templates as you desire. Be sure to reserve some space for the generation transaction, otherwise your work will not be able to fit a reward split.  See node configuration recommendations above.

Install the required libraries and development packages for dependencies: cmake, pkgconf, libcurl, jansson, libsodium, and libmicrohttpd. You may also need psmisc for your node to send blocknotify signals to the DATUM Gateway.

For Debian/Ubuntu:

    sudo apt install cmake pkgconf libcurl4-openssl-dev libjansson-dev libsodium-dev libmicrohttpd-dev psmisc

For Fedora/Amazon Linux:

    sudo dnf install cmake pkgconf libcurl-devel jansson-devel libsodium-devel libmicrohttpd-devel psmisc

For Alma Linux:

    sudo dnf install epel-release dnf-plugins-core
    sudo dnf config-manager --set-enabled crb
    sudo dnf install cmake pkgconf libcurl-devel jansson-devel libsodium-devel libmicrohttpd-devel psmisc

For Oracle Linux:

    sudo dnf install epel-release dnf-plugins-core
    sudo dnf config-manager --set-enabled ol9_codeready_builder
    sudo dnf install cmake pkgconf libcurl-devel jansson-devel libsodium-devel libmicrohttpd-devel psmisc

For Alpine (also needs a standalone argp library):

    sudo apk add build-base cmake pkgconf argp-standalone curl-dev jansson-dev libsodium-dev libmicrohttpd-dev psmisc

For Arch:

    sudo pacman -Syu base-devel cmake pkgconf curl jansson libsodium libmicrohttpd psmisc

For Clear Linux:

    sudo swupd bundle-add c-basic cmake pkgconf devpkg-curl devpkg-jansson devpkg-libsodium devpkg-libmicrohttpd psmisc

For FreeBSD:

    sudo pkg install cmake pkgconf curl jansson libsodium libmicrohttpd argp-standalone libepoll-shim

Compile DATUM by running:

    cmake . && make

## Usage

Run the datum_gateway executable with the -? flag for detailed configuration information, descriptions, and required options.  Then construct a configuration file (defaults to "datum_gateway_config.json" in the current working directory). Be sure to also set your coinbase tags.  The primary tag setting is unused in pooled mining, however the secondary tag is intended to show on things like block explorers when you mine a block.

There is an [example configuration file included in the doc/ directory](doc/example_datum_gateway_config.json) you may wish to use as a template.
Note that the API/web admin password is also used for preventing CSRF attacks, so it is crucial you set it to something reasonably secure (or disable the API/web interface entirely).

You should review the [documentation on usernames](doc/usernames.md) next.
Once you have everything running, you can point miners at the Gateway.

## Docker

The DATUM Gateway is also available as a Docker image.


### Building the Docker Image

To build the DATUM Gateway Docker image:

```bash
# From the root of the repository
docker build -t datum_gateway .
```

### Running the Container

To run the DATUM Gateway container:

```bash
# Run with default configuration
docker run -p 23334:23334 -p 7152:7152 --name datum-gateway datum_gateway
```

The container expects a configuration file at `/app/config/config.json`. Mount a volume to this path to use your own configuration:

```bash
docker run -v /path/to/your/config/directory:/app/config -p 23334:23334 -p 7152:7152 datum_gateway
```

You will need to disable the notify fallback in your configuration file if you are using Docker. And in bitcoin.conf, you will need to set the following:

```bash
blocknotify=wget -q -O /dev/null http://datum-gateway:7152/NOTIFY
```

### Connecting to a Bitcoin Node

When running the DATUM Gateway in Docker, you need to configure it to connect to your Bitcoin node. The connection method depends on where your Bitcoin node is running:

#### 1. Bitcoin Node Running in Docker (Same Network)

If your Bitcoin node is also running in a Docker container on the same network, use the container name as the hostname:

```json
{
  "rpc_host": "bitcoin-node",
  "rpc_port": 8332,
  "rpc_user": "your_rpc_user",
  "rpc_pass": "your_rpc_password"
}
```

In your `bitcoin.conf`, set the blocknotify to use the DATUM Gateway container name:

```
blocknotify=wget -q -O /dev/null http://datum-gateway:7152/NOTIFY
```

#### 2. Bitcoin Node Running on Host System

If your Bitcoin node is running directly on the host system or in a container that binds to host ports, you have two options:

**Option A: Using host.docker.internal (recommended)**
```json
{
  "rpc_host": "host.docker.internal",
  "rpc_port": 8332,
  "rpc_user": "your_rpc_user",
  "rpc_pass": "your_rpc_password"
}
```

**Option B: Using host networking mode**
Run the DATUM Gateway container with `--network host`:

```bash
docker run --network host -v /path/to/config:/app/config datum_gateway
```

Then configure using localhost:
```json
{
  "rpc_host": "localhost",
  "rpc_port": 8332,
  "rpc_user": "your_rpc_user",
  "rpc_pass": "your_rpc_password"
}
```

For blocknotify in `bitcoin.conf` when using host networking:
```
blocknotify=wget -q -O /dev/null http://localhost:7152/NOTIFY
```

#### 3. Bitcoin Node on Remote System

If your Bitcoin node is running on a different machine, use the hostname or IP address:

```json
{
  "rpc_host": "192.168.1.100",
  "rpc_port": 8332,
  "rpc_user": "your_rpc_user",
  "rpc_pass": "your_rpc_password"
}
```

In your remote Bitcoin node's `bitcoin.conf`:
```
blocknotify=wget -q -O /dev/null http://datum-gateway-host-ip:7152/NOTIFY
```

**Important Notes:**
- Ensure your Bitcoin node's RPC is configured to accept connections from the DATUM Gateway
- For remote connections, you may need to configure `rpcbind` and `rpcallowip` in your `bitcoin.conf`
- Always use strong RPC credentials and consider network security when exposing RPC endpoints
- Remember to disable the notify fallback in your DATUM Gateway configuration when using Docker

## Template/Share Requirements for Pooled Mining

 - Must be a valid block and conform to current Bitcoin consensus rules
 - Submitted work must be for the current latest block height, valid time, etc
 - Must include generation transaction outputs provided by the pool in the order provided
 - Must include the primary coinbase tag as provided by the pool
 - Must include the unique identifier provided by the pool
 - Work must include the work target and meet/exceed that target
 - Any additional requirements by pool documentation

## Notes/Known Issues/Limitations

- By default, if the connection with the pool is lost and fails to reconnect, the Gateway will disconnect all stratum clients. This way miners can use their built-in failover and switch to non-DATUM mining, or an alternate/backup Gateway.
- Accepted/rejected share counts on mining hardware may not perfectly match with the pool. The delta may vary depending on the Gateway's configuration. This is because shares are first accepted or rejected as valid for your local template based on your local node, and then again accepted or rejected based on the pool's requirements, latency to the pool (stale work), latency between your node and the network (stale work), etc.  Stratum v1 has no mechanism to report back to the miner that previously accepted work is now rejected, and it doesn't make sense to wait for the pool before responding, either.

**Most importantly**, please note that this is currently a public **BETA** release. While best efforts have been made to ensure this software is as stable and as useful as possible, you may still encounter issues.

This software is likely to undergo rapid development and revisions up until a v1.0 stable release. Some of these revisions may include changes, such as protocol changes, that require upgrading to the latest version with short or even no notice in order to continue using the software with a DATUM pool. Be sure to watch for important updates!

Be sure you have failover settings on your miners. As a best practice, when mining on a DATUM pool, set your miner's failover to use that pool's Stratum endpoint.

## License

The DATUM Gateway (including the DATUM Protocol) is free open source software and released under the terms of the MIT license.  See LICENSE.
