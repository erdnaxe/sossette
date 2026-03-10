# Sossette 🧦

<!--
SPDX-FileCopyrightText: 2023-2025 erdnaxe
SPDX-License-Identifier: CC0-1.0
-->

**Sossette** listens for incoming TCP connections and establishes bidirectional
bytes streams between users and instances of a program.

Compared to the `socat + timeout` combo:

  - The target process group always gets killed when the socket is closed.
    Works well with `cpulimit` and `qemu`.
  - Optional proof-of-work system.
  - Deployment using a single statically linked binary (using musl).

This project is developed for [France Cybersecurity Challenge](https://fcsc.fr/)
since 2023.

You might also want to have a look at these alternatives:

  - [`socaz` by Cybersecurity National Lab](https://hub.docker.com/r/cybersecnatlab/socaz) (closed-source)
  - [`socat + timeout`](https://docs.ctfd.io/tutorials/challenges/network-service-challenge-containers/)

## Release build

You may directly download release builds [from GitHub releases](https://github.com/erdnaxe/sossette/releases/).

Else, you can rebuild the binary:
 1. Make sure you have `x86_64-unknown-linux-musl` Rust target.
    If you are using `rustup` to manage your Rust installation,
    you may run `rustup target add x86_64-unknown-linux-musl`.
 2. Run `cargo build --release`.
 3. Output will be at `target/x86_64-unknown-linux-musl/release/sossette`.

`sossette` binary can be copied inside a empty Docker container as it is
statically compiled. `Dockerfile` example:
```Dockerfile
FROM scratch
WORKDIR /app/
COPY ./sossette .
EXPOSE 4000
CMD ["./sossette", "-l", "0.0.0.0:4000", "./my-challenge"]
```

## Debug build

For example, to run `cat` on `localhost:4000` with a timeout of 10 seconds
and a message of the day `Chaussette`:
```
$ cargo run -- -l localhost:4000 -t 10 -m "Chaussette" cat -- --show-nonprinting
[2023-01-30T12:00:19Z INFO  ctf_wrapper] Listening on localhost:4000
[2023-01-30T12:00:20Z INFO  ctf_wrapper] Client [::1]:55438 connected
[2023-01-30T12:00:27Z INFO  ctf_wrapper] Client [::1]:55438 disconnected
```

Then in another console:
```
$ nc localhost 4000
Chaussette
hello
hello
world
world
^C
```

## PROXY protocol support

Sossette supports the [PROXY protocol v2](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) to preserve client IP addresses when running behind a load balancer or reverse proxy.

### Usage

Enable PROXY protocol v2 with the `--proxy-protocol` flag. When enabled, a valid PROXY protocol v2 header is **required** and connections without one are rejected:

```bash
$ sossette --proxy-protocol -l 0.0.0.0:4000 cat
```

Or using the environment variable:

```bash
$ WRAPPER_PROXY_PROTOCOL=true sossette -l 0.0.0.0:4000 cat
```

### Accessing client information

When PROXY protocol is enabled and a valid header is received, sossette:

1. **Logs the real client IP** instead of the proxy's IP:
   ```
   [2024-03-09T10:15:23Z INFO  sossette] Client [::1]:55438 connected
   [2024-03-09T10:15:23Z INFO  sossette] Real client: 192.0.2.123:54321 (via proxy [::1]:55438)
   ```

2. **Passes client information to the wrapped process** via environment variables:
   - `CLIENT_IP`: The real client's IP address (e.g., `192.0.2.123`)
   - `CLIENT_PORT`: The real client's source port (e.g., `54321`)
   - `PROXY_DEST_IP`: The destination IP the client connected to
   - `PROXY_DEST_PORT`: The destination port the client connected to

   Example usage in a bash script:
   ```bash
   #!/bin/bash
   echo "Welcome! Your IP is: $CLIENT_IP:$CLIENT_PORT"
   ```

### Load balancer configuration

#### HAProxy

Configure HAProxy to send PROXY protocol v2 headers:

```haproxy
frontend tcp_front
    bind *:443
    mode tcp
    default_backend tcp_back

backend tcp_back
    mode tcp
    server sossette 127.0.0.1:4000 send-proxy-v2
```

#### nginx

Configure nginx stream module with PROXY protocol:

```nginx
stream {
    upstream sossette {
        server 127.0.0.1:4000;
    }

    server {
        listen 443;
        proxy_pass sossette;
        proxy_protocol on;
    }
}
```

**Security note**: When using PROXY protocol, ensure that only trusted load balancers can connect to sossette (e.g., using firewall rules). Otherwise, clients could spoof their IP addresses by sending fake PROXY protocol headers.

## Applying transformations to stdin

`process_stdin` in [src/main.rs](./src/main.rs) can be easily patched to apply
some transformation to users inputs before passing then to the underlaying
program.

For example [FCSC 2023 Sous Marin challenge](https://hackropole.fr/en/challenges/hardware/fcsc2023-hardware-sous-marin/) uses the following patch:

```diff
--- a/src/main.rs
+++ b/src/main.rs
@@ -71,10 +71,17 @@ async fn process_stdin(mut socket: OwnedReadHalf, mut child_stdin: ChildStdin) -
              debug!("Client sent Ctrl-C");
              return Ok(());
          }
-        child_stdin
-            .write_all(&in_buf[0..n])
-            .await
-            .context("Failed to write to stdin")?;
+        for b in in_buf[0..n].iter() {
+            // Handle serial protocol inversion
+            // b&0x01 must be 1 as it is the start bit
+            if b & 0x01 == 1 {
+                let tb = (b ^ 0xFF) >> 1;
+                child_stdin
+                    .write_all(&[tb])
+                    .await
+                    .context("Failed to write to stdin")?;
+            }
+        }
      }
  }
```
