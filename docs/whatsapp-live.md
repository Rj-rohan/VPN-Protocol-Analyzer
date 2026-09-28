# WhatsApp over a real IPsec VPN: live demo and labelled recording

This covers the last traffic type in problem statement part (a): **WhatsApp**. A phone connects through a **real IKEv2 IPsec VPN** to a strongSwan server that you run, all its traffic goes through the tunnel, and the encrypted packets are recorded. You can then:

1. **Record labelled sessions** (chat, voice call, video call, file) to test and train the traffic model on real WhatsApp;
2. **Demo it live** on the dashboard.

Tooling: `testbed/scripts/record_real_app.py`.

## Why a VM on a Windows laptop

The phone's VPN uses NAT traversal: ESP packets wrapped in UDP port 4500. **Windows' own network stack takes those packets for itself and drops them**, even with Windows' IPsec services stopped. The phone *connects*, because the handshake passes, but no data flows, so it has no internet. (Diagnosed on 27 Sep 2026: the ESP packets reached the laptop's Wi-Fi, but 0 reached the server.)

The fix is to run the VPN server in a **Linux VM with a bridged network adapter**. The VM gets its own address on the Wi-Fi, so the phone's packets go straight to Linux without passing through Windows' stack.

```
   📱 Phone A (hotspot, internet)          ← the other end of the WhatsApp call
        ▲ Wi-Fi                 ▲ Wi-Fi
   💻 Laptop                    📱 Phone B (VPN client + WhatsApp)
     └─ VirtualBox VM "ub" (bridged, own IP) ◄═══ IKE / ESP-in-UDP ═══┘
          strongSwan + NAT to internet + tcpdump ► /srv/sih-sessions/
```

**Network rules** (both learned the hard way):
- **The phone running the VPN must not be the hotspot.** Android sends a hotspot phone's VPN connection over mobile data, so it never reaches the laptop. Use a second phone's hotspot or a Wi-Fi router, and put the laptop *and* the VPN phone on it.
- Turn **mobile data off** on the VPN phone, so everything goes over Wi-Fi.

On a **Linux** host, the Docker mode (`record_real_app.py serve --build`) works directly and no VM is needed.

---

## Part 1: one-time setup

### 1.1 Laptop (Windows)

1. Connect the laptop and the VPN phone to the same hotspot or router.
2. Free some memory: quit Docker Desktop if you don't need it (tray icon → Quit), because the VM needs about 2 GB.
3. The VM **"ub"** already has a second network card **bridged to the Wi-Fi** adapter. To add it on another VM (while it's powered off):
   ```bat
   "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm ub --nic2 bridged --bridgeadapter2 "Intel(R) Dual Band Wireless-AC 8265"
   ```
4. Share the recorder with the VM. This file server is reachable only from the VM, as 10.0.2.2:
   ```bat
   cd C:\Users\Admin\Documents\sih
   .venv\Scripts\python -m http.server 8765 --bind 127.0.0.1 --directory testbed\scripts
   ```
   Leave this window open during setup.

### 1.2 Inside the VM (Ubuntu terminal)

1. Start the VM "ub" in VirtualBox, log in, and open a **Terminal**.
2. Check that the bridged card got an address on the hotspot:
   ```bash
   ip -4 addr
   ```
   The second card (usually `enp0s8`) should show an address on the same network as the laptop, for example `10.44.13.x`. If it has none: `sudo dhclient enp0s8`, or on Ubuntu 24.04 `sudo networkctl up enp0s8`.
3. Download the recorder and start the VPN server. This installs strongSwan the first time, so it needs internet:
   ```bash
   curl -O http://10.0.2.2:8765/record_real_app.py
   sudo python3 record_real_app.py --local serve --install --psk <YOUR-KEY>
   ```
   `--psk` reuses the key already typed into the phone. The command prints the **VM's address**. If it lists several addresses, add `--lan-ip <the bridged one>`.

### 1.3 Phone

Edit the **SIH lab** VPN (or create it). Set **Server address** to the **VM's address** printed above; iPhone also needs **Remote ID** set to the same address.

| Field | Value |
|---|---|
| Type | IKEv2/IPSec PSK (Android 11+) or IKEv2 (iPhone, Authentication *None*) |
| Server address | the VM's bridged address |
| IPSec identifier / Local ID | `phone` |
| Pre-shared key | `<YOUR-KEY>` |

Connect, and **open a website on the phone**. It must load.

### 1.4 Check (VM terminal)

```bash
sudo python3 record_real_app.py --local status
```

```
Phone connected: id 'phone', VPN address 10.10.10.1
  IKE SA : AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519
  ESP SA : AES_CBC-128/HMAC_SHA2_256_128  mode Tunnel, NAT-T True
  data   : 1843 packets / 912,334 bytes received from the phone
```

**`data` must be above 0.** If it stays at 0, the phone connects but no traffic flows; see Troubleshooting.

---

## Part 2: record labelled WhatsApp sessions (VM terminal)

Each recording captures **one activity**. Start the command, then do that activity on the VPN phone until the countdown ends:

```bash
sudo python3 record_real_app.py --local record --activity voice-call --seconds 120
sudo python3 record_real_app.py --local record --activity chat --seconds 120
sudo python3 record_real_app.py --local record --activity video-call --seconds 120
sudo python3 record_real_app.py --local record --activity file --seconds 60
sudo python3 record_real_app.py --local record --activity status --seconds 60
```

| Activity | What to do on the phone | Saved as class | Suggested count |
|---|---|---|---|
| `chat` | Normal back-and-forth text messages | Chat | 8 × 2 min |
| `voice-call` | WhatsApp voice call, both people talking | VoIP | 8 × 2 min |
| `video-call` | WhatsApp video call | Video (ISCX convention) | 6 × 2 min |
| `file` | Send photos, videos or a large document | File-Transfer | 5 × 1 min |
| `status` | Watch WhatsApp Status videos | Video | 4 × 1 min |

Recordings go to `/srv/sih-sessions/` in the VM. The command refuses to start if the tunnel carries no data, so you won't get empty files. Other apps work too: `--app instagram --activity status`, `--app telegram --activity chat`.

### Copy the recordings to Windows

In the VM, install an SSH server once:

```bash
sudo apt install -y openssh-server
```

Then on Windows (Command Prompt), with the VM's address and your VM user name:

```bat
scp "<vm-user>@<vm-address>:/srv/sih-sessions/*" C:\Users\Admin\Documents\sih\data\raw\traffic_sessions\
```

---

## Part 3: test the current model on WhatsApp first

Before training, **upload a few recordings** on the Upload page and note the predicted class. This is accuracy on an app the model has **never seen**, which is an honest number for judges. The analyzer should also report the phone's real settings: IKEv2, NAT-T Yes, AI mode Tunnel, AI cipher family matching the `negotiated` ESP value in the `.json`.

## Part 4: train with the WhatsApp sessions

```bat
cd C:\Users\Admin\Documents\sih\backend
..\.venv\Scripts\python -m app.ml.train --source combined
..\.venv\Scripts\python -m app.ml.protocol_models
```

The recordings join training as the source `real_app_phone_ikev2`. The model report shows accuracy for that source separately, and `python -m app.dataset_export --zip` includes them in the dataset.

## Part 5: live demo on the dashboard

The Live capture page records on a **Windows** interface. With the VM bridged, the phone's packets travel through the laptop's Wi-Fi adapter to the VM, so Windows can usually still capture them:

1. Dashboard → **Live capture** → Interface **Wi-Fi** → **IPsec only** → 120 s → **Start**.
2. On the phone, **disconnect and reconnect** the VPN, so the handshake is captured and the cipher and DH group are read directly.
3. Make a WhatsApp call.

If the live page shows no packets on your Wi-Fi driver, demo with a recording instead: upload a `whatsapp_voice-call_NN.pcap` made in Part 2.

---

## Clean up

```bash
sudo python3 record_real_app.py --local stop          # in the VM
```

On Windows (administrator), undo the earlier port changes if you made them:

```bat
sc config IKEEXT start= auto
net start IKEEXT
net start PolicyAgent
netsh advfirewall firewall delete rule name="SIH IPsec lab"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Phone stuck on "Connecting…", nothing reaches the server | The VPN phone is the hotspot, or the wrong server address | Use another hotspot or router; the server address is the **VM's** bridged address |
| Connected, but `status` shows `data: 0 packets` and the phone has no internet | The server is running on Windows (Docker), whose stack drops ESP-in-UDP | Use the VM (this page), not Docker on Windows |
| VM's bridged card has no address | DHCP not started on the new card | `sudo dhclient enp0s8` (or `sudo networkctl up enp0s8`) |
| `serve` lists several addresses | NAT and bridged cards both up | Add `--lan-ip <bridged address>` |
| Connected, data > 0, but websites don't load | NAT or DNS | Check that the VM itself has internet (`ping 8.8.8.8`); run `serve` again |
| iPhone: "Negotiation with the VPN server failed" | Remote ID mismatch | Remote ID = the VM's address; Authentication *None* |
| `curl http://10.0.2.2:8765/...` fails in the VM | File server not running, or the VM's first card isn't NAT | Start the `http.server` command from 1.1; VM card 1 must be NAT |

---

## Privacy

- Record only **your own** chats and calls, with people who agree.
- **Nothing readable is stored.** The recorder keeps only UDP 500/4500, meaning the encrypted IPsec packets, and WhatsApp content is end-to-end encrypted anyway.
- The pcaps contain only lab addresses: the VM, the phone's Wi-Fi address and the 10.10.10.x VPN pool. No phone number or message appears.
