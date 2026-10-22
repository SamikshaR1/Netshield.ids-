# NetShield IDS

NetShield IDS is a Flask dashboard for network intrusion detection. The dashboard
includes simulated attacks so you can try it without generating network traffic.

## Run locally

```bash
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. To capture real network packets, run locally with
the privileges required by your operating system and Scapy. The demo buttons
work without packet capture.

## Deploy a public demo on Render

1. Sign in to [Render](https://render.com/) and connect your GitHub account.
2. Select **New +** > **Blueprint** and choose the `SamikshaR1/Netshield.ids-`
   repository.
3. Apply the settings from `render.yaml`. Once the service finishes deploying,
   Render will show its public URL.

The hosted version is a demo: cloud hosts cannot capture packets from your
personal computer or local network. Use the dashboard's demo attack buttons to
generate sample alerts. For real packet capture, run the app on a machine that
has access to the network you want to monitor.
