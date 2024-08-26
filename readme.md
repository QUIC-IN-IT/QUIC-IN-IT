# Setup

`pip install -r requirements.txt`

Using Python>=3.12 is recommended.

# Procedure

Create a file named run.txt, and put some CIDR formatted IP addresses (or single IPs) in the text file. If you just want to do some tests you can simply use `1.1.1.1/24`.

IPv4 and IPv6 are both supported, but using IPv4 and v6 in the same file is not supported. Scan one type of IP at one time.

You can download IPv6 Hitlist [here](https://addrminer.github.io/IPv6_hitlist.github.io/).

Run `main.py` to scan all potential QUIC deployments within the given addresses. After finished the QUIC scanning, use `generate_quic_results.py` to extract QUIC deployments from all responses. Then, use `amp_test.py` followed by `final_amp_result.py` to test potential amplification under all configurations and summarize results. Finally use `categorize.py` to categorize these attack potential cause types.

See each file for arguments. Use `-g` for all IPv4 addresses for `main.py`.