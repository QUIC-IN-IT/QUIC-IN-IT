# Naming

The name "QUIC-IN-IT" is actually a pun. It means that we use Initial packets to perform our work (IN-IT for "Init"ial), and it can discover the deployments and amplification vulnerabilities, or to say to look whether there are some interestring things "in it" (deployment in an IP, or amplification in a deployment).

# Setup

`pip install -r requirements.txt`

Using Python>=3.12 is recommended.

# Procedure

Create a file named `run.txt`, and put some CIDR formatted IP addresses (or single IPs) in the text file. If you just want to do some tests you can simply use `1.1.1.1/24` for all the procedure.

IPv4 and IPv6 are both supported, but using IPv4 and v6 in the same file is not supported. Scan one type of IPs at one time.

You can download IPv6 Hitlist [here](https://addrminer.github.io/IPv6_hitlist.github.io/).

Run `main.py` to scan all potential QUIC deployments within the given addresses. After finishing the QUIC scanning, use `generate_quic_results.py` to extract QUIC deployments from all responses. Then, use `amp_test.py` followed by `final_amp_result.py` to test potential amplification under all configurations and summarize results. Finally use `categorize.py` to categorize these attack potential cause types.

`split.py` can roughly split the subnets you want to scan into series of smaller parts so that you can run on different servers; `merge.py` can merge multiple `resp_result.txt` together for `generate_quic_results.py` to use. `cat_count.py` can be used to count the occurrences of different types (and the combinations, if exist).

See each file for arguments. Use [bogon report](https://www.cidr-report.org/bogons/) to scan all allocated IPv4 addresses, or `-g` on `main.py` for all IPv4 addresses (not recommended).
