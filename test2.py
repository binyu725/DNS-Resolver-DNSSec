import dns.query

root_servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12","199.7.91.13",
                "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
                "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"]


if __name__ == '__main__':
    message_A = dns.message.make_query("microsoftonline.com", dns.rdatatype.A, want_dnssec=False)
    q_A = dns.query.tcp(message_A, "104.47.38.8")
    print(q_A)
    print()
    # message_DNSKEY = dns.message.make_query("org", dns.rdatatype.DNSKEY, want_dnssec=True)
    # q_DNSKEY = dns.query.tcp(message_DNSKEY, "199.19.56.1")
    # print(q_DNSKEY)
    # print()
    # message2_A = dns.message.make_query("www.apple.com.", dns.rdatatype.A, want_dnssec=True)
    # q2_A = dns.query.tcp(message2_A, "192.33.14.30")
    # print(q2_A)
    # print()
    # message2_DNSKEY = dns.message.make_query("com", dns.rdatatype.DNSKEY, want_dnssec=True)
    # q2_DNSKEY = dns.query.tcp(message2_DNSKEY, "192.33.14.30")
    # print(q2_DNSKEY)
    # print()
    # hash_key = dns.dnssec.make_ds(".", q_DNSKEY.answer[0][1], "sha256")
    # print(hash_key)

    # try:
    #     dns.dnssec.validate(q_A.authority[1], q_A.authority[2], {dns.name.from_text("."): q_DNSKEY.answer[0]})
    # except dns.dnssec.ValidationFailure:
    #     print("failed")

    # last = "com"
    # current_level = ""
    # split_domain = "www.google.com".split(".")
    # for i in range(len(split_domain) - 1, -1, -1):
    #     if last == ".":
    #         current_level = split_domain[-1]
    #     elif ".".join(split_domain[i:]) == last:
    #         if i > 0:
    #             current_level = ".".join(split_domain[i - 1:])
    #         else:
    #             current_level = "www.google.com"
    #         break
    # else:
    #     print("domain error")
    #
    # print(current_level)