import sys
import dns.query
from time import time, ctime


# root servers
root_servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12","199.7.91.13",
                "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
                "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"]

# root signing key
root_signing_key = ["19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5",
                    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]

# extract the ksk, zsk dnskey and the signature of zsk
def get_dnskey_rrsig(query_domain, server):
    query_message = dns.message.make_query(query_domain, dns.rdatatype.DNSKEY, want_dnssec=True)
    response = dns.query.tcp(query_message, server)
    zsk_rrsig = ksk_zsk_rrset = None

    for answer in response.answer:
        if answer.rdtype == dns.rdatatype.RRSIG:
            zsk_rrsig = answer
        elif answer.rdtype == dns.rdatatype.DNSKEY:
            ksk_zsk_rrset = answer
    return zsk_rrsig, ksk_zsk_rrset


def dns_resolver(domain, server, last_level, ds, ds_list=root_signing_key):
    # extract the ksk, zsk dnskey and signature of zsk
    try:
        zsk_rrsig, ksk_zsk_rrset = get_dnskey_rrsig(last_level, server)
        if not (zsk_rrsig and ksk_zsk_rrset):
            print("DNSSEC not supported")
            return None
    except Exception:
        print("DNSSEC not supported")
        return None

    ksk = zsk = None
    for i in ksk_zsk_rrset:
        if i.flags == 257:
            ksk = i
        elif i.flags == 256:
            zsk = i

    # verified ksk dnskey by last level ds
    ksk_dnskey_verified = False
    if last_level == ".":
        algo = "sha256"
        ksk_hash = dns.dnssec.make_ds(last_level, ksk, algo)
    else:
        algo = "sha1" if ds[0].digest_type == 1 else "sha256"
        ksk_hash = dns.dnssec.make_ds(last_level+".", ksk, algo)
    if last_level == ".":
        for i in ds_list:
            if ksk_hash.to_text() == i.lower():
                ksk_dnskey_verified = True
    else:
        if ksk_hash.to_text() == ds[0].to_text().lower():
            ksk_dnskey_verified = True

    if not ksk_dnskey_verified:
        print("DNSSEC verification failed")
        return None

    # verified zsk rrsig by ksk dnskey
    try:
        dns.dnssec.validate(ksk_zsk_rrset, zsk_rrsig, {dns.name.from_text(last_level): ksk_zsk_rrset})
    except dns.dnssec.ValidationFailure:
        print("DNSSEC verification failed")
        return None

    # make query of domain
    try:
        query = dns.message.make_query(domain, "A", want_dnssec=True)
        response = dns.query.tcp(query, server)
        server_responsed[0] = True
    except dns.query.BadResponse:
        print("No response from " + server)
        return None
    except Exception:
        print("error with getting response from server")
        return None

    # get the ds for the next level and the current query rrsig
    new_ds = None
    if not response.answer:
        query_rrsig = None
        if response.authority:
            authority = response.authority
            for auth in authority:
                if auth.rdtype == dns.rdatatype.DS:
                    new_ds = auth
                elif auth.rdtype == dns.rdatatype.RRSIG:
                    query_rrsig = auth
        else:
            print("DNSSEC not supported")
            return None
        if not query_rrsig or (not response.answer and not new_ds):
            print("DNSSEC not supported")
            return None

        # verified query rrsig by zsk dnskey
        try:
            dns.dnssec.validate(new_ds, query_rrsig, {dns.name.from_text(last_level): ksk_zsk_rrset})
        except dns.dnssec.ValidationFailure:
            print("DNSSEC verification failed")
            return None

    # get the current domain level for the usage of next level
    split_domain = domain.split(".")
    for i in range(len(split_domain) - 1, -1, -1):
        if last_level == ".":
            current_level = split_domain[-1]
            break
        elif ".".join(split_domain[i:]) == last_level:
            if i > 0:
                current_level = ".".join(split_domain[i - 1:])
            else:
                current_level = domain
            break
    else:
        print("DNSSEC not supported")
        return None

    # if there is an answer, then return the answer
    if response.answer:
        answer = []
        for a in response.answer:
            if a.rdtype == dns.rdatatype.A:
                answer.append(a)
        # answer = response.answer

        if answer[0].rdtype == dns.rdatatype.CNAME:
            cname_answer = root_resolver(str(answer[0][0].to_text()), 'A')
            answer += cname_answer

        return answer

    # if there is no answer in response, extract the next level ip from the additional section
    elif response.additional:
        for addi in response.additional:
            if addi[0].rdtype == dns.rdatatype.A:
                answer = dns_resolver(domain, addi[0].to_text(), current_level, new_ds)
                return answer

    # if the additional section has no next level ip address, find in authority
    elif response.authority:
        for auth in response.authority[0]:
            if auth.rdtype == dns.rdatatype.A:
                answer = dns_resolver(domain, auth.to_text(), current_level, new_ds)
            elif auth.rdtype == dns.rdatatype.NS:
                new_server = dns_resolver(auth.to_text().strip("."), root_servers[0], ".", "")
                answer = dns_resolver(domain, new_server[0][0].to_text(), current_level, new_ds)
            else:
                continue
            return answer

    return None


def root_resolver(domain):
    for server in root_servers:
        response = dns_resolver(domain, server, ".", "", root_signing_key)
        if response:
            return response
        elif server_responsed[0]:
            break
    else:
        print("No server answer.")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Wrong arguments format. Arguments format should be \"[domain]\"")
        quit()

    domain_name = sys.argv[1]
    server_responsed = [False]

    start_time = time()

    result = root_resolver(domain_name.strip("."))

    # if there is a result, then print it
    if result:
        query_time = time() - start_time

        print("QUESTION SECTION:")
        print(domain_name + ".   IN " + "A" + "\n")
        print("ANSWER SECTION:")
        for i in result:
            print(i)
        print("\nQuery time: " + str(round(query_time * 1000)) + "ms")
        print("WHEN: " + str(ctime()))
        print("MSG SIZE rcvd: " + str(sys.getsizeof(result)))