import sys
import dns.query
from time import time, ctime


# root servers
root_servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12","199.7.91.13",
                "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
                "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"]


def dns_resolver(domain, query_type, server):
    # send query to server
    try:
        query = dns.message.make_query(domain, query_type)
        response = dns.query.udp(query, server)
    except dns.query.BadResponse:
        print("No response from " + server)
        return None
    except Exception:
        return None

    # if the response has the answer, then return the answer
    if response.answer:
        answer = response.answer

        # if the answer type is cname, then do another resolution
        if answer[0].rdtype == dns.rdatatype.CNAME and query_type == 'A':
            cname_answer = root_resolver(str(answer[0][0].to_text()), 'A')
            answer += cname_answer

        return answer

    # if there is no answer in response, extract the next level ip from the additional section
    elif response.additional:
        for addi in response.additional:
            if addi[0].rdtype == dns.rdatatype.A:
                answer = dns_resolver(domain, query_type, addi[0].to_text())
                return answer

    # if the additional section has no next level ip address, find in authority
    elif response.authority:
        for auth in response.authority[0]:
            if auth.rdtype == dns.rdatatype.A:
                answer = dns_resolver(domain, query_type, auth.to_text())
            elif auth.rdtype == dns.rdatatype.NS: # if get the NS type, then resolve it to ip address
                new_server = root_resolver(auth.to_text().strip("."), 'A')
                answer = dns_resolver(domain, query_type, new_server[0][0].to_text())
            else:
                continue
            return answer

    return None


def root_resolver(domain, query_type):
    for server in root_servers:
        response = dns_resolver(domain, query_type, server)
        if response:
            return response
    else:
        print("No server answer.")


if __name__ == '__main__':
    # if the number of arguments is not 3, then quit the program
    if len(sys.argv) != 3:
        print("Wrong arguments format. Arguments format should be \"[domain] [query type]\"")
        quit()

    # read the arguments, domain and query type
    domain_name, dns_query_type = sys.argv[1], sys.argv[2]

    if dns_query_type == "MX" or dns_query_type == "NS":
        if domain_name.strip(".").split(".")[0] == "www":
            domain_name = domain_name.strip(".").split(".")[1:]

    start_time = time()

    # start to resolve the domain
    result = root_resolver(domain_name, dns_query_type)

    query_time = time() - start_time

    if result:
        # print the result
        print("QUESTION SECTION:")
        print(domain_name + ".   IN " + dns_query_type + "\n")
        print("ANSWER SECTION:")
        for i in result:
            print(i)
        print("\nQuery time: " + str(round(query_time * 1000)) + "ms")
        print("WHEN: " + str(ctime()))
        print("MSG SIZE rcvd: " + str(sys.getsizeof(result)))
    else:
        print("Could not resolve domain.")