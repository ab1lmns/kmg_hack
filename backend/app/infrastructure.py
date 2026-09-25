"""Read-only AD topology and fixed DNS diagnostics, separate from scan collection."""

import ipaddress
import ssl


FUNCTIONAL_LEVELS = {
    0: "Windows2000", 1: "Windows2003Interim", 2: "Windows2003",
    3: "Windows2008", 4: "Windows2008R2", 5: "Windows2012",
    6: "Windows2012R2", 7: "Windows2016",
}


def domain_from_dn(dn):
    return ".".join(part.split("=", 1)[1] for part in (dn or "").split(",")
                    if part.strip().lower().startswith("dc="))


def functional_level(value, kind):
    try:
        name = FUNCTIONAL_LEVELS[int(value)]
    except (TypeError, ValueError, KeyError):
        return None
    return name + kind


def parse_topology(root, cross_ref, endpoint):
    """Turn RootDSE and the domain crossRef into a fixed, public-safe model."""
    forest_dn = root.get("rootDomainNamingContext")
    domain_dn = root.get("defaultNamingContext")
    fqdn = root.get("dnsHostName")
    server_dn = root.get("serverName") or ""
    rdns = [part.strip() for part in server_dn.split(",")]
    site = next((rdns[i - 1].split("=", 1)[1] for i, part in enumerate(rdns)
                 if part.lower() == "cn=sites" and i > 0 and rdns[i - 1].lower().startswith("cn=")), None)
    forest = {"name": domain_from_dn(forest_dn) or None,
              "root_domain": domain_from_dn(forest_dn) or None,
              "functional_level": functional_level(root.get("forestFunctionality"), "Forest")}
    domain = {"name": domain_from_dn(domain_dn) or None,
              "distinguished_name": domain_dn, "netbios": cross_ref.get("nETBIOSName"),
              "functional_level": functional_level(root.get("domainFunctionality"), "Domain")}
    dc = {"hostname": fqdn.split(".", 1)[0] if fqdn else None, "fqdn": fqdn,
          "ip": endpoint, "site": site, "is_current": True,
          "ldap_endpoint": f"{endpoint}", "status": "pass" if fqdn else "not_evaluated"}
    forest["status"] = "pass" if all(forest.values()) else "not_evaluated"
    domain["status"] = "pass" if all(domain.values()) else "not_evaluated"
    return forest, domain, dc


def empty_infrastructure():
    forest = {"name": None, "root_domain": None, "functional_level": None, "status": "not_evaluated"}
    domain = {"name": None, "distinguished_name": None, "netbios": None,
              "functional_level": None, "status": "not_evaluated"}
    return {"forest": forest, "domain": domain, "domain_controller": None,
            "domain_controllers": [], "dns": {key: "not_evaluated" for key in
            ("domain_resolution", "dc_resolution", "ldap_srv", "kerberos_srv", "gc_srv")},
            "diagnostics": {key: "not_evaluated" for key in
            ("DNS_RESOLUTION", "LDAP_SRV", "KERBEROS_SRV", "GC_SRV", "LDAP_CONNECTION")},
            "sources": {key: "not_evaluated" for key in
            ("ldap", "users", "groups", "computers", "fgpp", "security_event_log")}}


def apply_scan_source_status(result, source_status):
    """Show source status from the local saved scan, including after Gateway restart."""
    if not source_status:
        return result
    if source_status.get("ldap") == "pass":
        result["sources"]["users"] = "pass"
        result["sources"]["groups"] = "pass"
    for target, source in (("computers", "computers"), ("fgpp", "fine_grained_policies"),
                           ("security_event_log", "security_event_log")):
        status = source_status.get(source)
        if status in ("pass", "error", "not_evaluated"):
            result["sources"][target] = status
    return result


def _dns_status(resolver, name, record_type):
    try:
        records = resolver.resolve(name, record_type)
        return "pass" if records else "not_evaluated"
    except Exception as exc:
        # NXDOMAIN and NoAnswer mean a missing record; timeout/refusal is a source error.
        import dns.resolver
        if isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
            return "not_evaluated"
        return "error"


def dns_diagnostics(domain_name, dc_fqdn, nameserver):
    import dns.resolver

    result = {key: "not_evaluated" for key in
              ("domain_resolution", "dc_resolution", "ldap_srv", "kerberos_srv", "gc_srv")}
    if not domain_name or not nameserver:
        return result
    resolver = dns.resolver.Resolver(configure=False)
    try:
        ipaddress.ip_address(nameserver)
        resolver.nameservers = [nameserver]
    except ValueError:
        # A hostname for the configured DC must first resolve through system DNS.
        resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    result["domain_resolution"] = _dns_status(resolver, domain_name, "A")
    if dc_fqdn:
        result["dc_resolution"] = _dns_status(resolver, dc_fqdn, "A")
    for key, name in (("ldap_srv", f"_ldap._tcp.dc._msdcs.{domain_name}"),
                      ("kerberos_srv", f"_kerberos._tcp.{domain_name}"),
                      ("gc_srv", f"_gc._tcp.{domain_name}")):
        result[key] = _dns_status(resolver, name, "SRV")
    return result


def collect_infrastructure(settings, source_status=None):
    result = apply_scan_source_status(empty_infrastructure(), source_status)
    if not all((settings.ldap_host, settings.ldap_username, settings.ldap_password)):
        return result

    try:
        from ldap3 import BASE, NONE, SUBTREE, Connection, Server, Tls
        from ldap3.utils.conv import escape_filter_chars

        tls = Tls(validate=ssl.CERT_REQUIRED if settings.ldap_validate_cert else ssl.CERT_NONE)
        server = Server(settings.ldap_host, port=settings.ldap_port, use_ssl=settings.ldap_use_ssl,
                        tls=tls, get_info=NONE, connect_timeout=5)
        with Connection(server, user=settings.ldap_username, password=settings.ldap_password,
                        auto_bind=True, receive_timeout=8, raise_exceptions=True,
                        check_names=False) as connection:
            result["diagnostics"]["LDAP_CONNECTION"] = "pass"
            result["sources"]["ldap"] = "pass"
            connection.search("", "(objectClass=*)", search_scope=BASE,
                              attributes=["rootDomainNamingContext", "defaultNamingContext",
                                          "configurationNamingContext", "dnsHostName", "serverName",
                                          "forestFunctionality", "domainFunctionality"])
            root = connection.entries[0].entry_attributes_as_dict if connection.entries else {}
            root = {key: value[0] if isinstance(value, list) and value else value
                    for key, value in root.items()}
            cross_ref = {}
            config_dn = root.get("configurationNamingContext")
            domain_dn = root.get("defaultNamingContext")
            if config_dn and domain_dn:
                connection.search(f"CN=Partitions,{config_dn}",
                                  f"(&(objectClass=crossRef)(nCName={escape_filter_chars(domain_dn)}))",
                                  search_scope=SUBTREE, attributes=["nETBIOSName"])
                if connection.entries:
                    attrs = connection.entries[0].entry_attributes_as_dict
                    cross_ref = {key: value[0] if isinstance(value, list) and value else value
                                 for key, value in attrs.items()}
            endpoint = f"{settings.ldap_host}:{settings.ldap_port}"
            forest, domain, dc = parse_topology(root, cross_ref, settings.ldap_host)
            dc["ldap_endpoint"] = endpoint
            result.update(forest=forest, domain=domain, domain_controller=dc, domain_controllers=[dc])
    except Exception:
        # Never return bind errors, server responses, credentials, or transport internals.
        result["diagnostics"]["LDAP_CONNECTION"] = "error"
        result["sources"]["ldap"] = "error"
        return result

    result["dns"] = dns_diagnostics(result["domain"]["name"], dc["fqdn"], settings.ldap_host)
    result["diagnostics"].update(
        DNS_RESOLUTION=("pass" if result["dns"]["domain_resolution"] == "pass" and
                        result["dns"]["dc_resolution"] == "pass" else
                        "error" if "error" in (result["dns"]["domain_resolution"], result["dns"]["dc_resolution"])
                        else "not_evaluated"),
        LDAP_SRV=result["dns"]["ldap_srv"], KERBEROS_SRV=result["dns"]["kerberos_srv"],
        GC_SRV=result["dns"]["gc_srv"])
    return result
