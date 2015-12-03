sym = SymantecCertificatePlugin()
##
# Order test:
##
#def issue_certificate_request(self, order_id, order_meta, plugin_meta,
csr = """-----BEGIN NEW CERTIFICATE REQUEST-----
MIICZzCCAU8CAQAwIjELMAkGA1UEBhMCREUxEzARBgNVBAMTCmJidGVzdC5uZXQw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQo9juJhMyJ8hFlakwTtCH
jgQNajgKxHe+eUGu9OwJ3VeiZkUCosUX8GCKbkuHXMcYQxoF1ZnE5Fu2iSvoqirG
Y8mRS3Wk1rOjhvf6RkVmLDM8U63CHhGEYTnhWWJ1qDlRQSuPWMdVJCP4UvR79X9H
9lV4x1bH1OpgH736Hobp+QcQJx+spTXkOwYPOW+8tdc89PqucPLquxmzkDaML5Cy
sPv0qIapQUxaeTTyrf6U8lbOukSckIg1E3c2WbilrajF9Mq9MTMW9+Q4T8OoD7al
31o9SiWWlK7jTWM/e5tT2j8V4A+7aEsmMncxXrpcv8rCcU85z1GbMnEz2XKLvkRf
AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEALXjYEEWN1+oJvOzRXwCgGOchMso7
+5GZ9skhtCKYZdrJOU8J7w0o4dYdz4xR81+3b2HgKTDhPeZB323Blb8/OWfTq0I0
BZOUlXx87UDiSaPGHXD0QMAhsiUoXzVXfUHI0kdb6ew9FSniRzx5bM9RIvMitax9
eeQVpaPIs8UVAFoaR9HMRGC973+3hCbQKuA9jg2BvPRqL6GACKVc1t6gM6tpxfNc
uEH4TnSxflSpLk+17eu2Ke35g4pDMZvOW4PALopxHMGWqeJEmVxAh1hry0jogJP8
TWPGx+Yjkmo1qtaxCYKuJewxci2kyL0bN3ZfUlFTi4VsE2vmiS9l9jgeIQ==
-----END NEW CERTIFICATE REQUEST-----"""
"""
res = sym.issue_certificate_request(
    "barbican_test6",
    {
    'ProductCode':"RapidSSL", "OrganizationName":"Tobias' Great Cookies",
    'AddressLine1':"Dough Ave 1",'AddressLine2':None,'AddressLine3':None,
    'City':"Stuttgart", "Region":"BW", "Fax":None,
    "PostalCode":"70168", "Country":"DE", "OrganizationPhone":"12309123",
    "ValidityPeriod":12, "ServerCount":1, "WebServerType":"apache2",
    "AdminContactFirstName":"Tobias", "AdminContactLastName":"Zatti",
    "AdminContactTitle":"Mr", "AdminContactPhone":"12345678",
    "AdminContactEmail":"tobias_zatti@symantec.com", 
    "AdminContactCity": "Stuttgart", "AdminContactTitle":None,
    "AdminContactAddressLine1":None, "AdminContactAddressLine2":None,
    "AdminContactOrganizationName":"MyOrg", "AdminContactRegion":"BW",
    "AdminContactPostalCode":"70168", "AdminContactCountry":"DE",
    "TechSameAsAdmin":True, "BillSameAsAdmin":True, 
    "ApproverEmail":"hostmaster@bbtest.net", "CSR":csr
    },
    {},{})
print res.status
print res.status_message
"""
## 
# Check order status test:
## 
res = sym.check_certificate_status("barbican_test6", [], {"importantData": "i like ice cream"}, [])
print res
print res.status
#def cancel_certificate_request(self, order_id, order_meta, plugin_meta,
#                               barbican_meta_dto):
##
# Cancel certificate test:
##
"""
res = sym.cancel_certificate_request("barbican_test2", [], [],[])
print res
print res.status
"""
##
# Modify Order test
##
res = sym.modify_certificate_request("barbican_test6", {"CSR":csr, "SignatureHashAlgorithm":"SHA256-Full-Chain", "ReissueEmail":'hostmaster@bbtest.net'}, {}, {})
print res
print res.status
print "Status Message:", res.status_message