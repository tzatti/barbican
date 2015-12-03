# Copyright (c) 2013-2014 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Barbican certificate processing plugins and support.
"""
from oslo_config import cfg
from requests import exceptions as request_exceptions
from barbican.common import config
from barbican import i18n as u
from barbican.plugin.interface import certificate_manager as cert
from barbican.plugin.interface.SymAPI import SymAPI

CONF = config.new_config()

symantec_plugin_group = cfg.OptGroup(name='symantec_plugin',
                                     title='Symantec Plugin Options')

symantec_plugin_opts = [
    cfg.StrOpt('username',
               help=u._('Symantec username for authentication')),
    cfg.StrOpt('password',
               help=u._('Symantec password for authentication')),
    cfg.StrOpt('partnercode',
               help=u._('Symantec partner code for authentication')),
    cfg.StrOpt('testmode',
               help=u._('If true, the sandbox environment will be used instead of production. This requires a dedicated sandbox account!'))
]

CONF.register_group(symantec_plugin_group)
CONF.register_opts(symantec_plugin_opts, group=symantec_plugin_group)
config.parse_args(CONF)


class SymantecCertificatePlugin(cert.CertificatePluginBase):
    """Symantec certificate plugin."""

    def __init__(self, conf=CONF):
        self.username = conf.symantec_plugin.username
        self.password = conf.symantec_plugin.password
        self.partnercode = conf.symantec_plugin.partnercode
        self.testmode = conf.symantec_plugin.testmode

        if self.username == None:
            raise ValueError(u._("username is required"))

        if self.password == None:
            raise ValueError(u._("password is required"))

        if self.partnercode == None:
            raise ValueError(u._("partnercode is required"))

        if self.testmode == None:
            raise ValueError(u._("testmode is required"))

        # We can't read booleans off the config file.
        # This means we need to treat them as a string.
        testmode = False
        if self.testmode.lower() == 'true':
            testmode = True
        # Create and configure the Symantec API plugin
        self.api = SymAPI(useTestAPI = testmode, verbose=False)
        self.api.setCredentials(self.partnercode, self.username, self.password)

    def get_default_ca_name(self):
        return "Symantec CA"

    def get_default_signing_cert(self):
        # TODO(chellygel) Add code to get the signing cert
        return None

    def get_default_intermediates(self):
        # TODO(chellygel) Add code to get the cert chain
        return None

    def issue_certificate_request(self, order_id, order_meta, plugin_meta,
                                  barbican_meta_dto):
        """Create the initial order with CA

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :param barbican_meta_dto: additional data needed to process order.
        :returns: ResultDTO
        """
        successful, error_msg, can_retry = self._ca_create_order(order_id, order_meta,
                                                            plugin_meta)

        status = cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST
        message = error_msg

        if successful:
            status = cert.CertificateStatus.WAITING_FOR_CA
        elif can_retry:
            status = cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN
            message = error_msg

        return cert.ResultDTO(status=status, status_message=message)

    def modify_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
        """Update the order meta-data

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :param barbican_meta_dto: additional data needed to process order.
        """

        """order_meta should cover:
        - CSR
        - ApproverEmail
        - order_id - the order ID that was used for the certificate
        """ 
        successful, error_msg, can_retry = self._ca_reissue_cert(order_id, order_meta, plugin_meta)
        if successful:
            status = cert.CertificateStatus.WAITING_FOR_CA
        elif can_retry:
            status = cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN
        else:
            status = cert.CertificateStatus.CLIENT_DATA_ISSUE_SEEN
        message = error_msg
        return cert.ResultDTO(status=status, status_message=message)

    def cancel_certificate_request(self, order_id, order_meta, plugin_meta,
                                   barbican_meta_dto):
        """Cancel the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :param barbican_meta_dto: additional data needed to process order.
        """
        successful, error_msg, can_retry = self._ca_modify_order(order_id, "CANCEL")
        if successful:
            status = cert.CertificateStatus.REQUEST_CANCELED
        else:
            status = cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST

        return cert.ResultDTO(status=status, status_message=error_msg)

    def check_certificate_status(self, order_id, order_meta, plugin_meta,
                                 barbican_meta_dto):
        """Check status of the order

        :param order_id: ID associated with the order
        :param order_meta: Dict of meta-data associated with the order.
        :param plugin_meta: Plugin meta-data previously set by calls to
                            this plugin. Plugins may also update/add
                            information here which Barbican will persist
                            on their behalf.
        :param barbican_meta_dto: additional data needed to process order.
        """
        successful, error_msg, can_retry, certificate, intermediate, root = self._ca_get_order_status(order_id)

        status = cert.CertificateStatus.CA_UNAVAILABLE_FOR_REQUEST
        message = None

        if successful:
            if error_msg == "CANCELLED":
                status = cert.CertificateStatus.REQUEST_CANCELED
            elif error_msg == "PENDING_REISSUE":
                status = cert.CertificateStatus.WAITING_FOR_CA
            else:
                status = cert.CertificateStatus.CERTIFICATE_GENERATED
        else:
            status = cert.CertificateStatus.WAITING_FOR_CA
            message = error_msg
            return cert.ResultDTO(status=status, status_message=message)

        return cert.ResultDTO(status=status, status_message=message, certificate=certificate,
            intermediates=({"type":"INTERMEDIATE", "cert":intermediate},{"type":"ROOT", "cert":root}))
        
        #raise NotImplementedError  # pragma: no cover

    def supports(self, certificate_spec):
        """Indicates if the plugin supports the certificate type.

        :param certificate_spec: Contains details on the certificate to
                                 generate the certificate order
        :returns: boolean indicating if the plugin supports the certificate
                  type
        """
        # TODO(chellygel): Research what certificate types are supported by
        # symantec. Returning True for testing purposes
        return True

    def _create_orginfo(self, order_meta):
        # Default all options to None so that non required arguments don't
        # have to be entered.
        orgName = order_meta["OrganizationName"] if "OrganizationName" in order_meta else None
        country = order_meta["Country"] if "Country" in order_meta else None
        region  = order_meta["Region"] if "Region" in order_meta else None
        city    = order_meta["City"] if "City" in order_meta else None
        al1     = order_meta["AddressLine1"] if "AddressLine1" in order_meta else None
        al2     = order_meta["AddressLine2"] if "AddressLine2" in order_meta else None
        al3     = order_meta["AddressLine3"] if "AddressLine3" in order_meta else None
        postal  = order_meta["PostalCode"] if "PostalCode" in order_meta else None
        phone   = order_meta["Phone"] if "Phone" in order_meta else None
        fax     = order_meta["Fax"] if "Fax" in order_meta else None
        return self.api.createOrganizationInfo(
            orgName,
            countryCode = country,
            region = region, 
            city = city, 
            addressLine1 = al1,
            addressLine2 = al2,
            addressLine3 = al3, 
            postalCode = postal,
            phone = phone,
            fax = fax)

    def _create_contacts(self, order_meta):
        # Default all options to None so that non required arguments don't
        # have to be entered.
        aFirst  = order_meta["AdminContactFirstName"] if "AdminContactFirstName" in order_meta else None
        aLast   = order_meta["AdminContactLastName"] if "AdminContactLastName" in order_meta else None
        aPhone  = order_meta["AdminContactPhone"] if "AdminContactPhone" in order_meta else None
        aEmail  = order_meta["AdminContactEmail"] if "AdminContactEmail" in order_meta else None
        aTitle  = order_meta["AdminContactTitle"] if "AdminContactTitle" in order_meta else None
        aCity   = order_meta["AdminContactCity"] if "AdminContactCity" in order_meta else None
        aAL1    = order_meta["AdminContactAddressLine1"] if "AdminContactAddressLine1" in order_meta else None
        aAL2    = order_meta["AdminContactAddressLine2"] if "AdminContactAddressLine2" in order_meta else None
        aOrgname= order_meta["AdminContactOrganizationName"] if "AdminContactOrganizationName" in order_meta else None
        aRegion = order_meta["AdminContactRegion"] if "AdminContactRegion" in order_meta else None
        aPostal = order_meta["AdminContactPostalCode"] if "AdminContactPostalCode" in order_meta else None
        aCountry= order_meta["AdminContactCountry"] if "AdminContactCountry" in order_meta else None
        
        admin = self.api.createContact(aFirst, aLast, aPhone, aEmail, title=aTitle,
                                       city=aCity, addressLine1=aAL1, addressLine2=aAL2, organizationName=aOrgname,
                                       region=aRegion, postalCode=aPostal, countryCode=aCountry)

        # Let's check if we can use the admin contact data for the tech contact
        if "TechSameAsAdmin" in order_meta and order_meta["TechSameAsAdmin"] == True:
            tech = admin
        else:
            tFirst  = order_meta["TechContactFirstName"] if "TechContactFirstName" in order_meta else None
            tLast   = order_meta["TechContactLastName"] if "TechContactLastName" in order_meta else None
            tPhone  = order_meta["TechContactPhone"] if "TechContactPhone" in order_meta else None
            tEmail  = order_meta["TechContactEmail"] if "TechContactEmail" in order_meta else None
            tTitle  = order_meta["TechContactTitle"] if "TechContactTitle" in order_meta else None
            tCity   = order_meta["TechContactCity"] if "TechContactCity" in order_meta else None
            tAL1    = order_meta["TechContactAddressLine1"] if "TechContactAddressLine1" in order_meta else None
            tAL2    = order_meta["TechContactAddressLine2"] if "TechContactAddressLine2" in order_meta else None
            tOrgname= order_meta["TechContactOrganizationName"] if "TechContactOrganizationName" in order_meta else None
            tRegion = order_meta["TechContactRegion"] if "TechContactRegion" in order_meta else None
            tPostal = order_meta["TechContactPostalCode"] if "TechContactPostalCode" in order_meta else None
            tCountry= order_meta["TechContactCountry"] if "TechContactCountry" in order_meta else None
            
            tech = self.api.createContact(tFirst, tLast, tPhone, tEmail, title=tTitle,
                                          city=tCity, addressLine1=tAL1, addressLine2=tAL2, organizationName=tOrgname,
                                          region=tRegion, postalCode=tPostal, countryCode=tCountry)

        if "BillSameAsAdmin" in order_meta and order_meta["BillSameAsAdmin"] == True:
            billing = admin
        else:
            bFirst  = order_meta["BillingContactFirstName"] if "BillingContactFirstName" in order_meta else None
            bLast   = order_meta["BillingContactLastName"] if "BillingContactLastName" in order_meta else None
            bPhone  = order_meta["BillingContactPhone"] if "BillingContactPhone" in order_meta else None
            bEmail  = order_meta["BillingContactEmail"] if "BillingContactEmail" in order_meta else None
            bTitle  = order_meta["BillingContactTitle"] if "BillingContactTitle" in order_meta else None
            bCity   = order_meta["BillingContactCity"] if "BillingContactCity" in order_meta else None
            bAL1    = order_meta["BillingContactAddressLine1"] if "BillingContactAddressLine1" in order_meta else None
            bAL2    = order_meta["BillingContactAddressLine2"] if "BillingContactAddressLine2" in order_meta else None
            bOrgname= order_meta["BillingContactOrganizationName"] if "BillingContactOrganizationName" in order_meta else None
            bRegion = order_meta["BillingContactRegion"] if "BillingContactRegion" in order_meta else None
            bPostal = order_meta["BillingContactPostalCode"] if "BillingContactPostalCode" in order_meta else None
            bCountry= order_meta["BillingContactCountry"] if "BillingContactCountry" in order_meta else None
            
            billing = self.api.createContact(bFirst, bLast, bPhone, bEmail, title=bTitle,
                                             city=bCity, addressLine1=bAL1, addressLine2=bAL2, organizationName=bOrgname,
                                             region=bRegion, postalCode=bPostal, countryCode=bCountry)
        # Merge contacts
        return {'admin':admin, 'tech':tech, 'billing':billing}

    def _ca_create_order(self, order_id, order_meta, plugin_meta):
        """Creates an order with the Symantec CA.

        The PartnerOrderId and GeoTrustOrderId are returned and stored in
        plugin_meta. PartnerCode and ProductCode are also stored in plugin_meta
        for future use.

        All required order parameters must be stored as a dict in
        order_meta.
        Required fields are:
        PartnerCode, ProductCode, PartnerOrderId, OrganizationName,
        AddressLine1, City, Region, PostalCode, Country, OrganizationPhone
        ValidityPeriod, ServerCount, WebServerType, AdminContactFirstName,
        AdminContactLastName, AdminContactPhone, AdminContactEmail,
        AdminContactTitle, AdminContactAddressLine1, AdminContactCity,
        AdminContactRegion, AdminContactPostalCode, AdminContactCountry,
        AdminContactOrganizationName, BillingContact*,  TechContact*, and CSR.

        *The Billing and Tech contact information follows the same convention
        as the AdminContact fields.

        Optional Parameters: TechSameAsAdmin, BillSameAsAdmin, more options can be
        found in Symantec's API docs. Contact Symantec for the API document.

        :returns: tuple with success, error message, and can retry
        """
        try:
            contacts = self._create_contacts(order_meta)
        except KeyError as e:
            return False, e, False
        try:
            orginfo = self._create_orginfo(order_meta)
        except KeyError as e:
            return False, e, False
        try:
            order_data = self.api.QuickOrder(
                order_meta["ProductCode"], 
                partnerOrderID      = order_id, 
                approverEmail       = order_meta["ApproverEmail"], 
                organizationInfo    = orginfo,
                contacts            = contacts, 
                options             = order_meta # This will simply take and verify all remaining options
            )
        except Exception as e:
            return False, e, False
        if order_data.OrderResponseHeader.SuccessCode < 0:
            return False, order_data.OrderResponseHeader.Errors, False
        try:
            # If a DV Authentication method has been used, add the metadata
            # for DNS or File Authentication.
            if "DVAuthMethod" in order_meta:
                if order_meta["DVAuthMethod"].upper() == "DNS":
                    plugin_meta["DNSEntry"] = order_data.DNSAuthDVDetails.DNSEntry
                if order_meta["DVAuthMethod"].upper() == "FILE":
                    plugin_meta["FileName"] = order_data.FileAuthDVDetails.FileName
                    plugin_meta["FileContents"] = order_data.FileAuthDVDetails.FileContents

            # GeotrustOrderId is used to handle emails from Symantec.
            # CSR is being stored in plugin_meta for convenience when calling _ca_modify_order
            # ProductCode are being stored in plugin_meta for convenience
            # The timestamp is important for DNS authentication. Also it's a nice to have info.
            plugin_meta["GeoTrustOrderID"] = order_data.GeoTrustOrderID
            plugin_meta["PartnerOrderID"] = order_data.OrderResponseHeader.PartnerOrderID
            plugin_meta["CSR"] = order_meta["CSR"]
            plugin_meta["ProductCode"] = order_meta["ProductCode"]
            plugin_meta["Timestamp"] =order_data.OrderResponseHeader.Timestamp
            # It always makes sense to store the actual response.
            return True, order_data, False
        except Exception as e:
            return False, e, False


    def _ca_get_order_status(self, order_id):
        """Sends a request to the Symantec CA for details on an order.

        Parameters needed for GetOrderByPartnerOrderID:
        plugin_meta parameters: PartnerOrderId, PartnerCode

        If the order is complete, the Certificate is returned as a string.
        returns: tuple with success, error message, can retry,
                 the certificate (if available), intermediate (if available) and root (if available).
        """
        order_data = self.api.GetOrderByPartnerOrderID(order_id, {'ReturnCertificateInfo':True, 'ReturnFulfillment':True, 
            'ReturnCACerts': True})

        if order_data.QueryResponseHeader.SuccessCode == 0 and order_data.QueryResponseHeader.ReturnCount != 0:
            try:
                if order_data.OrderDetail.OrderInfo.OrderState == "COMPLETED":
                    if order_data.OrderDetail.CertificateInfo.CertificateStatus != "PENDING_REISSUE":
                        cert = order_data.OrderDetail.Fulfillment.ServerCertificate
                        for c in order_data.OrderDetail.Fulfillment.CACertificates.CACertificate:
                            if c.Type == "INTERMEDIATE":
                                intermediate = c.CACert
                            elif c.Type == "ROOT":
                                root = c.CACert
                        return True, None, False, cert, intermediate, root
                    else:
                        return True, "PENDING_REISSUE", True, None, None, None
                elif order_data.OrderDetail.OrderInfo.OrderStatusMajor == "CANCELLED":
                    return True, "CANCELLED", True, None, None, None
                return False, "Certificate not yet issued", True, None, None, None
            except:
                return False, "Cannot fetch order Status", True, None, None, None

        else:
            return False, "Invalid order ID", True, None, None, None

    def _ca_modify_order(self, order_id, operation):
        """Sends a request to the Symantec CA to modify an order.

        Parameters needed for modifyOrder:
            PartnerOrderID - Needed to specify order
            ModifyOrderOperation

        returns: tuple with success, error message, and can retry.
        """
        order_data = self.api.ModifyOrder(order_id, operation)
        if order_data.OrderResponseHeader.SuccessCode < 0:
            return False, order_data.OrderResponseHeader.Errors, True
        
        return True, order_data, False

    def _ca_reissue_cert(self, order_id, order_meta, plugin_meta):
        """Sends a request to the Symantec CA to reissue a certificate.

        Parameters needed for Reissue:
            PartnerOrderID - Needed to specify order
            CSR - Needed to create certificate
            ReissueEmail - the original Approver Email that was used for the order
            - update_type: one of the following:

        returns: tuple with success, error message, and can retry.
        """

        # Allow order changes to be set or not
        if "OrderChanges" in order_meta:
            orderChanges = order_meta["OrderChanges"]
        else:
            orderChanges = None

        # Allow the user to change the Signature Hash Algorithm or not
        if "SignatureHashAlgorithm" in order_meta:
            algo = order_meta["SignatureHashAlgorithm"]
        else:
            algo = None

        # If no PartnerOrderID is set, Symantec will create one.
        # For Reissues, the PartnerOrderID is DIFFERENT from the PartnerOrderID
        # that is used for order recognition. To specify the order that needs
        # to be reissued, the "OriginalPartnerOrderID" parameter needs to be set.
        if "PartnerOrderID" in order_meta:
            p_orderID = order_meta["PartnerOrderID"]
        else:
            p_orderID = None

        try:
            order_data = self.api.Reissue(p_orderID, reissueEmail=order_meta["ReissueEmail"], 
                options={'CSR':csr, 'SignatureHashAlgorithm':algo, 
                'OriginalPartnerOrderID': order_id}, 
                orderChanges = orderChanges)
            if order_data.OrderResponseHeader.SuccessCode < 0:
                return False, order_data.OrderResponseHeader.Errors, True
            else:
                return True, order_data, False
        except Exception as e:
            return False, e, True
