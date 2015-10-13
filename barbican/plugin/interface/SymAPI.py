#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Symantec, GeoTrust and Thawte API Library
# This library has been written by Tobias Zatti
# Contact: tobias_zatti@symantec.com
#
# File name: SymAPI.py
#
# Requirements:
# suds module ( https://fedorahosted.org/suds/ )
#
#################################################
# System check to only support python 2.7
import sys
if sys.version_info[:2] > (2,7):
    print "This library only works with Python 2.7."
    exit()
from suds.client import Client
from suds.transport.http import HttpTransport
import urllib2, urllib, httplib, socket
import ssl
#httplib.HTTPConnection.debuglevel = 5

# Error Codes:
# 1000 - No credentials set

#################################################
# Class SymAPI
#
# @version   1.3
# @date	  07/05/2015
# @author    Tobias Zatti <tobias_zatti@symantec.com>
# @copyright Symantec Corp. 2014, 2015
#
# CHANGELOG:
# v1.3:
# - Added new API functions released in April 2015:
#   QUERY:
#       - GetModifiedOrderSummary
#       - GetModifiedPreAuthOrderSummary
# - Added setApiVersion operation to make use of ApiVersion in ReqestHeaders.
# v1.2:
# - Added new API functions released world-wide in February 2015 including
#   QUERY:
#       - GetPreAuthOrdersByDateRange
#       - GetPreAuthOrderByPartnerOrderID
#   ORDER:
#       - OrderPreAuthentication
#       - ValidatePreAuthenticationData
# - Added new parameters to existing functions.
# v1.1:
# - Added Proxy support.
#   Proxy can be set using:
#       setProxy(url, port) 
#   function.
#
# v1.0
# Initial version 
 ################################################

class SymAPI:
    # URL to WSDL-file for test environment order-API
    url_orderAPI_demo = 'https://test-api.geotrust.com/webtrust/order.jws?WSDL' 
    # URL to WSDL-file for productive environment order-API
    url_orderAPI = 'https://api.geotrust.com/webtrust/order.jws?WSDL'
    # URL to WSDL-file for test environment query-API
    #url_queryAPI_demo = 'https://dev-api.geotrust.com/webtrust/query.jws?WSDL'
    url_queryAPI_demo = 'https://test-api.ws.symantec.com/webtrust/query.jws?WSDL'
    # URL to WSDL-file for productive environment query-API
    url_queryAPI = 'https://api.ws.symantec.com/webtrust/query.jws?WSDL'
    
    def __version(self):
        return '1.3'

    def __str__(self):
        return "Symantec SSL API v%s" % self.__version() + "\nPython library by Tobias Zatti\nSupport: tobias_zatti@symantec.com"
        
        

    # Initializes the object and/or resets all values to default	
    def __init__ (self, partnerCode= '', username = '', password = '', 
        verbose = True, useTestAPI = True, proxy = None):
        # When enabled, this prints status and debug messages
        self.verbose = verbose
        if self.verbose:
            self.__enableLogging()

        s = "Symantec SSL API v%s" % self.__version()
        star = "*" * len(s)
        self.log (star)
        self.log(s)
        self.log (star)
        self.log("To turn off logging, set verbose = False")
       # Your Symantec Partner Code
        self.partnerCode = partnerCode
        # Your API username
        self.username = username
        # Your API password
        self.userpassword = password
        # The SOAP client 
        self.client = None
        # Proxy
        self.proxy = proxy
        # ApiVersion
        self.ApiVersion = None

        """
        Defines whether we run in productive or test mode.
        For security reasons, the default setting is true,
        which means we run in test mode. Set to false to change
        to productive mode.
        Default: True
        """
        self.useTestAPI = useTestAPI

    def setApiVersion(self, version):
        self.ApiVersion = version

    def __enableLogging(self):
        import logging
        logging.basicConfig(level=logging.INFO)
        logging.getLogger('suds.client').setLevel(logging.DEBUG)
        logging.getLogger('suds.transport').setLevel(logging.DEBUG)
   
    def setCredentials(self, partnercode, username, userpass):
        """Sets user credentials
        @param string: Partner Code
        @param string: Username
        @param string: User Password
        """
        self.partnerCode = partnercode
        self.username = username
        self.userpassword = userpass
        self.log("Credentials have been saved.")

    def setProxy(self, proxy_server, proxy_port):
        self.proxy = '%s:%s' % (proxy_server, proxy_port)
        self.log("Set proxy \"%s\"" % self.proxy)

    def __credentialsSet(self):
        """Checks if credentials have been entered
        """
        if (self.partnerCode == '' and self.username == '' and self.userpassword == ''):
            self.log("No credentials have been set. Please use \"setCredentials(partnercode, username, password)\".", type = 'err')
            return False
        else:
            return True

    def __getAPIURL (self, type):
        """Returns the URL to the correct API.
        
        Throws a ValueError on an incorrect parameter.
        """
        if type == "order" or type == "Validate":
            if self.useTestAPI:
                return self.url_orderAPI_demo
            else:
                return self.url_orderAPI
        elif type == "query":
            if self.useTestAPI:
                return self.url_queryAPI_demo
            else:
                return self.url_queryAPI
        else:
            raise ValueError("Parameter \"type\" should be either \"order\", \"Validate\" or \"query\"")

    def __createRequestHeader (self, type, replayToken = None):
        """Creates the RequestHeader needed for queries and orders
        It uses the credentials that can are set in the setCredentials
        function.
        """
        h = self.client.factory.create(type + 'RequestHeader')
        h.PartnerCode = self.partnerCode
        h.ApiVersion = self.ApiVersion
        at = self.client.factory.create('authToken')
        at.UserName = self.username
        at.Password = self.userpassword
        h.AuthToken = at
        if replayToken != None:
            h.ReplayToken = replayToken
            h.UseReplayToken = True

        return h

    def __prepareClient (self, type, method, replayToken):
        """Prepares the client object by selecting the correct WSDL-file
        and adding the Request Header (Auth data).

        Returns a request object (<FunctionName>Input) with already added request header.
        """
        if self.__credentialsSet():
            self.__setClient(type)
            r = self.client.factory.create(method + 'Input')
            if type == "query":
                r.QueryRequestHeader = self.__createRequestHeader("query", replayToken)
            elif type == "order":
                r.OrderRequestHeader = self.__createRequestHeader("order", replayToken)
            elif type == "Validate":
                r.ValidateRequestHeader = self.__createRequestHeader("order", replayToken)
            return r
        else:
            exit(1000)

    def __setClient(self, type):
        if self.proxy == None:
            self.log("Connecting directly..")
            self.client = Client(self.__getAPIURL(type))
        else:
            self.log("Connecting using proxy \"%s\"" % self.proxy)
            opener = urllib2.build_opener(ConnectHTTPHandler(proxy=self.proxy), ConnectHTTPSHandler(proxy=self.proxy))
            urllib2.install_opener(opener)
            t = HttpTransport()
            t.urlopener = opener
            print t
            self.client = Client(self.__getAPIURL(type), transport=t)    


    def setOrderAPIURL(self, url):
        """
        Changes the URL for the order API for the currently set mode.
        """
        if self.useTestAPI:
            self.url_orderAPI_demo = url
            self.log("Changed DEMO URL for order API to:", url)
        else:
            self.url_orderAPI = url
            self.log("Changed PRODUCTION URL for order API to:", url)

    def setQueryAPIURL(self, url):
        """
        Changes the URL for the query API for the currently set mode.
        """
        if self.useTestAPI:
            self.url_orderAPI_demo = url
            self.log("Changed DEMO URL for query API to:", url)
        else:
            self.url_orderAPI = url
            self.log("Changed PRODUCTION URL for query API to:", url)

    def log (self, string, force = False, type = "msg"):
        """Prints the given string with time stamp for debugging reasons.
        Only prints if verbose mode is on or when the force parameter is set.
        """
        if self.verbose or force:
            if type == "err":
                print "ERROR: ",
            print string
    
    """	
    ** HELPER FUNCTIONS **
    * These functions are made to help the user creating arrays with
    * the correct parameter names for the API, so the user doesn't
    * have to care about syntax.
    """

    def createContact(self, firstName, lastName, phone, email, countryCode = None, region = None, 
        postalCode = None, city = None, addressLine1 = None, addressLine2 = None, fax = None,
        title = None, organizationName = None):
        """Creates an object with the correct key names as they are required by the SOAP API.
        * You can use this function for Admin-, Billing- and Tech Contact.
        *
        * @param firstName: string - Contact person's First (given) name - middle names can also be entered here
        * @param lastName: string- Contact person's Last (family) name
        * @param phone: string - Contact's phone number
        * @param email: string - Contact's email address
        * @param countryCode: string - Contact's country code, example: 'DE' for Germany, 'US' for United States
        * @param region: string - Contact's region - It is from the Address structure. This is the region of the address such as state or province. If this is a U.S. state, it must have a valid two-character abbreviation.
        * @param city: string - Contact's city name
        * @param addressLine1: string - First address line
        * @param addressLine2: string - Second address line for longer addresses
        * @param postalCode: string - Contact's postal code
        * @param fax: string - Contact's fax number
        * @param title: string - Contact's title in the company
        * @param organizationName - This is the name of the organization applying for the product. This applies to Organization Vetted products and SSL123.
        * @return array
        * @access public
        """
        """
        Fixed bug: When a query request had alreada been sent, the client was existing but
        in query mode, meaning that a contact cannot be created, as the contact field is 
        not supported for the query API. We need to change the client to "order" to
        create a contact object.
        """
        if self.client == None or self.client.wsdl['url'] == self.url_queryAPI_demo \
        or self.client.wsdl['url'] == self.url_queryAPI:
            self.__setClient("order")

        c = self.client.factory.create('Contact')
        c.FirstName = firstName
        c.LastName = lastName
        c.Phone = phone
        c.Email = email
        c.Title = title
        c.Fax = fax
        c.OrganizationName = organizationName
        c.AddressLine1 = addressLine1
        c.AddressLine2 = addressLine2
        c.City = city
        c.Region = region
        c.PostalCode = postalCode
        c.Country = countryCode
        s = "Created contact: \"%s %s\"" % (firstName, lastName)
        self.log(s)
        return c

    def createOrganizationInfo (self, orgName = None, countryCode = None, region = None, city = None,
        addressLine1 = None, addressLine2 = None, addressLine3 = None, postalCode = None,
        phone = None, fax = None):
        """Creates an array with the correct key names as they are required by the SOAP API.
        * You can use this function for an Organization Address.
        *
        * @param countryCode: string - Contact's country code, example: 'DE' for Germany, 'US' for United States
        * @param region: string - Contact's region - It is from the Address structure. This is the region of the address such as state or province. If this is a U.S. state, it must have a valid two-character abbreviation.
        * @param city: string - Contact's city name
        * @param addressLine1: string - First address line
        * @param addressLine2: string - Second address line for longer addresses
        * @param addressLine3: string - Third address line for very long addresses
        * @param postalCode: string - The postal code
        * @param phone: string - The company phone number
        * @param fax: string - The company fax number
        * @return array
        * @access public
        """
        if self.client == None:
            self.__setClient("order")

        i = self.client.factory.create('organizationInfo')
        a = self.client.factory.create('organizationAddress')
        
        i.OrganizationName = orgName

        a.AddressLine1 = addressLine1
        a.AddressLine2 = addressLine2
        a.AddressLine3 = addressLine3
        a.City = city
        a.Region = region
        a.PostalCode = postalCode
        a.Country = countryCode
        a.Phone = phone
        a.Fax = fax

        i.OrganizationAddress = a
        return i	

    """
    ** SOAP API Functions **
    * Starting here, each function has the same name as an
    * according function on the API.
    * All functions return an array with the result parameters
    * PLEASE NOTE THAT ALL PARAMETER NAMES ARE CASE-SENSITIVE!
    """
###############################################################################
#                                                                             #
#                                                                             #
#                           QUERY API FUNCTIONS                               # 
#                                                                             #
#                                                                             #
###############################################################################

    def hello(self, string):
        """Returns the "Input" parameter as "helloResult" parameter.
        This is mainly useful to test the connection to the API
        and to see how responses are formatted.
        """
        from suds.client import Client
        self.__setClient("query")
        return self.client.service.hello(string)

    def GetOrderByPartnerOrderID(self, partnerOrderID, options = {}, replayToken = None):
        """Returns detailed order information for the order matching the PartnerOrderID. 
        * The PartnerOrderID can optionally be supplied during a QuickInvite or 
        * QuickOrder command. If the PartnerOrderID is not supplied, GeoTrust 
        * automatically generates a PartnerOrderID for an order after it is successfully 
        * submitted. A PartnerOrderID must be unique and cannot be reused.
        *
        * NOTE: This operation currently returns only orders. It does not return invitations
        * that have not been converted into orders (the results of a QuickInvite).
        *
        * **Required Parameters**
        * PartnerOrderID : string
        *
        * **Optional Parameters**
        * ReturnProductDetail : bool
        * ReturnContacts : bool
        * ReturnCertificateInfo : bool
        * ReturnFulfillment : bool
        * ReturnCACerts : bool
        * ReturnPKCS7Cert : bool
        * ReturnOrderAttributes : bool
        * ReturnAuthenticationComments : bool
        * ReturnAuthenticationStatuses : bool
        * ReturnTrustServicesSummary : bool
        * ReturnTrustServicesDetails : bool
        * ReturnVulnerabilityScanSummary : bool
        * ReturnVulnerabilityScanDetails : bool
        * ReturnFileAuthDVSummary : bool
        * ReturnDNSAuthDVSummary : bool
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "GetOrderByPartnerOrderID", replayToken)
        r.PartnerOrderID = partnerOrderID

        for (k,v) in options.items():
            if k in r.OrderQueryOptions:
                self.log("  - %s -> %s" % (k,v))
                r.OrderQueryOptions[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetOrderByPartnerOrderID(r)

    def CheckStatus(self, partnerOrderID, replayToken = None):
        """Returns the processing status of the order.
        * 
        * @param string - PartnerOrderID
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "CheckStatus", replayToken)
        r.PartnerOrderID = partnerOrderID
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.CheckStatus(r)	
	
    def GetFulfillment(self, partnerOrderID, replayToken = None, options = {}):
        """Returns the fulfillment of an order.
        * 
        * @param string - PartnerOrderID
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "GetFulfillment", replayToken)
        r.PartnerOrderID = partnerOrderID
        if 'ReturnCACerts' in options.keys():
            self.log("ReturnCACerts --> %s" % options['ReturnCACerts'])
            r.ReturnCACerts = options['ReturnCACerts']
        if 'ReturnPKCS7Cert' in options.keys():
            self.log("ReturnPKCS7Cert --> %s" % options['ReturnPKCS7Cert'])
            r.ReturnPKCS7Cert = options['ReturnPKCS7Cert']
        if 'ReturnIconScript' in options.keys():
            self.log("ReturnIconScript --> %s" % options['ReturnIconScript'])
            r.ReturnIconScript = options['ReturnIconScript']
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetFulfillment(r)   
	
    def GetModifiedOrders(self, fromDate, toDate, replayToken = None, options = {}):
        """Returns order detail records for all orders whose status was modified
        * in the specified date range.
        * This operation should ideally be run on a periodic basis (e.g. every 10
        * or 15 minutes) so that order status can be keupt up to date in a partner's
        * system. If no orders have changed status, a return count of zero is returned.
        * 
        * @param string - Timestamp in 'YYYY-MM-DDTHH:MM:SS' format. (24 hours)
        * @param string - Timestamp in 'YYYY-MM-DDTHH:MM:SS' format. (24 hours)
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "GetModifiedOrders", replayToken)
        r.FromDate = fromDate
        r.ToDate = toDate

        for (k,v) in options.items():
            if k in r.OrderQueryOptions:
                self.log("  - %s -> %s" % (k,v))
                r.OrderQueryOptions[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)
        
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetModifiedOrders(r)

    def GetModifiedOrderSummary(self, fromDate, toDate, replayToken = None):
        """ A lightweight version of GetModifiedOrders.
        * Returns simplified order details (partner order ID, GeoTrust order ID, 
        * last modified date, partner code, and order state) for all modified orders 
        * in the specified date range. The operation returns a ModifiedPartnerOrder 
        * object that contains summary information for each of the partner's orders. 
        * If the partner is a master reseller, an array containing ModifiedPartnerOrder 
        * objects for each sub-reseller will be returned. If the information returned 
        * by this operation is sufficient, consider using it instead of the more
        * expensive ModifiedPartnerOrder operation.
        * Ideally, this operation should run on a periodic basis (e.g., every 10 or 15 minutes)
        * so that order status can be kept up to date in a partner’s system. If no orders have
        * changed status, a return count of zero is returned.
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "GetModifiedOrderSummary", replayToken)
        r.FromDate = fromDate
        r.ToDate = toDate
        
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetModifiedOrderSummary(r)

    def GetModifiedPreAuthOrderSummary(self, fromDate, toDate, replayToken = None):
        """ Same as GetModifiedOrderSummary, but for PreAuth orders. """
        self.log("Generating request..")
        r = self.__prepareClient("query", "GetModifiedPreAuthOrderSummary", replayToken)
        r.FromDate = fromDate
        r.ToDate = toDate
        
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetModifiedPreAuthOrderSummary(r)

    def GetQuickApproverList(self, domain, replayToken = None, productCode = None):
        """Returns the complete list of valid approver email messages for a specified domain. 
        * This list contains three "types" of email addresses.
        * 
        * @param string - domain (example: 'yahoo.com')
        * @param productCode: The product code for the user agreement that may be shown if specified
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "GetQuickApproverList", replayToken)
        r.Domain = domain
        r.IncludeUserAgreement.UserAgreementProductCode = productCode

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetQuickApproverList(r)

    def GetOrdersByDateRange(self, fromDate, toDate, replayToken = None, options = {}):
        """Returns order detail records for all orders whose status was modified
        * in the specified date range.
        * This operation should ideally be run on a periodic basis (e.g. every 10
        * or 15 minutes) so that order status can be keupt up to date in a partner's
        * system. If no orders have changed status, a return count of zero is returned.
        * 
        * @param string - Timestamp in 'YYYY-MM-DDTHH:MM:SS' format. (24 hours)
        * @param string - Timestamp in 'YYYY-MM-DDTHH:MM:SS' format. (24 hours)
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "GetOrdersByDateRange", replayToken)
        r.FromDate = fromDate
        r.ToDate = toDate

        for (k,v) in options.items():
            if k in r.OrderQueryOptions:
                self.log("  - %s -> %s" % (k,v))
                r.OrderQueryOptions[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetOrdersByDateRange(r)

    def GetUserAgreement(self, productCode, replayToken = None, agreementType = "ORDERING"):
        """The GetUserAgreement operation allows partners to request the appropriate user agreement 
        * for a particular product.
        * 
        * Possible values for 'AgreementType' are 'ORDERING' and 'VULNERABILITY'.
        * @param string - ProductCode
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "GetUserAgreement", replayToken)
        r.UserAgreementProductCode = productCode
        r.AgreementType = agreementType

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetUserAgreement(r)

    def ParseCSR(self, csr, replayToken = None):
        """Parses a CSR and returns its' content.
        * 
        * @param string - CSR
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "ParseCSR", replayToken)
        r.CSR = csr

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.ParseCSR(r)     

    def GetPreAuthOrdersByDateRange(self, fromDate, toDate, organizationInfo=None, replayToken=None):
        """Returns orders that make use of the Pre Auth functionality.
        * 
        * @param string - Timestamp in 'YYYY-MM-DDTHH:MM:SS' format. (24 hours)
        * @param string - Timestamp in 'YYYY-MM-DDTHH:MM:SS' format. (24 hours)
        * @param array - All elements are optional but need to be from the following
        * set of elements: {OrganizationName, City, Region, Country}
        """
        self.log("Generating request..")
        r = None
        if self.__credentialsSet():
            self.__setClient("query")
            r = self.client.factory.create("GetPreAuthOrdersByDataRange" + 'Input')
            r.QueryRequestHeader = self.__createRequestHeader("query", replayToken)
        else:
            exit(1000)
        
        r.QueryParameters.FromDate = fromDate
        r.QueryParameters.ToDate = toDate
        r.QueryParameters.OrganizationInfo = organizationInfo
        
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetPreAuthOrdersByDateRange(r)

    def GetPreAuthOrderByPartnerOrderID(self, partnerOrderID, replayToken = None):
        """Returns detailed order information for the order matching the PartnerOrderID. 
        *
        * **Required Parameters**
        * PartnerOrderID : string
        """
        self.log("Generating request..")
        r = self.__prepareClient("query", "GetPreAuthOrderByPartnerOrderID", replayToken)
        r.PartnerOrderID = partnerOrderID

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.GetPreAuthOrderByPartnerOrderID(r)

           

###############################################################################
#                                                                             #
#                                                                             #
#                           ORDER API FUNCTIONS                               #
#                                                                             #
#                                                                             #	
###############################################################################
    def QuickOrder(self, productCode, approverEmail = None, replayToken = None, organizationInfo = None, contacts = {'admin':None, 'tech':None, 'billing':None},
        options = {}, partnerOrderID = None):
        """The QuickOrder command allows partners to perform all the actions that requestors would 
        * typically perform using our Web forms to place an order with one API operation call. 
        * This includes submitting the full order information, such as technical contact, 
        * administrative contact, and CSR, as well as approver email address (if applicable). 
        * Our system validates that the approver email address matches the set of approver email 
        * addresses that would have been presented to the requestor. Orders can only be successfully 
        * placed if there is a match between the addresses.
        *
        * @param array - options: ValidityPeriod, CSR, WebServerType
        * @param array - OrganizationInfo: OrganizationName, OrganizationAddress (array), ...
        * @param array - AdminContact: FirstName, LastName, Phone, Email, Title, ...
        * @param array - TechContact: FirstName, LastName, Phone, Email, Title, ...
        * @param array - BillingContact: FirstName, LastName, Phone, Email, Title, ...
        * @param string - ApproverEmail: required for TrueBusinessID with EV. If you have another
        *                   product, you can put an empty string here.
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("order", "QuickOrder", replayToken)

        # Order specific
        r.OrderRequestHeader.ProductCode = productCode
        r.OrderRequestHeader.PartnerOrderID = partnerOrderID
        # Contacts
        if 'admin' in contacts:
            r.AdminContact = contacts['admin']
        if 'tech' in contacts:
            r.TechContact = contacts['tech']
        if 'billing' in contacts:
            r.BillingContact = contacts['billing']
        r.ApproverEmail = approverEmail
        # Organization Info
        r.OrganizationInfo = organizationInfo

        # Optional Parameters
        for (k,v) in options.items():
            if k in r.OrderParameters:
                self.log("  - %s -> %s" % (k,v))
                r.OrderParameters[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)
        
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.QuickOrder(r)

    def QuickInvite(self, productCode, requestorEmail = None, replayToken = None, organizationInfo = None, contacts = {'admin':None, 'tech':None, 'billing':None},
        options = {}, partnerOrderID = None):
        """QuickInvite is a mechanism that allows partners to invite a third party to complete an order. With QuickInvite, partners can pre-fill a subset of order data. Upon receiving a submission, our system sends an email to the requestor inviting the requestor to complete the order. The information provided by the partner is protected and cannot be edited by the requestor. From this point, the order process proceeds in the same manner as a typical Domain Vetted, Organization Vetted, or Domain and Organization Vetted order. Section 5.3.1 contains a complete profile of the fields used in the QuickInvite command for all product categories.
        *
        * @param array - OrderParameters: ValidityPeriod, CSR, WebServerType
        * @param array - OrganizationInfo: OrganizationName, OrganizationAddress (array), ...
        * @param array - AdminContact: FirstName, LastName, Phone, Email, Title, ...
        * @param array - TechContact: FirstName, LastName, Phone, Email, Title, ...
        * @param array - BillingContact: FirstName, LastName, Phone, Email, Title, ...
        * @param string - ApproverEmail: required for TrueBusinessID with EV. If you have another
        *                   product, you can put an empty string here.
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("order", "QuickInvite", replayToken)

        # Order specific
        r.OrderRequestHeader.ProductCode = productCode
        r.OrderRequestHeader.PartnerOrderID = partnerOrderID
        # Contacts
        r.AdminContact = contacts['admin']
        r.TechContact = contacts['tech']
        r.BillingContact = contacts['billing']
        r.RequestorEmail = requestorEmail
        # Organization Info
        r.OrganizationInfo = organizationInfo

        # Optional Parameters
        for (k,v) in options.items():
            if k in r.OrderParameters:
                self.log("  - %s -> %s" % (k,v))
                r.OrderParameters[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)
        
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.QuickInvite(r)

    def OrderPreAuthentication(self, productCode, replayToken = None, organizationInfo = None, domainInfo = None, contactPairs = [],
        options = {}, partnerOrderID = None, billingContact=None):
        """
        The OrderPreAuthentication operation allows the submission of Symantec Ready
        Issuance orders. It requires an organization and optionally a domain name and
        contact pair.
        """
        self.log("Generating request..")
        # The input object for OrderPreAuthentication has inconsistent
        # naming and is called "AuthOrderInput". Hence we need to
        # send "AuthOrder" as service name to __prepareClient().
        r = self.__prepareClient("order", "AuthOrder", replayToken)

        # Order specific
        r.OrderRequestHeader.ProductCode = productCode
        r.OrderRequestHeader.PartnerOrderID = partnerOrderID
        # Billing contact
        r.BillingContact = billingContact
        # Auth Data
        r.AuthData.OrganizationInfo = organizationInfo
        r.AuthData.DomainInfo       = domainInfo
        r.AuthData.ContactInfo.ContactPair = contactPairs

        # Optional Parameters
        for (k,v) in options.items():
            if k in r.OrderParameters:
                self.log("  - %s -> %s" % (k,v))
                r.OrderParameters[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)
        
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.OrderPreAuthentication(r)

    def Reissue(self, partnerOrderID, reissueEmail, options = {}, replayToken = None, productCode = None, orderChanges = None):
        """The Reissue operation allows partners to initiate the reissue of an order so that customers 
        * do not need to visit the GeoTrust website to initiate a reissue. Partners are expected to 
        * properly validate the authority of customers to initiate certificate reissues prior to using 
        * the API command to help assure that only an authorized person initiates the reissue.
        * 
        * @param string
        * @param string reissue email
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("order", "Reissue", replayToken)

        r.OrderRequestHeader.PartnerOrderID = partnerOrderID
        r.OrderRequestHeader.ProductCode = productCode

        r.ReissueEmail = reissueEmail
        r.OrderChanges = orderChanges
        # Optional Parameters
        for (k,v) in options.items():
            if k in r.OrderParameters:
                self.log("  - %s -> %s" % (k,v))
                r.OrderParameters[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)
        
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.Reissue(r)

    def ModifyOrder(self, partnerOrderID, orderOperation, operationReasonMessage = None, 
        requestorEmail = None, options = {}, replayToken = None):
        """Lets you modify your order. This function only works in the test environment
        * and is to help you simulate a fully processed order.
        * 
        * Possible "ModifyOrderOperation" Values: (See API Section 5.3.4.12)            
        *        APPROVE, RESELLER_APPROVE, RESELLER_DISAPPROVE, APPROVE_ESSL,
        *        REJECT, CANCEL, UPDATE_POST_STATUS, DEACTIVATE, REQUEST_ON_DEMAND_SCAN,
        *        UPDATE_SEAL_PREFERENCES, REQUEST_VULNERABILITY SCAN
        *
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("order", "ModifyOrder", replayToken)

        r.OrderRequestHeader.PartnerOrderID = partnerOrderID
        r.ModifyOrderOperation = orderOperation
        r.ModifyOrderReasonMessage = operationReasonMessage
        r.RequestorEmail = requestorEmail

        # Optional Parameters
        for (k,v) in options.items():
            if k in r.OperationData:
                self.log("  - %s -> %s" % (k,v))
                r.OperationData[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)
        
        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.ModifyOrder(r)        
    
    def ChangeApproverEmail(self, partnerOrderID, approverEmail, replayToken = None, options = {}):
        """The ChangeApproverEmail operation allows partners to change the domain approver email for orders where the domain approval 
        * process has not been completed. This operation applies to all GeoTrust and Thawte domain validated and organization and domain 
        * validated certificates.
        *
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("order", "ChangeApproverEmail", replayToken)
        r.OrderRequestHeader.PartnerOrderID = partnerOrderID
        r.ApproverEmail = approverEmail

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.ChangeApproverEmail(r)                

    def ValidateOrderParameters(self, productCode, options = {}, replayToken = None):
        """Allows partners to validate a number of order fields in one API message. This allows partners to perform 
        * validation prior to submitting an order, which provides a better UI experience for users. 
        * If any of the fields are invalid, an error will be returned listing all the errors. If there are no errors, 
        * the operation will provide responses for many of the values and include additional information.
        * Optionally, the ValidateOrderParameters operation can also be invoked, specifying only the CSR to exclusively test validity of the CSR.
        *
        * @param string Product code
        * @param array of key => value pairs: order parameters
        * @param array of key => value pairs: further optional parameters (add ReplayToken here)
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("order", "ValidateOrderParameters", replayToken)

        r.OrderRequestHeader.ProductCode = productCode
        if 'PartnerOrderID' in options.keys():
            r.OrderRequestHeader.PartnerOrderID = options['PartnerOrderID']
        
        # Optional Parameters
        for (k,v) in options.items():
            if k in r.OrderParameters:
                self.log("  - %s -> %s" % (k,v))
                r.OrderParameters[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.ValidateOrderParameters(r)         

    def ResendEmail(self, productCode, partnerOrderID, resendMailType, options = {}, replayToken = None):
        """The ResendEmail operation allows partners to resend various email messages sent by GeoTrust 
        * in the course of processing orders. Certain email types may not apply for a particular order.
        *
        * @param string: ProductCode
        * @param string: PartnerOrderID
        * @param string: Possible values: InviteEmail, ApproverEmail, PickUpEmail, FulfillmentEmail, PhoneAuthEmail
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("order", "ResendEmail", replayToken)

        r.OrderRequestHeader.ProductCode = productCode
        r.OrderRequestHeader.PartnerOrderID = partnerOrderID
        r.ResendEmailType = resendMailType

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.ResendEmail(r)   

    def Revoke(self, certificate, revokeReason, options = {}, replayToken = None):
        """SSL revoke
        *
        * One of two reasons must be cited when submitting a GeoTrust revocation request via the API.
        *
        * - 'cessation of service' - this revocation request is used when a partner wants to ensure 
        *   non-use of a certificate the end customer has stopped paying for. In this instance, 
        *   Symantec verifies the certificate is still live on a server prior to revoking the certificate.
        *
        * - 'key Compromise' - this reason is cited when the certificates private key has been compromised. 
        *  Symantec immediately revokes the certificate on approval when this reason is cited in the request.
        *
        * In each case, the request must be confirmed via a link sent in an email to the technical contact.
        *
        * @param string: Certificate
        * @param string: Reason why you are revoking
        * @param array of key => value pairs
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        r = self.__prepareClient("order", "Revoke", replayToken)

        r.Certificate = certificate
        r.RevokeReason = revokeReason
        if 'SerialNumber' in options.keys():
            r.SerialNumber = options['SerialNumber']

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.Revoke(r) 
	
    def ShowReplayTokens(self, partnerCode):
        """Returns all Replay Tokens you have used so far.
        * @return array of strings
        * @access public
        """
        self.log("Generating request..")
        from suds.client import Client
        self.__setClient("order")

        return self.client.service.ShowReplayTokens(partnerCode)

    def ValidatePreAuthenticationData(self, productCode, partnerOrderID=None, organizationInfo=None, domainInfo=None, options = {}, replayToken = None, contactPairs = []):
        """Validates the given authentication data to check whether the given
        data is eligible for Pre-Authentication.
        """
        self.log("Generating request..")
        # Due to a naming inconsistency, the ValidatePreAuthenticationData input object
        # is called ValidateAuthDataInput, hence we need to send the operation name
        # "ValidateAuthData" to the __prepareClient() operation.
        r = self.__prepareClient("Validate", "ValidateAuthData", replayToken)

        r.ValidateRequestHeader.ProductCode = productCode
        r.ValidateRequestHeader.PartnerOrderID = partnerOrderID
        # Auth Data
        r.AuthData.OrganizationInfo = organizationInfo
        r.AuthData.DomainInfo       = domainInfo
        r.AuthData.ContactInfo.ContactPair = contactPairs

        # Optional Parameters
        for (k,v) in options.items():
            if k in r.AuthData:
                self.log("  - %s -> %s" % (k,v))
                r.OrderParameters[k] = v
            else:
                self.log("  - %s is not a valid parameter" % k)

        self.log(r)
        self.log("Connecting to API..")
        return self.client.service.ValidatePreAuthenticationData(r)         

####################################
# Proxy Addon
####################################
# CenturyLink Technology Solutions
# Author: Lindsay Weir
# Date: 09/23/2014
# Issues with SUDS and URLLIB2 modules to connect through the proxy servers.
#
# Code based on the following workarounds to URLLIB2:
#     http://www.infosec.pro/2013/11/26/python-suds-wsdl-https-proxy-and-soap-authentication/
#     http://code.activestate.com/recipes/456195/
#
# urllib2 opener to connection through a proxy using the CONNECT method, (useful for SSL)
# tested with python 2.4
class ProxyHTTPConnection(httplib.HTTPConnection):

    _ports = {'http' : 80, 'https' : 443}


    def request(self, method, url, body=None, headers={}):
        #request is called before connect, so can interpret url and get
        #real host/port to be used to make CONNECT request to proxy
        
        keys_ = self.__dict__.items()
        for (k,v) in keys_:
            print k, "->", v
        proto, rest = urllib.splittype(self.host)
        if proto is None:
            raise ValueError, "unknown URL type: %s" % url
        #get host
        host, rest = urllib.splithost(rest)
        #try to get port
        port = self.port
        proto = "https"
        print "--"
        print proto
        print host
        print port
        print method
        self.set_tunnel(self._tunnel_host+url, 443)
        url = "https://" + self._tunnel_host
        print "URL: ",url
        #if port is not defined try to get from proto
        if port is None:
            try:
                port = self._ports[proto]
            except KeyError:
                raise ValueError, "unknown protocol for: %s" % url
        self._real_host = host
        self._real_port = port
        httplib.HTTPConnection.request(self, method, url, body, headers)


    def connect(self):
        httplib.HTTPConnection.connect(self)
        #send proxy CONNECT request
        self.send("CONNECT %s:%d HTTP/1.0\r\n\r\n" % (self._real_host, int(self._real_port)))
        #expect a HTTP/1.0 200 Connection established
        response = self.response_class(self.sock, strict=self.strict, method=self._method)
        (version, code, message) = response._read_status()
        #probably here we can handle auth requests...
        if code != 200:
            #proxy returned and error, abort connection, and raise exception
            self.close()
            raise socket.error, "Proxy connection failed: %d %s" % (code, message.strip())
        #eat up header block from proxy....
        while True:
            #should not use directly fp probablu
            line = response.fp.readline()
            if line == '\r\n': break


class ProxyHTTPSConnection(ProxyHTTPConnection):

    default_port = 443

    def __init__(self, host, port = None, key_file = None, cert_file = None, strict = None,
        timeout=30):
        print host, port
        ProxyHTTPConnection.__init__(self, host, port)
        self.key_file = key_file
        self.cert_file = cert_file

    def connect(self):
        ProxyHTTPConnection.connect(self)
        #make the sock ssl-aware
        ssl = socket.ssl(self.sock, self.key_file, self.cert_file)
        self.sock = httplib.FakeSocket(self.sock, ssl)


class ConnectHTTPHandler(urllib2.HTTPHandler):

#    def do_open(self, http_class, req):
#        return urllib2.HTTPHandler.do_open(self, ProxyHTTPConnection, req)
    def __init__(self, proxy=None, debuglevel=0):
        self.proxy = proxy
        urllib2.HTTPHandler.__init__(self, debuglevel)

    def do_open(self, http_class, req):
        if self.proxy is not None:
            req.set_proxy(self.proxy, 'http')
        return urllib2.HTTPHandler.do_open(self, ProxyHTTPConnection, req)

class ConnectHTTPSHandler(urllib2.HTTPSHandler):

#    def do_open(self, http_class, req):
#        return urllib2.HTTPSHandler.do_open(self, ProxyHTTPSConnection, req)
    def __init__(self, proxy=None, debuglevel=0):
        self.proxy = proxy
        urllib2.HTTPSHandler.__init__(self, debuglevel)

    def do_open(self, http_class, req):
        if self.proxy is not None:
            req.set_proxy(self.proxy, 'https')
        return urllib2.HTTPSHandler.do_open(self, ProxyHTTPSConnection, req)

###############################################################################
#                                                                             #
#                                                                             #
#                           EXAMPLE CODE                                      #
#                                                                             #
#                                                                             # 
###############################################################################
if __name__ == "__main__":
    api = SymAPI()
    api.setCredentials("4600590NOT94031", "librarytest", '1libraryTest$')
    #api.setCredentials("bugbash", "bugbash", "Password@123")
    #api.client = Client(api.getAPIURL("query"))
    #print api.client
    #print api.GetOrderByPartnerOrderID("26_SAN_test", options = {'ReturnFulfillment':True})


    #api.setProxy("dc3itproxy01.sky.savvis.net","8080")
    admin = api.createContact("AdminFirst", "AdminLast", "+49-123-45678", "tobias_zatti@symantec.com", title="ITS3DS", 
        city="Stuttgart", addressLine1="Another Street 54", organizationName="My Company AG", region="BadenWuerttemberg", 
        postalCode="70123", countryCode="DE")
    tech = api.createContact("TechFirst", "TechLast", "+49-123-45678", "tobias_zatti@symantec.com", title="Produktion", 
        city="Stuttgart", addressLine1="A street 4", organizationName="My Company AG", region="Baden-Wuerttemberg", 
        postalCode="70123", countryCode="DE")
    admin2 = api.createContact("AdminFifrst", "AdminLast", "+49-123-456378", "tobias_zatti@symantec.com", title="ITS3DS", 
        city="Stuttgart", addressLine1="Another Street 54", organizationName="My Company AG", region="BadenWuerttemberg", 
        postalCode="70123", countryCode="DE")
    tech2 = api.createContact("TechFirst", "TechLast", "+49-123-45678", "tobias_zatti@symantec.com", title="Produktion", 
        city="Stuttgart", addressLine1="A street 4", organizationName="My Company AG", region="Baden-Wuerttemberg", 
        postalCode="70123", countryCode="DE")
    billing = api.createContact("BillingFirst", "BillingLast", "+49-123-45678", "tobias_zatti@symantec.com", title="SSL account manager", city="Berlin", addressLine1="Test Ave 1", organizationName="my Company GmbH", region="Berlin", postalCode="13961", countryCode="DE")

    orginfo = api.createOrganizationInfo("My Company AG", countryCode = 'DE', region = 'BadenWuerttemberg', 
         city = 'Stuttgart', addressLine1 = 'A street 20', postalCode = '70648', phone = '+49-123-45678', fax = '+49-123-123432')


    cp = [{"AdminContact":admin,"TechContact":tech,"ContactType":"PRIMARY"},{"AdminContact":admin2,"TechContact":tech2,"ContactType":"NON-PRIMARY"}]
    domains = [{"Domain":{"Name":"test.com"}}]
    res = api.ValidatePreAuthenticationData("PreAuthOV", organizationInfo=orginfo, domainInfo=domains, contactPairs=cp, options={"ValidityPeriod":24})
    #res = api.OrderPreAuthentication("PreAuthOV", organizationInfo=orginfo, domainInfo=domains, billingContact=billing, contactPairs=cp, options={"ValidityPeriod":24})
    print res


    
    #res = api.GetOrderByPartnerOrderID("pkcs7bug1", options={"ReturnFulfillment":True, "ReturnPKCS7Cert":True})
    #res = api.GetFulfillment("pkcs7bug1", options={"ReturnPKCS7Cert":True})
    #print res
    #exit()
    exit()
    api.GetPreAuthOrdersByDateRange("2015-01-01T00:00:00", "2016-01-01T00:00:00", organizationInfo={"OrganizationName":"Test", "Country":"DE"})
    csr = """
    -----BEGIN CERTIFICATE REQUEST-----
MIICsTCCAZkCADBtMQswCQYDVQQGEwJERTEWMBQGA1UEAxMNemRsb2dpc3Rpay5k
ZTESMBAGA1UEBxMJU3R1dHRnYXJ0MRIwEAYDVQQKEwlJcmdlbmR3YXMxCzAJBgNV
BAgTAkJXMREwDwYDVQQLEwhJcmVuZHdhczCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAMDcxVong7q9yo41/T0Kqu4ovZ/kNIWFv9R7SLm0L0ic+bpr0b1y
b//rjlFH+SUXQgTQm5geHTeTp8QVlW+NlqH0TeJDTeuJob7uiIrec+O8sQLXRDhB
7YtMam20Muh33UaYHv+kKehZMpmNc95tCZvS94meztwjKb0lIuzzsX4s59HWjmLl
eUlQBzryQSha/hz3kKpA+iw1hApAyYeHlvjZyS6ycxmgIeK4fxR75w4ivPhUQBUw
p6im1mSj9vfomX8vW+5pAtMjVaQsMyGdHEF6v8mXEPc7I5IGFtQg6aPv/PKe2fgK
UBEeOuRPw7nbvI1q8qjHM9/uOXOnZwfZ5d0CAwEAAaAAMA0GCSqGSIb3DQEBCwUA
A4IBAQCgun450V2J21NijQIdpyB07flX10KgL33lsVl+CrvRBBnIV7HLFm8bQNHu
8JPVeX5PQqOvdNFH+3B4ANI+6Y126H4OGsisUclcNIRCt3napgGMoLMEL1xwz7j8
4mztZ3gFvJt+0b3aRDF5Q7KxalysPLJpAlzrZPvxMhju5OHxH/SfHeEldBwJBPZs
qYyqYiwwYzSFiCXsENcrH2jHHqVqfzh/yFJGG1DmQ0hMPoQO8/PK/aX4NzDq/GmQ
cSd4i/dvARlZExwqZ2rr2YnbeTS9LLTuxYxcVjrz46gaBNLAnEfo7+3oE+BdD/r6
4ES75c9oWbz/JavJn2dbN0253iW8
-----END CERTIFICATE REQUEST-----"""
    admin = api.createContact("AdminFirst", "AdminLast", "+49-123-45678", "tobias_zatti@symantec.com", title="ITS3DS", city="Stuttgart", addressLine1="Another Street 54", organizationName="My Company AG", region="BadenWuerttemberg", postalCode="70123", countryCode="DE")
    tech = api.createContact("TechFirst", "TechLast", "+49-123-45678", "tobias_zatti@symantec.com", title="Produktion", city="Stuttgart", addressLine1="A street 4", organizationName="My Company AG", region="Baden-Wuerttemberg", postalCode="70123", countryCode="DE")
    billing = api.createContact("BillingFirst", "BillingLast", "+49-123-45678", "tobias_zatti@symantec.com", title="SSL account manager", city="Berlin", addressLine1="Test Ave 1", organizationName="my Company GmbH", region="Berlin", postalCode="13961", countryCode="DE")
    contacts = {'admin':admin, 'tech':tech, 'billing':billing}

    orginfo = api.createOrganizationInfo("My Company AG", countryCode = 'DE', region = 'BadenWuerttemberg', 
         city = 'Stuttgart', addressLine1 = 'A street 20', postalCode = '70648', phone = '+49-123-45678', fax = '+49-123-123432')
    
    res = api.QuickOrder("RapidSSL", partnerOrderID = "blocktest", approverEmail = "hostmaster@zdlogistik.de", organizationInfo = orginfo,
    contacts = contacts, options = {'CSR':csr, 'ValidityPeriod':12, 'WebServerType':'other', 'DVAuthMethod':"DNS"})

    print res
    exit()
    """
    
    
    #print api.ModifyOrder("CHANGEAUTH-RUNTIME-2", "UPDATE_DV_AUTH_METHOD", options={'DVAuthMethod':"EMAIL"})
    #exit()
    #print api.GetPreAuthOrdersByDateRange("2014-01-01T00:00:00", "2015-01-01T00:00:00")
    #res = api.ValidatePreAuthenticationData("QuickSSLPremium", {'OrganizationInfo':orginfo})
    #print res
    #print api.GetOrderByPartnerOrderID("api_findbug", options={"ReturnCertificateInfo":True, "ReturnFulfillment":True})
    #print api.client
    
    #api.ModifyOrder("RevocationTest", "DEACTIVATE")
    #exit()
    """
 #   print "Hello Response:", api.hello("Connection is running!")
 #   print api.client.wsdl['url']
    #print api.CheckStatus("26_SAN_test")

    ##############
    # GET FULFILLMENT EXAMPLE
    # Request with partner order id
    #response =  api.GetFulfillment("26_SAN_test")
    # This is how you access the actual certificate:
    #print response.Fulfillment.ServerCertificate
    # 
    # ALTERNATIVELY you can use this shortcut:
    # print api.GetFulfillment("26_SAN_test").Fulfillment.ServerCertificate
    ##############

    # GET MODIFIED ORDERS

    #print api.GetModifiedOrders("2014-09-01T00:00:00", "2015-01-01T00:00:00")

    # GET QUICK APPROVER LIST
    # print api.GetQuickApproverList("testsite.com", productCode = "TrueBizIDEV")

    # GET ORDERS BY DATE RANGE
    #res = api.GetOrdersByDateRange("2014-01-01T00:00:00", "2015-01-01T00:00:00", options = {'ReturnContacts':True})

    # GET USER AGREEMENT
    #res = api.GetUserAgreement("QuickSSL")
  

#     # PARSE CSR
#     #res = api.ParseCSR(csr)


#    orginfo.JurisdictionCity = "Karlsruhe"
#    orginfo.JurisdictionCountry = "DE"
    orginfo.JurisdictionRegion = "BadenWuerttemberg"



    """
    csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\
    MIIDBTCCAe0CAQAwgb8xCzAJBgNVBAYTAkRFMSwwKgYDVQQIEyNCYWRlbi1XdWVy\
    dHRlbWJlcmcscG9zdGFsQ29kZT03NjIyNzESMBAGA1UEBxMJS2FybHNydWhlMS8w\
    LQYDVQQKEyZGaWR1Y2lhIElUIEFHLHN0cmVldD1GaWR1Y2lhc3RyYXNzZSAyMDET\
    MBEGA1UECxMKUHJvZHVrdGlvbjEoMCYGA1UEAxMfZ2lyb3BheS5maW5hbnpwb3J0\
    YWwuZmlkdWNpYS5kZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKu3\
    aLLr76D8sHS+Co0vH5RfwqLWirxgGkopB5ZWmkTUHfuRXXwBiaMGqtd8V4wqACDk\
    HeCOihTnZ99YBG5UII8IE0VSzybJ/RTjGzjL2CV7flcTqncRYo/KOH4uJ6IgXveC\
    DBo7PNJNVGYZHPRs0J3YzdbMXAXtlRry25IDIHzs2O18To7oq/m3fwHU1QMZb7M2\
    z26lnEwYqreU4UnBcbctB6VUs5NETJKSamrD1SeoUDEsao3Jc7Miwi/91kKat1+Z\
    kCJtllVBdiLyersTmO3aejMSAMUUu8g5J/vn4QfdXn2XMevcpXWIwdrMK2hbXMoD\
    OKjA9ABk/fXojDg+hU8CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQAzjuX57HXs\
    4nJ+t/uUCj09Rf9fZ1xhTsBo3F6U2FN3+GfcYj2GYboZphlegFPUcnDO1hhnlGNb\
    ve2rgKLiTaRrDZxTM/9dHskugPOTanlT+Es5kGJLzLzlD6S05qV2+Vj5wMPUJtls\
    kmBwDhyJuhFDsGKTRRHiPSDDu7DFRPakzgaS431qkyX0S2LXnQLArTgpbYOztb6/\
    xi/JrcSj/vfN1jCkhCM8PVhtNv8cPjOCfxiizHBhhaJqFJaSSdzfjsx4OUJHSXFm\
    MbMv8PZ5tUUyfnmLlxpPm6DwwyuHV4NLL+DpZzNDg5iThUjoYyALWJeVtiv8rKKy\
    By/n2IH0vfKd\
    -----END NEW CERTIFICATE REQUEST-----'
    #res = api.QuickOrder("RapidSSL", partnerOrderID = "RevocationTest2", approverEmail = "hostmaster@fiducia.de", organizationInfo = orginfo,
    #contacts = contacts, options = {'CSR':csr, 'ValidityPeriod':12, 'WebServerType':'other'})

    #print res
    #exit()
    
    res = api.GetOrderByPartnerOrderID("RevocationTest2", {'ReturnCertificateInfo':True, 'ReturnFulfillment':True, 
        'ReturnProductDetail':True, 'ReturnOrderAttributes':True})
    #cert = res.OrderDetail.Fulfillment.ServerCertificate
    #print api.GetOrderByPartnerOrderID("RevocationTest2")
    #print api.Reissue("RevocationTest2", "tobias_zatti@symantec.com", options={'CSR':csr})

    print res
    #print api.Revoke(cert, "cessation of service")
    # print res

    # GET MODIFIED ORDERS

    #print api.GetModifiedOrders("2015-01-29T00:00:00", "2015-02-01T00:00:00")

    #res = api.QuickInvite("QuickSSLPremium", partnerOrderID = "pythontest_invite_01", requestorEmail = "hostmaster@tobiaszatti.com", organizationInfo = orginfo,
    # contacts = contacts, options = {'CSR':csr, 'ValidityPeriod':12})
    
    #res = api.Reissue("pythontest_04", "max@mustermann.com", options={'CSR':csr})
    #print res


    #res = api.ModifyOrder("RevocationTest2", "APPROVE")
    #print res
    #print res
    #exit()
    #res = api.ChangeApproverEmail("pythontest_01", "hans@mustermann.com")
    #print res

    #res = api.ValidateOrderParameters("QuickSSLPremium", {'CSR':csr, 'ValidityPeriod':12, 'WebServerType':'iis'})
    #print res

    #res = api.ResendEmail("TrueBizID", "pythontest_04", "FulfillmentEmail")
    #print res

    # Cert fpr revocation

    #cert = ''
    #print api.client
    #res = api.Revoke(cert, "key Compromise")
    #print res

#print api.ShowReplayTokens("4600590NOT94031")
"""