//
//  oid.js
//
//  Copyright © 2017 Trusted Key Solutions. All rights reserved.
//

/**
 * Some well-known OIDs, for convenience.
 */
module.exports = {

    /**
     * The OID in dotted notation for an identity document's ID number.
     */
    documentID: "1.3.6.1.4.1.53318295.2",

    /**
     * The OID in dotted notation for an identity document's type, for example "Passport".
     */
    documentType: "1.3.6.1.4.1.53318295.1",

    /**
     * The OID in dotted notation for an identity document's photo.
     */
    documentImage: "1.3.6.1.4.1.53318295.3",

    /**
     * The OID in dotted notation for an identity document's issuer.
     */
    documentIssuer: "1.3.6.1.4.1.53318295.4",

    /**
     * The OID in dotted notation for the result of the document verification.
     */
    documentResult: "1.3.6.1.4.1.53318295.5",

    /**
     * The OID in dotted notation for the gender (F/M) on an identity document.
     */
    gender: "1.3.6.1.5.5.7.9.3",

    /**
     * The OID in dotted notation for a person's email address.
     */
    email: "1.2.840.113549.1.9.1",

    /**
     * The OID in dotted notation for a person's full name.
     */
    commonName: "2.5.4.3",

    /**
     * The OID in dotted notation for the birthday on an identity document.
     */
    dateOfBirth: "1.3.6.1.5.5.7.9.1",

    /**
     * The OID in dotted notation for a person's registered phone number.
     */
    telephoneNumber: "2.5.4.20",

    /**
     * The OID in dotted notation for a person's last name.
     */
    surname: "2.5.4.4",

    /**
     * The OID in dotted notation for a document's country.
     */
    country: "2.5.4.6",

    /**
     * The OID in dotted notation for the organization's name.
     */
    organization: "2.5.4.10",

    /**
     * The OID in dotted notation for a person's first name.
     */
    givenName: "2.5.4.42",

    /**
     * The OID in dotted notation for the birth place on an identity document.
     */
    placeOfBirth: "1.3.6.1.5.5.7.9.2",

    /**
     * The OID in dotted notation for a person's registered postal address.
     */
    postalAddress: "2.5.4.16",
}
