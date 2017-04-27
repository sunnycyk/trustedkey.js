//
//  oid.js
//
//  Copyright © 2017 Trusted Key Solutions. All rights reserved.
//

/**
 * Some well-known OIDs, for convenience.
 *
 * @exports oid
 */
module.exports = {

    /**
     * The OID in dotted notation for an identity document's ID number.
     * @constant
     * @default
     */
    documentID: "1.3.6.1.4.1.53318295.2",

    /**
     * The OID in dotted notation for an identity document's type, for example "Passport".
     * @constant
     * @default
     */
    documentType: "1.3.6.1.4.1.53318295.1",

    /**
     * The OID in dotted notation for an identity document's photo.
     * @constant
     * @default
     */
    documentImage: "1.3.6.1.4.1.53318295.3",

    /**
     * The OID in dotted notation for an identity document's issuer.
     * @constant
     * @default
     */
    documentIssuer: "1.3.6.1.4.1.53318295.4",

    /**
     * The OID in dotted notation for the result of the document verification.
     * @constant
     * @default
     */
    documentResult: "1.3.6.1.4.1.53318295.5",

    /**
     * The OID in dotted notation for the gender (F/M) on an identity document.
     * @constant
     * @default
     */
    gender: "1.3.6.1.5.5.7.9.3",

    /**
     * The OID in dotted notation for a person's email address.
     * @constant
     * @default
     */
    email: "1.2.840.113549.1.9.1",

    /**
     * The OID in dotted notation for a person's full name.
     * @constant
     * @default
     */
    commonName: "2.5.4.3",

    /**
     * The OID in dotted notation for the birthday on an identity document.
     * @constant
     * @default
     */
    dateOfBirth: "1.3.6.1.5.5.7.9.1",

    /**
     * The OID in dotted notation for a person's registered phone number.
     * @constant
     * @default
     */
    telephoneNumber: "2.5.4.20",

    /**
     * The OID in dotted notation for a person's last name.
     * @constant
     * @default
     */
    surname: "2.5.4.4",

    /**
     * The OID in dotted notation for a document's country.
     * @constant
     * @default
     */
    country: "2.5.4.6",

    /**
     * The OID in dotted notation for the organization's name.
     * @constant
     * @default
     */
    organization: "2.5.4.10",

    /**
     * The OID in dotted notation for a person's first name.
     * @constant
     * @default
     */
    givenName: "2.5.4.42",

    /**
     * The OID in dotted notation for the birth place on an identity document.
     * @constant
     * @default
     */
    placeOfBirth: "1.3.6.1.5.5.7.9.2",

    /**
     * The OID in dotted notation for a person's registered postal address.
     * @constant
     * @default
     */
    postalAddress: "2.5.4.16",
}
