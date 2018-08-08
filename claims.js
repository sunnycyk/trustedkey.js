//
//  claims.js
//
//  Copyright © 2018 Trusted Key Solutions. All rights reserved.
//
const OID = require('./oid')

/**
 * Some well-known OpenID Connect claims, for convenience.
 * @type {Object.<string,Dotted?>}
 *
 * @exports Claims
 */
module.exports = {
  name: OID.commonName,
  family_name: OID.surname,
  given_name: OID.givenName,
  profile: OID.socialProfile,
  picture: OID.documentImageHead, // FIXME: should return URL
  email: OID.emailAddress,
  address: OID.postalAddress,
  phone_number: OID.telephoneNumber,
  phone_number_verified: OID.telephoneNumber,
  gender: OID.gender,
  birthdate: OID.dateOfBirth,
  'https://auth.trustedkey.com/root': null,
  // These are the known OIDs, excluding claims declared by OIDC spec:
  'https://auth.trustedkey.com/documentID': OID.documentID,
  'https://auth.trustedkey.com/documentType': OID.documentType,
  'https://auth.trustedkey.com/documentClass': OID.documentClass,
  'https://auth.trustedkey.com/documentImageFront': OID.documentImageFront,
  'https://auth.trustedkey.com/documentImageBack': OID.documentImageBack,
  'https://auth.trustedkey.com/documentIssuer': OID.documentIssuer,
  'https://auth.trustedkey.com/documentResult': OID.documentResult,
  'https://auth.trustedkey.com/documentIssueDate': OID.documentIssueDate,
  'https://auth.trustedkey.com/documentDigest': OID.documentDigest,
  'https://auth.trustedkey.com/documentThumb': OID.documentThumb,
  'https://auth.trustedkey.com/country': OID.country,
  'https://auth.trustedkey.com/locality': OID.locality,
  'https://auth.trustedkey.com/postalCode': OID.postalCode,
  'https://auth.trustedkey.com/stateOrProvinceName': OID.stateOrProvinceName,
  'https://auth.trustedkey.com/organization': OID.organization,
  'https://auth.trustedkey.com/placeOfBirth': OID.placeOfBirth,
  'https://auth.trustedkey.com/streetAddress': OID.streetAddress,
  'https://auth.trustedkey.com/courseName': OID.courseName,
  'https://auth.trustedkey.com/courseContents': OID.courseContents,
  'https://auth.trustedkey.com/publicKey': OID.publicKey,
  'https://auth.trustedkey.com/age21OrUp': OID.age21OrUp
}
