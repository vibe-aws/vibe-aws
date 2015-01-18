module vibe.aws.sigv4;

import std.array;
import std.algorithm;
import std.digest.sha;
import std.range;
import std.stdio;
import std.string;

import vibe.textfilter.urlencode;


const algorithm = "AWS4-HMAC-SHA256";

struct CanonicalRequest 
{
    string method;
    string uri;
    string[string] queryParameters;
    string[string] headers;
    ubyte[] payload;
}

string canonicalQueryString(string[string] queryParameters)
{
    alias encode = vibe.textfilter.urlencode.formEncode;

    string[string] encoded;
    foreach (p; queryParameters.keys()) 
    {
        encoded[encode(p)] = encode(queryParameters[p]);
    }
    string[] keys = encoded.keys();
    sort(keys);
    return keys.map!(k => k ~ "=" ~ encoded[k]).join("&");
}

string canonicalHeaders(string[string] headers)
{
    string[string] trimmed;
    foreach (h; headers.keys())
    {
        trimmed[h.toLower().strip()] = headers[h].strip();
    }
    string[] keys = trimmed.keys();
    sort(keys);
    return keys.map!(k => k ~ ":" ~ trimmed[k] ~ "\n").join("");
}

string signedHeaders(string[string] headers)
{
    string[] keys = headers.keys().map!(k => k.toLower()).array();
    sort(keys);
    return keys.join(";");
}

string hash(T)(T payload)
{
    auto hash = sha256Of(payload);
    return hash.toHexString().toLower();
}

string makeCRSigV4(CanonicalRequest r)
{
    auto cr = 
        r.method.toUpper() ~ "\n" ~
        (r.uri.empty ? "/" : r.uri) ~ "\n" ~
        canonicalQueryString(r.queryParameters) ~ "\n" ~
        canonicalHeaders(r.headers) ~ "\n" ~
        signedHeaders(r.headers) ~ "\n" ~
        hash(r.payload);

    return hash(cr);
}

unittest {
    string[string] empty;

    auto r = CanonicalRequest(
            "POST",
            "/",
            empty,
            ["content-type": "application/x-www-form-urlencoded; charset=utf-8",
             "host": "iam.amazonaws.com",
             "x-amz-date": "20110909T233600Z"],
            cast(ubyte[])"Action=ListUsers&Version=2010-05-08");

    auto sig = makeCRSigV4(r);

    assert(sig == "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2");
}

struct SignableRequest
{
    string dateString;
    string timeStringUTC;
    string region;
    string service;
    CanonicalRequest canonicalRequest;
}

string signableString(SignableRequest r) {
    return algorithm ~ "\n" ~
        r.dateString ~ "T" ~ r.timeStringUTC ~ "Z\n" ~
        r.dateString ~ "/" ~ r.region ~ "/" ~ r.service ~ "/aws4_request\n" ~
        makeCRSigV4(r.canonicalRequest);
}

unittest {
    string[string] empty;

    SignableRequest r;
    r.dateString = "20110909";
    r.timeStringUTC = "233600";
    r.region = "us-east-1";
    r.service = "iam";
    r.canonicalRequest = CanonicalRequest(
            "POST",
            "/",
            empty,
            ["content-type": "application/x-www-form-urlencoded; charset=utf-8",
             "host": "iam.amazonaws.com",
             "x-amz-date": "20110909T233600Z"],
            cast(ubyte[])"Action=ListUsers&Version=2010-05-08");

    auto sampleString =
        algorithm ~ "\n" ~
        "20110909T233600Z\n" ~
        "20110909/us-east-1/iam/aws4_request\n" ~ 
        "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2";

    assert(sampleString == signableString(r));
}

ubyte[] array_xor(ubyte[] b1, ubyte[] b2)
{
    assert(b1.length == b2.length);
    ubyte[] ret;
    for (uint i = 0; i < b1.length; i++)
        ret ~= b1[i] ^ b2[i];
    return ret;
}

auto hmac_sha256(R)(ubyte[] key, R message)
{
    ubyte[] paddedKey = key[0..$];
    while (paddedKey.length < 64) paddedKey ~= 0; // Pad to input block size of sha256
    ubyte[] opad = (cast(ubyte)0x5c).repeat().take(64).array();
    ubyte[] ipad = (cast(ubyte)0x36).repeat().take(64).array();

    return sha256Of(array_xor(paddedKey, opad).chain(cast(ubyte[])sha256Of(array_xor(paddedKey, ipad).chain(message))));
}

unittest {
    ubyte[] key = cast(ubyte[])"key";
    ubyte[] message = cast(ubyte[])"The quick brown fox jumps over the lazy dog";

    string mac = hmac_sha256(key, message).toHexString().toLower();
    assert(mac == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}

auto signingKey(string secret, string dateString, string region, string service)
{
    ubyte[] kSecret = cast(ubyte[])("AWS4" ~ secret);
    auto kDate = hmac_sha256(kSecret, cast(ubyte[])dateString);
    auto kRegion = hmac_sha256(kDate, cast(ubyte[])region);
    auto kService = hmac_sha256(kRegion, cast(ubyte[])service);
    return hmac_sha256(kService, cast(ubyte[])"aws4_request");
}

unittest {
    string secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    auto signKey = signingKey(secretKey, "20110909", "us-east-1", "iam");
    
    ubyte[] expected = [152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43, 171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229, 169, 76, 144, 239, 209, 227, 176, 231 ];
    assert(expected == signKey);
}

alias sign = hmac_sha256;

unittest {
    auto sampleString =
        "AWS4-HMAC-SHA256\n" ~
        "20110909T233600Z\n" ~
        "20110909/us-east-1/iam/aws4_request\n" ~ 
        "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2";

    auto secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    auto signKey = signingKey(secretKey, "20110909", "us-east-1", "iam");

    auto signature = sign(signKey, cast(ubyte[])sampleString).toHexString().toLower();
    auto expected = "ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c";

    assert(signature == expected);
}

/**
 * CredentialScope == date / region / service / aws4_request
 */
string createSignatureHeader(string accessKeyID, string credentialScope, string[string] reqHeaders, ubyte[] signature)
{
    return algorithm ~ " Credential=" ~ accessKeyID ~ "/" ~ credentialScope ~ "/aws4_request, SignedHeaders=" ~ signedHeaders(reqHeaders) ~ ", Signature=" ~ signature.toHexString().toLower();
}

string dateFromISOString(string iso)
{
    auto i = iso.indexOf('T');
    if (i == -1) throw new Exception("ISO time in wrong format: " ~ iso);
    return iso[0..i];
}

string timeFromISOString(string iso)
{
    auto t = iso.indexOf('T');
    auto z = iso.indexOf('Z');
    if (t == -1 || z == -1) throw new Exception("ISO time in wrong format: " ~ iso);
    return iso[t+1..z];
}

unittest {
    assert(dateFromISOString("20110909T1203Z") == "20110909");
}
