/**
  Vibe-based AWS client
 */

module vibe.aws.aws;

import std.algorithm;
import std.datetime;
import std.random;
import std.range;
import std.stdio;
import std.string;

import vibe.core.core;
import vibe.core.log;
import vibe.data.json;
import vibe.http.client;

import vibe.aws.sigv4;

public import vibe.aws.credentials;

class AWSException : Exception
{
    immutable string type;
    immutable bool retriable;

    this(string type, bool retriable, string message)
    {
        super(type ~ ": " ~ message);
        this.type = type;
        this.retriable = retriable;
    }

    /**
      Returns the 'ThrottlingException' from 'com.amazon.coral.service#ThrottlingException'
     */
    @property string simpleType() 
    {
        auto h = type.indexOf('#');
        if (h == -1) return type;
        return type[h+1..$];
    }
}

/**
  Configuraton for AWS clients
 */
struct ClientConfiguration
{
    uint maxErrorRetry = 3;
}

/**
  Thrown when the signature/authorization information is wrong
 */
class AuthorizationException : AWSException
{
    this(string type, string message)
    {
        super(type, false, message);
    }
}

struct ExponentialBackoff
{
    immutable uint maxRetries;
    uint tries = 0;
    uint maxSleepMs = 10;

    this(uint maxRetries)
    {
        this.maxRetries = maxRetries;
    }

    @property bool canRetry()
    {
        return tries < maxRetries;
    }

    @property bool finished()
    {
        return tries >= maxRetries + 1;
    }

    void inc()
    {
        tries++;
        maxSleepMs *= 2;
    }

    void sleep()
    {
        vibe.core.core.sleep(uniform!("[]")(1, maxSleepMs).msecs);
    }
}

class AWSClient {
    protected static immutable exceptionPrefix = "com.amazon.coral.service#";

    immutable string endpoint;
    immutable string region;
    immutable string service;

    private AWSCredentialSource m_credsSource;
    private ClientConfiguration m_config;

    this(string endpoint, string region, string service, AWSCredentialSource credsSource, ClientConfiguration config=ClientConfiguration()) 
    {
        this.region = region;
        this.endpoint = endpoint;
        this.service = service;
        this.m_credsSource = credsSource;
        this.m_config = config;
    }

    AWSResponse doRequest(string operation, Json request)
    {
        auto backoff = ExponentialBackoff(m_config.maxErrorRetry);

        for (; !backoff.finished; backoff.inc())
        {
            auto credScope = region ~ "/" ~ service;
            auto creds = m_credsSource.credentials(credScope);
            try
            {
                // FIXME: Auto-retries for retriable errors
                // FIXME: Report credential errors and retry for failed credentials
                auto resp = requestHTTP("https://" ~ endpoint ~ "/", (scope req) {
                    auto timeString = currentTimeString();
                    auto jsonString = cast(ubyte[])request.toString();

                    req.method = HTTPMethod.POST;
                    req.headers["x-amz-target"] = operation;
                    req.headers["x-amz-date"] = currentTimeString();
                    req.headers["host"] = endpoint;
                    if (creds.sessionToken && !creds.sessionToken.empty)
                        req.headers["x-amz-security-token"] = creds.sessionToken;
                    req.contentType = "application/x-amz-json-1.0";
                    signRequest(req, jsonString, creds, timeString, region, service);
                    req.writeBody(jsonString);
                });

                checkForError(resp);

                return new AWSResponse(resp);
            }
            catch (AuthorizationException ex)
            {
                logWarn(ex.msg);
                // Report credentials as invalid. Will retry if possible.
                m_credsSource.credentialsInvalid(credScope, creds, ex.msg);
                if (!backoff.canRetry) throw ex;
            }
            catch (AWSException ex)
            {
                logWarn(ex.msg);
                // Retry if possible and retriable, otherwise give up.
                if (!backoff.canRetry || !ex.retriable) throw ex;
            }

            // We're going again, but sleep first
            backoff.sleep();
        }
        assert(0);
    }

    protected auto currentTimeString()
    {
        auto t = Clock.currTime(UTC());
        t.fracSecs = Duration.zero;
        return t.toISOString();
    }

    void checkForError(HTTPClientResponse response)
    {
        if (response.statusCode < 400) return; // No error

        auto bod = response.readJson();

        //logError("error: %s",bod);

        throw makeException(bod["__type"].get!string, response.statusCode / 100 == 5, bod["Message"].opt!string(""));
    }
    
    AWSException makeException(string type, bool retriable, string message)
    {
        if (type == exceptionPrefix ~ "UnrecognizedClientException" || type == exceptionPrefix ~ "InvalidSignatureException" || type == exceptionPrefix ~ "AccessDeniedException")
            throw new AuthorizationException(type, message);
        return new AWSException(type, retriable, message);
    }
}

private void signRequest(HTTPClientRequest req, ubyte[] requestBody, AWSCredentials creds, string timeString, string region, string service)
{
    auto dateString = dateFromISOString(timeString);
    auto credScope = dateString ~ "/" ~ region ~ "/" ~ service;

    SignableRequest signRequest;
    signRequest.dateString = dateString;
    signRequest.timeStringUTC = timeFromISOString(timeString);
    signRequest.region = region;
    signRequest.service = service;
    import std.conv:to;
    signRequest.canonicalRequest.method = req.method.to!string();
    signRequest.canonicalRequest.uri = req.requestURL; // FIXME: Can include query params
    auto reqHeaders = req.headers.toRepresentation;
    foreach (x; reqHeaders) {
        if(x.key.toLower == "connection")
            continue;
        signRequest.canonicalRequest.headers[x.key] = x.value;
    }
    signRequest.canonicalRequest.payload = requestBody;

    ubyte[] signKey = signingKey(creds.accessKeySecret, dateString, region, service).dup;
    ubyte[] stringToSign = cast(ubyte[])signableString(signRequest);
    auto signature = sign(signKey, stringToSign);

    auto authHeader = createSignatureHeader(creds.accessKeyID, credScope, signRequest.canonicalRequest.headers, signature);
    req.headers["authorization"] = authHeader;
}

class AWSResponse
{
    private HTTPClientResponse m_response;
    private Json m_body;

    this(HTTPClientResponse response)
    {
        m_response = response;
        m_body = response.readJson();
    }

    @property Json responseBody() { return m_body; }
}
