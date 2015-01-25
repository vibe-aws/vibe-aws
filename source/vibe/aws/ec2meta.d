/**
  Access to the EC2 metadata service
 */

module vibe.aws.ec2meta;

import std.datetime;
import std.range;
import std.string;
import std.typecons;

import vibe.core.log;
import vibe.data.json;
import vibe.http.client;
import vibe.stream.operations;

import vibe.aws.aws;
import vibe.aws.credentials;

class EC2RoleException : AWSException
{
    this(bool retriable, string message)
    {
        super("EC2RoleException", retriable, message);
    }
}

/**
  Obtain AWS credentials from an EC2 role
 */
class EC2Role : AWSCredentialSource
{
    private static immutable string metadataURL = "http://169.254.169.254/latest/meta-data/";
    string m_role;
    private Nullable!AWSCredentials m_cachedCredentials;
    private SysTime m_expiry;

    this(string role=null)
    {
        m_role = role;
    }

    @property string role() 
    {
        return m_role;
    }

    @property bool cachedCredentialsAvailable()
    {
        return !m_cachedCredentials.isNull && Clock.currTime < m_expiry ;
    }

    AWSCredentials credentials(string credScope)
    {
        if (cachedCredentialsAvailable)
            return m_cachedCredentials;

        detectRole();

        logInfo("Retrieving " ~ metadataURL ~ "iam/security-credentials/" ~ m_role);
        auto resp = requestHTTP(metadataURL ~ "iam/security-credentials/" ~ m_role);
        if (resp.statusCode == 404)
            throw new EC2RoleException(false, "No such EC2 role for this instance: " ~ m_role);

        if (resp.statusCode != 200)
            throw new EC2RoleException(false, "Error getting credentials for role: " ~ m_role ~ ": " ~ resp.statusPhrase);

		auto bdy = resp.bodyReader.readAllUTF8();
        Json jsonResponse = parseJsonString(bdy);

        auto accessKeyID = jsonResponse["AccessKeyId"].get!string;
        auto accessKeySecret = jsonResponse["SecretAccessKey"].get!string;
        auto sessionToken = jsonResponse["Token"].get!string;

        auto expiryDT = SysTime.fromISOExtString(jsonResponse["Expiration"].get!string);

        m_cachedCredentials = AWSCredentials(accessKeyID, accessKeySecret, sessionToken);
        m_expiry = expiryDT;

        return m_cachedCredentials;
    }

    void credentialsInvalid(string credScope, AWSCredentials creds, string reason)
    {
        // Not much we can do about that, error it out
        m_cachedCredentials.nullify();
        throw new EC2RoleException(false,
                format("EC2 credentials for role %s rejected for scope %s: %s",
                       m_role,
                       credScope,
                       reason));
    }

    /**
      Try to auto-detect the instance's role name from the metadata service
     */
    private void detectRole()
    {
        if (m_role != null && !m_role.empty) return;

        logInfo("Retrieving " ~ metadataURL ~ "iam/security-credentials/");
        auto resp = requestHTTP(metadataURL ~ "iam/security-credentials/");
        if (resp.statusCode != 200)
            throw new EC2RoleException(false, "Error autodetecting EC2 role name: " ~ resp.statusPhrase);
		auto bdy = resp.bodyReader.readAllUTF8();
        if (bdy == "")
            throw new EC2RoleException(false, "Error autodetecting EC2 role name: no role found");
        logDebug("Response: " ~ bdy);
        m_role = bdy;
    }
}

unittest {
    // Should parse
    auto t = SysTime.fromISOExtString("2015-01-23T04:07:43Z");
}
