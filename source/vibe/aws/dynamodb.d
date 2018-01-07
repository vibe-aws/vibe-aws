/**
  DynamoDB client routines
 */

module vibe.aws.dynamodb;

import std.algorithm;
import std.array;
import std.base64;
import std.conv;
import std.container;
import std.stdio;
import std.string;
import std.traits;
import std.variant;

import vibe.data.json;

import vibe.aws.aws;
import vibe.aws.morejson;

public alias StringSet = RedBlackTree!string;
public alias stringSet = redBlackTree!(false, string);

/**
  Throttled by Control Plane API
 */
class ThrottlingException : AWSException
{
    this(string type, string message)
    {
        super(type, true, message);
    }
}

/**
  Throttled by Data Plane API
 */
class ProvisionedThroughputExceededException : AWSException
{
    this(string type, string message)
    {
        super(type, true, message);
    }
}

class ItemNotFoundException : AWSException
{
    this(string message)
    {
        super("ItemNotFoundException", false, message);
    }
}

/**
  Base DynamoDB client instance

  Construct an instance of this class for the appropriate region, pass in a
  credentials source, and grab a Table instance to do actual work.
 */
class DynamoDB : AWSClient
{
    private static immutable string apiVersion = "DynamoDB_20120810";

    this(string region, AWSCredentialSource credsSource) {
        super("dynamodb." ~ region ~ ".amazonaws.com", region, "dynamodb", credsSource);
    }

    override AWSException makeException(string type, bool retriable, string message)
    {
        // Recognize some specific DynamoDB exceptions that are actually
        // retriable (unlike their error code would suggest)
        if (type == exceptionPrefix ~ "ThrottlingException")
            return new ThrottlingException(type, message);
        if (type == exceptionPrefix ~ "ProvisionedThroughputExceededException")
            return new ProvisionedThroughputExceededException(type, message);
        return super.makeException(type, retriable, message);
    }

    private auto ddbRequest(string command, Json requestBody)
    {
        return doRequest(apiVersion ~ "." ~ command, requestBody);
    }

    @property Table table(string name)
    {
        return new Table(name, this);
    }

    @property auto tables()
    {
        auto resp = ddbRequest("ListTables", Json.emptyObject);
        return resp.responseBody["TableNames"].arrayIterator().map!(t => table(t.get!string));
        // FIXME: continuation token for > 100 tables, but who actually needs that...
    }
}

/**
  A DynamoDB table
 */
class Table
{
    immutable string name;

    private DynamoDB m_client;

    this(string name, DynamoDB client)
    {
        this.name = name;
        m_client = client;
    }

    void put(in Item item)
    {
        auto resp = m_client.ddbRequest("PutItem", Json([
            "TableName": Json(this.name),
            "Item": item.ddbJson
        ]));
    }

    void put(in Item item, string conditionExpression, Item attributeValues)
    {
        auto resp = m_client.ddbRequest("PutItem", Json([
            "TableName": Json(this.name),
            "Item": item.ddbJson,
            "ConditionExpression": Json(conditionExpression),
            "ExpressionAttributeValues": attributeValues.ddbJson
        ]));
    }

    Item get(T)(string hashKey, T hashValue) {
        return get(Json([
            hashKey: variantToDDB(toVariant(hashValue))
            ]));
    }

    Item get(T, U)(string hashKey, T hashValue, string rangeKey, U rangeValue) {
        return get(Json([
            hashKey: variantToDDB(toVariant(hashValue)),
            rangeKey: variantToDDB(toVariant(rangeValue))
            ]));
    }

    private Item get(Json key)
    {
        auto resp = m_client.ddbRequest("GetItem", Json([
            "TableName": Json(this.name),
            "Key": key
        ]));
        
        Item ret;
        auto itemKey = "Item" in resp.responseBody;
        if (!itemKey) 
            throw new ItemNotFoundException("No item with key " ~ key.toString());

        auto obj = itemKey.get!(Json[string]);
        foreach (k; obj.byKey)
        {
            ret.attrs[k] = DDBtoVariant(obj[k]);
        }

        return ret;
    }

    void del(T)(string hashKey, T hashValue) {
        return del(Json([
            hashKey: variantToDDB(toVariant(hashValue))
            ]));
    }

    void del(T, U)(string hashKey, T hashValue, string rangeKey, U rangeValue) {
        return del(Json([
            hashKey: variantToDDB(toVariant(hashValue)),
            rangeKey: variantToDDB(toVariant(rangeValue))
            ]));
    }

    private void del(Json key)
    {
        auto resp = m_client.ddbRequest("DeleteItem", Json([
            "TableName": Json(this.name),
            "Key": key
        ]));
    }
}

/**
  Convert a D variant value to a type-tagged DDB value
 */
private Json variantToDDB(Variant v)
{
    auto ret = Json.emptyObject;
    if (!v.hasValue)
        ret["NULL"] = true;
    else if (v.type == typeid(string))
        ret["S"] = Json(v.get!string);
    else if (v.type == typeid(ubyte[]))
        ret["B"] = Json(Base64.encode(v.get!(ubyte[])));
    else if (v.type == typeid(bool))
        ret["BOOL"] = Json(v.coerce!string);
    else if (v.convertsTo!double)
        ret["N"] = Json(v.coerce!string);
    else if (v.convertsTo!ulong)
        ret["N"] = Json(v.coerce!string);
    else if (v.convertsTo!long)
        ret["N"] = Json(v.coerce!string);
    else if (v.type == typeid(StringSet)) {
        ret["SS"] = Json(v.get!StringSet.array().map!(s => Json(s)).array());
    }
    else if (v.type == typeid(Variant[string])) {
        auto o = Json.emptyObject;
        auto value = v.get!(Variant[string]);
        foreach (name; value.byKey())
            o[name] = variantToDDB(value[name]);
        ret["M"] = o;
    }

    else
        throw new Exception("Unsupported DynamoDB value type: " ~ v.type.to!string);

    // FIXME: support more types
        
    return ret;
}

private Variant DDBtoVariant(Json obj)
{
    if ("NULL" in obj) return Variant();
    auto pv = "S" in obj;
    if (pv) return Variant(pv.get!string);
    pv = "B" in obj;
    if (pv) return Variant(Base64.decode(pv.get!string));
    pv = "BOOL" in obj;
    if (pv) return Variant(pv.get!string == "true");
    pv = "N" in obj;
    if (pv) {
        // Number, but which type?
        if (pv.get!string.indexOf(".") != -1)
            return Variant(pv.get!string.to!double);
        try {
            return Variant(pv.get!string.to!int);
        } catch (ConvOverflowException ex) {
            return Variant(pv.get!string.to!long);
        }
    }
    pv = "SS" in obj;
    if (pv) {
        StringSet ss = stringSet();
        foreach (x; arrayIterator(*pv)) 
        {
            ss.stableInsert(x.get!string);
        }
        return Variant(ss);
    }
    pv = "M" in obj;
    if (pv) {
        // Object
        Json[string] src = pv.get!(Json[string]);
        Variant[string] dest;
        foreach (k; src.byKey)
        {
            dest[k] = DDBtoVariant(src[k]);
        }
        return Variant(dest);
    }

    throw new Exception("Unsupported DynamoDB value: " ~ obj.toString());
}

unittest {
    assert(variantToDDB(Variant("foo"))["S"] == Json("foo"));
    assert(variantToDDB(Variant(3))["N"] == Json("3"));
    assert(variantToDDB(Variant(3.14))["N"] == Json("3.14"));
    assert(variantToDDB(Variant(true))["BOOL"] == Json("true"));
    assert(variantToDDB(Variant(stringSet("a", "b")))["SS"] == Json([Json("a"), Json("b")]));
    //assert(variantToDDB(Variant(["a", "b"]))["SS"] == Json([Json("a"), Json("b")]));
}

private Variant toVariant(T)(T value)
{
    return Variant(value);
}

private Variant toVariant(Variant v)
{
    return v;
}

/**
  A DynamoDB item
 */
struct Item
{
    Variant[string] attrs;

    ref Item set(T)(string key, T value)
        if (!isAssociativeArray!T)
    {
        attrs[key] = toVariant(value);
        return this;
    }

	inout(Variant)* opBinaryRight(string op)(string other) inout if(op == "in") {
		return other in attrs;
	}

    ref Item unset(string key)
    {
        attrs.remove(key);
        return this;
    }

    ref Item set(T)(string key, T[string] values)
    {
        Variant[string] obj;
        foreach (k; values.byKey)
        {
            obj[k] = toVariant(values[k]);
        }
        attrs[key] = obj;

        return this;
    }

    /**
      Convert the item to a DDB JSON representation
     */
    @property Json ddbJson() const
    {
        auto jsonItem = Json.emptyObject; 
        foreach (a; attrs.byKey())
        {
            jsonItem[a] = variantToDDB(attrs[a]);
        }
        return jsonItem;
    }

    Variant opIndex(string key)
    {
        return attrs[key];
    }

    void opIndexAssign(T)(string key, T value)
    {
        attrs[key] = value;
    }
}

unittest {
    Item u;
    u.set("set", stringSet());
    u["set"].get!StringSet.stableInsert("hoi");
    assert("hoi" in u["set"].get!StringSet);
}
